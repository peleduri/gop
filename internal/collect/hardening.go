package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Repo hardening: default-branch protection (classic and rulesets),
// CODEOWNERS and secret scanning. Every fact is context: the engine never
// reads it. Anything the token cannot read is "unknown" with not_visible
// evidence and a coverage entry, never "false" or "off".

// ---- secret scanning ----

type apiStatus struct {
	Status string `json:"status"`
}

// apiSecurityAnalysis is the security_and_analysis block of a repository,
// returned only to repo admins, org owners and security managers.
type apiSecurityAnalysis struct {
	SecretScanning *apiStatus `json:"secret_scanning"`
	PushProtection *apiStatus `json:"secret_scanning_push_protection"`
	ValidityChecks *apiStatus `json:"secret_scanning_validity_checks"`
}

func statusValue(s *apiStatus) (string, bool) {
	if s == nil {
		return "unknown", false
	}
	switch s.Status {
	case "enabled":
		return "on", true
	case "disabled":
		return "off", true
	}
	return "unknown", false
}

// secretTally counts the repos of one org whose secret scanning facts were
// not visible, for one coverage entry per org.
type secretTally struct {
	hidden, noValidity, repos int
}

// applySecretScanning records secret_scanning, push protection and validity
// checks on a non-archived repo from the listing's security_and_analysis.
func applySecretScanning(repo *graph.Node, sa *apiSecurityAnalysis, t *secretTally) {
	t.repos++
	if sa == nil {
		t.hidden++
		for _, a := range []string{graph.AttrSecretScanning, graph.AttrSecretPushProtection, graph.AttrSecretValidity} {
			setAttr(repo, a, "unknown", graph.NotVisible)
		}
		return
	}
	for _, f := range []struct {
		attr string
		s    *apiStatus
	}{{graph.AttrSecretScanning, sa.SecretScanning}, {graph.AttrSecretPushProtection, sa.PushProtection}, {graph.AttrSecretValidity, sa.ValidityChecks}} {
		v, ok := statusValue(f.s)
		ev := graph.Live
		if !ok {
			ev = graph.NotVisible
			if f.attr == graph.AttrSecretValidity {
				t.noValidity++
			}
		}
		setAttr(repo, f.attr, v, ev)
	}
}

func (k *collector) coverSecretScanning(o *orgState, t secretTally) {
	if t.hidden > 0 {
		k.cover(o.node.ID, graph.FactSecretScanning,
			fmt.Sprintf("security_and_analysis not returned for %d of %d repositories (shown only to repo admins, org owners and security managers)", t.hidden, t.repos),
			"admin on those repositories, or org owner or security manager in "+o.login)
	}
	if t.noValidity > 0 {
		k.cover(o.node.ID, graph.AttrSecretValidity,
			fmt.Sprintf("security_and_analysis did not report secret_scanning_validity_checks for %d repositories", t.noValidity),
			"a host and token that report validity checks in security_and_analysis (GitHub Advanced Security)")
	}
}

// ---- CODEOWNERS ----

// codeownersPaths are the locations GitHub reads CODEOWNERS from, in the
// order it looks: the first one that exists is used.
var codeownersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// codeownersExprs are the batched object expressions for codeownersPaths.
func codeownersExprs() []string {
	out := make([]string, len(codeownersPaths))
	for i, p := range codeownersPaths {
		out[i] = "HEAD:" + p
	}
	return out
}

// applyCodeownersObjs records CODEOWNERS facts from the batched objects for
// codeownersPaths (nil: no such file).
func (k *collector) applyCodeownersObjs(repo *graph.Node, objs []*gqlObject) {
	for i, obj := range objs {
		if obj == nil || obj.Typename != "Blob" {
			continue
		}
		if !obj.complete() {
			k.codeownersUnknown(repo, codeownersPaths[i], errTooLarge.Error())
			return
		}
		k.setCodeowners(repo, codeownersPaths[i], []byte(*obj.Text))
		return
	}
	setAttr(repo, graph.AttrCodeowners, "none", graph.Live)
	setAttr(repo, graph.AttrCodeownersWorkflows, "false", graph.Live)
}

// collectCodeowners reads CODEOWNERS over REST: up to one contents GET per
// location, stopping at the first file found.
func (k *collector) collectCodeowners(ctx context.Context, o *orgState, repo *graph.Node) error {
	name := repoName(o, repo)
	for _, p := range codeownersPaths {
		data, err := k.getFile(ctx, o.login, name, p, "")
		switch {
		case err == nil:
			k.setCodeowners(repo, p, data)
			return nil
		case ctx.Err() != nil:
			return ctx.Err()
		case IsNotFound(err):
			continue
		default:
			k.codeownersUnknown(repo, p, err.Error())
			return nil
		}
	}
	setAttr(repo, graph.AttrCodeowners, "none", graph.Live)
	setAttr(repo, graph.AttrCodeownersWorkflows, "false", graph.Live)
	return nil
}

func (k *collector) codeownersUnknown(repo *graph.Node, path, why string) {
	full := strings.TrimPrefix(repo.ID, "repo:")
	setAttr(repo, graph.AttrCodeowners, "unknown", graph.NotVisible)
	setAttr(repo, graph.AttrCodeownersWorkflows, "unknown", graph.NotVisible)
	k.cover(repo.ID, graph.FactCodeowners, "could not read "+path+": "+why, "read access to contents on "+full)
}

func (k *collector) setCodeowners(repo *graph.Node, path string, data []byte) {
	co := ParseCodeowners(data)
	k.codeowners[repo.ID] = co
	setAttr(repo, graph.AttrCodeowners, path, graph.Live)
	setAttr(repo, graph.AttrCodeownersValid, strconv.FormatBool(co.Valid), graph.Live)
	setAttr(repo, graph.AttrCodeownersWorkflows, strconv.FormatBool(co.Workflows), graph.Live)
}

// Codeowners is what gop keeps of a CODEOWNERS file: no owner names.
type Codeowners struct {
	// Valid is false when a line has syntax GitHub skips (a negation, a
	// character range, an owner that is neither @user, @org/team nor an
	// email).
	Valid bool
	// Workflows is true when the last rule matching files in
	// .github/workflows/ (both .yml and .yaml) names at least one owner, so a
	// workflow change needs a code owner's review when the branch requires it.
	Workflows bool
	// rules are the valid rules in file order, for Owns.
	rules []coRule
}

// coRule is one valid CODEOWNERS line: its pattern and whether it names an owner.
type coRule struct {
	pattern string
	owned   bool
}

// Owns reports whether the last rule matching path names an owner.
func (co Codeowners) Owns(path string) bool {
	owned := false
	for _, r := range co.rules {
		if coMatch(r.pattern, path) {
			owned = r.owned // the last matching rule wins
		}
	}
	return owned
}

var coOwnerRe = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9-]*(/[A-Za-z0-9._-]+)?|[^@\s]+@[^@\s]+\.[^@\s]+)$`)

// workflowProbes are the paths a rule must cover for Workflows.
var workflowProbes = []string{".github/workflows/gop.yml", ".github/workflows/gop.yaml"}

// ParseCodeowners parses CODEOWNERS text. Invalid lines are skipped, as
// GitHub does, and make Valid false.
func ParseCodeowners(data []byte) Codeowners {
	co := Codeowners{Valid: true}
	var rules []coRule
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		pat := strings.ReplaceAll(fields[0], `\#`, "#")
		ok := !strings.HasPrefix(pat, "!") && !strings.ContainsAny(pat, "[]")
		owners := 0
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break
			}
			if !coOwnerRe.MatchString(f) {
				ok = false
				break
			}
			owners++
		}
		if !ok {
			co.Valid = false
			continue
		}
		rules = append(rules, coRule{pat, owners > 0})
	}
	co.rules = rules
	co.Workflows = true
	for _, p := range workflowProbes {
		co.Workflows = co.Workflows && co.Owns(p)
	}
	return co
}

// coMatch reports whether a CODEOWNERS (gitignore-style) pattern matches
// path or one of its parent directories.
func coMatch(pattern, path string) bool {
	p := pattern
	anchored := strings.HasPrefix(p, "/")
	p = strings.TrimPrefix(p, "/")
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return false
	}
	if strings.Contains(p, "/") {
		anchored = true
	}
	re, err := regexp.Compile("^" + globRegex(p) + "$")
	if err != nil {
		return false
	}
	segs := strings.Split(path, "/")
	for i := 1; i <= len(segs); i++ {
		if dirOnly && i == len(segs) {
			continue // a directory pattern never matches the file itself
		}
		if anchored {
			if re.MatchString(strings.Join(segs[:i], "/")) {
				return true
			}
			continue
		}
		for j := 0; j < i; j++ {
			if re.MatchString(strings.Join(segs[j:i], "/")) {
				return true
			}
		}
	}
	return false
}

// globRegex turns a gitignore glob into a regexp: ** spans directories, *
// and ? stay within one path segment.
func globRegex(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '*' && i+1 < len(p) && p[i+1] == '*':
			i++
			if i+1 < len(p) && p[i+1] == '/' {
				i++
				b.WriteString("(?:.*/)?")
			} else {
				b.WriteString(".*")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// ---- default-branch protection ----

// protSource is one source of default-branch rules: classic branch
// protection or one ruleset.
type protSource struct {
	id            string // classic | ruleset:<id>
	reviews       int
	codeOwner     bool
	dismissStale  bool
	lastPush      bool
	signed        bool
	blocksForce   bool
	restrictsPush bool
	checks        []string
	// detailsHidden: a classic rule whose admin-only details (dismiss stale,
	// last push approval, push restrictions) are not visible.
	detailsHidden bool
	admin, app    string // true | false | unknown: admins / an app get past this source
	bypass        int
	bypassHidden  bool
	// apps are the GitHub Apps that get past this source, by app ID (the
	// value is the slug when known). nil when gop could not list them.
	apps map[int64]string
}

// protFacts is the default-branch protection of one repo before merging.
type protFacts struct {
	sources []protSource
	// unknownWhy is set when a source could not be read at all: values it
	// could set are unknown.
	unknownWhy, unknownFix string
	// hidden counts what only an admin sees, for the org coverage entry.
	hidden bool
	// skip: an empty repository (no default branch): no attrs are written.
	skip bool
}

func newRuleset(id string) protSource {
	return protSource{id: id, admin: "false", app: "false", apps: map[int64]string{}}
}

// merge turns the sources into repo attrs and per-value sources. A
// requirement holds when any source sets it; a bypass only when every source
// allows it. A source gop could not read makes every value it could change
// unknown, except a requirement another source already sets.
func (pf *protFacts) merge() (vals map[string]string, unknown map[string]bool, valueSrc []string) {
	vals, unknown = map[string]string{}, map[string]bool{}
	partial := pf.unknownWhy != ""
	set := func(attr, v string) {
		vals[attr] = v
		if v == "unknown" {
			unknown[attr] = true
		}
	}
	if len(pf.sources) == 0 {
		if partial {
			for _, a := range []string{graph.AttrBranchProtected, graph.AttrBranchReviews, graph.AttrBranchCodeOwnerReview,
				graph.AttrBranchForcePush} {
				set(a, "unknown")
			}
			return vals, unknown, nil
		}
		set(graph.AttrBranchProtected, "false")
		set(graph.AttrBranchReviews, "0")
		for _, a := range []string{graph.AttrBranchCodeOwnerReview, graph.AttrBranchDismissStale, graph.AttrBranchLastPush,
			graph.AttrBranchSignedCommits, graph.AttrBranchPushRestricted} {
			set(a, "false")
		}
		set(graph.AttrBranchStatusChecks, "0")
		set(graph.AttrBranchForcePush, "true")
		set(graph.AttrBranchBypassActors, "0")
		set(graph.AttrBranchSources, "none")
		return vals, unknown, nil
	}
	set(graph.AttrBranchProtected, "true")
	sort.SliceStable(pf.sources, func(i, j int) bool { return sourceLess(pf.sources[i].id, pf.sources[j].id) })
	ids := make([]string, 0, len(pf.sources))
	for _, s := range pf.sources {
		ids = append(ids, s.id)
	}
	set(graph.AttrBranchSources, strings.Join(ids, ","))
	who := func(key string, pick func(protSource) bool) {
		var by []string
		for _, s := range pf.sources {
			if pick(s) {
				by = append(by, s.id)
			}
		}
		if len(by) > 0 {
			valueSrc = append(valueSrc, key+"="+strings.Join(by, "+"))
		}
	}

	maxRev := 0
	for _, s := range pf.sources {
		maxRev = max(maxRev, s.reviews)
	}
	if maxRev == 0 && partial {
		set(graph.AttrBranchReviews, "unknown")
	} else {
		set(graph.AttrBranchReviews, strconv.Itoa(maxRev))
		if maxRev > 0 {
			who("required_reviews", func(s protSource) bool { return s.reviews == maxRev })
		}
	}

	flag := func(attr, key string, get func(protSource) bool, detail bool) {
		hidden := partial
		for _, s := range pf.sources {
			if detail && s.detailsHidden {
				hidden = true
			}
		}
		for _, s := range pf.sources {
			if get(s) {
				set(attr, "true")
				who(key, get)
				return
			}
		}
		if hidden {
			set(attr, "unknown")
		} else {
			set(attr, "false")
		}
	}
	flag(graph.AttrBranchCodeOwnerReview, "require_code_owner_review", func(s protSource) bool { return s.codeOwner }, false)
	flag(graph.AttrBranchDismissStale, "dismiss_stale_reviews", func(s protSource) bool { return s.dismissStale }, true)
	flag(graph.AttrBranchLastPush, "require_last_push_approval", func(s protSource) bool { return s.lastPush }, true)
	flag(graph.AttrBranchSignedCommits, "require_signed_commits", func(s protSource) bool { return s.signed }, false)
	flag(graph.AttrBranchPushRestricted, "push_restricted", func(s protSource) bool { return s.restrictsPush }, true)

	checks := map[string]bool{}
	for _, s := range pf.sources {
		for _, c := range s.checks {
			checks[c] = true
		}
	}
	if len(checks) == 0 && partial {
		set(graph.AttrBranchStatusChecks, "unknown")
	} else {
		set(graph.AttrBranchStatusChecks, strconv.Itoa(len(checks)))
		if len(checks) > 0 {
			who("required_status_checks", func(s protSource) bool { return len(s.checks) > 0 })
		}
	}

	// Force push: blocked by any source.
	blocked := false
	for _, s := range pf.sources {
		blocked = blocked || s.blocksForce
	}
	switch {
	case blocked:
		set(graph.AttrBranchForcePush, "false")
		who("allow_force_push", func(s protSource) bool { return s.blocksForce })
	case partial:
		set(graph.AttrBranchForcePush, "unknown")
	default:
		set(graph.AttrBranchForcePush, "true")
	}

	// Bypass: every source must allow it.
	bypass := func(attr, key string, get func(protSource) string) {
		anyUnknown := partial
		for _, s := range pf.sources {
			switch get(s) {
			case "false":
				set(attr, "false")
				who(key, func(s protSource) bool { return get(s) == "false" })
				return
			case "unknown":
				anyUnknown = true
			}
		}
		if anyUnknown {
			set(attr, "unknown")
			return
		}
		set(attr, "true")
		who(key, func(protSource) bool { return true })
	}
	bypass(graph.AttrBranchAdminBypass, "admin_bypass", func(s protSource) string { return s.admin })
	bypass(graph.AttrBranchAppBypass, "app_bypass", func(s protSource) string { return s.app })
	if vals[graph.AttrBranchAppBypass] == "true" {
		if apps := bypassApps(pf.sources); apps != "" {
			set(graph.AttrBranchBypassApps, apps)
		}
	}

	total, hidden := 0, partial
	for _, s := range pf.sources {
		total += s.bypass
		hidden = hidden || s.bypassHidden
	}
	if hidden {
		set(graph.AttrBranchBypassActors, "unknown")
	} else {
		set(graph.AttrBranchBypassActors, strconv.Itoa(total))
	}
	return vals, unknown, valueSrc
}

// sourceLess orders classic first, then rulesets by numeric ID.
func sourceLess(a, b string) bool {
	if (a == "classic") != (b == "classic") {
		return a == "classic"
	}
	na, ea := strconv.ParseInt(strings.TrimPrefix(a, "ruleset:"), 10, 64)
	nb, eb := strconv.ParseInt(strings.TrimPrefix(b, "ruleset:"), 10, 64)
	if ea == nil && eb == nil {
		return na < nb
	}
	return a < b
}

// protectionAttrs lists every attr merge can set, to clear them first.
var protectionAttrs = []string{graph.AttrBranchProtected, graph.AttrBranchReviews, graph.AttrBranchCodeOwnerReview,
	graph.AttrBranchDismissStale, graph.AttrBranchLastPush, graph.AttrBranchStatusChecks, graph.AttrBranchSignedCommits,
	graph.AttrBranchForcePush, graph.AttrBranchPushRestricted, graph.AttrBranchBypassActors, graph.AttrBranchAdminBypass,
	graph.AttrBranchAppBypass, graph.AttrBranchBypassApps, graph.AttrBranchSources, graph.AttrBranchValueSources}

// applyProtFacts writes the merged facts on repo.
func (k *collector) applyProtFacts(repo *graph.Node, pf *protFacts) {
	vals, unknown, valueSrc := pf.merge()
	for _, a := range protectionAttrs {
		v, ok := vals[a]
		if !ok {
			continue
		}
		ev := graph.Live
		if unknown[a] {
			ev = graph.NotVisible
		}
		setAttr(repo, a, v, ev)
	}
	if len(valueSrc) > 0 {
		setAttr(repo, graph.AttrBranchValueSources, strings.Join(valueSrc, ","), graph.Live)
	}
	if pf.unknownWhy != "" {
		k.cover(repo.ID, graph.FactBranchProtection, pf.unknownWhy, pf.unknownFix)
	}
}

// hardenRepo is one repo whose default-branch protection gop reads.
type hardenRepo struct {
	o    *orgState
	repo *graph.Node
}

// collectBranchProtection reads the default-branch protection of every
// collected, non-archived repository: in batched GraphQL queries (one per
// DefaultBatchSize repositories sharing a client), falling back to REST for
// a repository whose alias fails, or for all of them when batching is off.
func (k *collector) collectBranchProtection(ctx context.Context) error {
	var all []hardenRepo
	for _, o := range k.orgs {
		for _, r := range o.repos {
			if r.Attrs[graph.AttrArchived] == "true" {
				continue
			}
			all = append(all, hardenRepo{o, r})
		}
	}
	hidden := map[*orgState]int{}
	done, total := 0, len(all)
	for len(all) > 0 {
		c := k.cl(all[0].o.login)
		n := 1
		for n < len(all) && n < k.batch.size && k.cl(all[n].o.login) == c {
			n++
		}
		chunk := all[:n]
		all = all[n:]
		res, err := k.fetchProtection(ctx, c, chunk)
		if err != nil {
			return err
		}
		for i, hr := range chunk {
			pf := res[i]
			if pf == nil {
				if hr.repo.Attrs["default_branch"] == "" {
					done++
					continue // empty repository: no default branch to protect
				}
				if pf, err = k.restProtection(ctx, hr.o, hr.repo); err != nil {
					return err
				}
			}
			if pf.skip {
				done++
				continue
			}
			if pf.hidden {
				hidden[hr.o]++
			}
			k.applyProtFacts(hr.repo, pf)
			done++
		}
		k.progress(PhaseProtection, done, total)
	}
	for _, o := range k.orgs {
		if n := hidden[o]; n > 0 {
			k.cover(o.node.ID, graph.FactBranchProtection,
				fmt.Sprintf("classic branch protection details (stale review dismissal, last push approval, push restrictions, admin enforcement, bypass allowances) or ruleset bypass actors are visible only to repo admins: hidden on %d repositories", n),
				"admin on those repositories (org owner on "+o.login+" sees all)")
		}
	}
	return nil
}

// ---- batched GraphQL ----

const protectionFragment = `fragment gopProtection on Repository {
  viewerPermission
  defaultBranchRef {
    name
    refUpdateRule { requiredApprovingReviewCount requiresCodeOwnerReviews allowsForcePushes requiresSignatures requiredStatusCheckContexts }
    branchProtectionRule {
      requiresApprovingReviews requiredApprovingReviewCount requiresCodeOwnerReviews dismissesStaleReviews requireLastPushApproval
      isAdminEnforced allowsForcePushes requiresCommitSignatures requiredStatusCheckContexts restrictsPushes
      bypassPullRequestAllowances(first: 20) { totalCount nodes { actor { __typename ... on App { databaseId slug } } } }
    }
    %s
  }
}
`

// protectionRules is the rulesets part of the fragment, left out on a GHES
// version without rulesets.
const protectionRules = `rules(first: 50) {
      totalCount
      nodes {
        type
        parameters {
          __typename
          ... on PullRequestParameters { requiredApprovingReviewCount requireCodeOwnerReview dismissStaleReviewsOnPush requireLastPushApproval }
          ... on RequiredStatusChecksParameters { requiredStatusChecks { context } }
        }
        repositoryRuleset {
          databaseId
          source { __typename }
          bypassActors(first: 20) { totalCount nodes { organizationAdmin enterpriseOwner repositoryRoleName actor { __typename ... on App { databaseId slug } } } }
        }
      }
    }`

type gqlTypename struct {
	Typename string `json:"__typename"`
}

// gqlActor is a bypass actor: an App carries its database ID and slug.
type gqlActor struct {
	Typename   string `json:"__typename"`
	DatabaseID *int64 `json:"databaseId"`
	Slug       string `json:"slug"`
}

// gqlRuleset is the ruleset a rule comes from.
type gqlRuleset struct {
	DatabaseID   *int64       `json:"databaseId"`
	Source       *gqlTypename `json:"source"`
	BypassActors *struct {
		TotalCount int `json:"totalCount"`
		Nodes      []struct {
			OrganizationAdmin  bool      `json:"organizationAdmin"`
			EnterpriseOwner    bool      `json:"enterpriseOwner"`
			RepositoryRoleName string    `json:"repositoryRoleName"`
			Actor              *gqlActor `json:"actor"`
		} `json:"nodes"`
	} `json:"bypassActors"`
}

type gqlProtRepo struct {
	ViewerPermission string `json:"viewerPermission"`
	DefaultBranchRef *struct {
		Name          string `json:"name"`
		RefUpdateRule *struct {
			RequiredApprovingReviewCount *int     `json:"requiredApprovingReviewCount"`
			RequiresCodeOwnerReviews     bool     `json:"requiresCodeOwnerReviews"`
			AllowsForcePushes            bool     `json:"allowsForcePushes"`
			RequiresSignatures           bool     `json:"requiresSignatures"`
			RequiredStatusCheckContexts  []string `json:"requiredStatusCheckContexts"`
		} `json:"refUpdateRule"`
		BranchProtectionRule *struct {
			RequiresApprovingReviews     bool     `json:"requiresApprovingReviews"`
			RequiredApprovingReviewCount *int     `json:"requiredApprovingReviewCount"`
			RequiresCodeOwnerReviews     bool     `json:"requiresCodeOwnerReviews"`
			DismissesStaleReviews        bool     `json:"dismissesStaleReviews"`
			RequireLastPushApproval      bool     `json:"requireLastPushApproval"`
			IsAdminEnforced              bool     `json:"isAdminEnforced"`
			AllowsForcePushes            bool     `json:"allowsForcePushes"`
			RequiresCommitSignatures     bool     `json:"requiresCommitSignatures"`
			RequiredStatusCheckContexts  []string `json:"requiredStatusCheckContexts"`
			RestrictsPushes              bool     `json:"restrictsPushes"`
			BypassPullRequestAllowances  *struct {
				TotalCount int `json:"totalCount"`
				Nodes      []struct {
					Actor *gqlActor `json:"actor"`
				} `json:"nodes"`
			} `json:"bypassPullRequestAllowances"`
		} `json:"branchProtectionRule"`
		Rules *struct {
			TotalCount int `json:"totalCount"`
			Nodes      []struct {
				Type       string `json:"type"`
				Parameters *struct {
					Typename                     string `json:"__typename"`
					RequiredApprovingReviewCount int    `json:"requiredApprovingReviewCount"`
					RequireCodeOwnerReview       bool   `json:"requireCodeOwnerReview"`
					DismissStaleReviewsOnPush    bool   `json:"dismissStaleReviewsOnPush"`
					RequireLastPushApproval      bool   `json:"requireLastPushApproval"`
					RequiredStatusChecks         []struct {
						Context string `json:"context"`
					} `json:"requiredStatusChecks"`
				} `json:"parameters"`
				RepositoryRuleset *gqlRuleset `json:"repositoryRuleset"`
			} `json:"nodes"`
		} `json:"rules"`
	} `json:"defaultBranchRef"`
}

// buildProtectionQuery returns one query with an alias per repository.
// Owner and name travel as variables only.
func buildProtectionQuery(repos []hardenRepo, withRules bool) (string, map[string]any) {
	vars := map[string]any{}
	var decl, body strings.Builder
	for i, hr := range repos {
		is := strconv.Itoa(i)
		decl.WriteString("$o" + is + ": String!, $n" + is + ": String!, ")
		vars["o"+is], vars["n"+is] = hr.o.login, repoName(hr.o, hr.repo)
		body.WriteString("  r" + is + ": repository(owner: $o" + is + ", name: $n" + is + ") { ...gopProtection }\n")
	}
	rules := ""
	if withRules {
		rules = protectionRules
	}
	q := "query(" + strings.TrimSuffix(decl.String(), ", ") + ") {\n" + body.String() +
		"  rateLimit { cost remaining resetAt }\n}\n" + fmt.Sprintf(protectionFragment, rules)
	return q, vars
}

// adminOnlyField reports a field-level error on a field only admins read:
// its value comes back null and is handled as not visible.
func adminOnlyField(path []any) bool {
	for _, p := range path {
		if s, ok := p.(string); ok && (s == "branchProtectionRule" || s == "bypassActors" || s == "bypassPullRequestAllowances") {
			return true
		}
	}
	return false
}

// fetchProtection reads the protection of repos in batched queries. Entry i
// is nil when repos[i] must be read over REST. A query GitHub finds too
// expensive is split in two, down to one repository. The only error returned
// is the context's.
func (k *collector) fetchProtection(ctx context.Context, c *Client, repos []hardenRepo) ([]*protFacts, error) {
	out := make([]*protFacts, len(repos))
	if k.batch.off || k.protOff || len(repos) == 0 {
		return out, nil
	}
	_, _, noRules := k.ghesGate(capRulesets)
	q, vars := buildProtectionQuery(repos, !noRules)
	var data map[string]json.RawMessage
	k.batch.queries++
	gqlErrs, err := c.GraphQL(withAliasPlan(ctx, protectionPlan(repos, !noRules)), q, vars, &data)
	split := func() ([]*protFacts, error) {
		if len(repos) <= 1 {
			return out, nil
		}
		h := (len(repos) + 1) / 2
		a, err := k.fetchProtection(ctx, c, repos[:h])
		if err != nil {
			return nil, err
		}
		b, err := k.fetchProtection(ctx, c, repos[h:])
		if err != nil {
			return nil, err
		}
		return append(a, b...), nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if s := StatusOf(err); s == 0 || s >= http.StatusInternalServerError {
			return split()
		}
		k.disableProtectionBatch(err.Error())
		return out, nil
	}
	if isLimitError(gqlErrs) {
		return split()
	}
	if data == nil {
		k.disableProtectionBatch(gqlErrs.Error())
		return out, nil
	}
	failed := map[int]bool{}
	for _, e := range gqlErrs {
		i := aliasIndex(e.Path)
		if i < 0 {
			return out, nil // not tied to one repository: REST for the whole batch
		}
		if !adminOnlyField(e.Path) {
			failed[i] = true
		}
	}
	for i, hr := range repos {
		raw, present := data["r"+strconv.Itoa(i)]
		if failed[i] || !present || string(raw) == "null" {
			continue
		}
		var r gqlProtRepo
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		out[i] = k.gqlProtFacts(hr, &r, noRules)
	}
	if raw, ok := data["rateLimit"]; ok {
		var rl struct {
			Remaining *int      `json:"remaining"`
			ResetAt   time.Time `json:"resetAt"`
		}
		if json.Unmarshal(raw, &rl) == nil && rl.Remaining != nil {
			c.noteGraphQLRate(*rl.Remaining, rl.ResetAt)
		}
	}
	return out, nil
}

func (k *collector) disableProtectionBatch(why string) {
	if !k.protOff {
		k.protOff = true
		k.logf("collect: batched GraphQL branch protection reads disabled, using REST: %s", why)
	}
}

// gqlProtFacts builds the facts of one repository from its batched answer,
// or returns nil (REST fallback) when the answer is incomplete.
func (k *collector) gqlProtFacts(hr hardenRepo, r *gqlProtRepo, noRules bool) *protFacts {
	ref := r.DefaultBranchRef
	if ref == nil {
		return &protFacts{skip: true} // empty repository: no branch yet
	}
	if !noRules && (ref.Rules == nil || ref.Rules.TotalCount > len(ref.Rules.Nodes)) {
		return nil // rules not returned, or more than one page: REST reads them all
	}
	isAdmin := r.ViewerPermission == "ADMIN"
	pf := &protFacts{}
	if bp := ref.BranchProtectionRule; bp != nil {
		s := protSource{id: "classic", codeOwner: bp.RequiresCodeOwnerReviews, dismissStale: bp.DismissesStaleReviews,
			lastPush: bp.RequireLastPushApproval, signed: bp.RequiresCommitSignatures, blocksForce: !bp.AllowsForcePushes,
			restrictsPush: bp.RestrictsPushes, checks: bp.RequiredStatusCheckContexts,
			admin: strconv.FormatBool(!bp.IsAdminEnforced), app: "false", apps: map[int64]string{}}
		if bp.RequiresApprovingReviews && bp.RequiredApprovingReviewCount != nil {
			s.reviews = *bp.RequiredApprovingReviewCount
		}
		if a := bp.BypassPullRequestAllowances; a == nil {
			s.bypassHidden, s.app = true, "unknown"
			pf.hidden = true
		} else {
			s.bypass = a.TotalCount
			for _, n := range a.Nodes {
				if n.Actor != nil && n.Actor.Typename == "App" {
					s.app = "true"
					s.apps = addApp(s.apps, n.Actor)
				}
			}
			if a.TotalCount > len(a.Nodes) {
				s.apps = nil
				if s.app == "false" {
					s.app = "unknown"
				}
			}
		}
		pf.sources = append(pf.sources, s)
	} else if ru := ref.RefUpdateRule; ru != nil && !isAdmin {
		// Without admin, GraphQL shows a classic rule's non-admin view only.
		s := protSource{id: "classic", codeOwner: ru.RequiresCodeOwnerReviews, signed: ru.RequiresSignatures,
			blocksForce: !ru.AllowsForcePushes, checks: ru.RequiredStatusCheckContexts,
			detailsHidden: true, admin: "unknown", app: "unknown", bypassHidden: true}
		if ru.RequiredApprovingReviewCount != nil {
			s.reviews = *ru.RequiredApprovingReviewCount
		}
		pf.sources = append(pf.sources, s)
		pf.hidden = true
	}
	if ref.Rules != nil {
		byID := map[string]int{}
		for _, rule := range ref.Rules.Nodes {
			id := "ruleset"
			rs := rule.RepositoryRuleset
			if rs != nil && rs.DatabaseID != nil {
				id = "ruleset:" + strconv.FormatInt(*rs.DatabaseID, 10)
			}
			idx, ok := byID[id]
			if !ok {
				s := newRuleset(id)
				s.admin, s.app, s.bypass, s.bypassHidden = k.gqlBypass(hr.o, rs, isAdmin)
				s.apps = gqlBypassApps(rs, s.bypassHidden)
				if s.bypassHidden {
					pf.hidden = true
				}
				pf.sources = append(pf.sources, s)
				idx = len(pf.sources) - 1
				byID[id] = idx
			}
			s := &pf.sources[idx]
			switch rule.Type {
			case "PULL_REQUEST":
				if p := rule.Parameters; p != nil {
					s.reviews = max(s.reviews, p.RequiredApprovingReviewCount)
					s.codeOwner = s.codeOwner || p.RequireCodeOwnerReview
					s.dismissStale = s.dismissStale || p.DismissStaleReviewsOnPush
					s.lastPush = s.lastPush || p.RequireLastPushApproval
				}
			case "REQUIRED_STATUS_CHECKS":
				if p := rule.Parameters; p != nil {
					for _, c := range p.RequiredStatusChecks {
						s.checks = append(s.checks, c.Context)
					}
				}
			case "NON_FAST_FORWARD":
				s.blocksForce = true
			case "REQUIRED_SIGNATURES":
				s.signed = true
			case "UPDATE":
				s.restrictsPush = true
			}
		}
	}
	return pf
}

// gqlBypass reads a ruleset's bypass actors. An empty list counts as "no
// bypass actors" only when the token can administer the ruleset's source:
// GitHub hides the list from everyone else.
func (k *collector) gqlBypass(o *orgState, rs *gqlRuleset, isAdmin bool) (admin, app string, n int, hidden bool) {
	if rs == nil || rs.BypassActors == nil {
		return "unknown", "unknown", 0, true
	}
	canAdmin := false
	if rs.Source != nil {
		switch rs.Source.Typename {
		case "Repository":
			canAdmin = isAdmin
		case "Organization":
			canAdmin = o.ownerVisible
		}
	}
	ba := rs.BypassActors
	if ba.TotalCount == 0 && !canAdmin {
		return "unknown", "unknown", 0, true
	}
	admin, app = "false", "false"
	for _, a := range ba.Nodes {
		if a.OrganizationAdmin || a.EnterpriseOwner || strings.EqualFold(a.RepositoryRoleName, "admin") {
			admin = "true"
		}
		if a.Actor != nil && a.Actor.Typename == "App" {
			app = "true"
		}
	}
	if ba.TotalCount > len(ba.Nodes) {
		if admin == "false" {
			admin = "unknown"
		}
		if app == "false" {
			app = "unknown"
		}
	}
	return admin, app, ba.TotalCount, false
}

// ---- REST fallback ----

type apiDefaultRule struct {
	Type       string `json:"type"`
	RulesetID  int64  `json:"ruleset_id"`
	Parameters struct {
		RequiredApprovals       int  `json:"required_approving_review_count"`
		RequireCodeOwnerReview  bool `json:"require_code_owner_review"`
		DismissStaleOnPush      bool `json:"dismiss_stale_reviews_on_push"`
		RequireLastPushApproval bool `json:"require_last_push_approval"`
		RequiredStatusChecks    []struct {
			Context string `json:"context"`
		} `json:"required_status_checks"`
	} `json:"parameters"`
}

type apiEnabled struct {
	Enabled bool `json:"enabled"`
}

type apiFullProtection struct {
	RequiredStatusChecks *struct {
		Contexts []string `json:"contexts"`
		Checks   []struct {
			Context string `json:"context"`
		} `json:"checks"`
	} `json:"required_status_checks"`
	EnforceAdmins              *apiEnabled `json:"enforce_admins"`
	RequiredPullRequestReviews *struct {
		DismissStaleReviews     bool       `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews bool       `json:"require_code_owner_reviews"`
		RequiredApprovals       int        `json:"required_approving_review_count"`
		RequireLastPushApproval bool       `json:"require_last_push_approval"`
		BypassAllowances        *apiActors `json:"bypass_pull_request_allowances"`
	} `json:"required_pull_request_reviews"`
	Restrictions       *apiActors  `json:"restrictions"`
	RequiredSignatures *apiEnabled `json:"required_signatures"`
	AllowForcePushes   *apiEnabled `json:"allow_force_pushes"`
}

type apiRulesetBypass struct {
	BypassActors *[]struct {
		ActorID   *int64 `json:"actor_id"`
		ActorType string `json:"actor_type"`
	} `json:"bypass_actors"`
}

// restProtection reads one repository's default-branch protection over
// REST: the branch's effective rules (repo and org rulesets), the branch
// (whether classic protection applies), its classic protection (admin only)
// and the bypass actors of each ruleset (cached by ID: org rulesets repeat).
func (k *collector) restProtection(ctx context.Context, o *orgState, repo *graph.Node) (*protFacts, error) {
	full := strings.TrimPrefix(repo.ID, "repo:")
	name := repoName(o, repo)
	branch := repo.Attrs["default_branch"]
	pf := &protFacts{}
	var rules []apiDefaultRule
	if !k.ghesSkip("enterprise:"+k.enterprise, capRulesets, capRulesets) {
		err := k.cl(o.login).GetPages(ctx, branchPath(o.login, name, "rules/branches", branch)+"?per_page=100", func(page []byte) error {
			var batch []apiDefaultRule
			if err := json.Unmarshal(page, &batch); err != nil {
				return fmt.Errorf("decoding branch rules: %w", err)
			}
			rules = append(rules, batch...)
			return nil
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			rules = nil
			pf.unknownWhy = "could not read the default branch rules of " + full + ": " + err.Error()
			pf.unknownFix = k.fixFor(err, "read access to "+full)
		}
	}
	byID := map[int64]int{}
	for _, r := range rules {
		idx, ok := byID[r.RulesetID]
		if !ok {
			s := newRuleset("ruleset:" + strconv.FormatInt(r.RulesetID, 10))
			var err error
			s.admin, s.app, s.bypass, s.bypassHidden, err = k.restBypass(ctx, o.login, name, r.RulesetID)
			s.apps = k.restBypassApps(r.RulesetID, s.bypassHidden)
			if err != nil {
				return nil, err
			}
			if s.bypassHidden {
				pf.hidden = true
			}
			pf.sources = append(pf.sources, s)
			idx = len(pf.sources) - 1
			byID[r.RulesetID] = idx
		}
		s := &pf.sources[idx]
		p := r.Parameters
		switch r.Type {
		case "pull_request":
			s.reviews = max(s.reviews, p.RequiredApprovals)
			s.codeOwner = s.codeOwner || p.RequireCodeOwnerReview
			s.dismissStale = s.dismissStale || p.DismissStaleOnPush
			s.lastPush = s.lastPush || p.RequireLastPushApproval
		case "required_status_checks":
			for _, c := range p.RequiredStatusChecks {
				s.checks = append(s.checks, c.Context)
			}
		case "non_fast_forward":
			s.blocksForce = true
		case "required_signatures":
			s.signed = true
		case "update":
			s.restrictsPush = true
		}
	}

	var br apiBranch
	if err := k.cl(o.login).GetJSON(ctx, branchPath(o.login, name, "branches", branch), &br); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pf.unknownWhy = "could not read the default branch of " + full + ": " + err.Error()
		pf.unknownFix = k.fixFor(err, "read access to "+full)
		return pf, nil
	}
	if !br.Protected {
		return pf, nil
	}
	var cp apiFullProtection
	err := k.cl(o.login).GetJSON(ctx, branchPath(o.login, name, "branches", branch)+"/protection", &cp)
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		// Classic protection applies, but its rules are admin only: every
		// value it could set is unknown.
		pf.sources = append(pf.sources, protSource{id: "classic", detailsHidden: true, admin: "unknown", app: "unknown", bypassHidden: true})
		if pf.unknownWhy == "" {
			pf.unknownWhy = "the default branch of " + full + " has classic branch protection, but its rules are not visible: " + err.Error()
			pf.unknownFix = k.fixFor(err, "admin on "+full)
		}
		return pf, nil
	}
	s := protSource{id: "classic", admin: "true", app: "false", apps: map[int64]string{},
		blocksForce:   cp.AllowForcePushes == nil || !cp.AllowForcePushes.Enabled,
		signed:        cp.RequiredSignatures != nil && cp.RequiredSignatures.Enabled,
		restrictsPush: cp.Restrictions != nil}
	if cp.EnforceAdmins != nil && cp.EnforceAdmins.Enabled {
		s.admin = "false"
	}
	if sc := cp.RequiredStatusChecks; sc != nil {
		s.checks = append(s.checks, sc.Contexts...)
		for _, c := range sc.Checks {
			s.checks = append(s.checks, c.Context)
		}
	}
	if r := cp.RequiredPullRequestReviews; r != nil {
		s.reviews = r.RequiredApprovals
		s.codeOwner, s.dismissStale, s.lastPush = r.RequireCodeOwnerReviews, r.DismissStaleReviews, r.RequireLastPushApproval
		if a := r.BypassAllowances; a != nil {
			s.bypass = len(a.Users) + len(a.Teams) + len(a.Apps)
			if len(a.Apps) > 0 {
				s.app = "true"
			}
			for _, ap := range a.Apps {
				if ap.ID > 0 {
					s.apps[ap.ID] = strings.ToLower(ap.Slug)
				} else {
					s.apps = nil // an App without an ID: gop cannot list them
					break
				}
			}
		}
	}
	pf.sources = append(pf.sources, s)
	return pf, nil
}

// restBypass reads one ruleset's bypass actors through the repository
// (GET /repos/{o}/{r}/rulesets/{id}?includes_parents=true), cached by ID.
func (k *collector) restBypass(ctx context.Context, owner, repo string, id int64) (admin, app string, n int, hidden bool, err error) {
	if k.rulesetBypass == nil {
		k.rulesetBypass = map[int64]*apiRulesetBypass{}
	}
	rs, ok := k.rulesetBypass[id]
	if !ok {
		rs = &apiRulesetBypass{}
		path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/rulesets/" + strconv.FormatInt(id, 10) + "?includes_parents=true"
		if e := k.cl(owner).GetJSON(ctx, path, rs); e != nil {
			if ctx.Err() != nil {
				return "", "", 0, false, ctx.Err()
			}
			rs = &apiRulesetBypass{}
		}
		k.rulesetBypass[id] = rs
	}
	if rs.BypassActors == nil {
		return "unknown", "unknown", 0, true, nil
	}
	admin, app = "false", "false"
	for _, a := range *rs.BypassActors {
		switch a.ActorType {
		case actorOrgAdmin, "EnterpriseOwner":
			admin = "true"
		case actorRepoRole:
			if a.ActorID != nil && builtinRoleIDs[*a.ActorID] == "admin" {
				admin = "true"
			}
		case "Integration":
			app = "true"
		}
	}
	return admin, app, len(*rs.BypassActors), false, nil
}
