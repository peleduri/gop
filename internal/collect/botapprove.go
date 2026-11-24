package collect

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Two facts that decide whether a bot merge needs a human (issue #164):
//
//   - which GitHub App a merge mints its token for, matched against the Apps
//     listed as bypass actors of the default branch rules. Only a match
//     confirms an app_bypass review bypass: an App the workflow does not
//     name (a vars. or secrets. reference), or one gop cannot find in the
//     bypass list, leaves it possible.
//   - the repo's "Allow GitHub Actions to create and approve pull requests"
//     setting (can_approve_pull_request_reviews), read with a read-only GET
//     for a repo whose bot approval uses GITHUB_TOKEN, so that approval is
//     confirmed (or ruled out) instead of possible.

// appIDInputs are the with: keys App token actions read the app ID from;
// appSlugInputs the keys that name the App by slug.
var (
	appIDInputs   = []string{"app-id", "app_id", "appId", "application_id", "application-id"}
	appSlugInputs = []string{"app-slug", "app_slug"}
)

var (
	appIDValueRe   = regexp.MustCompile(`^[0-9]+$`)
	appSlugValueRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	envExprRe      = regexp.MustCompile(`^\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$`)
	envAppIDRe     = regexp.MustCompile(`(?i)(^|_)APP_?ID$`)
	envAppSlugRe   = regexp.MustCompile(`(?i)(^|_)APP_?SLUG$`)
)

// literalApp returns v as an app ID (slug false) or slug when it is a
// literal, following one ${{ env.X }} indirection. "" when it is not.
func literalApp(v string, env map[string]string, slug bool) string {
	v = strings.TrimSpace(strings.Trim(strings.TrimSpace(v), `"'`))
	if m := envExprRe.FindStringSubmatch(v); m != nil {
		v = strings.TrimSpace(strings.Trim(strings.TrimSpace(env[m[1]]), `"'`))
	}
	if slug {
		v = strings.ToLower(v)
		if appSlugValueRe.MatchString(v) {
			return v
		}
		return ""
	}
	if appIDValueRe.MatchString(v) {
		return v
	}
	return ""
}

// appStepRef is the App an App token step mints for: its literal app ID or
// slug, else graph.AppUnknown.
func appStepRef(w *yamlWalk, with *yamlMap, env map[string]string) string {
	for _, k := range appIDInputs {
		if r := literalApp(scalarOf(w, field(with, k)), env, false); r != "" {
			return r
		}
	}
	for _, k := range appSlugInputs {
		if r := literalApp(scalarOf(w, field(with, k)), env, true); r != "" {
			return r
		}
	}
	return graph.AppUnknown
}

// mergeAppRefs are the Apps a merging step's App token comes from: the App
// token steps its values name (steps.<id>.outputs.token), else the app ID or
// slug its env names beside a private key (APP_ID: 123456), else unknown.
func mergeAppRefs(vals []string, env map[string]string, appRefs map[string]string) []string {
	var out []string
	for _, v := range vals {
		for _, m := range appOutputRe.FindAllStringSubmatch(v, -1) {
			if r, ok := appRefs[m[1]]; ok {
				out = append(out, r)
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case envAppIDRe.MatchString(k):
			if r := literalApp(env[k], env, false); r != "" {
				return []string{r}
			}
		case envAppSlugRe.MatchString(k):
			if r := literalApp(env[k], env, true); r != "" {
				return []string{r}
			}
		}
	}
	return []string{graph.AppUnknown}
}

// ---- the bypass Apps of the default branch rules ----

// addApp records a GraphQL App bypass actor; an App without a database ID
// makes the list unknown (nil).
func addApp(apps map[int64]string, a *gqlActor) map[int64]string {
	if apps == nil {
		return nil
	}
	if a.DatabaseID == nil {
		return nil
	}
	apps[*a.DatabaseID] = strings.ToLower(a.Slug)
	return apps
}

// gqlBypassApps lists the Apps among a ruleset's GraphQL bypass actors; nil
// when the list is hidden or incomplete.
func gqlBypassApps(rs *gqlRuleset, hidden bool) map[int64]string {
	if hidden || rs == nil || rs.BypassActors == nil || rs.BypassActors.TotalCount > len(rs.BypassActors.Nodes) {
		return nil
	}
	apps := map[int64]string{}
	for _, n := range rs.BypassActors.Nodes {
		if n.Actor != nil && n.Actor.Typename == "App" {
			if apps = addApp(apps, n.Actor); apps == nil {
				return nil
			}
		}
	}
	return apps
}

// restBypassApps lists the Integration bypass actors of a ruleset restBypass
// read (cached by ID); nil when hidden.
func (k *collector) restBypassApps(id int64, hidden bool) map[int64]string {
	rs := k.rulesetBypass[id]
	if hidden || rs == nil || rs.BypassActors == nil {
		return nil
	}
	apps := map[int64]string{}
	for _, a := range *rs.BypassActors {
		if a.ActorType != "Integration" {
			continue
		}
		if a.ActorID == nil {
			return nil
		}
		apps[*a.ActorID] = ""
	}
	return apps
}

// bypassApps is the branch_bypass_apps value: the Apps every protecting
// source lets through, as sorted <id> or <id>:<slug>. "" when a source's
// list is unknown or no App gets past every source.
func bypassApps(sources []protSource) string {
	var common map[int64]string
	for i, s := range sources {
		if s.apps == nil {
			return ""
		}
		if i == 0 {
			common = map[int64]string{}
			for id, slug := range s.apps {
				common[id] = slug
			}
			continue
		}
		for id := range common {
			slug, ok := s.apps[id]
			if !ok {
				delete(common, id)
			} else if common[id] == "" {
				common[id] = slug
			}
		}
	}
	ids := make([]int64, 0, len(common))
	for id := range common {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		v := strconv.FormatInt(id, 10)
		if slug := common[id]; slug != "" {
			v += ":" + slug
		}
		out = append(out, v)
	}
	return strings.Join(out, ",")
}

// appMatch decides review_bypass_app_match: matched when one of the Apps the
// merge mints for (bot_merge_apps) is a bypass App (branch_bypass_apps) by
// ID or slug; unknown when either side is not known; unmatched otherwise.
func appMatch(bypass, merge string) string {
	if bypass == "" || merge == "" {
		return graph.AppUnknown
	}
	known := map[string]bool{}
	for _, e := range splitList(bypass) {
		id, slug, _ := strings.Cut(e, ":")
		known[id] = true
		if slug != "" {
			known[slug] = true
		}
	}
	unknown := false
	for _, r := range splitList(merge) {
		if r == graph.AppUnknown {
			unknown = true
			continue
		}
		if known[strings.ToLower(r)] {
			return graph.AppMatched
		}
	}
	if unknown {
		return graph.AppUnknown
	}
	return graph.AppUnmatched
}

// appList renders a branch_bypass_apps value for people: "77 (acme-merge)".
func appList(bypass string) string {
	var out []string
	for _, e := range splitList(bypass) {
		id, slug, _ := strings.Cut(e, ":")
		if slug != "" {
			id += " (" + slug + ")"
		}
		out = append(out, id)
	}
	return strings.Join(out, ", ")
}

// appMatchWhy is the coverage reason of an app_bypass outcome that is not
// matched.
func appMatchWhy(m *graph.Node, bypass, match string) string {
	switch {
	case match == graph.AppUnmatched:
		var refs []string
		for _, r := range splitList(m.Attrs[graph.AttrBotMergeApps]) {
			if r != graph.AppUnknown {
				refs = append(refs, r)
			}
		}
		return m.Name + " merges with a token of GitHub App " + strings.Join(refs, ", ") + ", which is not one of the bypass Apps gop read (" + appList(bypass) + "): the merge skips review only if its App gets past the rules some other way"
	case bypass == "":
		return m.Name + " merges with a GitHub App token and an App is a bypass actor of the default branch rules, but gop could not list which Apps: the merge skips review only if its App is one of them"
	}
	return m.Name + " merges with a GitHub App token but does not name the App (its app id comes from a variable or secret): the merge skips review only if that App is a bypass actor (bypass Apps: " + appList(bypass) + ")"
}

// ---- Allow GitHub Actions to create and approve pull requests ----

// orgCanApprove caches an org's can_approve_pull_request_reviews.
type orgCanApprove struct {
	val *bool
	err error
}

// collectActionsApprove reads can_approve_pull_request_reviews for each repo
// with a bot approval made with GITHUB_TOKEN, before the bot merge join.
func (k *collector) collectActionsApprove(ctx context.Context) error {
	need := map[string]bool{}
	for _, n := range k.nodes {
		if n.Kind == graph.KindWorkflow && n.Attrs[graph.AttrBotApproves] == "true" &&
			containsStr(splitList(n.Attrs[graph.AttrBotApproveToken]), graph.BotTokenGitHub) {
			need["repo:"+n.Attrs["repo"]] = true
		}
	}
	if len(need) == 0 {
		return nil
	}
	for _, o := range k.orgs {
		for _, repo := range o.repos {
			if !need[repo.ID] || repo.Attrs[graph.AttrArchived] == "true" {
				continue
			}
			v, why, err := k.readCanApprove(ctx, o, repo)
			if err != nil {
				return err
			}
			if v != "" {
				setAttr(repo, graph.AttrActionsCanApprove, v, graph.Live)
				continue
			}
			setAttr(repo, graph.AttrActionsCanApprove, "unknown", graph.NotVisible)
			k.cover(repo.ID, graph.AttrActionsCanApprove, why, "admin on "+strings.TrimPrefix(repo.ID, "repo:")+" (or org owner)")
		}
	}
	return nil
}

// readCanApprove returns "true" or "false", or "" with a reason when the
// setting is not visible. The repo setting is read first (the same GET as
// the default workflow permissions, served from the response cache). When
// it is refused the org setting is read once: an org that does not allow it
// proves the repo does not either, while an org that allows it leaves the
// repo unknown.
func (k *collector) readCanApprove(ctx context.Context, o *orgState, repo *graph.Node) (val, why string, err error) {
	owner, name, _ := strings.Cut(strings.TrimPrefix(repo.ID, "repo:"), "/")
	var body struct {
		CanApprove *bool `json:"can_approve_pull_request_reviews"`
	}
	rerr := k.cl(owner).GetJSON(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/actions/permissions/workflow", &body)
	if rerr == nil && body.CanApprove != nil {
		return strconv.FormatBool(*body.CanApprove), "", nil
	}
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	if rerr == nil {
		rerr = errors.New("the answer has no can_approve_pull_request_reviews")
	}
	if k.actionsApproveOrg == nil {
		k.actionsApproveOrg = map[string]*orgCanApprove{}
	}
	oc := k.actionsApproveOrg[o.login]
	if oc == nil {
		oc = &orgCanApprove{}
		var ob struct {
			CanApprove *bool `json:"can_approve_pull_request_reviews"`
		}
		oc.err = k.cl(o.login).GetJSON(ctx, "/orgs/"+url.PathEscape(o.login)+"/actions/permissions/workflow", &ob)
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		if oc.err == nil {
			if oc.val = ob.CanApprove; oc.val == nil {
				oc.err = errors.New("the answer has no can_approve_pull_request_reviews")
			}
		}
		k.actionsApproveOrg[o.login] = oc
	}
	switch {
	case oc.val != nil && !*oc.val:
		return "false", "", nil
	case oc.val != nil:
		return "", "could not read the repo's \"Allow GitHub Actions to create and approve pull requests\" setting (" + rerr.Error() + "); the org allows it, and the repo may turn it off", nil
	}
	return "", "could not read the \"Allow GitHub Actions to create and approve pull requests\" setting: repo: " + rerr.Error() + "; org: " + oc.err.Error(), nil
}
