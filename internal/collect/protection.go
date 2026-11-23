package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Source API labels for branch protection facts.
const (
	srcBranchProtection = "rest:GET /repos/{owner}/{repo}/branches/{branch}/protection"
	srcRuleset          = "rest:GET /repos/{owner}/{repo}/rulesets/{ruleset_id}"
)

// Labels recorded in the ref_protection attribute, in this order.
var protectionLabels = []string{"reviews", "dismiss_stale", "last_push_approval", "status_checks", "push_restricted", "admins_enforced"}

// Ruleset bypass actor types that map to principals.
const (
	actorTeam       = "Team"
	actorUser       = "User"
	actorOrgAdmin   = "OrganizationAdmin"
	actorRepoRole   = "RepositoryRole"
	attrBypassMode  = "bypass_mode"
	attrRuleSource  = "rule_source"
	ruleSourceClass = "branch_protection"
)

// builtinRoleIDs maps the actor_id of a built-in RepositoryRole bypass actor to
// its role name. Custom repository roles have their own IDs and are reported as
// coverage.
var builtinRoleIDs = map[int64]string{2: "maintain", 4: "write", 5: "admin"}

type apiRule struct {
	Type       string `json:"type"`
	RulesetID  int64  `json:"ruleset_id"`
	Parameters struct {
		RequiredApprovals       int  `json:"required_approving_review_count"`
		DismissStaleOnPush      bool `json:"dismiss_stale_reviews_on_push"`
		RequireLastPushApproval bool `json:"require_last_push_approval"`
	} `json:"parameters"`
}

type apiBranch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
}

type apiActors struct {
	Users []struct {
		Login string `json:"login"`
	} `json:"users"`
	Teams []struct {
		Slug string `json:"slug"`
	} `json:"teams"`
	Apps []struct {
		Slug string `json:"slug"`
	} `json:"apps"`
}

type apiClassicProtection struct {
	RequiredStatusChecks *json.RawMessage `json:"required_status_checks"`
	EnforceAdmins        *struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	RequiredPullRequestReviews *struct {
		DismissStaleReviews     bool       `json:"dismiss_stale_reviews"`
		RequiredApprovals       int        `json:"required_approving_review_count"`
		RequireLastPushApproval bool       `json:"require_last_push_approval"`
		BypassAllowances        *apiActors `json:"bypass_pull_request_allowances"`
	} `json:"required_pull_request_reviews"`
	Restrictions *apiActors `json:"restrictions"`
}

type apiRuleset struct {
	ID           int64 `json:"id"`
	BypassActors *[]struct {
		ActorID    *int64 `json:"actor_id"`
		ActorType  string `json:"actor_type"`
		BypassMode string `json:"bypass_mode"`
	} `json:"bypass_actors"`
}

// bypassGrant is one principal that can land code on a protected branch alone.
type bypassGrant struct {
	principal string
	src       string
	attrs     map[string]string
}

// refProtection is the protection verdict for one (repo, branch), or the
// immutability verdict for one (repo, tag).
type refProtection struct {
	protected     string // true | false | unknown
	lockedBy      string // tags: ref_immutable_reason when protected is true
	labels        map[string]bool
	reason, fix   string // why protected is unknown
	grants        []bypassGrant
	bypassUnknown bool     // a protecting rule's bypass list could not be read
	bypassWhy     string   // reason for bypassUnknown
	unresolved    []string // bypass actors that map to no principal
}

// collectRefProtection decides, for every enterprise-internal action ref on a
// branch, whether pushing to the host repo is enough to change what consumers
// run. It runs after expandNested, once per distinct (repo, branch).
//
// A branch counts as protected (ref_protected=true) when a pull request needs
// at least one approval and a stale approval cannot be reused
// (dismiss_stale_reviews_on_push / dismiss_stale_reviews, or
// require_last_push_approval), or when an update rule or classic restrictions
// limit who may push. Required status checks alone do not count: the pusher
// controls the code under test. Reviews without stale-approval dismissal do not
// count either: get a harmless change approved, then push more commits.
//
// The principals that can still land code alone (ruleset bypass actors,
// classic pull request bypass allowances or push restrictions, and repo admins
// when enforce_admins is off) become CAN_PUSH edges with via=ref_bypass and
// ref=<branch>. When several rules protect a branch the lists are united, an
// over-approximation: a real bypasser must bypass every one of them.
func (k *collector) collectRefProtection(ctx context.Context) error {
	resolves := map[string]string{} // action ID -> host repo ID
	for _, e := range k.edges {
		if e.Kind == graph.ResolvesTo {
			resolves[e.From] = e.To
		}
	}
	ids := make([]string, 0, len(k.nodes))
	for id, n := range k.nodes {
		if n.Kind == graph.KindActionRef && n.Attrs[graph.AttrRefKind] == "branch" && n.Attrs["in_enterprise"] == "true" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	cache := map[string]*refProtection{}
	teamIDs := map[string]map[int64]string{} // lower org -> team id -> slug
	for _, id := range ids {
		an := k.nodes[id]
		repoID := resolves[id]
		branch := an.Attrs["ref"]
		if repoID == "" || branch == "" {
			continue
		}
		key := strings.ToLower(repoID) + "@" + branch
		rp, ok := cache[key]
		if !ok {
			var err error
			rp, err = k.refProtection(ctx, repoID, branch, teamIDs)
			if err != nil {
				return err
			}
			cache[key] = rp
			for _, g := range rp.grants {
				k.bypassEdge(g, repoID, branch)
			}
		}
		k.applyProtection(an, repoID, branch, rp)
	}
	return nil
}

// bypassEdge records principal -CAN_PUSH-> repo with via=ref_bypass. These
// edges are keyed by branch too, so they sit next to (never replace) a normal
// grant from the same principal.
func (k *collector) bypassEdge(g bypassGrant, repoID, branch string) {
	key := g.principal + "\x00" + string(graph.CanPush) + "\x00" + repoID + "\x00" + graph.ViaRefBypass + "\x00" + branch
	if _, ok := k.edges[key]; ok {
		return
	}
	attrs := map[string]string{graph.AttrVia: graph.ViaRefBypass, graph.AttrRef: branch, attrPermission: "bypass"}
	for a, v := range g.attrs {
		attrs[a] = v
	}
	k.edges[key] = &graph.Edge{From: g.principal, To: repoID, Kind: graph.CanPush, Evidence: graph.Live,
		SourceAPI: g.src, ObservedAt: k.observedAt(), Attrs: attrs}
}

func (k *collector) applyProtection(an *graph.Node, repoID, branch string, rp *refProtection) {
	full := strings.TrimPrefix(repoID, "repo:")
	if rp.protected == "unknown" {
		setAttr(an, graph.AttrRefProtected, "unknown", graph.NotVisible)
		k.cover(an.ID, graph.AttrRefProtection, rp.reason, rp.fix)
		return
	}
	setAttr(an, graph.AttrRefProtected, rp.protected, graph.Live)
	var labels []string
	for _, l := range protectionLabels {
		if rp.labels[l] {
			labels = append(labels, l)
		}
	}
	if len(labels) > 0 {
		setAttr(an, graph.AttrRefProtection, strings.Join(labels, ","), graph.Live)
	}
	if rp.protected != "true" {
		return
	}
	k.applyBypass(an, full, branch, rp)
}

// applyBypass records the bypass attr of a locked ref (a protected branch or
// an immutable tag) and coverage for bypass actors gop cannot resolve.
func (k *collector) applyBypass(an *graph.Node, full, ref string, rp *refProtection) {
	switch {
	case rp.bypassUnknown:
		setAttr(an, graph.AttrBypass, "unknown", graph.NotVisible)
		k.cover(an.ID, graph.AttrBypass, rp.bypassWhy, "admin on "+full)
	default:
		seen := map[string]bool{}
		var ps []string
		for _, g := range rp.grants {
			if !seen[g.principal] {
				seen[g.principal] = true
				ps = append(ps, g.principal)
			}
		}
		sort.Strings(ps)
		val := strings.Join(ps, ",")
		if val == "" {
			val = "none"
		}
		setAttr(an, graph.AttrBypass, val, graph.Live)
	}
	if len(rp.unresolved) > 0 {
		var uniq []string
		seen := map[string]bool{}
		for _, u := range rp.unresolved {
			if !seen[u] {
				seen[u] = true
				uniq = append(uniq, u)
			}
		}
		k.cover(an.ID, "ref_bypass", "bypass actors on "+full+"@"+ref+" that map to no principal: "+
			strings.Join(uniq, ", "), "admin on "+full+" to resolve repository roles; apps and deploy keys are not modelled yet")
	}
}

// branchPath builds /repos/{owner}/{repo}/{kind}/{branch} with the branch
// escaped per segment (branch names may contain "/").
func branchPath(owner, repo, kind, branch string) string {
	segs := strings.Split(branch, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/" + kind + "/" + strings.Join(segs, "/")
}

func (k *collector) refProtection(ctx context.Context, repoID, branch string, teamIDs map[string]map[int64]string) (*refProtection, error) {
	full := strings.TrimPrefix(repoID, "repo:")
	owner, repo, _ := strings.Cut(full, "/")
	rp := &refProtection{labels: map[string]bool{}}
	unknown := func(reason, fix string) *refProtection {
		return &refProtection{protected: "unknown", reason: reason, fix: fix}
	}

	var rules []apiRule
	var err error
	// Without rulesets on this GHES version only classic protection can
	// protect the branch: read that, and say once why rulesets were not.
	if !k.ghesSkip("enterprise:"+k.enterprise, capRulesets, capRulesets) {
		err = k.cl(owner).GetPages(ctx, branchPath(owner, repo, "rules/branches", branch)+"?per_page=100", func(page []byte) error {
			var batch []apiRule
			if err := json.Unmarshal(page, &batch); err != nil {
				return fmt.Errorf("decoding branch rules: %w", err)
			}
			rules = append(rules, batch...)
			return nil
		})
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return unknown("could not read rules for "+full+"@"+branch+": "+err.Error(), k.fixFor(err, "read access to "+full)), nil
	}
	// Rulesets that hold a protecting rule; their bypass actors are the bypassers.
	strongSets := map[int64]bool{}
	for _, r := range rules {
		switch r.Type {
		case "pull_request":
			p := r.Parameters
			if p.RequiredApprovals < 1 {
				continue
			}
			rp.labels["reviews"] = true
			if p.DismissStaleOnPush {
				rp.labels["dismiss_stale"] = true
			}
			if p.RequireLastPushApproval {
				rp.labels["last_push_approval"] = true
			}
			if p.DismissStaleOnPush || p.RequireLastPushApproval {
				strongSets[r.RulesetID] = true
			}
		case "update":
			rp.labels["push_restricted"] = true
			strongSets[r.RulesetID] = true
		case "required_status_checks":
			rp.labels["status_checks"] = true
		}
	}

	var br apiBranch
	if err := k.cl(owner).GetJSON(ctx, branchPath(owner, repo, "branches", branch), &br); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(strongSets) == 0 {
			return unknown("could not read branch "+full+"@"+branch+": "+err.Error(), k.fixFor(err, "read access to "+full)), nil
		}
		// Rulesets already protect the branch; classic rules could only narrow the bypassers.
	}
	classicStrong := false
	if br.Protected {
		var cp apiClassicProtection
		err := k.cl(owner).GetJSON(ctx, branchPath(owner, repo, "branches", branch)+"/protection", &cp)
		switch {
		case err != nil && ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil && len(strongSets) == 0:
			return unknown("branch "+full+"@"+branch+" has branch protection, but its rules are not visible: "+err.Error(),
				k.fixFor(err, "admin on "+full)), nil
		case err == nil:
			var grants []bypassGrant
			classicStrong, grants = k.classicRules(owner, repoID, &cp, rp)
			if classicStrong {
				rp.grants = append(rp.grants, grants...)
			}
		}
	}

	if len(strongSets) == 0 && !classicStrong {
		rp.protected = "false"
		rp.grants = nil
		return rp, nil
	}
	rp.protected = "true"
	setIDs := make([]int64, 0, len(strongSets))
	for id := range strongSets {
		setIDs = append(setIDs, id)
	}
	sort.Slice(setIDs, func(i, j int) bool { return setIDs[i] < setIDs[j] })
	var rsGrants []bypassGrant
	for _, id := range setIDs {
		var rs apiRuleset
		path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/rulesets/" + strconv.FormatInt(id, 10) + "?includes_parents=true"
		if err := k.cl(owner).GetJSON(ctx, path, &rs); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			rp.bypassUnknown = true
			rp.bypassWhy = fmt.Sprintf("could not read ruleset %d on %s: %v", id, full, err)
			continue
		}
		rs.ID = id
		gs, err := k.rulesetGrants(ctx, owner, repoID, &rs, teamIDs, rp)
		if err != nil {
			return nil, err
		}
		rsGrants = append(rsGrants, gs...)
	}
	// Ruleset grants first: the first grant per principal names the edge's source.
	rp.grants = append(rsGrants, rp.grants...)
	return rp, nil
}

// rulesetGrants maps the bypass actors of one ruleset to grants. When the
// actors are not visible (repository admins only) it sets rp.bypassUnknown.
func (k *collector) rulesetGrants(ctx context.Context, owner, repoID string, rs *apiRuleset, teamIDs map[string]map[int64]string, rp *refProtection) ([]bypassGrant, error) {
	full := strings.TrimPrefix(repoID, "repo:")
	if rs.BypassActors == nil {
		rp.bypassUnknown = true
		rp.bypassWhy = fmt.Sprintf("bypass actors of ruleset %d on %s are visible to repository admins only", rs.ID, full)
		return nil, nil
	}
	var out []bypassGrant
	for _, a := range *rs.BypassActors {
		attrs := map[string]string{attrRuleSource: "ruleset:" + strconv.FormatInt(rs.ID, 10)}
		if a.BypassMode != "" {
			attrs[attrBypassMode] = a.BypassMode
		}
		var actorID int64
		if a.ActorID != nil {
			actorID = *a.ActorID
		}
		ps, err := k.resolveActor(ctx, owner, repoID, a.ActorType, actorID, teamIDs, rp)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			out = append(out, bypassGrant{principal: p, src: srcRuleset, attrs: attrs})
		}
	}
	return out, nil
}

// classicRules reads classic branch protection: labels, whether it protects,
// and who can still land code alone.
func (k *collector) classicRules(owner, repoID string, cp *apiClassicProtection, rp *refProtection) (bool, []bypassGrant) {
	reviewsStrong := false
	if cp.RequiredStatusChecks != nil && string(*cp.RequiredStatusChecks) != "null" {
		rp.labels["status_checks"] = true
	}
	adminsEnforced := cp.EnforceAdmins != nil && cp.EnforceAdmins.Enabled
	if adminsEnforced {
		rp.labels["admins_enforced"] = true
	}
	if r := cp.RequiredPullRequestReviews; r != nil && r.RequiredApprovals >= 1 {
		rp.labels["reviews"] = true
		if r.DismissStaleReviews {
			rp.labels["dismiss_stale"] = true
		}
		if r.RequireLastPushApproval {
			rp.labels["last_push_approval"] = true
		}
		reviewsStrong = r.DismissStaleReviews || r.RequireLastPushApproval
	}
	if cp.Restrictions != nil {
		rp.labels["push_restricted"] = true
	}
	strong := reviewsStrong || cp.Restrictions != nil
	if !strong {
		return false, nil
	}
	attrs := map[string]string{attrRuleSource: ruleSourceClass}
	var actors *apiActors
	if reviewsStrong {
		// Bypass allowances skip the review requirement; push restrictions, if
		// any, are not intersected (over-approximation).
		actors = cp.RequiredPullRequestReviews.BypassAllowances
	} else {
		actors = cp.Restrictions
	}
	var grants []bypassGrant
	add := func(p string) {
		grants = append(grants, bypassGrant{principal: p, src: srcBranchProtection, attrs: attrs})
	}
	if actors != nil {
		for _, u := range actors.Users {
			if u.Login != "" {
				add(k.identity(u.Login).ID)
			}
		}
		for _, t := range actors.Teams {
			if t.Slug != "" {
				add(k.teamNode(owner, t.Slug))
			}
		}
		for _, a := range actors.Apps {
			rp.unresolved = append(rp.unresolved, "app "+a.Slug)
		}
	}
	if !adminsEnforced {
		// Repository admins are not bound by classic protection.
		for _, p := range k.roleHolders(repoID, "admin", rp) {
			add(p)
		}
	}
	return true, grants
}

// teamNode returns the identity node ID of org/slug, declaring it when the team
// was not listed (so the edge has both endpoints).
func (k *collector) teamNode(org, slug string) string {
	id := "team:" + org + "/" + slug
	if _, ok := k.nodes[id]; !ok {
		n := k.node(id, graph.KindIdentity, org+"/"+slug)
		setAttr(n, attrOrg, org, graph.Live)
		setAttr(n, attrSlug, slug, graph.Live)
	}
	return id
}

// roleHolders lists the principals with exactly this repository role on the
// repo, from the CAN_PUSH grants already collected (org owners hold admin).
func (k *collector) roleHolders(repoID, role string, rp *refProtection) []string {
	set := map[string]bool{}
	for _, e := range k.edges {
		if e.Kind != graph.CanPush || e.To != repoID || e.Evidence != graph.Live ||
			e.Attrs[graph.AttrVia] == graph.ViaRefBypass || e.Attrs[graph.AttrVia] == graph.ViaDefaultPerm ||
			e.Attrs[graph.AttrVia] == graph.ViaTokenWrite {
			continue
		}
		if strings.EqualFold(e.Attrs[attrPermission], role) {
			set[e.From] = true
		}
	}
	if rn := k.nodes[repoID]; rn != nil {
		org := k.byLower[strings.ToLower(rn.Attrs["org"])]
		partial := rn.Attrs[attrCollabs] == "unknown" || rn.Attrs["collected"] == "false" ||
			org == nil || org.node.Attrs[attrTeamsPartial] == "true"
		if partial {
			rp.unresolved = append(rp.unresolved, "holders of the "+role+" role (repository grants are only partly visible)")
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// resolveActor maps one ruleset bypass actor to principal IDs. Actors that map
// to nothing gop models are recorded in rp.unresolved.
func (k *collector) resolveActor(ctx context.Context, org, repoID, typ string, id int64, teamIDs map[string]map[int64]string, rp *refProtection) ([]string, error) {
	switch typ {
	case actorTeam:
		slugs, ok := teamIDs[strings.ToLower(org)]
		if !ok {
			slugs = map[int64]string{}
			teamIDs[strings.ToLower(org)] = slugs
			err := k.cl(org).GetPages(ctx, "/orgs/"+url.PathEscape(org)+"/teams?per_page=100", func(page []byte) error {
				var batch []struct {
					ID   int64  `json:"id"`
					Slug string `json:"slug"`
				}
				if err := json.Unmarshal(page, &batch); err != nil {
					return fmt.Errorf("decoding teams: %w", err)
				}
				for _, t := range batch {
					slugs[t.ID] = t.Slug
				}
				return nil
			})
			if err != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if slug := slugs[id]; slug != "" {
			return []string{k.teamNode(org, slug)}, nil
		}
		rp.unresolved = append(rp.unresolved, fmt.Sprintf("team %d (not listed)", id))
	case actorUser:
		var u struct {
			Login string `json:"login"`
		}
		if err := k.cl(org).GetJSON(ctx, "/user/"+strconv.FormatInt(id, 10), &u); err != nil || u.Login == "" {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			rp.unresolved = append(rp.unresolved, fmt.Sprintf("user %d", id))
			return nil, nil
		}
		return []string{k.identity(u.Login).ID}, nil
	case actorOrgAdmin:
		o := k.byLower[strings.ToLower(org)]
		if o == nil || o.node.Attrs[graph.AttrMembers] == "unknown" {
			rp.unresolved = append(rp.unresolved, "owners of "+org+" (not visible)")
			return nil, nil
		}
		out := make([]string, 0, len(o.owners))
		for _, l := range o.owners {
			out = append(out, k.identity(l).ID)
		}
		return out, nil
	case actorRepoRole:
		if role, ok := builtinRoleIDs[id]; ok {
			return k.roleHolders(repoID, role, rp), nil
		}
		rp.unresolved = append(rp.unresolved, fmt.Sprintf("custom repository role %d", id))
	default:
		rp.unresolved = append(rp.unresolved, strings.ToLower(typ))
	}
	return nil, nil
}
