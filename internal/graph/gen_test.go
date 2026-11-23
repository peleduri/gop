package graph

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// genGraph builds a random but valid evidence graph of roughly size nodes over
// synthetic names (org:acme-o3, repo:acme-o3/r17, identity:u5, ...). It uses
// every EdgeKind, every Evidence value, random ref_kind and via attributes
// (including workflow -CAN_PUSH-> repo with via=token_write), CAN_TRIGGER
// edges from org members, identities and external:anyone into workflows, ref
// gates (ref_protected, ref_immutable, ref_ambiguous, bypass) with
// via=ref_bypass CAN_PUSH edges into action host repos,
// parallel edges and cycles through nested USES, and actions_access levels on
// action host repos. A few edge endpoints are left
// undeclared so kind inference from the ID is exercised too.
//
// ref_kind on USES edges always agrees with the ref in the action ID (a 40-hex
// ref is "sha", "v1" is "tag", "main" is "branch") or is absent, as the
// collector writes it. The node-level ref_kind attr may disagree with the ID:
// it takes priority, so it never makes mutability depend on which edges exist.
func genGraph(r *rand.Rand, size int) *Graph {
	if size < 5 {
		size = 5
	}
	g := &Graph{Schema: SchemaVersion, Enterprise: "acme", CollectedAt: genTime}
	declared := map[string]bool{}
	node := func(id string, kind NodeKind, attrs map[string]string) {
		if declared[id] {
			return
		}
		declared[id] = true
		// About 1 in 20 nodes is left undeclared: edges may point at IDs the
		// collector never described, and Index.Kind falls back to the prefix.
		if r.IntN(20) == 0 {
			return
		}
		g.Nodes = append(g.Nodes, Node{ID: id, Kind: kind, Name: id, Attrs: attrs, Evidence: Live})
	}
	evs := []Evidence{Live, Live, Live, Audit, NotVisible, NotVisible}
	ev := func() Evidence { return evs[r.IntN(len(evs))] }
	edge := func(from, to string, kind EdgeKind, attrs map[string]string) {
		g.Edges = append(g.Edges, Edge{From: from, To: to, Kind: kind, Evidence: ev(),
			SourceAPI: fmt.Sprintf("test:%s:%d", kind, r.IntN(3)), ObservedAt: genTime, Attrs: attrs})
	}
	pick := func(ids []string) string { return ids[r.IntN(len(ids))] }

	nOrgs := 1 + size/50
	nRepos := max(2, size/5)
	nIdents := max(1, size/10)
	nTeams := max(1, size/25)
	nActions := max(1, size/6)
	nWorkflows := max(1, size/6)
	nTerm := max(1, size/10)

	var orgs, members, repos, idents, teams, actions, workflows, terminals []string
	orgOf := func(i int) string { return fmt.Sprintf("acme-o%d", i%nOrgs) }
	perms := []string{"none", "read", "write", "admin"}
	ssos := []string{"enforced", "configured", "none", ""}
	tfs := []string{"required", "not_required", ""}
	for i := 0; i < nOrgs; i++ {
		o := orgOf(i)
		attrs := map[string]string{AttrDefaultPerm: perms[r.IntN(len(perms))]}
		if s := ssos[r.IntN(len(ssos))]; s != "" {
			attrs[AttrSSO] = s
		}
		if t := tfs[r.IntN(len(tfs))]; t != "" {
			attrs[AttrTwoFactor] = t
		}
		node("org:"+o, KindOrg, attrs)
		node("members:"+o, KindOrgMembers, nil)
		orgs = append(orgs, "org:"+o)
		members = append(members, "members:"+o)
	}
	for i := 0; i < nRepos; i++ {
		id := fmt.Sprintf("repo:%s/r%d", orgOf(r.IntN(nOrgs)), i)
		node(id, KindRepo, nil)
		repos = append(repos, id)
	}
	for i := 0; i < nIdents; i++ {
		id := fmt.Sprintf("identity:u%d", i)
		node(id, KindIdentity, nil)
		idents = append(idents, id)
	}
	for i := 0; i < nTeams; i++ {
		id := fmt.Sprintf("team:%s/t%d", orgOf(r.IntN(nOrgs)), i)
		node(id, KindIdentity, nil)
		teams = append(teams, id)
	}
	refs := []string{"main", "v1", fmt.Sprintf("%040x", r.Uint64())}
	refKindOf := map[string]string{refs[0]: "branch", refs[1]: "tag", refs[2]: "sha"}
	actionRefKind := map[string]string{}
	for i := 0; i < nActions; i++ {
		// Host repos are named a<N> so the action ID reads like the issue's examples.
		owner := orgOf(r.IntN(nOrgs))
		host := fmt.Sprintf("repo:%s/a%d", owner, i)
		// About half the host repos carry an Actions access level, so USES
		// hops are dropped, kept or made not_visible by the access gate.
		var hostAttrs map[string]string
		if l := accessLevels[r.IntN(len(accessLevels))]; l != "" {
			hostAttrs = map[string]string{AttrActionsAccess: l}
		}
		node(host, KindRepo, hostAttrs)
		repos = append(repos, host)
		ref := refs[r.IntN(len(refs))]
		id := fmt.Sprintf("action:%s/a%d@%s", owner, i, ref)
		attrs := map[string]string{}
		if r.IntN(5) == 0 {
			attrs[AttrRefKind] = []string{"sha", "tag", "branch"}[r.IntN(3)]
		}
		// Ref gates: branch protection or tag immutability, bypass actors,
		// ambiguous refs and the ref attr the bypass edges are matched on.
		if r.IntN(3) == 0 {
			key := []string{AttrRefProtected, AttrRefImmutable}[r.IntN(2)]
			attrs[key] = []string{"true", "true", "false", "unknown"}[r.IntN(4)]
			if key == AttrRefImmutable && r.IntN(2) == 0 {
				attrs[AttrRefKind] = "tag"
			}
			if r.IntN(3) == 0 {
				attrs[AttrBypass] = []string{"unknown", "none"}[r.IntN(2)]
			}
		}
		if r.IntN(8) == 0 {
			attrs[AttrRefAmbiguous] = "true"
		}
		bypassRef := ref
		if r.IntN(4) == 0 {
			bypassRef = "other"
			attrs[AttrRef] = []string{ref, "other"}[r.IntN(2)]
		}
		if len(attrs) == 0 {
			attrs = nil
		}
		node(id, KindActionRef, attrs)
		actions = append(actions, id)
		actionRefKind[id] = refKindOf[ref]
		edge(id, host, ResolvesTo, nil)
		for k := r.IntN(3); k > 0; k-- {
			bypassers := append(append([]string{}, idents...), teams...)
			edge(pick(bypassers), host, CanPush, map[string]string{AttrVia: ViaRefBypass, AttrRef: bypassRef})
		}
	}
	for i := 0; i < nWorkflows; i++ {
		repo := pick(repos)
		id := fmt.Sprintf("workflow:%s/.github/workflows/w%d.yml", repo[len("repo:"):], i)
		node(id, KindWorkflow, nil)
		workflows = append(workflows, id)
		edge(id, repo, DefinedIn, nil)
		if r.IntN(4) == 0 {
			// A write GITHUB_TOKEN: the workflow controls its own repo.
			edge(id, repo, CanPush, map[string]string{AttrVia: ViaTokenWrite})
		}
		if r.IntN(10) == 0 {
			edge(id, pick(repos), DefinedIn, nil) // odd, but valid input
		}
	}
	termKinds := []struct {
		prefix string
		kind   NodeKind
	}{{"secret", KindSecret}, {"oidc", KindOIDC}, {"runner", KindRunner}}
	for i := 0; i < nTerm; i++ {
		tk := termKinds[r.IntN(len(termKinds))]
		id := fmt.Sprintf("%s:%s/x%d", tk.prefix, orgOf(r.IntN(nOrgs)), i)
		node(id, tk.kind, nil)
		terminals = append(terminals, id)
	}

	usesAttrs := func(action string) map[string]string {
		if r.IntN(4) == 0 {
			return nil
		}
		return map[string]string{AttrRefKind: actionRefKind[action]}
	}
	vias := []string{ViaDirect, ViaOrgOwner, ViaOutsideCollaborator, ViaTeam}
	for _, m := range members {
		for k := r.IntN(3); k > 0; k-- {
			via := ViaDefaultPerm
			if r.IntN(5) == 0 {
				via = ViaDirect
			}
			edge(m, pick(repos), CanPush, map[string]string{AttrVia: via})
		}
	}
	for _, p := range append(append([]string{}, idents...), teams...) {
		for k := r.IntN(3); k > 0; k-- {
			edge(p, pick(repos), CanPush, map[string]string{AttrVia: vias[r.IntN(len(vias))]})
		}
	}
	for _, id := range idents {
		if r.IntN(4) != 0 {
			edge(id, pick(orgs), MemberOf, nil)
		}
		if r.IntN(3) == 0 {
			edge(id, pick(teams), MemberOf, nil)
		}
	}
	// Nested teams: a child team gets what its parent gets (cycles allowed).
	for _, tm := range teams {
		if r.IntN(3) == 0 {
			edge(tm, pick(teams), MemberOf, nil)
		}
	}
	for _, w := range workflows {
		for k := r.IntN(3); k > 0; k-- {
			a := pick(actions)
			edge(w, a, Uses, usesAttrs(a))
		}
		for k := r.IntN(2); k > 0; k-- {
			edge(w, pick(terminals), ExecutesWith, nil)
		}
	}
	// Risky triggers: anyone on the internet (a public repo), an org's
	// members (internal or private) or an identity can cause an untrusted
	// execution in some workflows. external:anyone is a declared external node
	// (or, 1 in 20, undeclared and inferred from the prefix).
	if r.IntN(3) != 0 {
		node("external:anyone", KindExternal, nil)
	}
	triggerers := append(append([]string{"external:anyone"}, members...), idents...)
	execs := []string{"checkout", "injection"}
	for _, w := range workflows {
		for k := r.IntN(4) - 1; k > 0; k-- {
			edge(pick(triggerers), w, CanTrigger, map[string]string{
				"trigger": "pull_request_target", "exec": execs[r.IntN(len(execs))], "job": "build"})
		}
	}
	// Nested USES, cycles allowed (a -> b -> a, self loops).
	for k := r.IntN(len(actions) + 1); k > 0; k-- {
		a, b := pick(actions), pick(actions)
		edge(a, b, Uses, usesAttrs(b))
	}
	// Parallel edges: duplicate a few existing edges with other evidence,
	// source_api or via, as two collector passes may record the same fact.
	for k := r.IntN(len(g.Edges)/8 + 1); k > 0; k-- {
		e := g.Edges[r.IntN(len(g.Edges))]
		attrs := map[string]string{}
		for key, v := range e.Attrs {
			attrs[key] = v
		}
		if e.Kind == CanPush && r.IntN(2) == 0 {
			attrs[AttrVia] = vias[r.IntN(len(vias))]
		}
		edge(e.From, e.To, e.Kind, attrs)
	}
	return g
}

var accessLevels = []string{"", "", "", "", "", "", AccessNone, AccessUser, AccessOrganization, AccessEnterprise, AccessPublic, AccessUnknown}

var genTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
