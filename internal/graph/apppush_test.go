package graph

import "testing"

// acmeAppPush: acme-app (default permission write, two repos) and
// acme-actions (one repo). acme-ai-reviewer is installed on all repositories
// of both orgs with contents: write (inferred edges); acme-deploy on selected
// repositories of acme-actions (a not_visible edge).
func acmeAppPush() *Graph {
	g := &Graph{Schema: SchemaVersion, Nodes: []Node{
		{ID: "org:acme-app", Kind: KindOrg, Evidence: Live},
		{ID: "org:acme-actions", Kind: KindOrg, Evidence: Live},
		{ID: "members:acme-app", Kind: KindOrgMembers, Evidence: Live},
		{ID: "identity:acme-ai-reviewer[bot]", Kind: KindIdentity, Name: "acme-ai-reviewer[bot]", Evidence: Live},
		{ID: "identity:acme-deploy[bot]", Kind: KindIdentity, Name: "acme-deploy[bot]", Evidence: Live},
	}}
	appEdge := func(app, repo string, ev Evidence, sel string) Edge {
		e := edge(app, "CAN_PUSH", repo, AttrVia, ViaAppInstall, AttrAppRepos, sel)
		e.Evidence = ev
		if ev == Inferred {
			e.Attrs[AttrRule] = RuleAppInstall
		}
		return e
	}
	for _, r := range []string{"repo:acme-app/web", "repo:acme-app/api", "repo:acme-actions/deploy"} {
		g.Nodes = append(g.Nodes, Node{ID: r, Kind: KindRepo, Evidence: Live})
		g.Edges = append(g.Edges, appEdge("identity:acme-ai-reviewer[bot]", r, Inferred, "all"))
	}
	for _, r := range []string{"repo:acme-app/web", "repo:acme-app/api"} {
		e := edge("members:acme-app", "CAN_PUSH", r, AttrVia, ViaDefaultPerm, AttrRule, RuleDefaultPerm)
		e.Evidence = Inferred
		g.Edges = append(g.Edges, e)
	}
	g.Edges = append(g.Edges, appEdge("identity:acme-deploy[bot]", "repo:acme-actions/deploy", NotVisible, "selected"))
	return g
}

// TestAppPushReach: an App with inferred push edges is a scoring principal
// whose reach is confirmed across both orgs; an App on selected repositories
// is possible only; who_can_reach lists both.
func TestAppPushReach(t *testing.T) {
	ix := NewIndex(acmeAppPush())
	sp := map[string]bool{}
	for _, p := range ix.ScoringPrincipals() {
		sp[p] = true
	}
	for _, p := range []string{"identity:acme-ai-reviewer[bot]", "identity:acme-deploy[bot]", "members:acme-app"} {
		if !sp[p] {
			t.Errorf("%s is not a scoring principal", p)
		}
	}
	r := ix.Reach("identity:acme-ai-reviewer[bot]", Options{})
	if len(r.Confirmed.Repos) != 3 {
		t.Errorf("reviewer confirmed repos = %v, want 3", r.Confirmed.Repos)
	}
	d := ix.Reach("identity:acme-deploy[bot]", Options{})
	if len(d.Confirmed.Repos) != 0 || len(d.Possible.Repos) != 1 {
		t.Errorf("deploy confirmed %v possible %v, want 0 and 1", d.Confirmed.Repos, d.Possible.Repos)
	}
	who := map[string]bool{}
	for _, p := range ix.WhoCanReach("repo:acme-actions/deploy") {
		who[p.From] = p.Unverified
	}
	if unv, ok := who["identity:acme-ai-reviewer[bot]"]; !ok || unv {
		t.Errorf("who_can_reach: reviewer confirmed = %v, %v", ok, !unv)
	}
	if unv, ok := who["identity:acme-deploy[bot]"]; !ok || !unv {
		t.Errorf("who_can_reach: deploy possible = %v, %v", ok, unv)
	}
}

// TestAppPushPairsOnce: an App installed in two orgs is one principal: its
// pairs count once per repo, beside the members' own pairs, and the possible
// selected installation never adds confirmed pairs.
func TestAppPushPairsOnce(t *testing.T) {
	tot := NewIndex(acmeAppPush()).Totals()
	// members:acme-app 2 + acme-ai-reviewer 3 = 5 confirmed; acme-deploy 1 possible.
	if tot.ConfirmedPairs != 5 || tot.PossiblePairs != 1 {
		t.Errorf("pairs confirmed %d possible %d, want 5 and 1", tot.ConfirmedPairs, tot.PossiblePairs)
	}
}
