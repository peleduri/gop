package graph

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loadAcme(t *testing.T) *Graph {
	t.Helper()
	g, err := LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestFixtureHasEvidenceEverywhere(t *testing.T) {
	g := loadAcme(t)
	for _, e := range g.Edges {
		if e.Evidence == "" || e.SourceAPI == "" || e.ObservedAt.IsZero() {
			t.Errorf("edge %s %s %s lacks evidence/source_api/observed_at", e.From, e.Kind, e.To)
		}
	}
	if len(g.Coverage) == 0 {
		t.Error("fixture should carry coverage entries")
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	for name, in := range map[string]string{
		"schema":   `{"schema":"gop.graph/v0"}`,
		"evidence": `{"schema":"gop.graph/v1","edges":[{"from":"a","to":"b","kind":"CAN_PUSH","evidence":"maybe"}]}`,
		"json":     `{`,
	} {
		if _, err := Load(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func appRepos(names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "repo:acme-app/" + n
	}
	return out
}

func TestReach(t *testing.T) {
	g := loadAcme(t)
	actionsRepos := append([]string{"repo:acme-actions/deploy", "repo:acme-actions/setup"},
		appRepos("admin", "api", "auth", "billing", "docs", "gateway", "mobile", "search", "web", "worker")...)
	tests := []struct {
		from          string
		repos         []string
		workflows     int
		secrets, oidc []string
		runners       []string
		orgs          []string
		possibleRepos []string
	}{
		{"members:acme-actions", actionsRepos, 11, []string{"secret:acme-app/billing"}, []string{"oidc:acme-app/web"}, []string{"runner:acme-app/worker"}, []string{"org:acme-actions", "org:acme-app"}, nil},
		{"identity:bob", actionsRepos, 11, []string{"secret:acme-app/billing"}, []string{"oidc:acme-app/web"}, []string{"runner:acme-app/worker"}, []string{"org:acme-actions", "org:acme-app"}, nil},
		{"identity:alice", appRepos("infra"), 1, nil, nil, nil, []string{"org:acme-app"}, nil},
		{"members:acme-secure", nil, 0, nil, nil, nil, nil, nil},
		{"members:acme-legacy", nil, 0, nil, nil, nil, nil, []string{"repo:acme-legacy/old-api"}},
	}
	for _, tc := range tests {
		t.Run(tc.from, func(t *testing.T) {
			r := Reach(g, tc.from, Options{})
			c := r.Confirmed
			if !reflect.DeepEqual(c.Repos, tc.repos) {
				t.Errorf("repos = %v\nwant %v", c.Repos, tc.repos)
			}
			if len(c.Workflows) != tc.workflows {
				t.Errorf("workflows = %d, want %d", len(c.Workflows), tc.workflows)
			}
			for name, pair := range map[string][2][]string{"secrets": {c.Secrets, tc.secrets}, "oidc": {c.OIDC, tc.oidc}, "runners": {c.Runners, tc.runners}, "orgs": {c.Orgs, tc.orgs}, "possible": {r.Possible.Repos, tc.possibleRepos}} {
				if !reflect.DeepEqual(pair[0], pair[1]) {
					t.Errorf("%s = %v, want %v", name, pair[0], pair[1])
				}
			}
			for _, id := range c.Repos {
				if r.Paths[id].Unverified {
					t.Errorf("confirmed %s has unverified path", id)
				}
			}
		})
	}
	r := Reach(g, "members:acme-actions", Options{})
	for _, id := range append(r.Confirmed.Repos, r.Confirmed.Workflows...) {
		if strings.Contains(id, "acme-app/infra") || strings.Contains(id, "acme-app/sandbox") || strings.Contains(id, "acme-secure") {
			t.Errorf("sha-pinned or action-free %s must not be reached", id)
		}
	}
}

func TestWhoCanReachOIDCRepo(t *testing.T) {
	g := loadAcme(t)
	paths := WhoCanReach(g, "repo:acme-app/web")
	var got *Path
	for i := range paths {
		if paths[i].From == "members:acme-actions" {
			got = &paths[i]
		}
	}
	if got == nil {
		t.Fatalf("members:acme-actions missing from %v", paths)
	}
	if len(got.Hops) < 4 || got.Unverified {
		t.Fatalf("path = %+v, want a verified 4+ hop path", got.Hops)
	}
	want := []EdgeKind{CanPush, ResolvesTo, Uses, DefinedIn}
	for i, k := range want {
		if got.Hops[i].Kind != k {
			t.Errorf("hop %d = %s, want %s", i, got.Hops[i].Kind, k)
		}
	}
	if got.Hops[0].From != "members:acme-actions" || got.Hops[3].To != "repo:acme-app/web" {
		t.Errorf("path endpoints wrong: %+v", got.Hops)
	}
	from := []string{}
	for _, p := range paths {
		from = append(from, p.From)
	}
	if !reflect.DeepEqual(from, []string{"identity:bob", "members:acme-actions"}) {
		t.Errorf("principals = %v", from)
	}
	// Terminal targets work too.
	if ps := WhoCanReach(g, "oidc:acme-app/web"); len(ps) != 2 || len(ps[0].Hops) != 4 {
		t.Errorf("oidc reachers = %+v", ps)
	}
}

func TestNotVisibleIsPossibleNotConfirmed(t *testing.T) {
	g := loadAcme(t)
	r := Reach(g, "members:acme-legacy", Options{})
	if len(r.Confirmed.Repos)+len(r.Confirmed.Secrets) != 0 {
		t.Fatalf("not_visible reach leaked into confirmed: %+v", r.Confirmed)
	}
	if !reflect.DeepEqual(r.Possible.Secrets, []string{"secret:acme-legacy/old-api"}) || !reflect.DeepEqual(r.Possible.Orgs, []string{"org:acme-legacy"}) {
		t.Fatalf("possible = %+v", r.Possible)
	}
	p := r.Paths["secret:acme-legacy/old-api"]
	if !p.Unverified || p.Evidence != NotVisible || len(p.Hops) != 3 {
		t.Fatalf("path = %+v, want unverified 3-hop", p)
	}
	s := BlastRadius(g, "members:acme-legacy")
	if s.Score != 0 || s.Possible.Repos != 1 || s.Possible.Secrets != 1 || s.PossibleScore != 19.125 {
		t.Errorf("score = %+v", s)
	}
	ws := WhoCanReach(g, "secret:acme-legacy/old-api")
	if len(ws) != 1 || !ws[0].Unverified {
		t.Errorf("WhoCanReach = %+v", ws)
	}
	d := WhatIf(g, nil)
	if d.Before.ConfirmedPairs != 25 || d.Before.PossiblePairs != 1 {
		t.Errorf("pairs confirmed=%d possible=%d", d.Before.ConfirmedPairs, d.Before.PossiblePairs)
	}
	for _, c := range NewIndex(g).Candidates() {
		if c.ID() == "default_perm:org:acme-legacy->read" {
			t.Error("fix touching only not_visible edges must not be a candidate")
		}
	}
}

func TestBlastRadiusAndTopPaths(t *testing.T) {
	g := loadAcme(t)
	s := BlastRadius(g, "members:acme-actions")
	want := Counts{Repos: 12, Orgs: 2, Workflows: 11, Secrets: 1, OIDC: 1, Runners: 1}
	if s.Confirmed != want || s.Multiplier != 2.25 || s.Score != 84.375 {
		t.Fatalf("score = %+v", s)
	}
	if a := BlastRadius(g, "identity:alice"); a.Multiplier != 1 || a.Score != 3.5 {
		t.Errorf("alice = %+v", a)
	}
	top := TopPaths(g, 3)
	var ids []string
	for _, s := range top {
		ids = append(ids, s.Principal)
	}
	if !reflect.DeepEqual(ids, []string{"identity:bob", "members:acme-actions", "identity:alice"}) {
		t.Errorf("top = %v", ids)
	}
	if len(TopPaths(g, 0)) != 6 {
		t.Errorf("TopPaths(0) should return all 6 principals")
	}
}

func TestWhatIfPinMain(t *testing.T) {
	g := loadAcme(t)
	d := WhatIf(g, []Fix{PinRef{Action: "action:acme-actions/deploy@main"}})
	for _, pd := range d.PerPrincipal {
		if pd.Principal == "members:acme-actions" {
			if got := pd.Before.Confirmed.Repos - pd.After.Confirmed.Repos; got != 9 {
				t.Errorf("members:acme-actions repo drop = %d, want 9", got)
			}
			if pd.After.Confirmed.OIDC != 0 || pd.After.Confirmed.Secrets != 0 || pd.After.Confirmed.Runners != 0 {
				t.Errorf("terminals should be gone: %+v", pd.After.Confirmed)
			}
		}
	}
	if d.Before.ConfirmedPairs-d.After.ConfirmedPairs != 18 {
		t.Errorf("total pair drop = %d, want 18", d.Before.ConfirmedPairs-d.After.ConfirmedPairs)
	}
	if d.After.PossiblePairs != 1 {
		t.Errorf("possible pairs should be untouched")
	}
	// Lowering acme-actions default perm leaves bob's direct grant.
	d2 := WhatIf(g, []Fix{LowerDefaultPerm{Org: "org:acme-actions", To: "read"}})
	if d2.After.ConfirmedPairs != 12 {
		t.Errorf("after lower default perm pairs = %d, want 12", d2.After.ConfirmedPairs)
	}
	if d3 := WhatIf(g, []Fix{LowerDefaultPerm{Org: "org:acme-actions", To: "write"}}); d3.After != d3.Before {
		t.Error("LowerDefaultPerm to write must be a no-op")
	}
}

func TestSuggestFixes(t *testing.T) {
	g := loadAcme(t)
	got := SuggestFixes(g, 2)
	type row struct {
		id       string
		removed  int
		pct      float64
		remained int
	}
	want := []row{
		{"pin:action:acme-actions/deploy@main", 18, 72, 7},
		{"default_perm:org:acme-actions->read", 4, 88, 3},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d suggestions: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if (row{g.FixID, g.Removed, g.CumulativePct, g.Remaining}) != w {
			t.Errorf("pick %d = %+v, want %+v", i, row{g.FixID, g.Removed, g.CumulativePct, g.Remaining}, w)
		}
	}
	all := SuggestFixes(g, 10)
	last := all[len(all)-1]
	if last.Removed == 0 {
		t.Error("greedy must stop when nothing more is removed")
	}
}

func TestDeterministic(t *testing.T) {
	g := loadAcme(t)
	enc := func() string {
		out := map[string]any{
			"reach":   Reach(g, "members:acme-actions", Options{}),
			"who":     WhoCanReach(g, "oidc:acme-app/web"),
			"top":     TopPaths(g, 0),
			"whatif":  WhatIf(g, []Fix{PinRef{Action: "action:acme-actions/deploy@v1"}}),
			"suggest": SuggestFixes(g, 3),
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	first := enc()
	for i := 0; i < 20; i++ {
		// Shuffle input order: results must not depend on it.
		g.Edges[0], g.Edges[len(g.Edges)-1-i] = g.Edges[len(g.Edges)-1-i], g.Edges[0]
		g.Nodes[0], g.Nodes[len(g.Nodes)-1-i] = g.Nodes[len(g.Nodes)-1-i], g.Nodes[0]
		if enc() != first {
			t.Fatalf("run %d differs", i)
		}
	}
}

// --- synthetic graphs ---

func edge(from, kind, to string, attrs ...string) Edge {
	e := Edge{From: from, To: to, Kind: EdgeKind(kind), Evidence: Live, SourceAPI: "test", ObservedAt: time.Unix(0, 0)}
	if len(attrs) > 0 {
		e.Attrs = map[string]string{}
		for i := 0; i+1 < len(attrs); i += 2 {
			e.Attrs[attrs[i]] = attrs[i+1]
		}
	}
	return e
}

func TestCycle(t *testing.T) {
	// repo o/a's workflow uses o/a's own action at a branch: a self loop.
	g := &Graph{Schema: SchemaVersion, Edges: []Edge{
		edge("members:o", "CAN_PUSH", "repo:o/a"),
		edge("workflow:o/a/.github/workflows/ci.yml", "DEFINED_IN", "repo:o/a"),
		edge("workflow:o/a/.github/workflows/ci.yml", "USES", "action:o/a@main", "ref_kind", "branch"),
		edge("action:o/a@main", "RESOLVES_TO", "repo:o/a"),
		edge("workflow:o/a/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:o/a"),
	}}
	r := Reach(g, "members:o", Options{})
	if !reflect.DeepEqual(r.Confirmed.Repos, []string{"repo:o/a"}) || len(r.Confirmed.Workflows) != 1 || len(r.Confirmed.Secrets) != 1 {
		t.Fatalf("cycle reach = %+v", r.Confirmed)
	}
	if got := len(r.Paths["secret:o/a"].Hops); got != 3 {
		t.Errorf("shortest path to secret = %d hops, want 3", got)
	}
	if ws := WhoCanReach(g, "repo:o/a"); len(ws) != 1 {
		t.Errorf("who = %+v", ws)
	}
}

func TestNestedActions(t *testing.T) {
	build := func(nestedKind, nestedRef string) *Graph {
		return &Graph{Schema: SchemaVersion, Edges: []Edge{
			edge("members:x", "CAN_PUSH", "repo:x/lib"),
			edge("workflow:o/app/.github/workflows/ci.yml", "DEFINED_IN", "repo:o/app"),
			edge("workflow:o/app/.github/workflows/ci.yml", "USES", "action:x/outer@0123456789abcdef0123456789abcdef01234567", "ref_kind", "sha"),
			edge("action:x/outer@0123456789abcdef0123456789abcdef01234567", "RESOLVES_TO", "repo:x/outer"),
			edge("action:x/outer@0123456789abcdef0123456789abcdef01234567", "USES", "action:x/lib@"+nestedRef, "ref_kind", nestedKind),
			edge("action:x/lib@"+nestedRef, "RESOLVES_TO", "repo:x/lib"),
		}}
	}
	open := Reach(build("branch", "main"), "members:x", Options{})
	if !reflect.DeepEqual(open.Confirmed.Repos, []string{"repo:o/app", "repo:x/lib"}) {
		t.Errorf("mutable nested ref under sha pin must keep path open: %v", open.Confirmed.Repos)
	}
	if n := len(open.Paths["repo:o/app"].Hops); n != 5 {
		t.Errorf("nested path hops = %d, want 5", n)
	}
	closed := Reach(build("sha", "fedcba9876543210fedcba9876543210fedcba98"), "members:x", Options{})
	if !reflect.DeepEqual(closed.Confirmed.Repos, []string{"repo:x/lib"}) {
		t.Errorf("fully immutable chain must block: %v", closed.Confirmed.Repos)
	}
	// Pinning the nested ref closes it.
	pinned := Reach(build("branch", "main"), "members:x", Options{Fixes: []Fix{PinRef{Action: "action:x/lib@main"}}})
	if !reflect.DeepEqual(pinned.Confirmed.Repos, []string{"repo:x/lib"}) {
		t.Errorf("PinRef on nested ref must block: %v", pinned.Confirmed.Repos)
	}
}

func TestEmptyGraph(t *testing.T) {
	for _, g := range []*Graph{nil, {Schema: SchemaVersion}} {
		r := Reach(g, "members:none", Options{})
		if len(r.Paths) != 0 || len(r.Confirmed.Repos) != 0 {
			t.Errorf("reach on empty = %+v", r)
		}
		if WhoCanReach(g, "repo:x/y") != nil || len(TopPaths(g, 5)) != 0 || len(SuggestFixes(g, 3)) != 0 {
			t.Error("empty graph should produce empty results")
		}
		if s := BlastRadius(g, "members:none"); s.Score != 0 {
			t.Errorf("score = %+v", s)
		}
		if d := WhatIf(g, []Fix{PinRef{Action: "action:x/y@main"}}); d.Before.Principals != 0 {
			t.Errorf("delta = %+v", d)
		}
	}
}

func TestLowerDefaultPermKeepsDirectGrants(t *testing.T) {
	g := &Graph{Schema: SchemaVersion, Edges: []Edge{
		edge("members:acme-actions", "CAN_PUSH", "repo:acme-actions/deploy", AttrVia, ViaDefaultPerm),
		edge("identity:bob", "CAN_PUSH", "repo:acme-actions/deploy", AttrVia, ViaDirect, "permission", "maintain"),
		edge("identity:alice", "CAN_PUSH", "repo:acme-actions/deploy", AttrVia, ViaOrgOwner, "permission", "admin"),
		edge("identity:frank", "CAN_PUSH", "repo:acme-actions/deploy", AttrVia, ViaOutsideCollaborator, "permission", "deployer"),
	}}
	lower := []Fix{LowerDefaultPerm{Org: "org:acme-actions", To: "read"}}
	if r := Reach(g, "members:acme-actions", Options{Fixes: lower}); len(r.Confirmed.Repos) != 0 {
		t.Errorf("default-perm edge should be removed: %v", r.Confirmed.Repos)
	}
	for _, p := range []string{"identity:bob", "identity:alice", "identity:frank"} {
		r := Reach(g, p, Options{Fixes: lower})
		if !reflect.DeepEqual(r.Confirmed.Repos, []string{"repo:acme-actions/deploy"}) {
			t.Errorf("%s lost its grant after LowerDefaultPerm: %v", p, r.Confirmed.Repos)
		}
	}
	if es := (LowerDefaultPerm{Org: "org:acme-actions", To: "read"}).edges(NewIndex(g)); len(es) != 1 || es[0].From != "members:acme-actions" {
		t.Errorf("LowerDefaultPerm edges = %+v", es)
	}
	d := WhatIf(g, lower)
	if d.Before.ConfirmedPairs != 4 || d.After.ConfirmedPairs != 3 {
		t.Errorf("pairs before=%d after=%d, want 4 and 3", d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
	}
}

func TestScoringPrincipals(t *testing.T) {
	g := &Graph{Schema: SchemaVersion,
		Nodes: []Node{
			{ID: "members:o", Kind: KindOrgMembers, Evidence: Live},
			{ID: "members:quiet", Kind: KindOrgMembers, Evidence: Live},
			{ID: "identity:dave", Kind: KindIdentity, Evidence: Live},
			{ID: "org:o", Kind: KindOrg, Evidence: Live, Attrs: map[string]string{AttrTwoFactor: "not_required", AttrSSO: "enforced"}},
		},
		Edges: []Edge{
			edge("members:o", "CAN_PUSH", "repo:o/a", AttrVia, ViaDefaultPerm),
			edge("identity:alice", "CAN_PUSH", "repo:o/b", AttrVia, ViaDirect),
			edge("identity:alice", "MEMBER_OF", "org:o"),
			edge("identity:dave", "MEMBER_OF", "org:o"),
			edge("identity:tess", "MEMBER_OF", "team:o/deployers"),
			// A weak attr on the edge would leak into the multiplier if the team
			// were mistaken for an org (orgAttr falls back to CAN_PUSH attrs).
			edge("identity:tess", "CAN_PUSH", "repo:o/c", AttrVia, ViaDirect, AttrTwoFactor, "not_required"),
		},
	}
	ix := NewIndex(g)
	if got, want := ix.Principals(), []string{"identity:alice", "identity:dave", "identity:tess", "members:o", "members:quiet"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Principals = %v, want %v", got, want)
	}
	// dave only shares members:o's reach: scoring him again would double count.
	if got, want := ix.ScoringPrincipals(), []string{"identity:alice", "identity:tess", "members:o", "members:quiet"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ScoringPrincipals = %v, want %v", got, want)
	}
	d := ix.WhatIf(nil)
	if d.Before.Principals != 4 || len(d.PerPrincipal) != 4 {
		t.Errorf("WhatIf principals = %d (%d rows), want 4", d.Before.Principals, len(d.PerPrincipal))
	}
	// alice: o/a through members:o plus o/b directly; members:o: o/a; tess: o/c.
	if d.Before.ConfirmedPairs != 4 {
		t.Errorf("confirmed pairs = %d, want 4", d.Before.ConfirmedPairs)
	}
	if len(ix.TopPaths(0)) != 4 {
		t.Errorf("TopPaths should score the 4 scoring principals")
	}
	// WhoCanReach still considers every principal.
	var from []string
	for _, p := range ix.WhoCanReach("repo:o/a") {
		from = append(from, p.From)
	}
	if !reflect.DeepEqual(from, []string{"members:o", "identity:alice", "identity:dave"}) {
		t.Errorf("WhoCanReach = %v", from)
	}
	// A MEMBER_OF to a team does not count as an org for the multiplier.
	if m := ix.BlastRadius("identity:tess").Multiplier; m != 1 {
		t.Errorf("team membership multiplier = %v, want 1", m)
	}
	if m := ix.BlastRadius("identity:alice").Multiplier; m != 1.5 {
		t.Errorf("org membership multiplier = %v, want 1.5", m)
	}

	// On the engine fixture every identity has a CAN_PUSH edge, so the scoring set
	// equals the full set and the pair totals are unchanged.
	fx := NewIndex(loadAcme(t))
	if !reflect.DeepEqual(fx.ScoringPrincipals(), fx.Principals()) {
		t.Errorf("fixture scoring set %v != principals %v", fx.ScoringPrincipals(), fx.Principals())
	}
	if d := fx.WhatIf(nil); d.Before.ConfirmedPairs != 25 {
		t.Errorf("fixture confirmed pairs = %d, want 25", d.Before.ConfirmedPairs)
	}
}
