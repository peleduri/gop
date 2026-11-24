package graph

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
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

func TestLoadOrgCollectedAt(t *testing.T) {
	in := `{"schema":"` + SchemaVersion + `","collected_at":"2026-11-20T10:00:00Z","enterprise":"acme",` +
		`"nodes":[],"edges":[],"coverage":[],` +
		`"org_collected_at":{"acme-actions":"2026-11-20T10:00:00Z","acme-app":"2026-11-13T10:00:00Z"}}`
	g, err := Load(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]time.Time{
		"acme-actions": time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		"acme-app":     time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
	}
	if len(g.OrgCollectedAt) != len(want) {
		t.Fatalf("org_collected_at = %v, want %v", g.OrgCollectedAt, want)
	}
	for o, w := range want {
		if !g.OrgCollectedAt[o].Equal(w) {
			t.Errorf("org_collected_at[%s] = %v, want %v", o, g.OrgCollectedAt[o], w)
		}
	}
	// Optional: a graph without it loads, and writes without it.
	g.OrgCollectedAt = nil
	out, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "org_collected_at") {
		t.Errorf("empty org_collected_at should be omitted: %s", out)
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
		{"members:acme-actions", actionsRepos, 13, []string{"secret:acme-app/billing"}, []string{"oidc:acme-app/web"}, []string{"runner:acme-app/worker"}, []string{"org:acme-actions", "org:acme-app"}, nil},
		{"identity:bob", actionsRepos, 13, []string{"secret:acme-app/billing"}, []string{"oidc:acme-app/web"}, []string{"runner:acme-app/worker"}, []string{"org:acme-actions", "org:acme-app"}, nil},
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
	// The last hop is web's write GITHUB_TOKEN (via=token_write): control of
	// the repo, not only its CI.
	want := []EdgeKind{CanPush, ResolvesTo, Uses, CanPush}
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
	if d.Before.ConfirmedPairs != 24 || d.Before.PossiblePairs != 1 {
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
	want := Counts{Repos: 12, Orgs: 2, Workflows: 13, Secrets: 1, OIDC: 1, Runners: 1}
	if s.Confirmed != want || s.Multiplier != 2.25 || s.Score != 86.625 {
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
		{"pin:action:acme-actions/deploy@main", 18, 75, 6},
		{"default_perm:org:acme-actions->read", 3, 87.5, 3},
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
	// members:o: o/a; alice: o/b directly (her o/a comes through members:o
	// and is counted once, on its row); tess: o/c.
	if d.Before.ConfirmedPairs != 3 {
		t.Errorf("confirmed pairs = %d, want 3", d.Before.ConfirmedPairs)
	}
	if s := ix.BlastRadius("identity:alice"); s.Confirmed.Repos != 2 {
		t.Errorf("alice's score: %d repos, want 2 (o/a through members:o and o/b)", s.Confirmed.Repos)
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
	// equals the full set.
	fx := NewIndex(loadAcme(t))
	if !reflect.DeepEqual(fx.ScoringPrincipals(), fx.Principals()) {
		t.Errorf("fixture scoring set %v != principals %v", fx.ScoringPrincipals(), fx.Principals())
	}
	if d := fx.WhatIf(nil); d.Before.ConfirmedPairs != 24 {
		t.Errorf("fixture confirmed pairs = %d, want 24", d.Before.ConfirmedPairs)
	}
}

func TestNestedTeamReach(t *testing.T) {
	g := &Graph{Schema: SchemaVersion,
		Nodes: []Node{
			{ID: "org:acme-actions", Kind: KindOrg, Evidence: Live, Attrs: map[string]string{AttrTwoFactor: "not_required", AttrSSO: "enforced"}},
			{ID: "team:acme-actions/platform", Kind: KindIdentity, Evidence: Live},
			{ID: "team:acme-actions/platform-oncall", Kind: KindIdentity, Evidence: Live},
			{ID: "identity:bob", Kind: KindIdentity, Evidence: Live},
			{ID: "identity:erin", Kind: KindIdentity, Evidence: Live},
		},
		Edges: []Edge{
			edge("team:acme-actions/platform", "CAN_PUSH", "repo:acme-actions/deploy", AttrVia, ViaTeam, "permission", "maintain"),
			edge("identity:bob", "MEMBER_OF", "team:acme-actions/platform"),
			edge("team:acme-actions/platform-oncall", "MEMBER_OF", "team:acme-actions/platform"),
			edge("identity:erin", "MEMBER_OF", "team:acme-actions/platform-oncall"),
		},
	}
	ix := NewIndex(g)
	r := ix.Reach("identity:erin", Options{})
	if !reflect.DeepEqual(r.Confirmed.Repos, []string{"repo:acme-actions/deploy"}) {
		t.Fatalf("erin confirmed repos = %v", r.Confirmed.Repos)
	}
	if !reflect.DeepEqual(r.Confirmed.Orgs, []string{"org:acme-actions"}) {
		t.Errorf("erin confirmed orgs = %v", r.Confirmed.Orgs)
	}
	var kinds []EdgeKind
	for _, h := range r.Paths["repo:acme-actions/deploy"].Hops {
		kinds = append(kinds, h.Kind)
	}
	if want := []EdgeKind{MemberOf, MemberOf, CanPush}; !reflect.DeepEqual(kinds, want) {
		t.Errorf("erin path = %v, want %v", kinds, want)
	}
	if r := ix.Reach("identity:bob", Options{}); len(r.Paths["repo:acme-actions/deploy"].Hops) != 2 {
		t.Errorf("bob path = %+v", r.Paths["repo:acme-actions/deploy"])
	}
	// The child team inherits the grant; the parent does not reach anything of the child's.
	if r := ix.Reach("team:acme-actions/platform-oncall", Options{}); !reflect.DeepEqual(r.Confirmed.Repos, []string{"repo:acme-actions/deploy"}) {
		t.Errorf("child team repos = %v", r.Confirmed.Repos)
	}
	var who []string
	for _, p := range ix.WhoCanReach("repo:acme-actions/deploy") {
		who = append(who, p.From)
	}
	sort.Strings(who)
	if want := []string{"identity:bob", "identity:erin", "team:acme-actions/platform", "team:acme-actions/platform-oncall"}; !reflect.DeepEqual(who, want) {
		t.Errorf("WhoCanReach = %v, want %v", who, want)
	}
	// Team principals are scored, and their org's weak controls apply to them.
	sp := ix.ScoringPrincipals()
	for _, team := range []string{"team:acme-actions/platform", "team:acme-actions/platform-oncall"} {
		if !slices.Contains(sp, team) {
			t.Errorf("ScoringPrincipals %v lacks %s", sp, team)
		}
	}
	if m := ix.BlastRadius("team:acme-actions/platform").Multiplier; m != 1.5 {
		t.Errorf("team multiplier = %v, want 1.5", m)
	}
}

func TestTeamCycle(t *testing.T) {
	g := &Graph{Schema: SchemaVersion, Edges: []Edge{
		edge("team:o/a", "MEMBER_OF", "team:o/b"),
		edge("team:o/b", "MEMBER_OF", "team:o/a"),
		edge("team:o/b", "CAN_PUSH", "repo:o/r", AttrVia, ViaTeam),
		edge("identity:alice", "MEMBER_OF", "team:o/a"),
	}}
	r := Reach(g, "identity:alice", Options{})
	if !reflect.DeepEqual(r.Confirmed.Repos, []string{"repo:o/r"}) {
		t.Fatalf("cycle reach = %v", r.Confirmed.Repos)
	}
	if n := len(r.Paths["repo:o/r"].Hops); n != 3 {
		t.Errorf("cycle path hops = %d, want 3", n)
	}
	if r := Reach(g, "team:o/a", Options{}); !reflect.DeepEqual(r.Confirmed.Repos, []string{"repo:o/r"}) {
		t.Errorf("team:o/a reach = %v", r.Confirmed.Repos)
	}
}

func TestOrgOf(t *testing.T) {
	for id, want := range map[string]string{
		"team:acme-actions/platform":                     "org:acme-actions",
		"team:acme-actions":                              "org:acme-actions",
		"repo:acme-app/web":                              "org:acme-app",
		"members:acme-app":                               "org:acme-app",
		"org:acme-app":                                   "org:acme-app",
		"workflow:acme-app/web/.github/workflows/ci.yml": "org:acme-app",
		"identity:alice":                                 "",
		"team:":                                          "",
		"nonsense":                                       "",
	} {
		if got := OrgOf(id); got != want {
			t.Errorf("OrgOf(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestTokenWriteControlsRepo: a workflow whose GITHUB_TOKEN can write contents
// controls its repo, so whoever controls the workflow reaches every workflow
// defined in that repo, not only the repo's CI.
func TestTokenWriteControlsRepo(t *testing.T) {
	g := loadAcme(t)
	const (
		web     = "repo:acme-app/web"
		webCI   = "workflow:acme-app/web/.github/workflows/ci.yml"
		nightly = "workflow:acme-app/web/.github/workflows/nightly.yml"
	)
	r := Reach(g, "members:acme-actions", Options{})
	p := r.Paths[web]
	if last := p.Hops[len(p.Hops)-1]; last.Kind != CanPush || last.From != webCI || p.Unverified {
		t.Errorf("path to %s = %+v, want a verified final CAN_PUSH from %s", web, p.Hops, webCI)
	}
	if !slices.Contains(r.Confirmed.Workflows, nightly) {
		t.Errorf("%s not reached: %v", nightly, r.Confirmed.Workflows)
	}
	if h := r.Paths[nightly].Hops; len(h) != 5 || h[4].Kind != DefinedIn || !h[4].Reverse {
		t.Errorf("path to %s = %+v", nightly, h)
	}

	// Without the token edge the repo is CI reach only and nightly is unreached.
	base := cloneGraph(g)
	base.Edges = base.Edges[:0]
	for _, e := range g.Edges {
		if e.Attrs[AttrVia] != ViaTokenWrite {
			base.Edges = append(base.Edges, e)
		}
	}
	r0 := Reach(base, "members:acme-actions", Options{})
	if slices.Contains(r0.Confirmed.Workflows, nightly) {
		t.Errorf("base graph should not reach %s", nightly)
	}
	if h := r0.Paths[web].Hops; h[len(h)-1].Kind != DefinedIn {
		t.Errorf("base path to %s = %+v, want CI reach", web, h)
	}

	// A workflow is never a principal.
	for _, pr := range NewIndex(g).Principals() {
		if KindFromID(pr) == KindWorkflow {
			t.Errorf("principal %s", pr)
		}
	}
	// A not_visible token edge makes control possible, never confirmed.
	hidden := cloneGraph(g)
	for i, e := range hidden.Edges {
		if e.Attrs[AttrVia] == ViaTokenWrite {
			hidden.Edges[i].Evidence = NotVisible
		}
	}
	rh := Reach(hidden, "members:acme-actions", Options{})
	if slices.Contains(rh.Confirmed.Workflows, nightly) || !slices.Contains(rh.Possible.Workflows, nightly) {
		t.Errorf("hidden token edge: confirmed %v possible %v", rh.Confirmed.Workflows, rh.Possible.Workflows)
	}
}

// TestCanTriggerControlsWorkflow: anyone on the internet who can open a pull
// request against a public repo's pull_request_target workflow that checks
// out the head controls that workflow: its secrets, its repo's CI and, with a
// write token, the repo itself and every workflow in it.
func TestCanTriggerControlsWorkflow(t *testing.T) {
	const (
		anyone  = "external:anyone"
		preview = "workflow:acme-app/docs/.github/workflows/preview.yml"
		build   = "workflow:acme-app/docs/.github/workflows/build.yml"
		docs    = "repo:acme-app/docs"
		secret  = "secret:acme-app/docs"
	)
	g := &Graph{Schema: SchemaVersion,
		Nodes: []Node{{ID: anyone, Kind: KindExternal, Name: "anyone on the internet", Evidence: Live}},
		Edges: []Edge{
			edge(anyone, "CAN_TRIGGER", preview, "trigger", "pull_request_target", "exec", "checkout", "job", "preview"),
			edge(preview, "DEFINED_IN", docs),
			edge(preview, "EXECUTES_WITH", secret),
			edge(build, "DEFINED_IN", docs),
			edge(build, "EXECUTES_WITH", "oidc:acme-app/docs"),
		}}
	ix := NewIndex(g)
	if !slices.Contains(ix.Principals(), anyone) || !slices.Contains(ix.ScoringPrincipals(), anyone) {
		t.Fatalf("principals %v, scoring %v: want %s in both", ix.Principals(), ix.ScoringPrincipals(), anyone)
	}
	if KindFromID(anyone) != KindExternal {
		t.Errorf("KindFromID(%s) = %q", anyone, KindFromID(anyone))
	}
	r := ix.Reach(anyone, Options{})
	if !slices.Equal(r.Confirmed.Secrets, []string{secret}) || !slices.Equal(r.Confirmed.Workflows, []string{preview}) {
		t.Errorf("confirmed = %+v", r.Confirmed)
	}
	if h := r.Paths[secret].Hops; len(h) != 2 || h[0].Kind != CanTrigger || h[0].Reverse {
		t.Errorf("path to %s = %+v", secret, h)
	}
	// The repo is CI reach only: build.yml and its OIDC token are not reached.
	if !slices.Equal(r.Confirmed.Repos, []string{docs}) || len(r.Confirmed.OIDC) != 0 {
		t.Errorf("without a write token: confirmed %+v", r.Confirmed)
	}
	if m := ix.multiplier(anyone); m != 1 {
		t.Errorf("multiplier = %v, want 1", m)
	}

	// With a write GITHUB_TOKEN the trigger reaches the repo and build.yml.
	tw := cloneGraph(g)
	tw.Edges = append(tw.Edges, edge(preview, "CAN_PUSH", docs, AttrVia, ViaTokenWrite))
	rw := Reach(tw, anyone, Options{})
	if !slices.Contains(rw.Confirmed.Workflows, build) || !slices.Equal(rw.Confirmed.OIDC, []string{"oidc:acme-app/docs"}) {
		t.Errorf("with a write token: confirmed %+v", rw.Confirmed)
	}

	// A not_visible trigger (fork setting unknown) is possible reach only.
	hidden := cloneGraph(g)
	hidden.Edges[0].Evidence = NotVisible
	rh := Reach(hidden, anyone, Options{})
	if len(rh.Confirmed.Secrets) != 0 || !slices.Equal(rh.Possible.Secrets, []string{secret}) {
		t.Errorf("hidden trigger: confirmed %+v possible %+v", rh.Confirmed, rh.Possible)
	}

	// Who can reach the secret lists anyone on the internet.
	who := ix.WhoCanReach(secret)
	if len(who) != 1 || who[0].From != anyone {
		t.Errorf("WhoCanReach(%s) = %+v", secret, who)
	}
}

// tagGraph: members:x push to repo:x/deploy, which hosts action x/deploy@v3
// (a tag), used by a workflow in o/app that holds secrets. team:x/release may
// bypass the tag ruleset on v3; team:x/other bypasses a branch named main.
func tagGraph(attrs map[string]string) *Graph {
	a := map[string]string{AttrRefKind: "tag", AttrRef: "v3"}
	for k, v := range attrs {
		a[k] = v
	}
	return &Graph{Schema: SchemaVersion,
		Nodes: []Node{
			{ID: "action:x/deploy@v3", Kind: KindActionRef, Name: "x/deploy@v3", Evidence: Live, Attrs: a},
			{ID: "team:x/release", Kind: KindIdentity, Name: "x/release", Evidence: Live},
			{ID: "team:x/other", Kind: KindIdentity, Name: "x/other", Evidence: Live},
		},
		Edges: []Edge{
			edge("members:x", "CAN_PUSH", "repo:x/deploy", AttrVia, ViaDefaultPerm),
			edge("team:x/release", "CAN_PUSH", "repo:x/deploy", AttrVia, ViaRefBypass, AttrRef, "v3"),
			edge("team:x/other", "CAN_PUSH", "repo:x/deploy", AttrVia, ViaRefBypass, AttrRef, "main"),
			edge("workflow:o/app/.github/workflows/ci.yml", "DEFINED_IN", "repo:o/app"),
			edge("workflow:o/app/.github/workflows/ci.yml", "USES", "action:x/deploy@v3", AttrRefKind, "tag"),
			edge("action:x/deploy@v3", "RESOLVES_TO", "repo:x/deploy"),
			edge("workflow:o/app/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:o/app"),
		}}
}

func TestRefImmutableGatesResolvesTo(t *testing.T) {
	const secret = "secret:o/app"
	cases := []struct {
		name  string
		attrs map[string]string
		// reach of secret:o/app for members:x, team:x/release, team:x/other:
		// "c" confirmed, "p" possible, "" none
		members, release, other string
		pin                     bool // Candidates has pin:action:x/deploy@v3
	}{
		{"no attr", nil, "c", "c", "c", true},
		{"mutable", map[string]string{AttrRefImmutable: "false"}, "c", "c", "c", true},
		{"immutable release", map[string]string{AttrRefImmutable: "true", AttrRefImmutableBy: RefImmutableRelease, AttrBypass: "none"}, "", "c", "", true},
		{"unknown", map[string]string{AttrRefImmutable: "unknown"}, "p", "p", "p", true},
		{"bypass unknown", map[string]string{AttrRefImmutable: "true", AttrBypass: "unknown"}, "p", "c", "p", true},
		{"ambiguous", map[string]string{AttrRefImmutable: "true", AttrRefAmbiguous: "true", AttrRefKind: "branch"}, "c", "c", "c", true},
		// ref_protected is the branch gate: a tag reads ref_immutable only.
		{"protected tag", map[string]string{AttrRefProtected: "true"}, "c", "c", "c", true},
		{"immutable branch", map[string]string{AttrRefKind: "branch", AttrRefImmutable: "true"}, "c", "c", "c", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ix := NewIndex(tagGraph(tc.attrs))
			for p, want := range map[string]string{"members:x": tc.members, "team:x/release": tc.release, "team:x/other": tc.other} {
				r := ix.Reach(p, Options{})
				got := ""
				switch {
				case slices.Contains(r.Confirmed.Secrets, secret):
					got = "c"
				case slices.Contains(r.Possible.Secrets, secret):
					got = "p"
				}
				if got != want {
					t.Errorf("%s reach = %q, want %q", p, got, want)
				}
			}
			hasPin := false
			for _, c := range ix.Candidates() {
				hasPin = hasPin || c.ID() == "pin:action:x/deploy@v3"
			}
			if hasPin != tc.pin {
				t.Errorf("pin candidate = %v, want %v", hasPin, tc.pin)
			}
		})
	}

	// Immutable with no bypass edge for v3: no pin candidate, and no reach.
	g := tagGraph(map[string]string{AttrRefImmutable: "true", AttrBypass: "none"})
	g.Edges = slices.DeleteFunc(g.Edges, func(e Edge) bool { return e.From == "team:x/release" })
	ix := NewIndex(g)
	for _, c := range ix.Candidates() {
		if c.ID() == "pin:action:x/deploy@v3" {
			t.Error("pin candidate for an immutable tag with no bypass")
		}
	}
	if r := ix.Reach("members:x", Options{}); slices.Contains(r.Confirmed.Secrets, secret) || slices.Contains(r.Possible.Secrets, secret) {
		t.Errorf("immutable tag still reached: %+v", r)
	}
	// The unknown hop is the RESOLVES_TO hop at not_visible.
	u := NewIndex(tagGraph(map[string]string{AttrRefImmutable: "unknown"})).Reach("members:x", Options{})
	if p := u.Paths[secret]; !p.Unverified || p.Hops[1].Kind != ResolvesTo || p.Hops[1].Evidence != NotVisible {
		t.Errorf("unknown path = %+v", p)
	}
}

// TestRestrictToken: setting contents: read on web/ci.yml removes its
// token_write edge, so whoever controls ci.yml keeps web's CI reach but no
// longer reaches nightly.yml through a push, and the confirmed pairs drop
// where that edge was the only path. Suggest_fixes can pick it.
func TestRestrictToken(t *testing.T) {
	g := loadAcme(t)
	const (
		web     = "repo:acme-app/web"
		webCI   = "workflow:acme-app/web/.github/workflows/ci.yml"
		nightly = "workflow:acme-app/web/.github/workflows/nightly.yml"
	)
	fix := RestrictToken{Workflow: webCI}
	if fix.ID() != "restrict_token:"+webCI {
		t.Errorf("ID = %q", fix.ID())
	}
	ix := NewIndex(g)
	es := FixEdges(ix, fix)
	if len(es) != 1 || es[0].From != webCI || es[0].To != web || es[0].Attrs[AttrVia] != ViaTokenWrite {
		t.Fatalf("edges = %+v", es)
	}
	r := ix.Reach("members:acme-actions", Options{Fixes: []Fix{fix}})
	if slices.Contains(r.Confirmed.Workflows, nightly) || slices.Contains(r.Possible.Workflows, nightly) {
		t.Errorf("%s still reached after %s", nightly, fix.ID())
	}
	if h := r.Paths[web].Hops; len(h) == 0 || h[len(h)-1].Kind != DefinedIn {
		t.Errorf("path to %s = %+v, want CI reach only", web, h)
	}
	d := ix.WhatIf([]Fix{fix})
	if d.After.Confirmed.Workflows >= d.Before.Confirmed.Workflows || d.After.Score >= d.Before.Score {
		t.Errorf("WhatIf(%s): before %+v after %+v, want fewer workflows and a lower score", fix.ID(), d.Before, d.After)
	}
	if !slices.ContainsFunc(ix.Candidates(), func(f Fix) bool { return f.ID() == fix.ID() }) {
		t.Errorf("Candidates misses %s", fix.ID())
	}
	// nightly.yml has token_write=false and no edge: restricting it is a no-op
	// and never a candidate.
	if d := ix.WhatIf([]Fix{RestrictToken{Workflow: nightly}}); d.After != d.Before {
		t.Error("RestrictToken on a workflow without token_write must be a no-op")
	}
	// A not_visible token edge (default unreadable) is never a candidate.
	hidden := cloneGraph(g)
	for i, e := range hidden.Edges {
		if e.Attrs[AttrVia] == ViaTokenWrite {
			hidden.Edges[i].Evidence = NotVisible
		}
	}
	if slices.ContainsFunc(NewIndex(hidden).Candidates(), func(f Fix) bool { return f.ID() == fix.ID() }) {
		t.Errorf("%s proposed for a not_visible edge", fix.ID())
	}
}

// TestHardenTrigger: hardening the public docs repo's preview.yml removes
// every CAN_TRIGGER edge into it, so anyone on the internet loses the docs
// secret, and the fix is a candidate that suggest_fixes picks first.
func TestHardenTrigger(t *testing.T) {
	const (
		anyone  = "external:anyone"
		preview = "workflow:acme-app/docs/.github/workflows/preview.yml"
		docs    = "repo:acme-app/docs"
		secret  = "secret:acme-app/docs"
	)
	g := &Graph{Schema: SchemaVersion,
		Nodes: []Node{{ID: anyone, Kind: KindExternal, Name: "anyone on the internet", Evidence: Live}},
		Edges: []Edge{
			edge(anyone, "CAN_TRIGGER", preview, "trigger", "pull_request_target", "exec", "checkout", "job", "preview"),
			edge("members:acme-app", "CAN_TRIGGER", preview, "trigger", "issue_comment", "exec", "injection", "job", "preview"),
			edge(preview, "DEFINED_IN", docs),
			edge(preview, "EXECUTES_WITH", secret),
			edge(preview, "CAN_PUSH", docs, AttrVia, ViaTokenWrite),
		}}
	fix := HardenTrigger{Workflow: preview}
	ix := NewIndex(g)
	if es := FixEdges(ix, fix); len(es) != 2 {
		t.Fatalf("edges = %+v, want both CAN_TRIGGER edges", es)
	}
	before := ix.Reach(anyone, Options{})
	if !slices.Contains(before.Confirmed.Secrets, secret) {
		t.Fatalf("baseline: %+v", before.Confirmed)
	}
	after := ix.Reach(anyone, Options{Fixes: []Fix{fix}})
	if len(after.Confirmed.Secrets)+len(after.Possible.Secrets)+len(after.Confirmed.Repos)+len(after.Possible.Repos) != 0 {
		t.Errorf("after %s: confirmed %+v possible %+v", fix.ID(), after.Confirmed, after.Possible)
	}
	if d := ix.WhatIf([]Fix{fix}); d.After.ConfirmedPairs != 0 || d.Before.ConfirmedPairs != 2 {
		t.Errorf("WhatIf pairs %d -> %d, want 2 -> 0", d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
	}
	sug := ix.SuggestFixes(3)
	if len(sug) != 1 || sug[0].FixID != "harden_trigger:"+preview || sug[0].Remaining != 0 {
		t.Errorf("SuggestFixes = %+v", sug)
	}
	// RestrictToken alone keeps the secret reachable (the trigger still runs
	// attacker code) but drops the push: the docs repo becomes CI reach only.
	rt := ix.Reach(anyone, Options{Fixes: []Fix{RestrictToken{Workflow: preview}}})
	if !slices.Contains(rt.Confirmed.Secrets, secret) || rt.Paths[docs].Hops[len(rt.Paths[docs].Hops)-1].Kind != DefinedIn {
		t.Errorf("RestrictToken: %+v %+v", rt.Confirmed, rt.Paths[docs])
	}
	// Only not_visible trigger edges: not a candidate.
	hidden := cloneGraph(g)
	hidden.Edges[0].Evidence = NotVisible
	hidden.Edges[1].Evidence = NotVisible
	if slices.ContainsFunc(NewIndex(hidden).Candidates(), func(f Fix) bool { return f.ID() == fix.ID() }) {
		t.Errorf("%s proposed for not_visible edges", fix.ID())
	}
}

// TestSuggestFixesPicksRestrictToken: alice pushes to docs, whose ci.yml has
// a write token that can push to web (as odd input, so the token edge is the
// only way into web), and web hosts an action api's workflow uses at a
// branch. Restricting the token removes web and api from alice's reach, and
// suggest_fixes picks it.
func TestSuggestFixesPicksRestrictToken(t *testing.T) {
	const (
		docsCI = "workflow:acme-app/docs/.github/workflows/ci.yml"
		apiCI  = "workflow:acme-app/api/.github/workflows/ci.yml"
		action = "action:acme-app/web@main"
	)
	g := &Graph{Schema: SchemaVersion, Edges: []Edge{
		edge("identity:alice", "CAN_PUSH", "repo:acme-app/docs", AttrVia, ViaDirect),
		edge(docsCI, "DEFINED_IN", "repo:acme-app/docs"),
		edge(docsCI, "CAN_PUSH", "repo:acme-app/web", AttrVia, ViaTokenWrite, AttrJobs, "build"),
		edge(action, "RESOLVES_TO", "repo:acme-app/web"),
		edge(apiCI, "USES", action, AttrRefKind, "branch"),
		edge(apiCI, "DEFINED_IN", "repo:acme-app/api"),
	}}
	ix := NewIndex(g)
	sug := ix.SuggestFixes(3)
	if len(sug) == 0 || sug[0].FixID != "restrict_token:"+docsCI || sug[0].Removed != 2 {
		t.Fatalf("SuggestFixes = %+v, want restrict_token:%s first, removing 2 pairs", sug, docsCI)
	}
	r := ix.Reach("identity:alice", Options{Fixes: []Fix{sug[0].Fix}})
	if !slices.Equal(r.Confirmed.Repos, []string{"repo:acme-app/docs"}) {
		t.Errorf("after %s alice reaches %v", sug[0].FixID, r.Confirmed.Repos)
	}
}

func TestLoadV1V2(t *testing.T) {
	// v1 documents load unchanged and are upgraded in memory.
	v1, err := LoadFile("../../testdata/acme/graph.v1.json")
	if err != nil {
		t.Fatalf("v1 fixture: %v", err)
	}
	if v1.Schema != SchemaVersion {
		t.Errorf("v1 schema after load = %q, want %q", v1.Schema, SchemaVersion)
	}
	v2 := loadAcme(t)
	inferred := 0
	for _, e := range v2.Edges {
		if e.Evidence == Inferred {
			inferred++
		}
	}
	if inferred == 0 {
		t.Fatal("v2 fixture should carry inferred edges")
	}
	if len(v1.Edges) != len(v2.Edges) || len(v1.Nodes) != len(v2.Nodes) {
		t.Errorf("v1 and v2 fixtures differ in size: %d/%d edges, %d/%d nodes", len(v1.Edges), len(v2.Edges), len(v1.Nodes), len(v2.Nodes))
	}

	edge := `{"from":"members:acme","to":"repo:acme/web","kind":"CAN_PUSH","evidence":"inferred","source_api":"rest:/orgs/{org}","attrs":{"via":"default_perm","rule":"default_perm"}}`
	if _, err := Load(strings.NewReader(`{"schema":"gop.graph/v2","edges":[` + edge + `]}`)); err != nil {
		t.Errorf("v2 with inferred: %v", err)
	}
	_, err = Load(strings.NewReader(`{"schema":"gop.graph/v1","edges":[` + edge + `]}`))
	if err == nil || !strings.Contains(err.Error(), `evidence "inferred" needs schema "gop.graph/v2"`) || !strings.Contains(err.Error(), `claims "gop.graph/v1"`) {
		t.Errorf("v1 with inferred: err = %v", err)
	}
	if _, err := Load(strings.NewReader(`{"schema":"gop.graph/v2","audit_retention_days":-1}`)); err == nil {
		t.Error("negative audit_retention_days accepted")
	}
}

func TestInferredIsConfirmed(t *testing.T) {
	g := loadAcme(t)
	before := Reach(g, "members:acme-actions", Options{})
	// The same graph with every inferred edge read live: confirmed reach is
	// the same, only the evidence label differs.
	live := *g
	live.Edges = append([]Edge(nil), g.Edges...)
	for i := range live.Edges {
		if live.Edges[i].Evidence == Inferred {
			live.Edges[i].Evidence = Live
		}
	}
	after := Reach(&live, "members:acme-actions", Options{})
	if !reflect.DeepEqual(before.Confirmed, after.Confirmed) || !reflect.DeepEqual(before.Possible, after.Possible) {
		t.Errorf("inferred changed reach: confirmed %+v vs %+v", before.Confirmed, after.Confirmed)
	}
	p := before.Paths["repo:acme-actions/deploy"]
	if p.Unverified || p.Evidence != Inferred || len(p.Hops) != 1 || p.Hops[0].Evidence != Inferred {
		t.Errorf("default-perm path = %+v, want one confirmed inferred hop", p)
	}
	if !Verified(Inferred) || evRank(Inferred) <= evRank(Audit) || evRank(Inferred) >= evRank(Live) {
		t.Error("inferred must be verified and rank between audit and live")
	}
	if weakest(Live, Inferred) != Inferred || weakest(Inferred, Audit) != Audit {
		t.Error("weakest does not order inferred between live and audit")
	}
}

// staleGraph: identity:bob -CAN_PUSH(audit, observed age before collection)->
// repo:acme/web <-DEFINED_IN(live)- workflow -EXECUTES_WITH(live)-> secret.
func staleGraph(age time.Duration, retentionDays int) *Graph {
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	wf := "workflow:acme/web/.github/workflows/ci.yml"
	return &Graph{Schema: SchemaVersion, CollectedAt: at, Enterprise: "acme", AuditRetentionDays: retentionDays,
		Edges: []Edge{
			{From: "identity:bob", To: "repo:acme/web", Kind: CanPush, Evidence: Audit, SourceAPI: "audit:repo.add_member",
				ObservedAt: at.Add(-age), Attrs: map[string]string{AttrVia: ViaDirect}},
			{From: wf, To: "repo:acme/web", Kind: DefinedIn, Evidence: Live, SourceAPI: "test", ObservedAt: at},
			{From: wf, To: "secret:acme/web", Kind: ExecutesWith, Evidence: Live, SourceAPI: "test", ObservedAt: at},
		}}
}

func TestStaleAuditIsPossible(t *testing.T) {
	const day = 24 * time.Hour
	stale := Reach(staleGraph(200*day, 0), "identity:bob", Options{MaxAuditAge: 90 * day})
	if len(stale.Confirmed.Repos) != 0 || !slices.Equal(stale.Possible.Repos, []string{"repo:acme/web"}) ||
		!slices.Equal(stale.Possible.Secrets, []string{"secret:acme/web"}) {
		t.Errorf("200d audit: confirmed %+v possible %+v, want everything possible", stale.Confirmed, stale.Possible)
	}
	p := stale.Paths["repo:acme/web"]
	if !p.Stale || !p.Unverified || len(p.Hops) != 1 || !p.Hops[0].Stale || p.Hops[0].Evidence != NotVisible {
		t.Errorf("stale path = %+v", p)
	}
	if !stale.Paths["secret:acme/web"].Stale {
		t.Errorf("downstream path should be stale: %+v", stale.Paths["secret:acme/web"])
	}

	fresh := Reach(staleGraph(10*day, 0), "identity:bob", Options{MaxAuditAge: 90 * day})
	if !slices.Equal(fresh.Confirmed.Repos, []string{"repo:acme/web"}) || len(fresh.Possible.Repos) != 0 {
		t.Errorf("10d audit: confirmed %+v possible %+v, want confirmed", fresh.Confirmed, fresh.Possible)
	}
	if p := fresh.Paths["repo:acme/web"]; p.Stale || p.Unverified || p.Evidence != Audit {
		t.Errorf("fresh path = %+v", p)
	}

	// Defaults: 90 days, or half the recorded audit retention.
	if r := Reach(staleGraph(100*day, 0), "identity:bob", Options{}); len(r.Confirmed.Repos) != 0 {
		t.Errorf("100d audit with the 90d default is confirmed: %+v", r.Confirmed)
	}
	if r := Reach(staleGraph(100*day, 400), "identity:bob", Options{}); len(r.Confirmed.Repos) != 1 {
		t.Errorf("100d audit with 400d retention (200d max) is not confirmed: %+v", r.Possible)
	}
	if r := Reach(staleGraph(100*day, 400), "identity:bob", Options{MaxAuditAge: 30 * day}); len(r.Confirmed.Repos) != 0 {
		t.Errorf("MaxAuditAge overrides the retention: %+v", r.Confirmed)
	}
	// No timestamp, no age: never stale.
	g := staleGraph(200*day, 0)
	g.Edges[0].ObservedAt = time.Time{}
	if r := Reach(g, "identity:bob", Options{}); len(r.Confirmed.Repos) != 1 {
		t.Errorf("audit edge without observed_at should stay confirmed: %+v", r.Possible)
	}

	// acme-legacy's audit facts are recent: same classification as before
	// (possible through the not_visible push hop, never stale).
	for id, lp := range Reach(loadAcme(t), "members:acme-legacy", Options{}).Paths {
		if lp.Stale {
			t.Errorf("acme-legacy path to %s is stale: %+v", id, lp)
		}
	}
}

func TestCandidatesSkipStaleAudit(t *testing.T) {
	const day = 24 * time.Hour
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := func(age time.Duration) *Graph {
		return &Graph{Schema: SchemaVersion, CollectedAt: at, Edges: []Edge{
			{From: "members:acme", To: "repo:acme/web", Kind: CanPush, Evidence: Audit, SourceAPI: "audit:org.update_default_repository_permission",
				ObservedAt: at.Add(-age), Attrs: map[string]string{AttrVia: ViaDefaultPerm}},
		}}
	}
	has := func(fs []Fix) bool {
		for _, f := range fs {
			if f.ID() == "default_perm:org:acme->read" {
				return true
			}
		}
		return false
	}
	if !has(NewIndex(g(10 * day)).Candidates()) {
		t.Error("fresh audit edge: lower default perm should be a candidate")
	}
	if has(NewIndex(g(200 * day)).Candidates()) {
		t.Error("stale audit edge: lower default perm must not be a candidate")
	}
}
