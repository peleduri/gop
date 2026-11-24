package graph

import (
	"reflect"
	"testing"
)

// acmeDoubleCount: org acme-big has default_perm=write and three repos. Four
// members; alice, bob and carol also belong to a team in acme-other that grants
// nothing. With daveInTeam, dave joins that team too.
func acmeDoubleCount(daveInTeam bool) *Graph {
	g := &Graph{Schema: SchemaVersion,
		Nodes: []Node{
			{ID: "org:acme-big", Kind: KindOrg, Evidence: Live, Attrs: map[string]string{AttrDefaultPerm: "write", AttrTwoFactor: "required", AttrSSO: "enforced"}},
			{ID: "members:acme-big", Kind: KindOrgMembers, Evidence: Live},
			{ID: "team:acme-other/readers", Kind: KindIdentity, Evidence: Live},
		},
	}
	for _, r := range []string{"r1", "r2", "r3"} {
		g.Nodes = append(g.Nodes, Node{ID: "repo:acme-big/" + r, Kind: KindRepo, Evidence: Live})
		g.Edges = append(g.Edges, edge("members:acme-big", "CAN_PUSH", "repo:acme-big/"+r, AttrVia, ViaDefaultPerm))
	}
	for _, u := range []string{"alice", "bob", "carol", "dave"} {
		g.Nodes = append(g.Nodes, Node{ID: "identity:" + u, Kind: KindIdentity, Evidence: Live})
		g.Edges = append(g.Edges, edge("identity:"+u, "MEMBER_OF", "org:acme-big"))
		if u != "dave" || daveInTeam {
			g.Edges = append(g.Edges, edge("identity:"+u, "MEMBER_OF", "team:acme-other/readers"))
		}
	}
	return g
}

// ScoringPrincipals says an identity reaching only what members:X reaches must
// not be counted again ("would multiply the totals by the number of licensed
// users without adding reach"). An unrelated team membership that grants
// nothing must therefore not change the pair totals or a fix's Removed count.
func TestPopulationReachNotMultipliedByMembers(t *testing.T) {
	fix := []Fix{LowerDefaultPerm{Org: "org:acme-big", To: "read"}}
	for _, daveInTeam := range []bool{false, true} {
		d := NewIndex(acmeDoubleCount(daveInTeam)).WhatIf(fix)
		removed := d.Before.ConfirmedPairs - d.After.ConfirmedPairs
		// Three repos are reached only through members:acme-big's default
		// permission: counted once, the fix removes 3 pairs.
		if d.Before.ConfirmedPairs != 3 || removed != 3 {
			t.Errorf("daveInTeam=%v: confirmed pairs %d -> %d (removed %d), want 3 -> 0 (removed 3)",
				daveInTeam, d.Before.ConfirmedPairs, d.After.ConfirmedPairs, removed)
		}
	}
	a := NewIndex(acmeDoubleCount(false)).WhatIf(nil).Before.ConfirmedPairs
	b := NewIndex(acmeDoubleCount(true)).WhatIf(nil).Before.ConfirmedPairs
	if a != b {
		t.Errorf("a team membership that grants nothing changed confirmed pairs: %d -> %d", a, b)
	}
}

// Individual scores keep a member's full reach; SuggestFixes counts the
// population once like WhatIf; a member's own grant is still its own pair.
func TestPopulationReachScoresAndSuggest(t *testing.T) {
	ix := NewIndex(acmeDoubleCount(true))
	if s := ix.BlastRadius("identity:alice"); s.Confirmed.Repos != 3 {
		t.Errorf("alice's own score: %d repos, want 3 (her full reach through members:acme-big)", s.Confirmed.Repos)
	}
	for _, s := range ix.Scores() {
		if s.Principal == "identity:alice" && s.Confirmed.Repos != 3 {
			t.Errorf("Scores: alice has %d repos, want 3", s.Confirmed.Repos)
		}
	}
	if got := ix.Totals().ConfirmedPairs; got != 3 {
		t.Errorf("Totals().ConfirmedPairs = %d, want 3", got)
	}
	sugg := ix.SuggestFixes(5)
	if len(sugg) != 1 || sugg[0].FixID != "default_perm:org:acme-big->read" || sugg[0].Removed != 3 || sugg[0].CumulativePct != 100 {
		t.Errorf("SuggestFixes = %+v, want one LowerDefaultPerm removing 3 of 3 (100%%)", sugg)
	}

	// bob also has a direct push grant on r1: (bob, r1) is his own pair, and
	// it survives lowering the default permission.
	g := acmeDoubleCount(true)
	g.Edges = append(g.Edges, edge("identity:bob", "CAN_PUSH", "repo:acme-big/r1", AttrVia, ViaDirect))
	d := NewIndex(g).WhatIf([]Fix{LowerDefaultPerm{Org: "org:acme-big", To: "read"}})
	if d.Before.ConfirmedPairs != 4 || d.After.ConfirmedPairs != 1 {
		t.Errorf("with bob's direct grant: confirmed pairs %d -> %d, want 4 -> 1", d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
	}
	for _, pd := range d.PerPrincipal {
		if pd.Principal == "identity:bob" && (pd.Before.Confirmed.Repos != 3 || pd.After.Confirmed.Repos != 1) {
			t.Errorf("bob per principal: %d -> %d repos, want 3 -> 1 (full reach)", pd.Before.Confirmed.Repos, pd.After.Confirmed.Repos)
		}
	}
}

// ScoresAndTotals walks the graph once and returns exactly what Scores and
// Totals return separately.
func TestScoresAndTotalsMatchesSeparateCalls(t *testing.T) {
	for _, daveInTeam := range []bool{false, true} {
		ix := NewIndex(acmeDoubleCount(daveInTeam))
		scores, totals := ix.ScoresAndTotals()
		if !reflect.DeepEqual(scores, ix.Scores()) {
			t.Errorf("daveInTeam=%v: scores differ from Scores()", daveInTeam)
		}
		if !reflect.DeepEqual(totals, ix.Totals()) {
			t.Errorf("daveInTeam=%v: totals %+v, Totals() %+v", daveInTeam, totals, ix.Totals())
		}
		if totals.ConfirmedPairs != 3 {
			t.Errorf("daveInTeam=%v: confirmed pairs %d, want 3", daveInTeam, totals.ConfirmedPairs)
		}
	}
}
