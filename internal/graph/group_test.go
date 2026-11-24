package graph

import (
	"fmt"
	"reflect"
	"testing"
)

func loadOwners(t *testing.T) *Graph {
	t.Helper()
	g, err := LoadFile("../../testdata/owners/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func owners() []string {
	out := make([]string, 14)
	for i := range out {
		out[i] = fmt.Sprintf("identity:owner%02d", i+1)
	}
	return out
}

// 14 org owners with the same reach fold into one row ahead of 3 distinct
// principals; bob and carol have equal scores over different repos and stay
// apart.
func TestTopGroupsFoldsIdenticalReach(t *testing.T) {
	ix := NewIndex(loadOwners(t))
	gs := ix.TopGroups(10)
	var got []string
	for _, g := range gs {
		got = append(got, fmt.Sprintf("%s x%d", g.Principal, g.Size()))
	}
	want := []string{"identity:owner01 x14", "identity:alice x1", "identity:bob x1", "identity:carol x1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	g := gs[0]
	if !reflect.DeepEqual(g.Members, owners()) || !reflect.DeepEqual(g.MemberIDs(), owners()) {
		t.Errorf("members = %v", g.Members)
	}
	if g.Via != ViaOrgOwner || !reflect.DeepEqual(g.ViaScope, []string{"org:acme-security"}) {
		t.Errorf("via = %q %v", g.Via, g.ViaScope)
	}
	if gs[1].Members != nil || gs[1].Via != "" {
		t.Errorf("a single principal carries no members or via: %+v", gs[1])
	}
	// Presentation only: the row's score is its first member's, unchanged.
	if !reflect.DeepEqual(g.GroupScore, ix.BlastRadius("identity:owner01")) {
		t.Errorf("group score = %+v, want %+v", g.GroupScore, ix.BlastRadius("identity:owner01"))
	}
	if bob, carol := gs[2].GroupScore, gs[3].GroupScore; bob.Score != carol.Score || bob.Confirmed != carol.Confirmed {
		t.Errorf("bob and carol should tie on score and counts: %+v %+v", bob, carol)
	}
	// n counts groups.
	if n := len(ix.TopGroups(2)); n != 2 {
		t.Errorf("TopGroups(2) = %d rows", n)
	}
	if n := len(ix.TopPaths(0)); n != 17 {
		t.Errorf("TopPaths(0) = %d principals, want 17 (ranking is unchanged)", n)
	}
}

// Members of one team that reach the same repos share via=team.
func TestGroupRisksSharedTeam(t *testing.T) {
	g := &Graph{Schema: SchemaVersion, Enterprise: "acme"}
	g.Nodes = append(g.Nodes, Node{ID: "repo:acme-app/web", Kind: KindRepo, Evidence: Live})
	g.Edges = append(g.Edges, Edge{From: "team:acme-app/web", To: "repo:acme-app/web", Kind: CanPush, Evidence: Live, Attrs: map[string]string{AttrVia: ViaTeam}})
	for _, who := range []string{"identity:alice", "identity:bob"} {
		g.Edges = append(g.Edges, Edge{From: who, To: "team:acme-app/web", Kind: MemberOf, Evidence: Live})
	}
	gs := NewIndex(g).TopGroups(0)
	if len(gs) != 1 || gs[0].Size() != 3 {
		t.Fatalf("groups = %+v", gs)
	}
	if gs[0].Via != ViaTeam || !reflect.DeepEqual(gs[0].ViaScope, []string{"team:acme-app/web"}) {
		t.Errorf("via = %q %v", gs[0].Via, gs[0].ViaScope)
	}
}

// Principals that reach nothing confirmed never group: there is no shared
// reach to report.
func TestGroupRisksSkipsEmptyReach(t *testing.T) {
	ix := NewIndex(loadOwners(t))
	in := []Score{{Principal: "identity:nobody1"}, {Principal: "identity:nobody2"}}
	if gs := ix.GroupRisks(in); len(gs) != 2 {
		t.Errorf("groups = %+v", gs)
	}
}

// A population (an org's members) never folds into a group, even when an
// identity in it reaches exactly the same targets: its own name says more.
func TestGroupRisksKeepsPopulationsApart(t *testing.T) {
	ix := NewIndex(loadAcme(t))
	bob, members := ix.Reach("identity:bob", Options{}), ix.Reach("members:acme-actions", Options{})
	if bob.ConfirmedKey() != members.ConfirmedKey() {
		t.Fatal("fixture: bob and members:acme-actions should reach the same targets")
	}
	if ix.GroupKey(members) != "" || ix.GroupKey(bob) == "" {
		t.Errorf("GroupKey: members %q, bob %q", ix.GroupKey(members), ix.GroupKey(bob))
	}
	for _, g := range ix.TopGroups(0) {
		if g.Size() != 1 {
			t.Errorf("acme has no identical-reach group, got %v", g.Members)
		}
	}
}
