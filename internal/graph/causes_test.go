package graph

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// testdata/causes: 23 orgs. admin-a..d own 18 to 20 of them with slightly
// different org sets, lead-1..9 own 5 to 8, maint-01..12 own 1 or 2; bob is
// a direct collaborator on orgs 1-17 (reach close to the owners'), alice is
// in a team, carol has one direct grant, and orgs acme-o22 and acme-o23 keep
// default write.
func loadCauses(t *testing.T) *Graph {
	t.Helper()
	g, err := LoadFile("../../testdata/causes/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var heavyOwners = []string{"identity:admin-a", "identity:admin-b", "identity:admin-c", "identity:admin-d"}

// The 4 heavy owners share one cause row (alice and her team are an exact
// group already) with the range of their reach;
// their reach sets differ, so the exact tier alone does not group them.
func TestCauseGroupFoldsOwnersOfManyOrgs(t *testing.T) {
	ix := NewIndex(loadCauses(t))
	exact := ix.GroupRisksExact(ix.TopPaths(0))
	for _, g := range exact {
		if g.Size() > 1 && strings.HasPrefix(g.Principal, "identity:admin-") {
			t.Fatalf("exact tier should not group the owners: %+v", g.Members)
		}
	}
	gs := ix.TopGroups(0)
	top := gs[0]
	if !reflect.DeepEqual(top.Members, heavyOwners) {
		t.Fatalf("top row members = %v, want %v", top.Members, heavyOwners)
	}
	if top.Cause != CauseOrgOwner || top.CauseScope != nil {
		t.Errorf("cause = %q %v", top.Cause, top.CauseScope)
	}
	want := GroupRange{Repos: MinMax{54, 56}, Orgs: MinMax{18, 20}, OwnedOrgs: &MinMax{18, 20}}
	if top.Range == nil || !reflect.DeepEqual(*top.Range, want) {
		t.Errorf("range = %+v, want %+v", top.Range, want)
	}
	if len(top.MemberScores) != 4 {
		t.Fatalf("member scores = %d", len(top.MemberScores))
	}
	for i, m := range heavyOwners {
		if !reflect.DeepEqual(top.MemberScores[i], ix.BlastRadius(m)) {
			t.Errorf("member score %s = %+v, want its own score", m, top.MemberScores[i])
		}
	}
	// The org sets differ, so no single shared via.
	if top.Via != "" {
		t.Errorf("via = %q, want none (the owned orgs differ)", top.Via)
	}
	// bob: similar reach, other cause (direct grants): his own row.
	if gs[1].Principal != "identity:bob" || gs[1].Size() != 1 || gs[1].Cause != "" {
		t.Errorf("row 2 = %+v, want bob alone", gs[1])
	}
	for _, g := range gs[1:] {
		if g.Cause != "" {
			t.Errorf("only the heavy owners group: %s %v", g.Cause, g.Members)
		}
	}
}

// Principals with similar counts but different causes never group: bob's
// reach overlaps admin-a's by Jaccard 0.9 or more, but it comes through
// direct grants.
func TestCauseGroupNeedsTheSameCause(t *testing.T) {
	ix := NewIndex(loadCauses(t))
	a, b := ix.reach(ix.base, "identity:admin-a"), ix.reach(ix.base, "identity:bob")
	if !jaccardAtLeast(strings.Split(a.ConfirmedKey(), "\n"), strings.Split(b.ConfirmedKey(), "\n"), CauseJaccardTenths) {
		t.Fatal("fixture: bob's reach should overlap admin-a's by 0.9 or more, or this test proves nothing")
	}
	if c := ix.causeOf("identity:admin-a", a); c != CauseOrgOwner {
		t.Errorf("admin-a cause = %q", c)
	}
	if c := ix.causeOf("identity:bob", b); c != "" {
		t.Errorf("bob cause = %q, want none (direct grants)", c)
	}
	if c := ix.causeOf("identity:alice", ix.reach(ix.base, "identity:alice")); c != "team:acme-o01/dev" {
		t.Errorf("alice cause = %q, want her team", c)
	}
}

// Grouping is presentation only: scores and rank order are the same with
// and without the cause tier.
func TestCauseGroupKeepsScoresAndOrder(t *testing.T) {
	for _, g := range []*Graph{loadCauses(t), loadOwners(t)} {
		ix := NewIndex(g)
		ranked := ix.TopPaths(0)
		before := append([]Score{}, ranked...)
		cause, exact := ix.GroupRisks(ranked), ix.GroupRisksExact(ranked)
		if !reflect.DeepEqual(ranked, before) || !reflect.DeepEqual(ix.TopPaths(0), before) {
			t.Fatal("grouping changed the ranked scores")
		}
		rank := map[string]int{}
		for i, s := range ranked {
			rank[s.Principal] = i
		}
		for _, rows := range [][]RiskGroup{cause, exact} {
			n, last := 0, -1
			for _, r := range rows {
				if !reflect.DeepEqual(r.GroupScore, ranked[rank[r.Principal]]) {
					t.Errorf("row %s score changed", r.Principal)
				}
				if rank[r.Principal] <= last {
					t.Errorf("row %s out of rank order", r.Principal)
				}
				last = rank[r.Principal]
				prev := -1
				for _, m := range r.MemberIDs() {
					if rank[m] <= prev {
						t.Errorf("members of %s out of rank order", r.Principal)
					}
					prev = rank[m]
					n++
				}
			}
			if n != len(ranked) {
				t.Errorf("rows hold %d principals, want %d", n, len(ranked))
			}
		}
	}
}

func TestOwnershipHistogram(t *testing.T) {
	ix := NewIndex(loadCauses(t))
	o, ok := ix.Ownership()
	if !ok {
		t.Fatal("no ownership")
	}
	var got []string
	for _, b := range o.Buckets {
		got = append(got, fmt.Sprintf("%s=%d", b.Label, b.Accounts))
		if len(b.Members) != b.Accounts {
			t.Errorf("%s lists %d members", b.Label, len(b.Members))
		}
	}
	want := []string{"1 org=2", "2-4 orgs=10", "5-9 orgs=9", "10+ orgs=4"}
	if !reflect.DeepEqual(got, want) || o.Owners != 25 {
		t.Errorf("histogram = %v (%d owners), want %v (25)", got, o.Owners, want)
	}
	if !reflect.DeepEqual(o.Buckets[3].Members, heavyOwners) {
		t.Errorf("10+ = %v", o.Buckets[3].Members)
	}
	d := ix.WhatIf(nil)
	if o.ConfirmedPairs != d.Before.ConfirmedPairs || o.OwnerPairs <= 0 || o.OwnerPairs > o.ConfirmedPairs {
		t.Errorf("owner pairs %d of %d", o.OwnerPairs, o.ConfirmedPairs)
	}
	if _, ok := NewIndex(&Graph{Schema: SchemaVersion}).Ownership(); ok {
		t.Error("a graph without owners has no ownership block")
	}
}

// ReduceOwners at 5 cuts the 13 accounts that own 5 or more orgs, never
// leaves an org with fewer than 2 owners, and is the top suggested fix.
func TestReduceOwners(t *testing.T) {
	g := loadCauses(t)
	ix := NewIndex(g)
	f := ix.ReduceOwners(0)
	if f.Threshold != DefaultOwnerThreshold || f.ID() != "reduce_owners:>=5" {
		t.Errorf("fix = %d %s", f.Threshold, f.ID())
	}
	accts := f.Accounts()
	if len(accts) != 13 {
		t.Errorf("accounts = %v, want the 4 admins and 9 leads", accts)
	}
	for _, a := range accts {
		if !strings.HasPrefix(a, "identity:admin-") && !strings.HasPrefix(a, "identity:lead-") {
			t.Errorf("cut %s, which owns fewer than 5 orgs", a)
		}
	}
	byOrg, _ := ix.orgOwners()
	cut := map[string]bool{}
	for _, c := range f.Cuts {
		cut[ownerKey(c.Principal, c.Org)] = true
	}
	for _, k := range f.Kept {
		if cut[ownerKey(k.Principal, k.Org)] {
			t.Errorf("%v both kept and cut", k)
		}
	}
	for o, owners := range byOrg {
		left := 0
		for _, p := range owners {
			if !cut[ownerKey(p, o)] {
				left++
			}
		}
		if left < MinOwnersPerOrg {
			t.Errorf("%s keeps %d owners", o, left)
		}
		if len(owners) >= MinOwnersPerOrg && left != MinOwnersPerOrg && left != countUnder(ix, owners, 5) {
			t.Errorf("%s keeps %d owners: more heavy owners than needed", o, left)
		}
	}
	// acme-o15 has no light owner: the two that own the most orgs stay.
	var kept15 []string
	for _, k := range f.Kept {
		if k.Org == "org:acme-o15" {
			kept15 = append(kept15, k.Principal)
		}
	}
	if !reflect.DeepEqual(kept15, []string{"identity:admin-a", "identity:admin-b"}) {
		t.Errorf("acme-o15 keeps %v", kept15)
	}
	// Measured: the pairs WhatIf removes are the suggestion's.
	d := ix.WhatIf([]Fix{f})
	removed := d.Before.ConfirmedPairs - d.After.ConfirmedPairs
	sug := ix.SuggestFixes(3)
	if len(sug) == 0 || sug[0].FixID != f.ID() || sug[0].Removed != removed || sug[0].Caveat != CaveatReduceOwners {
		t.Fatalf("suggestions = %+v, want reduce_owners first removing %d", sug, removed)
	}
	for i := 1; i < len(sug); i++ {
		if sug[i].Removed > sug[i-1].Removed {
			t.Errorf("not ranked by impact: %+v", sug)
		}
	}
	if want := suggestFixesNaive(NewIndex(g), 3); !reflect.DeepEqual(sug, want) {
		_, jg, jw := jsonEqual(sug, want)
		t.Errorf("SuggestFixes differs from the naive greedy\n got: %s\nwant: %s", jg, jw)
	}
	// A higher threshold cuts only the 4 admins.
	if f19 := ix.ReduceOwners(19); !reflect.DeepEqual(f19.Accounts(), []string{"identity:admin-a", "identity:admin-b", "identity:admin-c"}) {
		t.Errorf("threshold 19 accounts = %v", f19.Accounts())
	}
	if s := ix.SuggestFixesOwners(1, 19); len(s) != 1 || s[0].FixID != "reduce_owners:>=19" {
		t.Errorf("SuggestFixesOwners(1, 19) = %+v", s)
	}
}

func countUnder(ix *Index, owners []string, threshold int) int {
	n := 0
	for _, p := range owners {
		if len(ix.OwnedOrgs(p)) < threshold {
			n++
		}
	}
	return n
}
