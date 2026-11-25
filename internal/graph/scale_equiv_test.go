package graph

import (
	"fmt"
	"reflect"
	"testing"
)

// The report's scale shortcuts must return exactly what the plain
// computations return: these tests check each against its naive form on
// the generated graphs of the other equivalence tests.

// pinnedExposuresNaive is the original PinnedExposures pick: a full reach
// from every principal, keeping the best path per candidate action.
func pinnedExposuresNaive(ix *Index) map[string]Path {
	cands := map[string]bool{}
	for _, e := range ix.g.Edges {
		if e.Kind == Uses && ix.Kind(e.From) == KindActionRef && !ix.LockCovered(e.From) {
			if st := ix.RefState(e.From); st == RefPinned || st == RefLocked {
				cands[e.From] = true
			}
		}
	}
	better := func(a, b Path) bool {
		if a.Unverified != b.Unverified {
			return !a.Unverified
		}
		if len(a.Hops) != len(b.Hops) {
			return len(a.Hops) < len(b.Hops)
		}
		return a.From < b.From
	}
	best := map[string]Path{}
	for _, p := range ix.Principals() {
		r := ix.reach(ix.base, p)
		for a := range cands {
			if path, ok := r.Paths[a]; ok {
				if old, seen := best[a]; !seen || better(path, old) {
					best[a] = path
				}
			}
		}
	}
	return best
}

func TestBestPathToMatchesWhoCanReach(t *testing.T) {
	for seed := uint64(0); seed < equivSeeds; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			g := equivGraph(seed)
			ix := NewIndex(g)
			targets := map[string]bool{"repo:does-not/exist": true}
			for _, e := range g.Edges {
				targets[e.To] = true
			}
			for _, target := range sortedKeys(targets) {
				got, ok := ix.bestPathTo(target)
				who := ix.WhoCanReach(target)
				if ok != (len(who) > 0) {
					t.Fatalf("bestPathTo(%s) found=%v, WhoCanReach has %d paths", target, ok, len(who))
				}
				if ok && !reflect.DeepEqual(got, who[0]) {
					_, jg, jw := jsonEqual(got, who[0])
					t.Fatalf("bestPathTo(%s) differs from WhoCanReach's first\n got: %s\nwant: %s", target, jg, jw)
				}
			}
		})
	}
}

func TestPinnedExposuresMatchesNaive(t *testing.T) {
	for seed := uint64(0); seed < equivSeeds; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			ix := NewIndex(equivGraph(seed))
			got := map[string]Path{}
			for _, pe := range ix.PinnedExposures() {
				got[pe.Action] = pe.Path
			}
			want := pinnedExposuresNaive(ix)
			if len(want) == 0 {
				want = map[string]Path{}
			}
			if !reflect.DeepEqual(got, want) {
				_, jg, jw := jsonEqual(got, want)
				t.Errorf("PinnedExposures differs from the naive loop\n got: %s\nwant: %s", jg, jw)
			}
		})
	}
}

// TestConfirmedPairsMatchesWhatIf: the counting walk Ownership uses gives
// WhatIf's confirmed pair totals, for every single candidate fix and for the
// ReduceOwners cut of every ownership.
func TestConfirmedPairsMatchesWhatIf(t *testing.T) {
	for seed := uint64(0); seed < equivSeeds; seed += 3 {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			ix := NewIndex(equivGraph(seed))
			sets := [][]Fix{nil}
			for _, f := range ix.Candidates() {
				sets = append(sets, []Fix{f})
			}
			_, byOwner := ix.orgOwners()
			var all []OwnerCut
			for p, orgs := range byOwner {
				for _, o := range orgs {
					all = append(all, OwnerCut{Principal: p, Org: o})
				}
			}
			if len(all) > 0 {
				sets = append(sets, []Fix{ReduceOwners{Cuts: all}})
			}
			for _, fs := range sets {
				d := ix.WhatIf(fs)
				b, a := ix.confirmedPairs(fs)
				if b != d.Before.ConfirmedPairs || a != d.After.ConfirmedPairs {
					t.Fatalf("confirmedPairs(%v) = %d, %d; WhatIf says %d, %d", fs, b, a, d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
				}
			}
		})
	}
}

// TestSyntheticLargeShape keeps the scale benchmark's graph what its name
// says at a small size: agent workflows, org owners, deterministic output.
func TestSyntheticLargeShape(t *testing.T) {
	s := LargeSpec{Orgs: 6, Repos: 120, Actions: 30, Principals: 200, Agents: 12, Owners: 5, OwnedOrgs: 3, ExtraMemberships: 1}
	a, b := SyntheticLarge(7, s), SyntheticLarge(7, s)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("SyntheticLarge is not deterministic for a seed")
	}
	ix := NewIndex(a)
	if n := len(ix.AgentWorkflows()); n != s.Agents {
		t.Errorf("%d agent workflows, want %d", n, s.Agents)
	}
	if _, byOwner := ix.orgOwners(); len(byOwner) < s.Owners {
		t.Errorf("%d org owners, want at least %d", len(byOwner), s.Owners)
	}
}
