package graph

import (
	"reflect"
	"testing"
)

// TestReachEachMatchesReach checks ReachEach and ReachEachChanged against a
// plain Reach with the same fix, for every candidate fix: ReachEach returns
// the same results in order, and ReachEachChanged skips only principals
// whose reach the fix leaves exactly as it was.
func TestReachEachMatchesReach(t *testing.T) {
	for _, seed := range []uint64{1, 2, 3} {
		ix := NewIndex(genEnterprise(seed, 3+int(seed%2), 60, 12, 40))
		ps := ix.ScoringPrincipals()
		cands := append(ix.Candidates(), ix.ReduceOwners(1))
		for _, f := range cands {
			opts := Options{Fixes: []Fix{f}}
			i := 0
			ix.ReachEach(ps, opts, func(r Result) {
				if want := ix.Reach(ps[i], opts); !reflect.DeepEqual(r, want) {
					t.Errorf("seed %d %s: ReachEach(%s) differs from Reach", seed, f.ID(), ps[i])
				}
				i++
			})
			if i != len(ps) {
				t.Errorf("seed %d %s: ReachEach called fn %d times, want %d", seed, f.ID(), i, len(ps))
			}
			got := map[string]Result{}
			ix.ReachEachChanged(ps, opts, func(r Result) { got[r.From] = r })
			for _, p := range ps {
				after := ix.Reach(p, opts)
				r, ok := got[p]
				switch {
				case ok && !reflect.DeepEqual(r, after):
					t.Errorf("seed %d %s: ReachEachChanged(%s) differs from Reach", seed, f.ID(), p)
				case !ok && !reflect.DeepEqual(after, ix.Reach(p, Options{})):
					t.Errorf("seed %d %s: ReachEachChanged skipped %s, whose reach changes", seed, f.ID(), p)
				}
			}
		}
	}
	ix := NewIndex(genEnterprise(1, 3, 20, 4, 10))
	ix.ReachEachChanged(ix.ScoringPrincipals(), Options{}, func(Result) { t.Error("no fixes: fn must not be called") })
}
