package graph

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// suggestFixesNaive is the original SuggestFixes: every round it rebuilds the
// control graph for picked+candidate and runs the full reach for every
// scoring principal. The optimized SuggestFixes must return exactly this.
func suggestFixesNaive(ix *Index, budget int) []FixSuggestion {
	pairs := func(fixes []Fix) int {
		cg := ix.control(fixes, 0)
		n := 0
		for _, p := range ix.ScoringPrincipals() {
			n += len(ix.reach(cg, p).Confirmed.Repos)
		}
		return n
	}
	baseline := pairs(nil)
	cands := ix.Candidates()
	var (
		picked []Fix
		out    []FixSuggestion
	)
	current := baseline
	used := map[string]bool{}
	for len(out) < budget && current > 0 {
		bestIdx, bestAfter := -1, current
		for i, c := range cands {
			if used[c.ID()] {
				continue
			}
			after := pairs(append(append([]Fix{}, picked...), c))
			if after < bestAfter {
				bestIdx, bestAfter = i, after
			}
		}
		if bestIdx < 0 {
			break
		}
		f := cands[bestIdx]
		used[f.ID()] = true
		picked = append(picked, f)
		var es []string
		for _, e := range f.edges(ix) {
			es = append(es, strings.Join([]string{e.From, string(e.Kind), e.To}, " "))
		}
		removedTotal := baseline - bestAfter
		out = append(out, FixSuggestion{
			Fix: f, FixID: f.ID(), Edges: es,
			Removed: current - bestAfter, CumulativeRemoved: removedTotal, Remaining: bestAfter,
			CumulativePct: 100 * float64(removedTotal) / float64(baseline),
			Caveat:        fixCaveat(ix, f),
		})
		current = bestAfter
	}
	return out
}

// whoCanReachNaive is the original WhoCanReach: a full reach from every
// principal.
func whoCanReachNaive(ix *Index, target string) []Path {
	var out []Path
	for _, p := range ix.Principals() {
		if p == target {
			continue
		}
		if path, ok := ix.reach(ix.base, p).Paths[target]; ok {
			out = append(out, path)
		}
	}
	sortWho(out)
	return out
}

// whoTargets bounds the WhoCanReach targets checked per graph.
const whoTargets = 40

// equivSeeds is the number of generated graphs each equivalence test checks.
const equivSeeds = 200

// equivGraph returns graph number seed: mostly genGraph (every edge kind,
// evidence, gate and parallel edge, up to 300 nodes), and every fourth one a
// small genEnterprise, whose shape (shared actions, default-perm orgs,
// many principals) gives the greedy more to choose from.
func equivGraph(seed uint64) *Graph {
	if seed%4 == 3 {
		return genEnterprise(seed, 2+int(seed%3), 10+int(seed%40), 4+int(seed%12), 5+int(seed%20))
	}
	return genGraph(propRand(seed^0x5eed), 5+int(seed%296))
}

func jsonEqual(a, b any) (bool, string, string) {
	ja, err := json.Marshal(a)
	if err != nil {
		return false, err.Error(), ""
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false, err.Error(), ""
	}
	return string(ja) == string(jb), string(ja), string(jb)
}

func TestSuggestFixesMatchesNaive(t *testing.T) {
	for seed := uint64(0); seed < equivSeeds; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			g := equivGraph(seed)
			budget := 1 + int(seed%8)
			got := NewIndex(g).SuggestFixes(budget)
			want := suggestFixesNaive(NewIndex(g), budget)
			if !reflect.DeepEqual(got, want) {
				_, jg, jw := jsonEqual(got, want)
				t.Errorf("SuggestFixes(%d) differs from the naive greedy\n got: %s\nwant: %s", budget, jg, jw)
			}
		})
	}
}

func TestWhoCanReachMatchesNaive(t *testing.T) {
	for seed := uint64(0); seed < equivSeeds; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			g := equivGraph(seed)
			ix := NewIndex(g)
			targets := map[string]bool{"repo:does-not/exist": true}
			for _, n := range g.Nodes {
				targets[n.ID] = true
			}
			for _, e := range g.Edges {
				targets[e.To] = true
			}
			ids := sortedKeys(targets)
			// Every target of small graphs; an even spread of whoTargets
			// of larger ones, to keep the naive side cheap.
			if len(ids) > whoTargets {
				step := float64(len(ids)) / whoTargets
				var spread []string
				for i := 0; i < whoTargets; i++ {
					spread = append(spread, ids[int(float64(i)*step)])
				}
				ids = spread
			}
			for _, target := range ids {
				got, want := ix.WhoCanReach(target), whoCanReachNaive(ix, target)
				if !reflect.DeepEqual(got, want) {
					_, jg, jw := jsonEqual(got, want)
					t.Fatalf("WhoCanReach(%s) differs from the naive version\n got: %s\nwant: %s", target, jg, jw)
				}
			}
		})
	}
}
