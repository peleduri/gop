package graph

import "testing"

// genEnterprise is SyntheticEnterprise (benchgen.go).
func genEnterprise(seed uint64, orgs, repos, actions, principals int) *Graph {
	return SyntheticEnterprise(seed, orgs, repos, actions, principals)
}

const popularRepo = "repo:acme-o1/r0"

// bench10k is the 10k-repo enterprise of the benchmarks: 10 orgs, 10,000
// consumer repos, 2,000 action refs and 2,000 identities and teams.
func bench10k() *Graph { return genEnterprise(1, 10, 10000, 2000, 2000) }

var benchSink any

func BenchmarkNewIndex(b *testing.B) {
	g := bench10k()
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = NewIndex(g)
		}
	})
}

func BenchmarkReach(b *testing.B) {
	ix := NewIndex(bench10k())
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = ix.Reach("members:acme-o1", Options{})
		}
	})
}

func BenchmarkWhoCanReach(b *testing.B) {
	ix := NewIndex(bench10k())
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = ix.WhoCanReach(popularRepo)
		}
	})
}

func BenchmarkTopPaths(b *testing.B) {
	ix := NewIndex(bench10k())
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = ix.TopPaths(10)
		}
	})
}

func BenchmarkSuggestFixes(b *testing.B) {
	g := bench10k()
	b.Run("10k_budget10", func(b *testing.B) {
		for b.Loop() {
			// A fresh index each time: the fix overlay is built lazily, and
			// an MCP call pays for it once per loaded graph.
			benchSink = NewIndex(g).SuggestFixes(10)
		}
	})
}

// TestGenEnterpriseShape keeps the benchmark generator honest: its graph is
// valid input, deterministic, and has the shape the doc comment promises.
func TestGenEnterpriseShape(t *testing.T) {
	g := genEnterprise(7, 4, 200, 40, 60)
	h := genEnterprise(7, 4, 200, 40, 60)
	if len(g.Edges) != len(h.Edges) || len(g.Nodes) != len(h.Nodes) {
		t.Fatalf("genEnterprise is not deterministic: %d/%d edges, %d/%d nodes", len(g.Edges), len(h.Edges), len(g.Nodes), len(h.Nodes))
	}
	kinds := map[EdgeKind]int{}
	evs := map[Evidence]int{}
	for _, e := range g.Edges {
		kinds[e.Kind]++
		evs[e.Evidence]++
	}
	for _, k := range []EdgeKind{CanPush, MemberOf, DefinedIn, ResolvesTo, Uses, CanTrigger, ExecutesWith} {
		if kinds[k] == 0 {
			t.Errorf("no %s edges", k)
		}
	}
	if evs[Live] == 0 || evs[Audit] == 0 {
		t.Errorf("evidence mix %v: want live and audit edges", evs)
	}
	ix := NewIndex(g)
	if len(ix.WhoCanReach(popularRepo)) == 0 {
		t.Errorf("nobody reaches %s", popularRepo)
	}
	if len(ix.Candidates()) == 0 {
		t.Error("no fix candidates")
	}
}
