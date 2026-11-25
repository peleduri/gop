package report

import (
	"io"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// controlBuildsFor renders g as HTML and returns how many control graphs the
// render built.
func controlBuildsFor(t *testing.T, g *graph.Graph) int64 {
	t.Helper()
	before := graph.ControlBuilds()
	if err := Render(io.Discard, g, Options{}); err != nil {
		t.Fatal(err)
	}
	return graph.ControlBuilds() - before
}

// TestRenderControlBuildsBounded keeps the number of control graph builds per
// report independent of the graph's size: the base graph, the fast index,
// the ReduceOwners what-if and one per Graph tab what-if fix. Rebuilding per
// principal (a Reach with fixes in a loop) made a 10k-repo report take hours.
// Not parallel: graph.ControlBuilds is process-wide.
func TestRenderControlBuildsBounded(t *testing.T) {
	const bound = 3 + graphWhatIfFixes
	small := controlBuildsFor(t, graph.SyntheticEnterprise(3, 4, 200, 40, 60))
	big := controlBuildsFor(t, graph.SyntheticEnterprise(3, 4, 800, 80, 600))
	if small > bound || big > bound {
		t.Errorf("control graph builds per report: %d (small), %d (10x principals); want at most %d each", small, big, bound)
	}
}

// BenchmarkRender times a full HTML report on the 10k-repo enterprise of the
// engine benchmarks (10 orgs, 10,000 repos, 2,000 action refs, 2,000
// identities and teams).
func BenchmarkRender(b *testing.B) {
	g := graph.SyntheticEnterprise(1, 10, 10000, 2000, 2000)
	b.Run("10k", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := Render(io.Discard, g, Options{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
