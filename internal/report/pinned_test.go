package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

// demoWithSetup is the demo graph with extra attrs on the nested setup@main
// ref that its SHA-pinned release action runs.
func demoWithSetup(attrs map[string]string) *graph.Graph {
	g := demo.Generate(demo.Options{Seed: 1})
	for i, n := range g.Nodes {
		if n.ID == demo.SetupMain {
			if g.Nodes[i].Attrs == nil {
				g.Nodes[i].Attrs = map[string]string{}
			}
			for k, v := range attrs {
				g.Nodes[i].Attrs[k] = v
			}
		}
	}
	return g
}

func TestPinnedFollowsRefGate(t *testing.T) {
	locked := demoWithSetup(map[string]string{graph.AttrRefKind: "tag", graph.AttrRefImmutable: "true", graph.AttrBypass: "none"})
	for _, f := range []string{"html", "md"} {
		if out := render(t, locked, f); strings.Contains(out, "Pinned, still reachable") {
			t.Errorf("%s: an immutable nested tag still shows a pinned exposure", f)
		}
	}
	unknown := demoWithSetup(map[string]string{graph.AttrRefKind: "tag", graph.AttrRefImmutable: "unknown"})
	for _, f := range []string{"html", "md"} {
		out := render(t, unknown, f)
		for _, want := range []string{"Pinned, still reachable", "(possibly mutable (immutability not visible))", "possible: a hop is not visible"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q", f, want)
			}
		}
	}
}
