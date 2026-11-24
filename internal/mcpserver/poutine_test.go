package mcpserver

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestTopRisksPoutine: top_risks ranks the principal that reaches a workflow
// with an injection finding from poutine first and cites poutine.
func TestTopRisksPoutine(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.Nodes {
		if g.Nodes[i].ID == "workflow:acme-app/infra/.github/workflows/ci.yml" {
			g.Nodes[i].Attrs = map[string]string{graph.AttrPoutineRules: "injection"}
		}
	}
	out, err := NewEngine(g).TopRisks(TopRisksInput{N: 3})
	if err != nil {
		t.Fatal(err)
	}
	if out.Risks[0].Principal != "identity:alice" || out.Risks[0].PoutineInjectable != 1 {
		t.Fatalf("risks = %+v", out.Risks)
	}
	if !strings.Contains(out.Summary, "1 reached workflow with an injection finding from poutine (cited, not proved by gop)") {
		t.Errorf("summary = %q", out.Summary)
	}
}
