package fixplan

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

func TestPinPlanForAdvisoryMovesToFixed(t *testing.T) {
	g := demo.Generate(demo.Options{Seed: 1})
	for i := range g.Edges {
		if g.Edges[i].To == demo.CheckoutIsh {
			g.Edges[i].Attrs[graph.AttrFile] = ".github/workflows/preview.yml"
			g.Edges[i].Attrs[graph.AttrLine] = "12"
		}
	}
	p := Build(graph.NewIndex(g), graph.PinRef{Action: demo.CheckoutIsh})
	e := edits(p)
	if len(e) != 1 || !strings.Contains(e[0].Diff, "-uses: acme-oss/checkout-ish@v2\n+uses: acme-oss/checkout-ish@<sha-of-v2.4.1> # v2.4.1\n") {
		t.Fatalf("edits %+v", e)
	}
	if !strings.HasPrefix(p.Description, "Move acme-oss/checkout-ish@v2 (known advisory) to v2.4.1") {
		t.Errorf("description %q", p.Description)
	}
	if len(p.Caveats) == 0 || !strings.Contains(p.Caveats[0], demo.DemoAdvisory) {
		t.Errorf("caveats %v", p.Caveats)
	}
}

func TestPinPlanForAdvisoryWithoutFix(t *testing.T) {
	g := demo.Generate(demo.Options{Seed: 1})
	for i := range g.Nodes {
		if g.Nodes[i].ID == demo.CheckoutIsh {
			delete(g.Nodes[i].Attrs, graph.AttrAdvisoryFixed)
		}
	}
	p := Build(graph.NewIndex(g), graph.PinRef{Action: demo.CheckoutIsh})
	if !strings.Contains(strings.Join(p.Caveats, "\n"), "no fixed version") {
		t.Errorf("caveats %v", p.Caveats)
	}
}
