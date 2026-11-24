package redact

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

func TestRedactKeepsAdvisoriesWithoutTheirIDs(t *testing.T) {
	g := demo.Generate(demo.Options{Seed: 1})
	g.Coverage = append(g.Coverage, graph.Coverage{Scope: demo.CheckoutIsh, Fact: graph.CoverageAdvisories,
		Reason: "unknown, not safe: GHSA-acme-test-0009: ref main is not a version"})
	res, err := Redact(g, Options{Salt: []byte("test-salt")})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range res.Graph.Nodes {
		if !graph.HasAdvisory(n) {
			continue
		}
		found = true
		a := n.Attrs
		if !strings.HasPrefix(a[graph.AttrAdvisories], "ADV-") || a[graph.AttrAdvisorySeverity] != "critical" || a[graph.AttrAdvisoryFixed] != "2.4.1" {
			t.Errorf("redacted attrs %v", a)
		}
	}
	if !found {
		t.Fatal("the advisory attrs were dropped")
	}
	for _, c := range res.Graph.Coverage {
		if strings.Contains(c.Reason, "GHSA-") {
			t.Errorf("advisory ID left in coverage: %q", c.Reason)
		}
	}
	top := graph.NewIndex(res.Graph).TopPaths(1)
	if len(top) != 1 || len(top[0].Advisories) == 0 {
		t.Errorf("the advisory must still rank first after redaction: %+v", top)
	}
}
