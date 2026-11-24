package redact

import (
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

func TestRedactKeepsPartial(t *testing.T) {
	g := demo.Generate(demo.Options{Seed: 1})
	g.Partial, g.PartialReason = true, graph.PartialMaxRequests
	res, err := Redact(g, Options{Salt: []byte("test-salt")})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Graph.Partial || res.Graph.PartialReason != graph.PartialMaxRequests {
		t.Errorf("redacted graph: partial %v reason %q", res.Graph.Partial, res.Graph.PartialReason)
	}
}
