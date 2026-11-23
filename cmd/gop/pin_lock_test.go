package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// linesWithSetup writes the lines fixture with extra attrs on the nested
// acme-actions/setup@main ref (made a tag with node-level ref_kind) and
// returns its path.
func linesWithSetup(t *testing.T, attrs map[string]string) string {
	t.Helper()
	g, err := graph.LoadFile(linesFixture)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range g.Nodes {
		if n.ID == "action:acme-actions/setup@main" {
			for k, v := range attrs {
				g.Nodes[i].Attrs[k] = v
			}
		}
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The nested-ref warning follows the ref gate: an immutable tag drops out, a
// tag whose immutability is not visible stays with the not-visible label.
func TestPinNestedRefGate(t *testing.T) {
	for _, tc := range []struct {
		golden string
		attrs  map[string]string
	}{
		{"pin_graph_nested_immutable.txt", map[string]string{graph.AttrRefKind: "tag", graph.AttrRefImmutable: "true", graph.AttrBypass: "none"}},
		{"pin_graph_nested_unknown.txt", map[string]string{graph.AttrRefKind: "tag", graph.AttrRefImmutable: "unknown"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			r := runPin(t, nil, "--action", "acme-actions/deploy@main", "--graph", linesWithSetup(t, tc.attrs), "--format", "text")
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%+v", r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}
