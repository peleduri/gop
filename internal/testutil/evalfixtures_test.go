package testutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestEvalFixtures keeps the graphs the agent-behaviour eval serves
// (evals/fixtures) equal to HostileGraphJSON and SemanticGraphJSON of the
// acme fixture, so the eval and the Go hostile tests use the same payloads.
// Run go test ./internal/testutil -update to rewrite them.
func TestEvalFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func([]byte) []byte{
		"hostile.json":  HostileGraphJSON,
		"semantic.json": SemanticGraphJSON,
	} {
		got := build(raw)
		if _, err := graph.Load(bytes.NewReader(got)); err != nil {
			t.Fatalf("%s does not load: %v", name, err)
		}
		path := filepath.Join("..", "..", "evals", "fixtures", name)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/testutil -update to create it)", path, err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs from %s of testdata/acme/graph.json; run go test ./internal/testutil -update", path, name)
		}
	}
}
