package cypher

import (
	"bytes"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// The Cypher export carries the repo hardening attrs as node properties.
func TestHardeningAttrs(t *testing.T) {
	g, err := graph.LoadFile("../schema/testdata/valid/repo-hardening.json")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, g, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"branch_protected", "branch_required_reviews", "branch_value_sources",
		"attr_codeowners_workflows", "attr_secret_scanning_push_protection", "'classic,ruleset:7'"} {
		if !strings.Contains(out, want) {
			t.Errorf("Cypher export lacks %s", want)
		}
	}
}
