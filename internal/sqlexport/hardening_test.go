package sqlexport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// The SQL export carries the repo hardening attrs as node_attrs rows, with
// their evidence.
func TestHardeningAttrs(t *testing.T) {
	g, err := graph.LoadFile("../schema/testdata/valid/repo-hardening.json")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, []*graph.Graph{g}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"'repo:acme-actions/deploy', 'branch_required_reviews', '2'",
		"'repo:acme-actions/deploy', 'branch_protection_sources', 'classic,ruleset:7'",
		"'repo:acme-actions/deploy', 'codeowners_workflows', 'true'",
		"'repo:acme-actions/deploy', 'secret_scanning_push_protection', 'off'",
		"'repo:acme-legacy/old-site', 'branch_protected', 'unknown', 'not_visible'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("SQL export lacks %s", want)
		}
	}
}
