package sarif

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestAgentMemoryRule(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	rs := byRule(build(t, g, Options{}), RuleAgentMemory)
	if len(rs) != 1 {
		t.Fatalf("want 1 GOP006 result (claude.yml), got %d", len(rs))
	}
	r := rs[0]
	loc := r.Locations[0].PhysicalLocation
	if r.Properties.Repository != "acme-app/docs" || r.Properties.Possible || r.Level != "error" || r.Properties.Severity == SeverityLow ||
		loc == nil || loc.ArtifactLocation.URI != ".github/workflows/claude.yml" || loc.Region == nil || loc.Region.StartLine != 23 ||
		strings.Join(r.Properties.ConfirmedPrincipals, ",") != "external:anyone" ||
		strings.Join(r.Properties.MemoryReaders, ",") != "workflow:acme-app/docs/.github/workflows/claude-nightly.yml" ||
		strings.Join(r.Properties.MemoryDirs, ",") != ".claude" || len(r.Properties.MemoryFixes) != 3 || r.Properties.Evidence != graph.Live {
		t.Errorf("GOP006 result %+v at %+v", r.Properties, loc)
	}
	for _, want := range []string{"external:anyone can start", ".claude/memory", "issue_comment", "acme-app/docs/.github/workflows/claude-nightly.yml restores it", "prefix key match"} {
		if !strings.Contains(r.Message.Text, want) {
			t.Errorf("message %q lacks %q", r.Message.Text, want)
		}
	}

	// Without a verified match the result is possible and dropped by default.
	for i := range g.Nodes {
		if g.Nodes[i].Attrs[graph.AttrAgentMemoryReaders] != "" {
			if g.Nodes[i].AttrEvidence == nil {
				g.Nodes[i].AttrEvidence = map[string]graph.Evidence{}
			}
			g.Nodes[i].AttrEvidence[graph.AttrAgentMemoryReaders] = graph.NotVisible
		}
	}
	if rs := byRule(build(t, g, Options{}), RuleAgentMemory); len(rs) != 0 {
		t.Errorf("possible GOP006 kept by default: %+v", rs)
	}
	if rs := byRule(build(t, g, Options{IncludePossible: true}), RuleAgentMemory); len(rs) != 1 || !rs[0].Properties.Possible || rs[0].Level != "note" {
		t.Errorf("possible GOP006 = %+v", rs)
	}
	if Rules()[ruleIndex(RuleAgentMemory)].Name != "agent-memory-poisoning-across-runs" {
		t.Error("rule name")
	}
}
