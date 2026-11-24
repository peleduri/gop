package sarif

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestAgentRule(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	l := build(t, g, Options{})
	rs := results(l)
	agents := byRule(l, RuleAgent)
	if len(agents) != 2 {
		t.Fatalf("want 2 GOP004 results (claude, codex), got %d", len(agents))
	}
	if rs[0].RuleID != RuleAgent {
		t.Errorf("first result is %s, want GOP004", rs[0].RuleID)
	}
	byRepo := map[string]Result{}
	for _, r := range agents {
		byRepo[r.Properties.Repository] = r
	}
	c := byRepo["acme-app/docs"]
	loc := c.Locations[0].PhysicalLocation
	if c.Properties.Agent != "claude-code-action" || c.Properties.Possible || c.Level != "error" ||
		loc == nil || loc.ArtifactLocation.URI != ".github/workflows/claude.yml" || loc.Region == nil || loc.Region.StartLine != 16 ||
		strings.Join(c.Properties.ConfirmedPrincipals, ",") != "external:anyone" || c.Properties.Fix.Type != "harden_trigger" {
		t.Errorf("claude result %+v at %+v", c.Properties, loc)
	}
	if !strings.Contains(c.Message.Text, "external:anyone can start on issue_comment") || !strings.Contains(c.Message.Text, "contents:write") ||
		len(c.Properties.AgentFixes) == 0 {
		t.Errorf("claude message %q fixes %v", c.Message.Text, c.Properties.AgentFixes)
	}
	x := byRepo["acme-actions/setup"]
	if x.Properties.Agent != "codex-cli" || !strings.Contains(x.Message.Text, "github.event.pull_request.title") {
		t.Errorf("codex result %+v: %q", x.Properties, x.Message.Text)
	}
	// The read-only reviewer and the name-only match have no GOP004 result.
	for _, r := range agents {
		if strings.Contains(r.Properties.Edge, "gemini-review") || strings.Contains(r.Properties.Edge, "ai-labeler") {
			t.Errorf("unexpected GOP004 on %s", r.Properties.Edge)
		}
	}
	if Rules()[ruleIndex(RuleAgent)].Name != "agent-workflow-exposed" {
		t.Error("rule name")
	}
}
