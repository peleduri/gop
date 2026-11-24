package mcpserver

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestTopRisksAgent: top_risks ranks a principal that can start an exposed
// AI agent workflow first and marks it; explain describes the agent.
func TestTopRisksAgent(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(g)
	out, err := e.TopRisks(TopRisksInput{N: 3})
	if err != nil {
		t.Fatal(err)
	}
	if out.Risks[0].AgentExposed == 0 {
		t.Fatalf("risks = %+v", out.Risks)
	}
	if !strings.Contains(out.Summary, "AI agent workflow that holds write, secrets or OIDC without push access [agent_exposed]") {
		t.Errorf("summary = %q", out.Summary)
	}

	ex, err := e.Explain(ExplainInput{From: "external:anyone", To: "workflow:acme-app/docs/.github/workflows/claude.yml"})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"claude-code-action (action)", "people without push access can start it on issue_comment",
		"contents:write", "dangerously_skip_permissions", "Fix: Restrict who can start it"} {
		if !strings.Contains(ex.Agent, w) || !strings.Contains(ex.Summary, w) {
			t.Errorf("explain lacks %q: %q", w, ex.Summary)
		}
	}
	lab, err := e.Explain(ExplainInput{From: "workflow:acme-app/docs/.github/workflows/ai-labeler.yml", To: "repo:acme-app/docs"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lab.Agent, "name only") {
		t.Errorf("labeler agent note = %q", lab.Agent)
	}
}
