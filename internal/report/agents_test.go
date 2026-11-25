package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// TestRenderAgents: the AI agents in CI section lists each agent workflow,
// the exposed one first, with who can start it, what it holds, the
// prompt-injection exposure and the fixes.
func TestRenderAgents(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	md := render(t, g, "md")
	testutil.Golden(t, "agents.md", []byte(md), "dev")
	sec := md[strings.Index(md, "## AI agents in CI"):]
	for _, want := range []string{
		"5 workflows run an AI coding agent; 2 can be started by people without push access, 2 of them while the agent holds write, secrets or OIDC.",
		"### acme-app/docs/.github/workflows/claude.yml (claude-code-action)",
		"- Who can start it: outsiders: people without push access: anyone on the internet on issue\\_comment",
		"- What it holds: contents:write, issues:write, pull-requests:write, secrets",
		"- Prompt injection: reads the triggering comment text",
		"- Approvals off: dangerously\\_skip\\_permissions",
		"github.event.pull\\_request.title in the prompt",
		"### acme-app/docs/.github/workflows/gemini-review.yml (gemini-cli-action)",
		"anyone, from a fork's pull\\_request (read-only token, no secrets)",
		"### acme-app/docs/.github/workflows/ai-labeler.yml (name only)",
		"- Memory across runs [GOP006]: the agent job saves the cache .claude/memory (agent memory: .claude) on issue\\_comment, and acme-app/docs/.github/workflows/claude-nightly.yml restores it",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("agents section lacks %q", want)
		}
	}
	if i, j := strings.Index(sec, "claude.yml"), strings.Index(sec, "gemini-review.yml"); i > j {
		t.Error("the exposed agent is not listed before the read-only reviewer")
	}
	if !strings.Contains(md, "can start 1 exposed AI agent workflow without push access") {
		t.Error("risks table does not mark the agent-exposed principal")
	}

	html := render(t, g, "html")
	for _, want := range []string{`<h2 id="ai-agents">AI agents in CI</h2>`, `href="#ai-agents">AI agents</a>`,
		`<span class="adv">exposed: ranks first</span>`, "starts 1 exposed AI agent", "<dt>Memory across runs</dt>"} {
		if !strings.Contains(html, want) {
			t.Errorf("html lacks %q", want)
		}
	}

	// No agents: no section.
	acme, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(render(t, acme, "html"), "ai-agents") {
		t.Error("section rendered without agents")
	}
}
