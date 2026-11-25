package report

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

func agentsIndex(t *testing.T) *graph.Index {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return graph.NewIndex(g)
}

// TestAgentPathsRankAndHops: the outsider-startable agent in dangerous mode
// ranks first; its hops run who → input → workflow → agent → code → secrets
// → write in order, every hop after the agent is attacker-controlled, and the
// what-if fixes cut the chain at the trigger and at code execution.
func TestAgentPathsRankAndHops(t *testing.T) {
	ps := buildAgentPaths(agentsIndex(t))
	if len(ps) == 0 {
		t.Fatal("no agent paths")
	}
	p := ps[0]
	if !strings.HasSuffix(p.Workflow, "claude.yml") || p.Mode != "dangerously_skip_permissions" || !p.Outsider || p.Tone != "crit" {
		t.Fatalf("first path = %s mode %q outsider %v tone %s", p.Workflow, p.Mode, p.Outsider, p.Tone)
	}
	var kinds []string
	for i, h := range p.Present {
		if h.N != i+1 {
			t.Errorf("hop %d numbered %d", i+1, h.N)
		}
		kinds = append(kinds, slotName[h.Slot])
		if (h.Slot > hopAgent) != h.Red {
			t.Errorf("hop %s red=%v", slotName[h.Slot], h.Red)
		}
		if h.Slot == hopAgent && !h.Danger {
			t.Error("agent hop not marked dangerous")
		}
	}
	if got := strings.Join(kinds, ">"); got != "Who>Input>Workflow>Agent>Code runs>Secrets>Write" {
		t.Errorf("hops = %s", got)
	}
	if len(p.Edges) != len(p.Present)-1 {
		t.Errorf("%d edges for %d hops", len(p.Edges), len(p.Present))
	}
	fix := map[string]pathFix{}
	for _, f := range p.Fixes {
		fix[f.ID] = f
	}
	if f := fix["trigger"]; !f.Chain || f.CutsAttr != "1" || !strings.Contains(f.Command, "--harden-trigger") {
		t.Errorf("trigger fix = %+v", f)
	}
	if f := fix["mode"]; !f.Chain || f.CutsAttr != "5" {
		t.Errorf("mode fix = %+v", f)
	}
	if f := fix["token"]; f.Chain || f.CutsAttr != "7" {
		t.Errorf("token fix = %+v", f)
	}
	total := 0
	for _, part := range strings.Split(p.EvCount, ", ") {
		var k string
		var n int
		if i := strings.LastIndex(part, " "); i > 0 {
			k = part[:i]
			fmt.Sscan(part[i+1:], &n)
		}
		if k == "" {
			t.Errorf("bad evidence count %q", part)
		}
		total += n
	}
	if total != len(p.Present) {
		t.Errorf("evidence counts %q cover %d of %d hops", p.EvCount, total, len(p.Present))
	}
	if !strings.Contains(p.Banner, "in dangerous mode") {
		t.Errorf("banner = %q", p.Banner)
	}
	for i := 1; i < len(ps); i++ {
		if ps[i-1].rank > ps[i].rank {
			t.Errorf("paths out of rank order at %d", i)
		}
	}
}

// TestAgentPathsForkReadOnly: a fork's pull_request run never shows the
// job's secrets or write scopes as reachable.
func TestAgentPathsForkReadOnly(t *testing.T) {
	for _, p := range buildAgentPaths(agentsIndex(t)) {
		if !strings.HasSuffix(p.Workflow, "gemini-review.yml") {
			continue
		}
		for _, h := range p.Present {
			if h.Slot >= hopSecrets {
				t.Errorf("fork path reaches %s", slotName[h.Slot])
			}
		}
		if !strings.Contains(p.Banner, "read-only token") {
			t.Errorf("fork banner = %q", p.Banner)
		}
		return
	}
	t.Fatal("no fork path")
}

// TestAgentPathsHTML: the section renders server-side with a focusable node
// per present hop, a hop list the SVG points to, disabled what-if toggles
// (the script enables them) and hidden controls (the script shows them).
func TestAgentPathsHTML(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, g, "html")
	for _, want := range []string{`<h2 id="agent-paths">Agent paths</h2>`, `href="#agent-paths"`, `aria-describedby="ap-1-hops"`, `id="ap-1-hops"`,
		`data-ap-ctl hidden`, `data-chain="true" disabled`, `class="ap-node danger" transform`, `data-ap-dot`} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if n := strings.Count(out, `class="ap-node`); n%hopCount != 0 {
		t.Errorf("%d nodes is not a whole number of paths", n)
	}
}

// TestAgentPathsHostileNames: attacker-written workflow, agent and repo names
// pass through the existing escaping in both formats.
func TestAgentPathsHostileNames(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.Load(bytes.NewReader(testutil.HostileGraphJSON(raw)))
	if err != nil {
		t.Fatal(err)
	}
	html := render(t, g, "html")
	if !strings.Contains(html, `id="agent-paths"`) {
		t.Fatal("no agent paths section over the hostile graph")
	}
	if r, bad := testutil.RawUnsafe(html); bad {
		t.Errorf("HTML has a raw unsafe character %U", r)
	}
	for _, s := range []string{"<img src=x", "<tool_result>", "</tool_result>"} {
		if strings.Contains(html, s) {
			t.Errorf("HTML has a raw %q", s)
		}
	}
	md := render(t, g, "md")
	if i := strings.Index(md, "## Agent paths"); i >= 0 {
		sec := md[i+3:]
		if j := strings.Index(sec, "\n## "); j >= 0 {
			sec = sec[:j]
		}
		for _, l := range strings.Split(sec, "\n") {
			if strings.HasPrefix(l, "<") || strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "## ") {
				t.Errorf("markdown line starts with a hostile value: %.80q", l)
			}
		}
	}
}
