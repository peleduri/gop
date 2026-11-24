package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sanitize"
	"github.com/peleduri/gop/internal/testutil"
)

// hostileGraph is the acme fixture with attacker-written repo, login and
// workflow file names (testutil.HostileGraphJSON).
func hostileGraph(t *testing.T) *graph.Graph {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.Load(bytes.NewReader(testutil.HostileGraphJSON(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// checkHostile asserts the prompt-injection rules on one text output. A
// prompt or resource has no summary line to bound: a prompt names the IDs
// the user passed in full, so the agent can pass them back to the tools.
func checkHostile(t *testing.T, name, out string) {
	t.Helper()
	checkLines(t, name, out)
	first, _, _ := strings.Cut(out, "\n")
	if n := utf8.RuneCountInString(first); n > sanitize.MaxLine {
		t.Errorf("%s: summary line has %d runes, want <= %d", name, n, sanitize.MaxLine)
	}
}

// checkLines asserts no line starts with a hostile value and no raw unsafe
// character is left.
func checkLines(t *testing.T, name, out string) {
	t.Helper()
	if l := testutil.HostileLineStart(out); l != "" {
		t.Errorf("%s: a line starts with a hostile value: %.120q", name, l)
	}
	if r, bad := testutil.RawUnsafe(out); bad {
		t.Errorf("%s: raw unsafe character %U in output", name, r)
	}
}

// TestHostileNames runs every MCP tool, prompt and resource over a graph
// with attacker-written names and checks that no output line starts with a
// hostile value, control and bidi characters are escaped, and summaries stay
// bounded, while the structured output keeps the full values.
func TestHostileNames(t *testing.T) {
	g := hostileGraph(t)
	old := loadAcme(t)
	cs := connectServer(t, NewServerWith(g, "test", ServerOptions{Baseline: old}))

	repo := "repo:acme-app/" + testutil.HostileRepo
	login := "identity:" + testutil.HostileLogin
	wf := "workflow:acme-app/" + testutil.HostileRepo + "/.github/workflows/" + testutil.HostileFile
	if !NewEngine(g).set[repo] || !NewEngine(g).set[login] || !NewEngine(g).set[wf] {
		t.Fatal("hostile fixture is missing its hostile nodes")
	}
	explainTo := ""
	for _, ed := range g.Edges {
		if ed.From == login {
			explainTo = ed.To
			break
		}
	}
	if explainTo == "" {
		t.Fatal("no edge from the hostile login")
	}

	args := map[string]map[string]any{
		"who_can_reach":    {"target": repo},
		"blast_radius":     {"principal": login},
		"paths":            {"from": login, "to": repo},
		"top_risks":        {"n": 5},
		"what_if":          {"fixes": []map[string]any{{"type": "restrict_token", "workflow": wf}}},
		"suggest_fixes":    {"budget": 5},
		"explain":          {"from": login, "to": explainTo},
		"coverage":         {},
		"diff":             {},
		"fix_plan":         {"fix": map[string]any{"type": "restrict_token", "workflow": wf}},
		"check_answerable": {"question_kind": "who_can_reach", "subject": repo},
	}
	fullRuns := 0
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if !strings.Contains(tool.Description, strings.TrimSpace(DataNote)) {
			t.Errorf("%s: description lacks the data note", tool.Name)
		}
		a, ok := args[tool.Name]
		if !ok {
			t.Errorf("%s: no hostile-names case: add one to TestHostileNames", tool.Name)
			continue
		}
		// A tool with a detail input runs brief (the default) and full.
		variants := []map[string]any{a}
		if strings.Contains(tool.Description, strings.TrimSpace(detailNote)) {
			full := map[string]any{"detail": DetailFull}
			for k, v := range a {
				full[k] = v
			}
			variants = append(variants, full)
			fullRuns++
		}
		for _, v := range variants {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool.Name, Arguments: v})
			if err != nil {
				t.Fatalf("%s: %v", tool.Name, err)
			}
			if res.IsError {
				t.Fatalf("%s %v: tool error: %s", tool.Name, v["detail"], text(res))
			}
			checkHostile(t, tool.Name, text(res))
		}
	}

	if fullRuns == 0 {
		t.Error("no tool ran with detail full")
	}

	// The structured output keeps the full, raw value.
	var who WhoCanReachOutput
	call(t, cs, "who_can_reach", args["who_can_reach"], &who)
	if who.Target != repo {
		t.Errorf("structured target was changed: %d bytes, want %d", len(who.Target), len(repo))
	}
	if !strings.Contains(who.Summary, sanitize.Ellipsis+"`") {
		t.Errorf("summary does not cut the 10 kB name: %.200q", who.Summary)
	}

	// Errors name close node IDs: they are delimited too.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "who_can_reach",
		Arguments: map[string]any{"target": "repo:acme-app/we"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("unknown target: want a tool error")
	}
	checkHostile(t, "who_can_reach error", text(res))

	for _, p := range []struct {
		name string
		args map[string]string
	}{
		{"triage_enterprise", nil},
		{"review_action", map[string]string{"action": "action:acme-actions/deploy@main"}},
		{"explain_path", map[string]string{"from": login, "to": repo}},
	} {
		pr, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: p.name, Arguments: p.args})
		if err != nil {
			t.Fatalf("prompt %s: %v", p.name, err)
		}
		for _, m := range pr.Messages {
			if tc, ok := m.Content.(*mcp.TextContent); ok {
				checkLines(t, "prompt "+p.name, tc.Text)
			}
		}
	}

	for _, uri := range []string{SummaryURI, NodeURIPrefix + url.PathEscape(wf)} {
		rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			t.Fatalf("read %.60s: %v", uri, err)
		}
		for _, c := range rr.Contents {
			checkLines(t, "resource", c.Text)
			if !json.Valid([]byte(c.Text)) {
				t.Errorf("resource %.60s: not valid JSON", uri)
			}
		}
	}
	n, err := NewEngine(g).NodeResource(wf)
	if err != nil {
		t.Fatal(err)
	}
	if n.Node == nil || !strings.Contains(n.Node.ID, testutil.HostileFile) {
		t.Error("node resource changed the raw ID")
	}
}

// TestDataNote checks the server instructions carry the data note.
func TestDataNote(t *testing.T) {
	cs := connect(t)
	if !strings.Contains(cs.InitializeResult().Instructions, strings.TrimSpace(DataNote)) {
		t.Error("server instructions lack the data note")
	}
}
