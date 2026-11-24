package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
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
func hostileGraph(t *testing.T) *graph.Graph { return swappedGraph(t, testutil.HostileGraphJSON) }

// semanticGraph is the acme fixture with the semantic and lookalike names
// (testutil.SemanticGraphJSON).
func semanticGraph(t *testing.T) *graph.Graph { return swappedGraph(t, testutil.SemanticGraphJSON) }

func swappedGraph(t *testing.T, swap func([]byte) []byte) *graph.Graph {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.Load(bytes.NewReader(swap(raw)))
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

// TestHostileNames runs every MCP tool, prompt and resource over graphs
// with attacker-written names: structural names (newlines, tags, bidi,
// zero-width, 10 kB) and semantic ones (printable instructions, fake output
// fields and tool results, Markdown links, a lookalike repo).
func TestHostileNames(t *testing.T) {
	t.Run("structural", testHostileStructural)
	t.Run("semantic", testHostileSemantic)
}

// testHostileStructural checks that no output line starts with a hostile
// value, control and bidi characters are escaped, and summaries stay
// bounded, while the structured output keeps the full values.
func testHostileStructural(t *testing.T) {
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

// testHostileSemantic runs every tool over the semantic graph. Those names
// pass the sanitizer unchanged, so it pins what is deterministic: the
// summary never shows a name outside backticks, the JSON copy decodes to
// exactly the structured output (a fake tool result cannot break out of its
// string), no line starts with a name, the fix_plan markdown never turns a
// name into a live link, and the lookalike and the real repo stay two nodes.
func testHostileSemantic(t *testing.T) {
	g := semanticGraph(t)
	cs := connectServer(t, NewServerWith(g, "test", ServerOptions{Baseline: loadAcme(t)}))

	real := "repo:acme-app/web"
	look := "repo:acme-app/" + testutil.LookalikeRepo
	instr := "repo:acme-app/" + testutil.InstructionRepo
	mimic := "repo:acme-app/" + testutil.MimicRepo
	login := "identity:" + testutil.LinkLogin
	imgWF := "workflow:acme-app/web/.github/workflows/" + testutil.ImageFile
	fakeWF := "workflow:acme-app/billing/.github/workflows/" + testutil.FakeResultFile
	set := NewEngine(g).set
	for _, id := range []string{real, look, instr, mimic, login, imgWF, fakeWF} {
		if !set[id] {
			t.Fatalf("semantic fixture is missing %q", id)
		}
	}
	explainTo := ""
	for _, ed := range g.Edges {
		if ed.From == login {
			explainTo = ed.To
			break
		}
	}
	if explainTo == "" {
		t.Fatal("no edge from the link login")
	}

	args := map[string]map[string]any{
		"who_can_reach":    {"target": look},
		"blast_radius":     {"principal": login},
		"paths":            {"from": login, "to": look},
		"top_risks":        {"n": 10},
		"what_if":          {"fixes": []map[string]any{{"type": "restrict_token", "workflow": imgWF}}},
		"suggest_fixes":    {"budget": 10},
		"explain":          {"from": login, "to": explainTo},
		"coverage":         {},
		"diff":             {},
		"fix_plan":         {"fix": map[string]any{"type": "restrict_token", "workflow": imgWF}},
		"check_answerable": {"question_kind": "who_can_reach", "subject": mimic},
	}
	extra := []struct {
		tool string
		args map[string]any
	}{
		{"who_can_reach", map[string]any{"target": instr}},
		{"who_can_reach", map[string]any{"target": real}},
		{"check_answerable", map[string]any{"question_kind": "blast_radius", "subject": login}},
		{"fix_plan", map[string]any{"fix": map[string]any{"type": "pin_ref", "action": "action:acme-actions/deploy@main"}}},
	}
	values := testutil.SemanticValues()
	check := func(name string, res *mcp.CallToolResult) {
		t.Helper()
		out := text(res)
		checkHostile(t, name, out)
		if l := testutil.LineStart(out, values); l != "" {
			t.Errorf("%s: a line starts with a semantic name: %.120q", name, l)
		}
		first, body, _ := strings.Cut(out, "\n\n")
		for _, v := range values {
			if testutil.OutsideBackticks(first, v) {
				t.Errorf("%s: summary shows %q outside backticks: %.200q", name, v, first)
			}
		}
		if name == "fix_plan" {
			if l := testutil.LiveLink(body); l != "" {
				t.Errorf("fix_plan: markdown has a live link from a name: %q", l)
			}
			return
		}
		var copied, structured any
		if err := json.Unmarshal([]byte(body), &copied); err != nil {
			t.Errorf("%s: JSON copy does not decode: %v", name, err)
			return
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &structured); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(copied, structured) {
			t.Errorf("%s: JSON copy in the text differs from the structured output", name)
		}
	}

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		a, ok := args[tool.Name]
		if !ok {
			t.Errorf("%s: no semantic-names case: add one to testHostileSemantic", tool.Name)
			continue
		}
		variants := []map[string]any{a}
		if strings.Contains(tool.Description, strings.TrimSpace(detailNote)) {
			full := map[string]any{"detail": DetailFull}
			for k, v := range a {
				full[k] = v
			}
			variants = append(variants, full)
		}
		for _, v := range variants {
			extra = append(extra, struct {
				tool string
				args map[string]any
			}{tool.Name, v})
		}
	}
	for _, x := range extra {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: x.tool, Arguments: x.args})
		if err != nil {
			t.Fatalf("%s: %v", x.tool, err)
		}
		if res.IsError {
			t.Fatalf("%s %v: tool error: %s", x.tool, x.args, text(res))
		}
		check(x.tool, res)
	}

	// The lookalike and the real repo are two nodes: each answer keeps its
	// own ID, and an answer that reaches both lists both.
	for _, id := range []string{real, look} {
		var who WhoCanReachOutput
		call(t, cs, "who_can_reach", map[string]any{"target": id}, &who)
		if who.Target != id {
			t.Errorf("who_can_reach %q answered for %q", id, who.Target)
		}
		if len(who.Confirmed) == 0 {
			t.Errorf("who_can_reach %q: no confirmed principal; the lookalike copy should have the same reach", id)
		}
	}
	var br BlastRadiusOutput
	res := call(t, cs, "blast_radius", map[string]any{"principal": login, "detail": DetailFull}, &br)
	body, _ := json.Marshal(res.StructuredContent)
	for _, id := range []string{real, look} {
		if !bytes.Contains(body, []byte(`"`+id+`"`)) {
			t.Errorf("blast_radius of the link login does not list %q", id)
		}
	}
	if br.Score.Confirmed.Repos < 2 {
		t.Errorf("blast_radius counts %d confirmed repos, want the real repo and the lookalike counted apart", br.Score.Confirmed.Repos)
	}
}

// TestDataNote checks the server instructions carry the data note.
func TestDataNote(t *testing.T) {
	cs := connect(t)
	if !strings.Contains(cs.InitializeResult().Instructions, strings.TrimSpace(DataNote)) {
		t.Error("server instructions lack the data note")
	}
}
