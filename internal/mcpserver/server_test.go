package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

func loadAcme(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	return connectGraph(t, loadAcme(t))
}

func connectGraph(t *testing.T, g *graph.Graph) *mcp.ClientSession {
	t.Helper()
	return connectServer(t, NewServer(g, "test"))
}

func connectServer(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call invokes a tool and decodes its structured output into out.
func call(t *testing.T, cs *mcp.ClientSession, name string, args any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: tool error: %s", name, text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: decode: %v", name, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestToolsListed(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"who_can_reach": true, "blast_radius": true, "paths": true, "top_risks": true,
		"what_if": true, "suggest_fixes": true, "explain": true, "coverage": true, "diff": true}
	for _, tl := range res.Tools {
		if !want[tl.Name] {
			t.Errorf("unexpected tool %s", tl.Name)
		}
		delete(want, tl.Name)
		if !strings.Contains(tl.Description, "Confirmed means") || !strings.Contains(tl.Description, "Possible means") {
			t.Errorf("%s: description does not explain confirmed vs possible", tl.Name)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing tools: %v", want)
	}
}

func TestWhoCanReach(t *testing.T) {
	cs := connect(t)
	var out WhoCanReachOutput
	res := call(t, cs, "who_can_reach", map[string]any{"target": "repo:acme-app/web"}, &out)
	found := false
	for _, p := range out.Confirmed {
		if p.From == "members:acme-actions" {
			found = true
			for _, h := range p.Hops {
				if h.Evidence == "" {
					t.Errorf("hop %s -> %s has no evidence", h.From, h.To)
				}
			}
		}
	}
	if !found {
		t.Fatalf("members:acme-actions not in confirmed: %+v", out.Confirmed)
	}
	if first := strings.SplitN(text(res), "\n", 2)[0]; first != out.Summary || !strings.Contains(first, "confirmed") {
		t.Errorf("text first line %q, summary %q", first, out.Summary)
	}
}

func TestBlastRadius(t *testing.T) {
	cs := connect(t)
	var out BlastRadiusOutput
	call(t, cs, "blast_radius", map[string]any{"principal": "members:acme-actions"}, &out)
	if out.Score.Confirmed.Repos != 12 {
		t.Errorf("confirmed repos = %d, want 12", out.Score.Confirmed.Repos)
	}
	if !strings.HasPrefix(out.Summary, "members:acme-actions can control 12 repos across 2 orgs (confirmed)") {
		t.Errorf("summary = %q", out.Summary)
	}
}

func TestWhatIfPinLowersConfirmedPairs(t *testing.T) {
	cs := connect(t)
	var out WhatIfOutput
	call(t, cs, "what_if", map[string]any{"fixes": []map[string]any{
		{"type": "pin_ref", "action": "action:acme-actions/deploy@main"},
	}}, &out)
	if out.Delta.After.ConfirmedPairs >= out.Delta.Before.ConfirmedPairs {
		t.Errorf("pairs before %d after %d: pin should lower them", out.Delta.Before.ConfirmedPairs, out.Delta.After.ConfirmedPairs)
	}
}

func TestSuggestFixes(t *testing.T) {
	cs := connect(t)
	var out SuggestFixesOutput
	call(t, cs, "suggest_fixes", map[string]any{"budget": 2}, &out)
	if len(out.Fixes) == 0 || out.Fixes[0].FixID != "pin:action:acme-actions/deploy@main" {
		t.Fatalf("first fix = %+v", out.Fixes)
	}
	if len(out.Fixes) > 2 {
		t.Errorf("budget 2 returned %d fixes", len(out.Fixes))
	}
	if out.Fixes[0].CumulativePct <= 0 {
		t.Errorf("cumulative pct = %v", out.Fixes[0].CumulativePct)
	}
}

func TestUnknownIDSuggests(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "blast_radius",
		Arguments: map[string]any{"principal": "members:acme-act"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "members:acme-actions") {
		t.Fatalf("want tool error suggesting members:acme-actions, got %q", text(res))
	}
	// A typo past the end still finds the close match by shrinking the prefix.
	_, err = NewEngine(loadAcme(t)).WhoCanReach(WhoCanReachInput{Target: "repo:acme-app/webb"})
	if err == nil || !strings.Contains(err.Error(), "repo:acme-app/web") {
		t.Fatalf("err = %v", err)
	}
	if s := NewEngine(loadAcme(t)).Suggest("repo:acme-app/"); len(s) > 5 {
		t.Errorf("suggestions capped at 5, got %d", len(s))
	}
}

func TestPathsExplainCoverageTopRisks(t *testing.T) {
	cs := connect(t)
	var p PathsOutput
	call(t, cs, "paths", map[string]any{"from": "members:acme-actions", "to": "oidc:acme-app/web"}, &p)
	if len(p.Confirmed) != 1 || len(p.Confirmed[0].Hops) == 0 {
		t.Fatalf("paths = %+v", p)
	}
	h := p.Confirmed[0].Hops[len(p.Confirmed[0].Hops)-1]
	var ex ExplainOutput
	call(t, cs, "explain", map[string]any{"from": h.From, "to": h.To, "kind": string(h.Kind)}, &ex)
	if len(ex.Edges) != 1 || ex.Edges[0].SourceAPI == "" || ex.Edges[0].ObservedAt == "" {
		t.Errorf("explain = %+v", ex)
	}
	// A reversed hop (repo controls action via RESOLVES_TO) is explained too.
	call(t, cs, "explain", map[string]any{"from": "repo:acme-actions/deploy", "to": "action:acme-actions/deploy@main"}, &ex)
	if len(ex.Edges) != 1 || !ex.Edges[0].Reversed {
		t.Errorf("reversed explain = %+v", ex)
	}

	var lp PathsOutput
	call(t, cs, "paths", map[string]any{"from": "members:acme-legacy"}, &lp)
	if len(lp.Confirmed) != 0 || len(lp.Possible) == 0 {
		t.Errorf("legacy paths should be possible only: %+v", lp)
	}

	var cov CoverageOutput
	call(t, cs, "coverage", map[string]any{}, &cov)
	if len(cov.Entries) != 2 {
		t.Errorf("coverage entries = %d", len(cov.Entries))
	}
	var tr TopRisksOutput
	call(t, cs, "top_risks", map[string]any{"n": 3}, &tr)
	if len(tr.Risks) != 3 || tr.Risks[0].Principal == "" {
		t.Errorf("top risks = %+v", tr.Risks)
	}
}

func TestWhatIfValidation(t *testing.T) {
	e := NewEngine(loadAcme(t))
	for _, in := range []WhatIfInput{
		{},
		{Fixes: []FixSpec{{Type: "nope"}}},
		{Fixes: []FixSpec{{Type: "lower_default_perm", Org: "org:acme-actions", To: "write"}}},
		{Fixes: []FixSpec{{Type: "pin_ref", Action: "repo:acme-app/web"}}},
	} {
		if _, err := e.WhatIf(in); err == nil {
			t.Errorf("%+v: expected error", in)
		}
	}
	out, err := e.WhatIf(WhatIfInput{Fixes: []FixSpec{{Type: "lower_default_perm", Org: "org:acme-actions", To: "read"}}})
	if err != nil || out.Delta.After.ConfirmedPairs >= out.Delta.Before.ConfirmedPairs {
		t.Errorf("lower default perm: %v %+v", err, out.Delta.After)
	}
}

func TestExplainFileLine(t *testing.T) {
	g := loadAcme(t)
	i := -1
	for j, ed := range g.Edges {
		if ed.Kind == graph.Uses {
			i = j
			break
		}
	}
	if i < 0 {
		t.Fatal("no USES edge in acme graph")
	}
	ed := g.Edges[i]
	// Graphs collected before position attrs existed explain without a location.
	ex, err := NewEngine(g).Explain(ExplainInput{From: ed.From, To: ed.To, Kind: string(graph.Uses)})
	if err != nil || strings.Contains(ex.Summary, ", at ") {
		t.Errorf("no-position summary = %q err=%v", ex.Summary, err)
	}
	g.Edges[i].Attrs = map[string]string{graph.AttrFile: ".github/workflows/release.yml", graph.AttrLine: "42",
		graph.AttrCol: "15", graph.AttrFileRef: "main"}
	ex, err = NewEngine(g).Explain(ExplainInput{From: ed.From, To: ed.To, Kind: string(graph.Uses)})
	if err != nil || !strings.HasSuffix(ex.Summary, ", at .github/workflows/release.yml:42 (main)") {
		t.Errorf("summary = %q err=%v", ex.Summary, err)
	}
}

// demoCalls is one valid call per tool against the demo graph.
var demoCalls = map[string]map[string]any{
	"who_can_reach": {"target": "repo:acme-app/web"},
	"blast_radius":  {"principal": demo.ActionsMembers},
	"paths":         {"from": demo.ActionsMembers, "to": "oidc:acme-secure/signer"},
	"top_risks":     {"n": 3},
	"what_if":       {"fixes": []map[string]any{{"type": "pin_ref", "action": demo.DeployMain}}},
	"suggest_fixes": {"budget": 2},
	"explain":       {"from": demo.SetupMain, "to": demo.ReleaseSHA},
	"coverage":      {},
	"diff":          {},
}

func TestDemoMarkerOnEveryTool(t *testing.T) {
	g := demo.Generate(demo.Options{Seed: 1})
	cs := connectServer(t, NewServerWith(g, "test", ServerOptions{Baseline: g}))
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		args, ok := demoCalls[tool.Name]
		if !ok {
			t.Errorf("no demo call for tool %s", tool.Name)
			continue
		}
		var out struct {
			Summary string `json:"summary"`
		}
		res := call(t, cs, tool.Name, args, &out)
		if !strings.HasPrefix(text(res), DemoMarker+" ") || !strings.HasPrefix(out.Summary, DemoMarker+" ") {
			t.Errorf("%s: summary not marked: %q", tool.Name, out.Summary)
		}
	}
	// A collected graph is never marked.
	var out struct {
		Summary string `json:"summary"`
	}
	call(t, connect(t), "coverage", map[string]any{}, &out)
	if strings.Contains(out.Summary, DemoMarker) {
		t.Errorf("non-demo summary marked: %q", out.Summary)
	}
}

func TestDemoWhatIfKeepsNestedPath(t *testing.T) {
	cs := connectGraph(t, demo.Generate(demo.Options{Seed: 1}))
	var w WhatIfOutput
	call(t, cs, "what_if", demoCalls["what_if"], &w)
	if w.Delta.After.ConfirmedPairs >= w.Delta.Before.ConfirmedPairs {
		t.Errorf("pin did not lower confirmed pairs: %+v", w.Delta.Before)
	}
	var who WhoCanReachOutput
	call(t, cs, "who_can_reach", map[string]any{"target": "repo:acme-app/web"}, &who)
	if len(who.Confirmed) == 0 {
		t.Fatal("no confirmed principals for repo:acme-app/web")
	}
}
