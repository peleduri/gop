package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

// briefBudget is the byte budget of a brief answer on a large enterprise.
const briefBudget = 8 * 1024

// largeGraph is a synthetic enterprise of 40 orgs x 50 repos (2,000 repos)
// with 50 teams. Every team can push to repo:acme-org-01/svc-001, so
// who_can_reach on it lists more than 50 principals, and each team pushes to
// 40 more repos spread over the orgs. seed varies the demo filler, so two
// seeds give a large diff.
func largeGraph(t *testing.T, seed int64) *graph.Graph {
	t.Helper()
	g := demo.Generate(demo.Options{Seed: seed, Orgs: 40, ReposPerOrg: 50})
	var repos []string
	for _, n := range g.Nodes {
		if n.Kind == graph.KindRepo && n.Evidence == graph.Live {
			repos = append(repos, n.ID)
		}
	}
	if len(repos) < 1900 {
		t.Fatalf("large graph has %d visible repos, want about 2,000", len(repos))
	}
	edge := func(from string, kind graph.EdgeKind, to string, attrs map[string]string) {
		g.Edges = append(g.Edges, graph.Edge{From: from, To: to, Kind: kind, Evidence: graph.Live,
			SourceAPI: "demo:team", ObservedAt: g.CollectedAt, Attrs: attrs})
	}
	for i := 1; i <= 50; i++ {
		org := fmt.Sprintf("acme-org-%02d", 1+i%36)
		id := fmt.Sprintf("team:%s/team-%02d", org, i)
		g.Nodes = append(g.Nodes, graph.Node{ID: id, Kind: graph.KindIdentity, Name: id[len("team:"):], Evidence: graph.Live,
			Attrs: map[string]string{"source_api": "demo:team"}})
		push := map[string]string{graph.AttrVia: "team", "permission": "write"}
		edge(id, graph.CanPush, "repo:acme-org-01/svc-001", push)
		for k := range 40 {
			edge(id, graph.CanPush, repos[(i*97+k*53)%len(repos)], push)
		}
		edge(fmt.Sprintf("identity:user-%03d", i), graph.MemberOf, id, nil)
	}
	return g
}

// briefCases are the list-returning tools with arguments that give long
// lists on largeGraph.
var briefCases = []struct {
	tool string
	args map[string]any
}{
	{"who_can_reach", map[string]any{"target": "repo:acme-org-01/svc-001"}},
	{"blast_radius", map[string]any{"principal": "members:acme-actions"}},
	{"paths", map[string]any{"from": "members:acme-actions"}},
	{"top_risks", map[string]any{"n": 50}},
	{"suggest_fixes", map[string]any{"budget": 5}},
	{"diff", map[string]any{}},
	{"fix_plan", map[string]any{"suggestion_rank": 1}},
}

// withArg returns a copy of args with k set to v.
func withArg(args map[string]any, k string, v any) map[string]any {
	out := map[string]any{k: v}
	for key, val := range args {
		out[key] = val
	}
	return out
}

func callRaw(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, []byte) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		t.Fatalf("%s: tool error: %s", tool, text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	return text(res), b
}

func TestBriefStaysUnderBudgetOnLargeGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("large graph")
	}
	srv := NewServerWith(largeGraph(t, 1), "test", ServerOptions{Baseline: largeGraph(t, 2)})
	cs := connectServer(t, srv)
	truncated := 0
	for _, tc := range briefCases {
		t.Run(tc.tool, func(t *testing.T) {
			fullText, fullJSON := callRaw(t, cs, tc.tool, withArg(tc.args, "detail", "full"))
			briefText, briefJSON := callRaw(t, cs, tc.tool, tc.args) // brief is the default
			t.Logf("%s: full %d bytes text, %d bytes structured; brief %d bytes text, %d bytes structured",
				tc.tool, len(fullText), len(fullJSON), len(briefText), len(briefJSON))
			if len(briefText) > briefBudget || len(briefJSON) > briefBudget {
				t.Errorf("brief answer is %d bytes text, %d bytes structured; budget %d", len(briefText), len(briefJSON), briefBudget)
			}
			var out struct {
				Brief *Brief `json:"brief"`
			}
			if err := json.Unmarshal(briefJSON, &out); err != nil {
				t.Fatal(err)
			}
			if out.Brief == nil {
				t.Fatal("brief answer has no brief object")
			}
			if !strings.Contains(string(briefJSON), `"truncated":`) || len(out.Brief.Total) == 0 {
				t.Errorf("brief object %+v lacks truncated or total", out.Brief)
			}
			if out.Brief.Truncated {
				truncated++
			}
			if strings.Contains(string(fullJSON), `"brief"`) {
				t.Error("full answer carries a brief object")
			}
			checkEvidenceKept(t, briefJSON)
		})
	}
	if truncated < 5 {
		t.Errorf("only %d of %d tools were truncated on the large graph; the fixture is too small to test the budget", truncated, len(briefCases))
	}
}

// checkEvidenceKept fails when a listed path or edge fact in a brief answer
// has no evidence level.
func checkEvidenceKept(t *testing.T, b []byte) {
	t.Helper()
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			_, hasHops := x["hops"]
			_, hasUnverified := x["unverified"]
			if hasHops || hasUnverified {
				if ev, _ := x["evidence"].(string); ev == "" {
					t.Errorf("listed path %v -> %v has no evidence", x["from"], x["to"])
				}
			}
			for _, side := range []string{"old", "new"} {
				if f, ok := x[side].(map[string]any); ok && x["kind"] != nil {
					if ev, _ := f["evidence"].(string); ev == "" {
						t.Errorf("edge change %v %v %v: %s side has no evidence", x["from"], x["kind"], x["to"], side)
					}
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	walk(v)
}

func TestBriefShape(t *testing.T) {
	cs := connectGraph(t, largeGraph(t, 1))

	var who WhoCanReachOutput
	call(t, cs, "who_can_reach", map[string]any{"target": "repo:acme-org-01/svc-001", "limit": 3}, &who)
	if who.Brief == nil || !who.Brief.Truncated || who.Brief.Limit != 3 {
		t.Fatalf("brief = %+v, want truncated with limit 3", who.Brief)
	}
	if len(who.Confirmed) != 3 || who.Brief.Total["confirmed"] <= 50 {
		t.Errorf("confirmed %d listed of %d, want 3 of more than 50", len(who.Confirmed), who.Brief.Total["confirmed"])
	}
	for _, p := range who.Confirmed {
		if p.Hops != nil || p.Evidence == "" || p.From == "" || p.To == "" {
			t.Errorf("brief path %+v: want ends and evidence without hops", p)
		}
	}
	if len(who.Brief.Omitted) != 1 || who.Brief.Omitted[0] != "hops" {
		t.Errorf("omitted = %v, want [hops]", who.Brief.Omitted)
	}

	// The detail call a brief list points to keeps its hops.
	var one PathsOutput
	call(t, cs, "paths", map[string]any{"from": who.Confirmed[0].From, "to": who.Confirmed[0].To}, &one)
	if len(one.Confirmed) != 1 || len(one.Confirmed[0].Hops) == 0 {
		t.Errorf("paths from-to in brief: %+v, want one path with hops", one.Confirmed)
	}

	var full WhoCanReachOutput
	call(t, cs, "who_can_reach", map[string]any{"target": "repo:acme-org-01/svc-001", "detail": "full", "limit": 3}, &full)
	if full.Brief != nil || len(full.Confirmed) != who.Brief.Total["confirmed"] || len(full.Confirmed[0].Hops) == 0 {
		t.Errorf("full: brief %+v, %d confirmed paths; want every path with hops and no brief object", full.Brief, len(full.Confirmed))
	}

	var top TopRisksOutput
	call(t, cs, "top_risks", map[string]any{"n": 3}, &top)
	if len(top.Risks) != 3 || !top.Brief.Truncated || top.Brief.Total["risks"] <= 3 {
		t.Errorf("top_risks n=3: %d risks, brief %+v; want 3 and the total of ranked principals", len(top.Risks), top.Brief)
	}
}

func TestBriefDiffDefaults(t *testing.T) {
	cs := connectServer(t, NewServerWith(largeGraph(t, 1), "test", ServerOptions{Baseline: largeGraph(t, 2)}))
	var brief, full DiffOutput
	call(t, cs, "diff", map[string]any{}, &brief)
	call(t, cs, "diff", map[string]any{"detail": "full"}, &full)
	if brief.Brief == nil || brief.Brief.Limit != DefaultBriefLimit || !brief.Truncated {
		t.Fatalf("brief diff: brief %+v truncated %t, want limit %d and truncated", brief.Brief, brief.Truncated, DefaultBriefLimit)
	}
	r := brief.Report
	listed := len(r.Paths) + len(r.Settings) + len(r.Edges.Added) + len(r.Edges.Removed) + len(r.Edges.Changed) +
		len(r.Edges.LostVisibility) + len(r.Scores) + len(r.Coverage.Opened) + len(r.Coverage.Closed)
	if listed != DefaultBriefLimit || len(r.Paths) == 0 || len(r.Scores) == 0 {
		t.Errorf("brief diff lists %d entries (%d paths, %d scores), want %d in all with every changed section shown",
			listed, len(r.Paths), len(r.Scores), DefaultBriefLimit)
	}
	if len(full.Report.Paths) != DefaultDiffLimit {
		t.Errorf("full diff lists %d paths, want %d", len(full.Report.Paths), DefaultDiffLimit)
	}
	if brief.Brief.Total["paths"] <= DefaultDiffLimit {
		t.Errorf("total paths %d, want more than %d", brief.Brief.Total["paths"], DefaultDiffLimit)
	}
	for _, c := range brief.Report.Paths {
		for _, p := range []*graph.Path{c.Old, c.New} {
			if p != nil && (p.Hops != nil || p.Evidence == "") {
				t.Errorf("brief path change %s -> %s: want evidence without hops", c.Principal, c.Target)
			}
		}
	}
	if full.Brief != nil {
		t.Errorf("full diff has a brief object: %+v", full.Brief)
	}
}

func TestShareLimit(t *testing.T) {
	for _, tc := range []struct {
		lens  []int
		limit int
		want  []int
	}{
		{[]int{50, 0, 3, 1}, 10, []int{6, 0, 3, 1}},
		{[]int{50, 50, 50}, 2, []int{1, 1, 0}},
		{[]int{1, 2}, 10, []int{1, 2}},
		{[]int{}, 10, []int{}},
	} {
		if got := shareLimit(tc.lens, tc.limit); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("shareLimit(%v, %d) = %v, want %v", tc.lens, tc.limit, got, tc.want)
		}
	}
}

func TestDetailInputErrors(t *testing.T) {
	cs := connect(t)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"top_risks", map[string]any{"detail": "short"}, `detail must be brief or full, got "short"`},
		{"paths", map[string]any{"from": "members:acme-actions", "limit": -1}, "limit must be positive"},
		{"fix_plan", map[string]any{"suggestion_rank": 1, "detail": "everything"}, "detail must be brief or full"},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		if !res.IsError || !strings.Contains(text(res), tc.want) {
			t.Errorf("%s %v: got %q, want an error containing %q", tc.tool, tc.args, text(res), tc.want)
		}
	}
}
