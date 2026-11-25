package report

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

// funnelGraphs are the graphs the funnel tests run on: every fixture with
// agent workflows, the demo, and a small synthetic enterprise.
func funnelGraphs(t *testing.T) map[string]*graph.Graph {
	t.Helper()
	return map[string]*graph.Graph{
		"agents":   loadGraph(t, "../../testdata/agents/graph.json"),
		"botmerge": loadGraph(t, "../../testdata/botmerge-script/graph.json"),
		"demo":     demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}),
		"large": graph.SyntheticLarge(1, graph.LargeSpec{Orgs: 4, Repos: 120, Actions: 30, Principals: 200,
			Agents: 24, Owners: 6, OwnedOrgs: 2, ExtraMemberships: 1}),
	}
}

func renderAll(t *testing.T, g *graph.Graph, format string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, g, Options{Format: format, Version: "v0.0.0-test", Rows: -1}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

var (
	stageRe    = regexp.MustCompile(`<li class="fs t-[a-z]+" data-fs="(\d+)" data-count="(\d+)">`)
	agentCard  = regexp.MustCompile(`<div class="card agent t-[a-z]+" data-fs="(\d+)">`)
	agentLede  = regexp.MustCompile(`(\d+) workflows? runs? an AI coding agent; (\d+) can be started by people without push access, (\d+) of them`)
	mdStageRow = regexp.MustCompile(`(?m)^\| (\d) \| [^|]+ \| (\d+) \|`)
)

// mdFunnel is the funnel block of a Markdown report.
func mdFunnel(md string) string {
	i, j := strings.Index(md, "**AI agents in CI:**"), strings.Index(md, "**Also:**")
	if i < 0 || j < i {
		return ""
	}
	return md[i:j]
}

// funnelCounts reads the stage counts from a rendered HTML report.
func funnelCounts(t *testing.T, page string) []int {
	t.Helper()
	var out []int
	for i, m := range stageRe.FindAllStringSubmatch(page, -1) {
		if n, _ := strconv.Atoi(m[1]); n != i+1 {
			t.Fatalf("funnel stage %d is out of order (want %d)", n, i+1)
		}
		c, _ := strconv.Atoi(m[2])
		out = append(out, c)
	}
	return out
}

// TestFunnelMatchesAgentsSection: every stage count equals the number of
// cards the stage's link filters to in "AI agents in CI" (every row listed),
// and the stages the section's lede names agree with it.
func TestFunnelMatchesAgentsSection(t *testing.T) {
	for name, g := range funnelGraphs(t) {
		t.Run(name, func(t *testing.T) {
			page := renderAll(t, g, "html")
			counts := funnelCounts(t, page)
			if len(counts) != funnelStages {
				t.Fatalf("%d funnel stages, want %d", len(counts), funnelStages)
			}
			var cards []int
			for _, m := range agentCard.FindAllStringSubmatch(page, -1) {
				s, _ := strconv.Atoi(m[1])
				cards = append(cards, s)
			}
			for k, want := range counts {
				got := 0
				for _, s := range cards {
					if s >= k+1 {
						got++
					}
				}
				if got != want {
					t.Errorf("stage %d shows %d, the agents section has %d cards at that stage", k+1, want, got)
				}
			}
			if n := len(graph.NewIndex(g).AgentWorkflows()); counts[0] != n {
				t.Errorf("stage 1 is %d, the graph has %d agent workflows", counts[0], n)
			}
			m := agentLede.FindStringSubmatch(page)
			if m == nil {
				t.Fatal("no AI agents lede")
			}
			for i, k := range []int{stageLooks, stageOutsiders, stageHolds} {
				if n, _ := strconv.Atoi(m[i+1]); counts[k-1] != n {
					t.Errorf("stage %d is %d, the AI agents lede says %d", k, counts[k-1], n)
				}
			}
			for _, href := range regexp.MustCompile(`<a href="([^"]+)" data-fs=`).FindAllStringSubmatch(page, -1) {
				if href[1] != "#ai-agents" {
					t.Errorf("a funnel stage links to %s, want #ai-agents", href[1])
				}
			}
			// The Markdown table has the same stages and counts.
			rows := mdStageRow.FindAllStringSubmatch(mdFunnel(renderAll(t, g, "md")), -1)
			if len(rows) != funnelStages {
				t.Fatalf("Markdown funnel has %d rows, want %d", len(rows), funnelStages)
			}
			for i, r := range rows {
				if c, _ := strconv.Atoi(r[2]); c != counts[i] {
					t.Errorf("Markdown stage %s is %d, HTML %d", r[1], c, counts[i])
				}
			}
		})
	}
}

// TestFunnelNeverGrows: each stage is a subset of the one before it, so the
// counts never increase down the funnel, and a row's stage follows from its
// own facts.
func TestFunnelNeverGrows(t *testing.T) {
	for name, g := range funnelGraphs(t) {
		t.Run(name, func(t *testing.T) {
			counts := funnelCounts(t, renderAll(t, g, "html"))
			for k := 1; k < len(counts); k++ {
				if counts[k] > counts[k-1] {
					t.Errorf("stage %d (%d) is larger than stage %d (%d)", k+1, counts[k], k, counts[k-1])
				}
			}
			rows, _, _, _ := agentRows(graph.NewIndex(g), -1)
			for _, r := range rows {
				s := r.Stage
				if (s >= stageKnown) == r.NameOnly || (s >= stageOutsiders) != (r.Outsider && !r.NameOnly) ||
					(s >= stageHolds) != r.Exposed || (s >= stageEndToEnd) != (r.Exposed && !r.Possible) ||
					(s >= stageDanger) != (r.Exposed && !r.Possible && r.Tools != "") {
					t.Errorf("%s: stage %d does not match its facts %+v", r.Workflow, s, r)
				}
			}
		})
	}
}

// TestFunnelEmptyGraph: with no agent workflow the funnel says so plainly
// and draws no bars, in both formats; the stat widgets stay.
func TestFunnelEmptyGraph(t *testing.T) {
	for name, g := range map[string]*graph.Graph{"acme": loadAcme(t), "empty": {Schema: graph.SchemaVersion, Enterprise: "acme"}} {
		t.Run(name, func(t *testing.T) {
			page := renderAll(t, g, "html")
			if !strings.Contains(page, `<p class="fun-empty">No workflow in this graph looks like an AI agent`) {
				t.Error("HTML funnel does not say there are no agent workflows")
			}
			if strings.Contains(page, `class="fs `) || strings.Contains(page, `class="fun-st"`) {
				t.Error("HTML draws funnel bars with no agent workflow")
			}
			if !strings.Contains(page, `class="fun-stats"`) {
				t.Error("stat widgets missing")
			}
			md := renderAll(t, g, "md")
			if !strings.Contains(md, "**AI agents in CI:** No workflow in this graph looks like an AI agent") || mdStageRow.MatchString(mdFunnel(md)) {
				t.Error("Markdown funnel does not say there are no agent workflows, or draws a table")
			}
		})
	}
}

// TestBuildFunnel: bar widths keep small stages visible, a stage that comes
// to zero reads as none (ok, not a zero-width danger bar), and the drop of
// possible-only workflows is marked possible.
func TestBuildFunnel(t *testing.T) {
	f := buildFunnel([funnelStages + 1]int{0, 200, 180, 20, 9, 5, 0})
	if len(f.Stages) != funnelStages {
		t.Fatalf("%d stages", len(f.Stages))
	}
	want := []struct{ width, tone string }{{"w100", "path"}, {"w92", "path"}, {"w12", "danger"}, {"w8", "danger"}, {"w8", "danger"}, {"w0", "ok"}}
	for i, s := range f.Stages {
		if s.Width != want[i].width || s.Tone != want[i].tone {
			t.Errorf("stage %d: width %s tone %s, want %s %s", i+1, s.Width, s.Tone, want[i].width, want[i].tone)
		}
	}
	if s := f.Stages[stageEndToEnd-1]; !s.DropPossible || !strings.HasPrefix(s.Drop, "−4: possible only") {
		t.Errorf("stage 5 drop %q possible=%v", s.Drop, s.DropPossible)
	}
	if f.Stages[0].Drop != "" || f.Stages[1].Drop != "−20: name-only matches: listed, never ranked" {
		t.Errorf("drops %q %q", f.Stages[0].Drop, f.Stages[1].Drop)
	}
	if f.Line != "From 200 workflows that look like an AI agent to 0 confirmed agent paths in dangerous mode to fix first." {
		t.Errorf("line %q", f.Line)
	}
}

// TestStatWidgetsKeepPossibleApart: the bot merge widget shows confirmed
// and possible as two numbers, never their sum.
func TestStatWidgetsKeepPossibleApart(t *testing.T) {
	ws := statWidgets(&graph.Graph{}, graph.NewIndex(&graph.Graph{}), []botMergeRow{{Repo: "acme-app/web"}, {Repo: "acme-app/api", Possible: true}, {Repo: "acme-app/docs", Possible: true}})
	got := ws[0].Parts
	if len(got) != 2 || got[0].Value != "1" || got[0].Kind != "conf" || got[1].Value != "2" || got[1].Kind != "poss" {
		t.Errorf("bot merge parts %+v, want 1 confirmed and 2 possible", got)
	}
	if ws[0].Tone != "crit" || ws[0].Href != "#ai-self-merge" {
		t.Errorf("bot merge widget tone %s href %s", ws[0].Tone, ws[0].Href)
	}
}
