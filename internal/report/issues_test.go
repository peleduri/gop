package report

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// issueGraphs are the funnel graphs plus the acme fixture (no issue).
func issueGraphs(t *testing.T) map[string]*graph.Graph {
	t.Helper()
	gs := funnelGraphs(t)
	gs["acme"] = loadAcme(t)
	return gs
}

var (
	issueLi   = regexp.MustCompile(`<li class="is-row" data-sev="([a-z]+)" data-f="([a-z -]*)" data-ev="([a-z]+)" data-k="([a-z_]+)">\s*<details class="is-d( is-p)?" id="(is-\d+)"><summary class="is-s">(.*?)</summary>`)
	mdIssueRe = regexp.MustCompile(`(?m)^\| \d+ \| (critical|high|medium) \| .* \| (✓ confirmed|\? possible) \| `)
)

// wantIssues recomputes, from the graph alone, how many issues of each kind
// there should be and the severity each place should get.
func wantIssues(ix *graph.Index) (counts map[string]int, sev map[string]string) {
	counts, sev = map[string]int{}, map[string]string{}
	for _, id := range ix.AgentWorkflows() {
		n, _ := ix.Node(id)
		if !graph.AgentExposed(n) {
			continue
		}
		counts[issueAgent]++
		s := "high"
		if len(graph.AgentUnrestricted(n)) > 0 {
			s = "critical"
		}
		sev[issueAgent+" "+strings.TrimPrefix(id, "workflow:")] = s
	}
	for _, id := range ix.BotMergeRepos() {
		n, _ := ix.Node(id)
		counts[issueBotMerge]++
		s := "high"
		if n.Attrs[graph.AttrAgentHoldsMergeKey] == "true" {
			s = "critical"
		}
		sev[issueBotMerge+" "+strings.TrimPrefix(id, "repo:")] = s
	}
	impact := func(r graph.Reached) bool {
		return len(r.Secrets)+len(r.Runners)+len(r.OIDC)+len(r.CloudTargets) > 0
	}
	for _, a := range ix.AdvisoryActions() {
		res := ix.Reach(a, graph.Options{})
		if !impact(res.Confirmed) && !impact(res.Possible) {
			continue
		}
		counts[issueAdvisory]++
		n, _ := ix.Node(a)
		s := "high"
		if n.Attrs[graph.AttrAdvisorySeverity] == "critical" || strings.Contains(advisoryLabel(ix, a), "severity critical") {
			s = "critical"
		}
		sev[issueAdvisory+" "+strings.TrimPrefix(a, "action:")] = s
	}
	for _, pe := range ix.PinnedExposures() {
		counts[issuePinned]++
		s := "medium"
		if impact(ix.Reach(pe.Action, graph.Options{}).Confirmed) {
			s = "high"
		}
		sev[issuePinned+" "+strings.TrimPrefix(pe.Action, "action:")] = s
	}
	return counts, sev
}

// TestIssuesMatchFacts: every Issues row comes from one fact gop detects,
// with the severity its facts give it, and the rendered HTML list, the
// summary cards and the Markdown table all show the same rows.
func TestIssuesMatchFacts(t *testing.T) {
	for name, g := range issueGraphs(t) {
		t.Run(name, func(t *testing.T) {
			ix := graph.NewIndex(g)
			rows, sum := buildIssues(ix, botMergeRows(ix), buildAgentPaths(ix))
			wantN, wantSev := wantIssues(ix)
			got := map[string]int{}
			for _, r := range rows {
				got[r.Kind]++
				key := r.Kind + " " + r.Where
				if s, ok := wantSev[key]; !ok {
					t.Errorf("issue %s has no fact behind it", key)
				} else if s != r.Sev {
					t.Errorf("issue %s is %s, its facts make it %s", key, r.Sev, s)
				}
				if len(r.Factors) == 0 || len(r.Fixes) == 0 {
					t.Errorf("issue %s has no risk factor or no fix", key)
				}
			}
			for _, k := range []string{issueAgent, issueBotMerge, issueAdvisory, issuePinned} {
				if got[k] != wantN[k] {
					t.Errorf("%d %s issues, the graph has %d", got[k], k, wantN[k])
				}
			}
			if sum.Total != len(rows) || sum.Critical+sum.High+sum.Medium != sum.Total || sum.Confirmed+sum.Possible != sum.Total {
				t.Errorf("summary %+v does not add up to %d rows", sum, len(rows))
			}
			for i := 1; i < len(rows); i++ {
				if issueSevRank[rows[i-1].Sev] > issueSevRank[rows[i].Sev] {
					t.Errorf("row %d (%s) after a %s row: not most severe first", i+1, rows[i].Sev, rows[i-1].Sev)
				}
			}

			page := renderAll(t, g, "html")
			lis := issueLi.FindAllStringSubmatch(page, -1)
			if len(lis) != len(rows) {
				t.Fatalf("HTML lists %d issues, want %d", len(lis), len(rows))
			}
			bySev := map[string]int{}
			for i, m := range lis {
				r := rows[i]
				bySev[m[1]]++
				if m[1] != r.Sev || m[2] != r.FactorKeys || m[4] != r.Kind {
					t.Errorf("HTML row %d is %s/%q/%s, built %s/%q/%s", i+1, m[1], m[2], m[4], r.Sev, r.FactorKeys, r.Kind)
				}
				if !strings.Contains(m[7], `<span class="sev s-`+r.Sev+`">`+r.Sev+`</span>`) {
					t.Errorf("HTML row %d does not show severity %s", i+1, r.Sev)
				}
			}
			if len(rows) > 0 {
				for sev, n := range map[string]int{"Critical": sum.Critical, "High": sum.High, "Medium": sum.Medium} {
					card := `<span class="k-label">` + sev + `</span><strong>` + strconv.Itoa(n) + `</strong>`
					if !strings.Contains(page, card) {
						t.Errorf("summary card %s does not show %d", sev, n)
					}
				}
				if bySev["critical"] != sum.Critical || bySev["high"] != sum.High || bySev["medium"] != sum.Medium {
					t.Errorf("rows by severity %v, summary %+v", bySev, sum)
				}
			}
			mdRows := mdIssueRe.FindAllStringSubmatch(renderAll(t, g, "md"), -1)
			if len(mdRows) != len(rows) {
				t.Fatalf("Markdown lists %d issues, want %d", len(mdRows), len(rows))
			}
			for i, m := range mdRows {
				if m[1] != rows[i].Sev || (m[2] == "✓ confirmed") != rows[i].Confirmed {
					t.Errorf("Markdown row %d is %s %s, built %s confirmed=%v", i+1, m[1], m[2], rows[i].Sev, rows[i].Confirmed)
				}
			}
		})
	}
}

// TestIssuesPossibleNeverConfirmed: a row whose deciding facts include one
// gop could not see is possible everywhere it shows, never confirmed, and
// its facts really are unverified.
func TestIssuesPossibleNeverConfirmed(t *testing.T) {
	possible := 0
	for name, g := range issueGraphs(t) {
		t.Run(name, func(t *testing.T) {
			ix := graph.NewIndex(g)
			rows, _ := buildIssues(ix, botMergeRows(ix), buildAgentPaths(ix))
			page := renderAll(t, g, "html")
			lis := issueLi.FindAllStringSubmatch(page, -1)
			if len(lis) != len(rows) {
				t.Fatalf("HTML lists %d issues, want %d", len(lis), len(rows))
			}
			for i, r := range rows {
				m := lis[i]
				if r.Confirmed {
					if m[3] != "confirmed" || m[5] != "" || !strings.Contains(m[7], "✓</span> confirmed") {
						t.Errorf("confirmed row %s is not shown as confirmed", r.ID)
					}
					continue
				}
				possible++
				if m[3] != "possible" || m[5] != " is-p" {
					t.Errorf("possible row %s has data-ev %q class %q", r.ID, m[3], m[5])
				}
				if strings.Contains(m[7], "confirmed") || !strings.Contains(m[7], "?</span> possible") {
					t.Errorf("possible row %s shows as confirmed: %s", r.ID, m[7])
				}
				if r.Kind == issueAgent {
					conf := false
					for _, e := range ix.In("workflow:" + r.Where) {
						if e.Kind == graph.CanTrigger && graph.Verified(e.Evidence) {
							conf = true
						}
					}
					n, _ := ix.Node("workflow:" + r.Where)
					if conf && n.Attrs[graph.AttrAgentGate] != graph.GateUnknown {
						t.Errorf("agent issue %s is possible but its trigger and gate were read", r.Where)
					}
				}
			}
		})
	}
	if possible == 0 {
		t.Fatal("no possible issue in any test graph: the test checks nothing")
	}
}

// TestIssuesEmptyGraph: a graph with nothing in it has no issue rows, says
// so, and still renders the section and the rail link.
func TestIssuesEmptyGraph(t *testing.T) {
	g := &graph.Graph{Enterprise: "acme"}
	ix := graph.NewIndex(g)
	if rows, sum := buildIssues(ix, botMergeRows(ix), buildAgentPaths(ix)); len(rows) != 0 || sum.Total != 0 {
		t.Fatalf("empty graph: %d issues, summary %+v", len(rows), sum)
	}
	page := render(t, g, "html")
	for _, want := range []string{`<section id="issues"`, `<a class="rg-t" href="#issues">Issues</a>`, "No issue: no AI agent outsiders can start"} {
		if !strings.Contains(page, want) {
			t.Errorf("empty graph HTML lacks %q", want)
		}
	}
	for _, bad := range []string{`class="is-row"`, `id="is-filters"`, `class="rc"`} {
		if strings.Contains(page, bad) {
			t.Errorf("empty graph HTML has %q", bad)
		}
	}
	if md := render(t, g, "md"); !strings.Contains(md, "## Issues\n\nNo issue:") {
		t.Error("empty graph Markdown lacks the no-issue line")
	}
}
