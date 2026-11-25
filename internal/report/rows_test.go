package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestRowsCapLongSections: Options.Rows caps AI agents in CI, pinned
// actions and repos on the top paths at their best rows, says how many were
// left out, and keeps the section counts exact; a negative Rows lists every
// row.
func TestRowsCapLongSections(t *testing.T) {
	g := graph.SyntheticLarge(2, graph.LargeSpec{Orgs: 6, Repos: 300, Actions: 400, Principals: 600, Agents: 30, Owners: 6, OwnedOrgs: 3, ExtraMemberships: 1})
	all := build(g, Options{Top: 10, FixBudget: 5, Rows: -1})
	capped := build(g, Options{Top: 10, FixBudget: 5, Rows: 2})
	if len(all.Agents) != 30 || all.AgentsMore != 0 || all.AgentsMoreLine != "" {
		t.Fatalf("Rows -1: %d agent rows, %d more (%q); want all 30", len(all.Agents), all.AgentsMore, all.AgentsMoreLine)
	}
	if len(capped.Agents) != 2 || capped.AgentsMore != 28 {
		t.Errorf("Rows 4: %d agent rows, %d more; want 2 and 28", len(capped.Agents), capped.AgentsMore)
	}
	if capped.AgentLine != all.AgentLine {
		t.Errorf("capping changed the agent counts:\n%s\n%s", capped.AgentLine, all.AgentLine)
	}
	for i, r := range capped.Agents {
		if w := all.Agents[i]; r.Workflow != w.Workflow || r.Reach != w.Reach {
			t.Errorf("agent row %d: %s (%s), want the full list's %s (%s)", i, r.Workflow, r.Reach, w.Workflow, w.Reach)
		}
	}
	if want := "28 more agent workflows are not listed here (the counts above include them): " + moreHint + "."; capped.AgentsMoreLine != want {
		t.Errorf("AgentsMoreLine = %q, want %q", capped.AgentsMoreLine, want)
	}
	if n := len(all.Pinned); n > 2 {
		if len(capped.Pinned) != 2 || capped.PinnedMore != n-2 || capped.PinLine != all.PinLine {
			t.Errorf("pinned: %d rows, %d more, line %q; want 2, %d, %q", len(capped.Pinned), capped.PinnedMore, capped.PinLine, n-2, all.PinLine)
		}
		for i := 1; i < len(capped.Pinned); i++ {
			a, b := capped.Pinned[i-1], capped.Pinned[i]
			if !a.Path.Confirmed && b.Path.Confirmed {
				t.Errorf("pinned row %d is possible but row %d is confirmed: confirmed rows come first", i-1, i)
			}
		}
	} else {
		t.Errorf("want more than 2 pinned exposures in the test graph, got %d", n)
	}
	if n := len(all.HardenRepos); n > 2 {
		if len(capped.HardenRepos) != 2 || capped.HardenReposMore != n-2 {
			t.Errorf("top-path repos: %d rows, %d more; want 2 and %d", len(capped.HardenRepos), capped.HardenReposMore, n-2)
		}
	} else {
		t.Errorf("want more than 2 top-path repos in the test graph, got %d", n)
	}
	for _, format := range []string{"html", "md"} {
		var b strings.Builder
		if err := Render(&b, g, Options{Format: format, Rows: 2}); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{capped.AgentsMoreLine, capped.PinnedMoreLine, capped.HardenReposMoreLine} {
			if !strings.Contains(b.String(), want) {
				t.Errorf("%s report missing %q", format, want)
			}
		}
	}
}

// TestRowsDefault: a zero Options.Rows is DefaultRows.
func TestRowsDefault(t *testing.T) {
	g := graph.SyntheticLarge(2, graph.LargeSpec{Orgs: 6, Repos: 300, Actions: 120, Principals: 400, Agents: DefaultRows + 3, Owners: 6, OwnedOrgs: 3})
	d := build(g, Options{Top: 10, FixBudget: 5})
	if len(d.Agents) != DefaultRows || d.AgentsMore != 3 {
		t.Errorf("default: %d agent rows, %d more; want %d and 3", len(d.Agents), d.AgentsMore, DefaultRows)
	}
}
