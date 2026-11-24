package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// TestRenderBotMerge: the AI approve + self-merge section names the repo,
// the chain, who can use it and the fixes, and the risks table marks the
// principal that lands code through it.
func TestRenderBotMerge(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	md := render(t, g, "md")
	testutil.Golden(t, "botmerge.md", []byte(md), "dev")
	i := strings.Index(md, "## AI approve + self-merge")
	if i < 0 {
		t.Fatal("no AI approve + self-merge section")
	}
	sec := md[i:]
	for _, want := range []string{
		"### acme-app/web",
		"a PR author can get code onto \\`main\\` without human review: \\`ai-review.yml\\` + \\`ai-merge.yml\\`",
		"- Who: external:anyone",
		"- Why no human review: app\\_bypass",
		"- Merging App: 77, a bypass actor of the default branch rules",
		"Remove the GitHub App \\`77\\` from the bypass actors",
		"Do not let PR authors trigger the merge",
		"Do not give the reviewer write or approve rights",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q", want)
		}
	}
	if !strings.Contains(md, "external:anyone can get code onto the default branch of 1 repo without human review [bot_self_merge]") {
		t.Error("risks table does not mark the bot self-merge principal")
	}

	acme, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(render(t, acme, "md"), "self-merge") {
		t.Error("section rendered without a review bypass")
	}
}

// TestRenderBotMergeScript: the script variant names the script, marks the
// stale approvals as suspected, says the approval may not cover the merged
// code and that the AI step holds the merge key.
func TestRenderBotMergeScript(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge-script/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	md := render(t, g, "md")
	testutil.Golden(t, "botmerge-script.md", []byte(md), "dev")
	i := strings.Index(md, "## AI approve + self-merge")
	if i < 0 {
		t.Fatal("no AI approve + self-merge section")
	}
	sec := md[i:]
	for _, want := range []string{
		"\\`ai-merge.yml\\` (merges in \\`tools/merge.py\\`)",
		"the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic",
		"- Merge rules in a script: \\`tools/merge.py\\`",
		"- Stale approvals (suspected, heuristic): the script re-counts approvals GitHub dismissed",
		"- The AI step holds the merge key: .github/workflows/ai-review.yml",
		"Stop counting DISMISSED reviews in \\`tools/merge.py\\`",
		"add synchronize to the pull\\_request types of \\`ai-review.yml\\`",
		"Keep the merge key out of the AI step",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q", want)
		}
	}
	if strings.Contains(sec, "confirmed stale") {
		t.Error("stale approvals rendered as confirmed")
	}
}

// TestRenderBotMergeHTML: the HTML report has the AI approve + self-merge
// section (linked from the nav), the [bot_self_merge] marker on the risk
// row, the script, the suspected stale approvals and the fixes, with code
// spans escaped.
func TestRenderBotMergeHTML(t *testing.T) {
	g := loadGraph(t, "../../testdata/botmerge-script/graph.json")
	out := render(t, g, "html")
	assertSelfContained(t, []byte(out))
	raw := embeddedJSON(t, out)
	testutil.Golden(t, "botmerge-script.html", []byte(strings.Replace(out, raw, "@@data@@", 1)), "v0.0.0-test")
	for _, want := range []string{
		`<li><a href="#ai-self-merge">AI self-merge</a></li>`,
		`<h2 id="ai-self-merge">AI approve + self-merge</h2>`,
		`<a class="adv inj" href="#ai-self-merge"><span aria-hidden="true">!</span> lands code on 1 repo without human review [bot_self_merge]</a>`,
		`<p class="ag-h"><code>acme-app/web</code> <span class="badge live"><span aria-hidden="true">✓</span> confirmed</span></p>`,
		"<code>ai-review.yml</code> + <code>ai-merge.yml</code> (merges in <code>tools/merge.py</code>)",
		"<dt>Merging App</dt><dd>77, a bypass actor of the default branch rules</dd>",
		"<dt>Merge rules</dt><dd>in <code>tools/merge.py</code>",
		`<dt>Stale approvals</dt><dd><span class="badge nv"><span aria-hidden="true">?</span> suspected, heuristic</span> the script re-counts approvals GitHub dismissed`,
		"<li>Stop counting DISMISSED reviews in <code>tools/merge.py</code>",
		"<li>Keep the merge key out of the AI step",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if strings.Contains(render(t, loadAcme(t), "html"), "ai-self-merge") {
		t.Error("HTML self-merge section without a review bypass")
	}
}

// TestBotMergeRowPossible: an unmatched App reads possible in the section,
// with the App line saying why.
func TestBotMergeRowPossible(t *testing.T) {
	g := loadGraph(t, "../../testdata/botmerge/graph.json")
	for i, n := range g.Nodes {
		if n.ID != "repo:acme-app/web" {
			continue
		}
		g.Nodes[i].Attrs[graph.AttrReviewBypassAppMatch] = graph.AppUnmatched
		g.Nodes[i].Attrs[graph.AttrBotMergeApps] = "88"
		if g.Nodes[i].AttrEvidence == nil {
			g.Nodes[i].AttrEvidence = map[string]graph.Evidence{}
		}
		g.Nodes[i].AttrEvidence[graph.AttrReviewBypass] = graph.NotVisible
	}
	rows := botMergeRows(graph.NewIndex(g))
	if len(rows) != 1 || !rows[0].Possible || !strings.Contains(rows[0].App, "88, not one of the bypass Apps gop read") ||
		!strings.Contains(rows[0].Note, "may get code onto") {
		t.Errorf("rows = %+v", rows)
	}
	out := render(t, g, "html")
	if !strings.Contains(out, `<span class="badge nv"><span aria-hidden="true">?</span> possible: a deciding fact is not visible</span>`) {
		t.Error("HTML does not mark the possible review bypass")
	}
}

func TestTicks(t *testing.T) {
	for in, want := range map[string]string{
		"run `a<b` now": "run <code>a&lt;b</code> now",
		"odd ` tick":    "odd ` tick",
		"<i>":           "&lt;i&gt;",
	} {
		if got := string(ticks(in)); got != want {
			t.Errorf("ticks(%q) = %q, want %q", in, got, want)
		}
	}
}

func loadGraph(t *testing.T, path string) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
