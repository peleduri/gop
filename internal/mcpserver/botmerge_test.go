package mcpserver

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestBotMergeTools: top_risks marks the principal that lands code through
// a bot approve + self-merge, explain gives the note and fixes, and what_if
// takes block_bot_merge.
func TestBotMergeTools(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(g)
	out, err := e.TopRisks(TopRisksInput{N: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range out.Risks {
		if r.Principal == "external:anyone" {
			found = r.BotSelfMerge == 1
		}
	}
	if !found {
		t.Errorf("external:anyone not marked: %+v", out.Risks)
	}
	br, err := e.BlastRadius(BlastRadiusInput{Principal: "external:anyone"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(br.Summary, "without human review [bot_self_merge]") {
		t.Errorf("blast_radius summary = %q", br.Summary)
	}

	ex, err := e.Explain(ExplainInput{From: "external:anyone", To: "repo:acme-app/web"})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"a PR author can get code onto `main` without human review: `ai-review.yml` + `ai-merge.yml`",
		"fix 2: Remove the GitHub App `77` from the bypass actors"} {
		if !strings.Contains(ex.Summary, w) {
			t.Errorf("explain lacks %q: %q", w, ex.Summary)
		}
	}

	wi, err := e.WhatIf(WhatIfInput{Fixes: []FixSpec{{Type: "block_bot_merge", Repo: "repo:acme-app/web"}}})
	if err != nil {
		t.Fatal(err)
	}
	if wi.Delta.After.ConfirmedPairs >= wi.Delta.Before.ConfirmedPairs {
		t.Errorf("what_if = %+v", wi.Delta)
	}
	if _, err := e.WhatIf(WhatIfInput{Fixes: []FixSpec{{Type: "block_bot_merge", Repo: "org:acme-app"}}}); err == nil {
		t.Error("block_bot_merge on an org: no error")
	}
}

// TestBotMergeScriptExplain: explain names the script, keeps the stale
// approvals suspected and lists the extra fixes.
func TestBotMergeScriptExplain(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge-script/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	ex, err := NewEngine(g).Explain(ExplainInput{From: "external:anyone", To: "repo:acme-app/web"})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"(merges in `tools/merge.py`)", "the approval may not cover the merged code (suspected, heuristic",
		"fix 5: Stop counting DISMISSED reviews in `tools/merge.py`", "the script re-counts approvals GitHub dismissed", "fix 7: Keep the merge key out of the AI step"} {
		if !strings.Contains(ex.Summary, w) {
			t.Errorf("explain lacks %q: %q", w, ex.Summary)
		}
	}
}
