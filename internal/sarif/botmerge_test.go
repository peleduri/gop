package sarif

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// TestBotSelfMergeRule: one GOP005 result per merge workflow line, at the
// merging step, with the fixes; the golden is the script fixture's log.
func TestBotSelfMergeRule(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge-script/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	l := build(t, g, Options{Version: testutil.TestVersion})
	data := encode(t, l)
	validate(t, loadSARIFSchema(t), data)
	testutil.Golden(t, "botmerge-script.sarif", data)
	rs := byRule(l, RuleBotSelfMerge)
	if len(rs) != 1 {
		t.Fatalf("want 1 GOP005 result, got %d", len(rs))
	}
	r := rs[0]
	loc := r.Locations[0].PhysicalLocation
	if r.Properties.Possible || r.Level != "error" || r.Properties.Severity != SeverityHigh ||
		loc == nil || loc.ArtifactLocation.URI != ".github/workflows/ai-merge.yml" || loc.Region == nil || loc.Region.StartLine != 24 ||
		r.Properties.Repository != "acme-app/web" || strings.Join(r.Properties.ConfirmedPrincipals, ",") != "external:anyone" ||
		r.Properties.Fix.Type != "block_bot_merge" || r.Properties.Evidence != graph.Live {
		t.Errorf("result %+v at %+v", r.Properties, loc)
	}
	if len(r.Properties.BotMergeFixes) != 7 || !strings.Contains(r.Properties.BotMergeFixes[4], "Stop counting DISMISSED reviews") {
		t.Errorf("fixes = %q", r.Properties.BotMergeFixes)
	}
	for _, w := range []string{".github/workflows/ai-merge.yml: a PR author can get code onto `main` without human review",
		"the script re-counts approvals GitHub dismissed", "external:anyone can use it", "Require a human approval that bots cannot give"} {
		if !strings.Contains(r.Message.Text, w) {
			t.Errorf("message lacks %q: %q", w, r.Message.Text)
		}
	}
	if Rules()[ruleIndex(RuleBotSelfMerge)].Name != "review-bypass-bot-self-merge" {
		t.Error("rule name")
	}
	for key, sub := range Split(l) {
		validate(t, loadSARIFSchema(t), encode(t, sub))
		_ = key
	}
}

// A review bypass that is possible only gives a possible GOP005 result,
// dropped unless --include-possible, and then at level note.
func TestBotSelfMergeRulePossible(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.Edges {
		if g.Edges[i].Kind == graph.CanMergeViaBot {
			g.Edges[i].Evidence = graph.NotVisible
		}
	}
	if rs := byRule(build(t, g, Options{}), RuleBotSelfMerge); len(rs) != 0 {
		t.Errorf("possible GOP005 kept without --include-possible: %+v", rs)
	}
	rs := byRule(build(t, g, Options{IncludePossible: true}), RuleBotSelfMerge)
	if len(rs) != 1 || !rs[0].Properties.Possible || rs[0].Level != "note" || rs[0].Properties.Evidence != graph.NotVisible ||
		strings.Join(rs[0].Properties.PossiblePrincipals, ",") != "external:anyone" || !strings.Contains(rs[0].Message.Text, "(possible)") {
		t.Errorf("possible result = %+v", rs)
	}
}

// No review bypass: no GOP005 result.
func TestBotSelfMergeRuleAbsent(t *testing.T) {
	if rs := byRule(build(t, load(t), Options{IncludePossible: true}), RuleBotSelfMerge); len(rs) != 0 {
		t.Errorf("GOP005 on acme: %+v", rs)
	}
}
