package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

func init() { demoCalls["fix_plan"] = map[string]any{"suggestion_rank": 1} }

// TestGoldenFixPlan goldens the fix_plan text content (summary plus the
// markdown checklist) through the in-memory MCP transport.
func TestGoldenFixPlan(t *testing.T) {
	lines, err := graph.LoadFile("../fixplan/testdata/lines.json")
	if err != nil {
		t.Fatal(err)
	}
	triggers, err := graph.LoadFile("../fixplan/testdata/triggers.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		golden string
		g      *graph.Graph
		args   map[string]any
	}{
		{"fix_plan_pin.md", lines, map[string]any{"fix": map[string]any{"type": "pin_ref", "action": "action:acme-actions/deploy@main"}}},
		{"fix_plan_rank1.md", loadAcme(t), map[string]any{"suggestion_rank": 1}},
		{"fix_plan_lower.md", lines, map[string]any{"fix": map[string]any{"type": "lower_default_perm", "org": "org:acme-actions", "to": "read"}}},
		{"fix_plan_restrict.md", loadAcme(t), map[string]any{"fix": map[string]any{"type": "restrict_token", "workflow": "workflow:acme-app/web/.github/workflows/ci.yml"}}},
		{"fix_plan_harden.md", triggers, map[string]any{"fix": map[string]any{"type": "harden_trigger", "workflow": "workflow:acme-app/docs/.github/workflows/preview.yml"}}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			res, err := connectGraph(t, tc.g).CallTool(context.Background(), &mcp.CallToolParams{Name: "fix_plan", Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("tool error: %s", text(res))
			}
			testutil.Golden(t, tc.golden, []byte(text(res)))
		})
	}
}

func TestFixPlanRankMatchesSuggestFixes(t *testing.T) {
	cs := connect(t)
	var sug SuggestFixesOutput
	call(t, cs, "suggest_fixes", map[string]any{}, &sug)
	if len(sug.Fixes) == 0 {
		t.Fatal("no suggestions")
	}
	for i, f := range sug.Fixes {
		var out FixPlanOutput
		res := call(t, cs, "fix_plan", map[string]any{"suggestion_rank": i + 1}, &out)
		if out.Plan.FixID != f.FixID || out.Plan.Fix != fixplan.FixSpec(f.Fix) {
			t.Errorf("rank %d: plan for %s, suggestion %s", i+1, out.Plan.FixID, f.FixID)
		}
		if first := strings.SplitN(text(res), "\n", 2)[0]; first != out.Summary {
			t.Errorf("text first line %q, summary %q", first, out.Summary)
		}
		if len(out.Plan.Steps) == 0 {
			t.Errorf("rank %d: no steps", i+1)
		}
	}
}

func TestFixPlanErrors(t *testing.T) {
	cs := connect(t)
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{}, "give fix"},
		{map[string]any{"suggestion_rank": 1, "fix": map[string]any{"type": "pin_ref", "action": "action:acme-actions/deploy@main"}}, "not both"},
		{map[string]any{"suggestion_rank": 99}, "suggest_fixes returns only"},
		{map[string]any{"suggestion_rank": -1}, "must be positive"},
		{map[string]any{"fix": map[string]any{"type": "pin_ref", "action": "action:acme-actions/deploy@mian"}}, "unknown fix.action"},
		{map[string]any{"fix": map[string]any{"type": "lower_default_perm", "org": "org:acme-actions", "to": "write"}}, "fix.to"},
		{map[string]any{"fix": map[string]any{"type": "restrict_token", "workflow": "action:acme-actions/deploy@main"}}, "fix.workflow: action:acme-actions/deploy@main is not a workflow"},
		{map[string]any{"fix": map[string]any{"type": "harden_trigger"}}, "fix.workflow is required"},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "fix_plan", Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(text(res), tc.want) {
			t.Errorf("%v: want error containing %q, got %q", tc.args, tc.want, text(res))
		}
	}
}
