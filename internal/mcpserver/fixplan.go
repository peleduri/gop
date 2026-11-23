package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
)

// FixPlanInput is the fix_plan tool input: exactly one of Fix and SuggestionRank.
type FixPlanInput struct {
	Fix            *FixSpec `json:"fix,omitempty" jsonschema:"the fix to plan, as in what_if: {type:pin_ref,action}, {type:lower_default_perm,org,to}, {type:restrict_token,workflow} or {type:harden_trigger,workflow}"`
	SuggestionRank int      `json:"suggestion_rank,omitempty" jsonschema:"1-based rank of a fix in the suggest_fixes output with the default budget; use instead of fix"`
}

// FixPlanOutput is a plan of concrete change steps and its headline.
type FixPlanOutput struct {
	Summary string       `json:"summary"`
	Plan    fixplan.Plan `json:"plan"`
}

// FixPlan turns one fix into change steps. It never runs them.
func (e *Engine) FixPlan(in FixPlanInput) (res FixPlanOutput, _ error) {
	defer e.mark(&res.Summary)
	var fx graph.Fix
	switch {
	case in.Fix != nil && in.SuggestionRank != 0:
		return FixPlanOutput{}, errors.New("give fix or suggestion_rank, not both")
	case in.Fix != nil:
		f, err := e.toFix(0, *in.Fix)
		if err != nil {
			return FixPlanOutput{}, errors.New(strings.Replace(err.Error(), "fixes[0].", "fix.", 1))
		}
		fx = f
	case in.SuggestionRank < 0:
		return FixPlanOutput{}, fmt.Errorf("suggestion_rank must be positive, got %d", in.SuggestionRank)
	case in.SuggestionRank > 0:
		// The greedy is prefix-stable: rank r is the same with any budget >= r.
		sug := e.ix.SuggestFixes(max(DefaultBudget, in.SuggestionRank))
		if in.SuggestionRank > len(sug) {
			return FixPlanOutput{}, fmt.Errorf("suggestion_rank %d: suggest_fixes returns only %s", in.SuggestionRank, plural(len(sug), "fix", "fixes"))
		}
		fx = sug[in.SuggestionRank-1].Fix
	default:
		return FixPlanOutput{}, errors.New("give fix (" + fixShapes + ") or suggestion_rank")
	}
	p := fixplan.Build(e.ix, fx)
	return FixPlanOutput{Summary: fixplan.Summary(p), Plan: p}, nil
}

// addFixPlanTool registers fix_plan. Its text content is the summary and the
// plan as a markdown checklist; the structured content is FixPlanOutput.
func addFixPlanTool(s *mcp.Server, e *Engine) {
	t := &mcp.Tool{
		Name: "fix_plan",
		Description: "Turn one fix into concrete change steps: for pin_ref, every workflow and nested action line " +
			"that uses the ref (repo, file, line and a one-line diff when the graph has line attributes); for " +
			"lower_default_perm, the org setting with its UI path and REST call, and the repos where members lose push; " +
			"for restrict_token, where to set permissions: contents: read in the workflow (top level or per job); for " +
			"harden_trigger, the job and line of each checkout of the pull request head or script injection, with the change. " +
			"Pass fix (same shape as what_if) or suggestion_rank (1-based, from suggest_fixes). gop never runs the " +
			"steps or calls write APIs: the REST call is text for whoever makes the change." + evidenceNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(bool)},
	}
	mcp.AddTool(s, t, func(_ context.Context, _ *mcp.CallToolRequest, in FixPlanInput) (*mcp.CallToolResult, FixPlanOutput, error) {
		out, err := e.FixPlan(in)
		if err != nil {
			return nil, FixPlanOutput{}, err
		}
		var md bytes.Buffer
		fixplan.WriteMarkdown(&md, out.Plan)
		text := firstLine(out.Summary) + "\n\n" + md.String()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})
}
