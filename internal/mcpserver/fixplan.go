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
	"github.com/peleduri/gop/internal/sanitize"
)

// FixPlanInput is the fix_plan tool input: exactly one of Fix and SuggestionRank.
type FixPlanInput struct {
	Fix            *FixSpec `json:"fix,omitempty" jsonschema:"the fix to plan, as in what_if: {type:pin_ref,action}, {type:lower_default_perm,org,to}, {type:restrict_token,workflow} or {type:harden_trigger,workflow}"`
	SuggestionRank int      `json:"suggestion_rank,omitempty" jsonschema:"1-based rank of a fix in the suggest_fixes output with the default budget; use instead of fix"`
	DetailInput
}

// FixPlanOutput is a plan of concrete change steps and its headline.
type FixPlanOutput struct {
	Summary string       `json:"summary"`
	Plan    fixplan.Plan `json:"plan"`
	Brief   *Brief       `json:"brief,omitempty"`
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
	q := p
	q.Description = quotedDescription(p.Fix)
	return FixPlanOutput{Summary: fixplan.Summary(q), Plan: p}, nil
}

// quotedDescription is fixplan.Spec's sentence for a fix with the name in
// backticks (sanitize.Value), for text summaries.
func quotedDescription(f FixSpec) string {
	switch f.Type {
	case "pin_ref":
		return "Pin " + sanitize.Value(strings.TrimPrefix(f.Action, "action:")) + " to a commit SHA in every workflow that uses it"
	case "lower_default_perm":
		return "Lower the default repository permission of " + sanitize.Value(strings.TrimPrefix(f.Org, "org:")) + " to " + sanitize.Value(f.To)
	case "restrict_token":
		return "Set permissions: contents: read on the GITHUB_TOKEN of " + sanitize.Value(strings.TrimPrefix(f.Workflow, "workflow:"))
	case "harden_trigger":
		return "Stop " + sanitize.Value(strings.TrimPrefix(f.Workflow, "workflow:")) + " from running attacker-controlled code on its risky triggers"
	}
	return "fix " + sanitize.Value(f.Type)
}

// cleanPlan is a copy of p for the markdown text: every string that can hold
// a GitHub name is escaped, so no value can start a new line or hide text
// (sanitize.Clean). Fields the markdown puts inside a code span or fence
// (file, edge, API, diff lines) also get backticks escaped (sanitize.Code),
// so a value cannot end the span. A diff keeps its own line breaks; each of
// its lines is escaped. The structured output keeps the raw plan.
func cleanPlan(p fixplan.Plan) fixplan.Plan {
	c, code := sanitize.Clean, sanitize.Code
	p.Description = c(p.Description)
	p.Caveats = append([]string{}, p.Caveats...)
	for i := range p.Caveats {
		p.Caveats[i] = c(p.Caveats[i])
	}
	p.Steps = append([]fixplan.Step{}, p.Steps...)
	for i := range p.Steps {
		s := &p.Steps[i]
		for _, f := range []*string{&s.Repo, &s.FileRef, &s.Change, &s.Setting, &s.Owner, &s.Note} {
			*f = c(*f)
		}
		for _, f := range []*string{&s.File, &s.API, &s.Edge} {
			*f = code(*f)
		}
		if s.Diff != "" {
			lines := strings.Split(strings.TrimSuffix(s.Diff, "\n"), "\n")
			for j := range lines {
				lines[j] = code(lines[j])
			}
			s.Diff = strings.Join(lines, "\n") + "\n"
		}
	}
	return p
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
			"steps or calls write APIs: the REST call is text for whoever makes the change." + detailNote + evidenceNote + DataNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(bool)},
	}
	mcp.AddTool(s, t, func(_ context.Context, _ *mcp.CallToolRequest, in FixPlanInput) (*mcp.CallToolResult, FixPlanOutput, error) {
		out, err := withDetail(e.FixPlan, briefPlan)(in)
		if err != nil {
			return nil, FixPlanOutput{}, err
		}
		var md bytes.Buffer
		fixplan.WriteMarkdown(&md, cleanPlan(out.Plan))
		text := textContent(out.Summary, md.String())
		if b := out.Brief; b != nil && b.Total["steps"] > len(out.Plan.Steps) {
			text += fmt.Sprintf("\n(brief: %d of %s shown; pass detail full for the rest)\n",
				len(out.Plan.Steps), plural(b.Total["steps"], "step", "steps"))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})
}
