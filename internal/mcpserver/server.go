package mcpserver

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/graph"
)

// evidenceNote is appended to every tool description.
const evidenceNote = " Confirmed means every hop was read live from the API or from the audit log, or (a cloud hop) " +
	"from a trust file the user supplied, which the answer then names. " +
	"Possible means at least one hop is not_visible: the token could not read that fact, so the path " +
	"may exist but is unproven (unknown, not absent). Headline numbers count confirmed reach only."

// NewServerWith builds an MCP server over g. The graph is indexed once and only read.
func NewServerWith(g *graph.Graph, version string, opts ServerOptions) *mcp.Server {
	e := NewEngine(g)
	s := mcp.NewServer(&mcp.Implementation{Name: "gop", Title: "gop: who can make code run where", Version: version}, nil)

	addTool(s, "who_can_reach",
		"List the principals (org members, users, teams, apps) that can make code run in a target "+
			"repo, workflow, action, secret scope, OIDC trust, runner pool or cloud role (cloud:...), with one shortest path each. "+
			"Every hop shows its evidence (live, audit, supplied, not_visible) and API source.",
		e.WhoCanReach, func(o WhoCanReachOutput) string { return o.Summary })
	addTool(s, "blast_radius",
		"Score everything one principal can make code run in: repos, orgs, workflows, secrets, OIDC trusts, "+
			"self-hosted runners and cloud roles from supplied trust files, with confirmed and possible counts kept separate.",
		e.BlastRadius, func(o BlastRadiusOutput) string { return o.Summary })
	addTool(s, "paths",
		"Show the concrete control paths from a principal, optionally only to one target. "+
			"Each hop carries its edge kind, evidence level and API source.",
		e.Paths, func(o PathsOutput) string { return o.Summary })
	addTool(s, "top_risks",
		"Rank principals by confirmed blast radius score (ties broken by possible score) and return the top n.",
		e.TopRisks, func(o TopRisksOutput) string { return o.Summary })
	addTool(s, "what_if",
		"Apply hypothetical fixes and compare reach before and after. Fix types: "+
			`{type:"pin_ref",action:"action:O/R@ref"} pins an action to a commit SHA; `+
			`{type:"lower_default_perm",org:"org:X",to:"read"|"none"} lowers an org's default repository permission. `+
			"Reports confirmed and possible (principal, repo) pairs separately.",
		e.WhatIf, func(o WhatIfOutput) string { return o.Summary })
	addTool(s, "suggest_fixes",
		"Suggest up to budget fixes by a greedy pick of the fix that removes the most confirmed "+
			"(principal, repo) pairs, with the cumulative percentage removed. Fixes that touch only "+
			"not_visible edges are never suggested.",
		e.SuggestFixes, func(o SuggestFixesOutput) string { return o.Summary })
	addTool(s, "explain",
		"Explain why an edge exists: its evidence level, source_api, observed_at and attributes. "+
			"Pass a hop's from and to (reversed hops are matched too) and optionally its kind.",
		e.Explain, func(o ExplainOutput) string { return o.Summary })
	addTool(s, "coverage",
		"List what the token could not see (not_visible facts) and the access that would make each visible.",
		e.Coverage, func(o CoverageOutput) string { return o.Summary })
	addTool(s, "diff", diffDescription, newDiffer(g, opts.Baseline).Diff, func(o DiffOutput) string { return o.Summary })
	addFixPlanTool(s, e)
	addResources(s, e, opts.clock())
	addPrompts(s, e, opts.clock())
	return s
}

func addTool[In, Out any](s *mcp.Server, name, desc string, fn func(In) (Out, error), summary func(Out) string) {
	t := &mcp.Tool{
		Name:        name,
		Description: desc + evidenceNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(bool)},
	}
	mcp.AddTool(s, t, func(_ context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		out, err := fn(in)
		if err != nil {
			var zero Out
			return nil, zero, err
		}
		body, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			var zero Out
			return nil, zero, err
		}
		text := firstLine(summary(out)) + "\n\n" + string(body)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})
}

// Serve runs the MCP server over stdio until the client disconnects or ctx ends.
func Serve(ctx context.Context, g *graph.Graph, version string) error {
	return NewServer(g, version).Run(ctx, &mcp.StdioTransport{})
}
