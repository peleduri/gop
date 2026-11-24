package report

import (
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// writeMDBotMerge writes the "AI approve + self-merge" section: each repo
// where a pull request's author can get code onto the default branch with
// no human review, who can, through which workflows, and the fixes (see
// docs/agents-in-ci.md). Nothing when no repo has one.
func writeMDBotMerge(p func(string, ...any), d data) {
	repos := d.ix.BotMergeRepos()
	if len(repos) == 0 {
		return
	}
	p("## AI approve + self-merge\n\nA bot approves a pull request its author can steer, and a workflow the author can start merges it with a bot token the default branch's rules let through: anyone who can open a pull request lands code with no human review. gop treats it like push access.\n\n")
	for _, id := range repos {
		n, _ := d.ix.Node(id)
		p("### %s\n\n", md(strings.TrimPrefix(id, "repo:")))
		p("- %s\n", md(graph.BotMergeNote(n)))
		var conf, poss []string
		for _, e := range d.ix.In(id) {
			if e.Kind != graph.CanMergeViaBot {
				continue
			}
			if graph.Verified(e.Evidence) {
				conf = append(conf, e.From)
			} else {
				poss = append(poss, e.From)
			}
		}
		sort.Strings(conf)
		sort.Strings(poss)
		switch {
		case len(conf) > 0:
			p("- Who: %s\n", md(strings.Join(conf, ", ")))
		case len(poss) > 0:
			p("- Who: possible: %s\n", md(strings.Join(poss, ", ")))
		}
		if r := n.Attrs[graph.AttrReviewBypassReason]; r != "" {
			p("- Why no human review: %s\n", md(r))
		}
		if s := graph.BotMergeScript(n); s != "" {
			p("- Merge rules in a script: %s (read from the default branch, not run)\n", md("`"+s+"`"))
		}
		if graph.StaleApprovalsSuspected(n) {
			p("- Stale approvals (suspected, heuristic): the merge seems to count approvals not tied to the head commit; confirm by hand\n")
		}
		if n.Attrs[graph.AttrAgentHoldsMergeKey] == "true" {
			p("- The AI step holds the merge key: %s\n", md(strings.ReplaceAll(n.Attrs[graph.AttrAgentMergeKeyWorkflows], ",", ", ")))
		}
		for i, f := range graph.BotMergeFixes(n) {
			p("  %d. %s\n", i+1, md(f))
		}
		p("\n")
	}
}
