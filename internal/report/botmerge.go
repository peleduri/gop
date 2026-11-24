package report

import (
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// botMergeRow is one repo of the "AI approve + self-merge" section, shared
// by the Markdown and HTML reports. Every field is plain text; each writer
// escapes it.
type botMergeRow struct {
	Repo string // "acme-app/web"
	Note string // graph.BotMergeNote
	// Possible is set when the review bypass is possible only (a deciding
	// fact is not visible); Who lists the principals who can use it, and
	// WhoPossible is set when every one of them is possible.
	Possible    bool
	Who         string
	WhoPossible bool
	Reason      string // review_bypass_reason
	Script      string // the repo script the merge runs, "" when in the workflow
	// App says which App the merge mints for and whether it is the bypass
	// App (app_bypass only); Approve is the "Allow GitHub Actions to create
	// and approve pull requests" setting, when read.
	App     string
	Approve string
	// Stale is the stale-approval line (suspected, heuristic), "" when the
	// heuristic did not match; KeyHolders the workflows whose AI step holds
	// the merge key.
	Stale      string
	KeyHolders string
	// Policy lists the agent and review policy files no CODEOWNERS rule
	// protects; PolicyUnknown is set when ownership could not be read.
	Policy        string
	PolicyUnknown bool
	Fixes         []string
}

// botMergeRows builds the section's rows, one per repo with a review bypass.
func botMergeRows(ix *graph.Index) []botMergeRow {
	var out []botMergeRow
	for _, id := range ix.BotMergeRepos() {
		n, _ := ix.Node(id)
		r := botMergeRow{
			Repo:     strings.TrimPrefix(id, "repo:"),
			Note:     graph.BotMergeNote(n),
			Possible: !graph.ReviewBypassConfirmed(n),
			Reason:   n.Attrs[graph.AttrReviewBypassReason],
			Script:   graph.BotMergeScript(n),
			Fixes:    graph.BotMergeFixes(n),
		}
		var conf, poss []string
		for _, e := range ix.In(id) {
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
			r.Who = strings.Join(conf, ", ")
		case len(poss) > 0:
			r.Who, r.WhoPossible = strings.Join(poss, ", "), true
		}
		if r.Reason == graph.ReviewBypassApp {
			r.App = botMergeAppLine(n)
		}
		switch n.Attrs[graph.AttrActionsCanApprove] {
		case "true":
			r.Approve = "on: GITHUB_TOKEN can approve pull requests"
		case "false":
			r.Approve = "off: GITHUB_TOKEN approvals are refused"
		case "unknown":
			r.Approve = "not visible"
		}
		switch {
		case graph.RecountsDismissed(n):
			r.Stale = "the script re-counts approvals GitHub dismissed: the rules dismiss stale reviews on push, and the merge counts DISMISSED reviews; confirm by hand"
		case graph.StaleApprovalsSuspected(n):
			r.Stale = "the merge seems to count approvals not tied to the head commit; confirm by hand"
		}
		if n.Attrs[graph.AttrAgentHoldsMergeKey] == "true" {
			r.KeyHolders = strings.ReplaceAll(n.Attrs[graph.AttrAgentMergeKeyWorkflows], ",", ", ")
		}
		r.Policy = strings.Join(graph.SelfEditablePolicy(n), ", ")
		r.PolicyUnknown = graph.PolicyUnknown(n)
		out = append(out, r)
	}
	return out
}

// botMergeAppLine says which App an app_bypass merge mints for and whether
// it matched a bypass App.
func botMergeAppLine(n graph.Node) string {
	app := strings.ReplaceAll(graph.BotMergeApp(n), "`", "")
	if app == "" {
		app = "not named in the workflow"
	}
	switch n.Attrs[graph.AttrReviewBypassAppMatch] {
	case graph.AppMatched:
		return app + ", a bypass actor of the default branch rules"
	case graph.AppUnmatched:
		return app + ", not one of the bypass Apps gop read (possible: it may get past the rules some other way)"
	}
	return app + " (possible: gop could not match it to the bypass Apps)"
}

// writeMDBotMerge writes the "AI approve + self-merge" section: each repo
// where a pull request's author can get code onto the default branch with
// no human review, who can, through which workflows, and the fixes (see
// docs/agents-in-ci.md). Nothing when no repo has one.
func writeMDBotMerge(p func(string, ...any), d data) {
	rows := botMergeRows(d.ix)
	if len(rows) == 0 {
		return
	}
	p("## AI approve + self-merge\n\nA bot approves a pull request its author can steer, and a workflow the author can start merges it with a bot token the default branch's rules let through: anyone who can open a pull request lands code with no human review. gop treats it like push access.\n\n")
	for _, r := range rows {
		p("### %s\n\n", md(r.Repo))
		p("- %s\n", md(r.Note))
		switch {
		case r.Who != "" && r.WhoPossible:
			p("- Who: possible: %s\n", md(r.Who))
		case r.Who != "":
			p("- Who: %s\n", md(r.Who))
		}
		if r.Reason != "" {
			p("- Why no human review: %s\n", md(r.Reason))
		}
		if r.App != "" {
			p("- Merging App: %s\n", md(r.App))
		}
		if r.Approve != "" {
			p("- Allow GitHub Actions to create and approve pull requests: %s\n", md(r.Approve))
		}
		if r.Script != "" {
			p("- Merge rules in a script: %s (read from the default branch, not run)\n", md("`"+r.Script+"`"))
		}
		if r.Stale != "" {
			p("- Stale approvals (suspected, heuristic): %s\n", md(r.Stale))
		}
		if r.KeyHolders != "" {
			p("- The AI step holds the merge key: %s\n", md(r.KeyHolders))
		}
		switch {
		case r.Policy != "":
			p("- Policy files a pull request can edit without a code owner: %s\n", md(r.Policy))
		case r.PolicyUnknown:
			p("- Policy files: CODEOWNERS not visible, ownership unknown\n")
		}
		for i, f := range r.Fixes {
			p("  %d. %s\n", i+1, md(f))
		}
		p("\n")
	}
}

// botMergeLine is the HTML section's lede.
func botMergeLine(rows []botMergeRow) string {
	conf := 0
	for _, r := range rows {
		if !r.Possible {
			conf++
		}
	}
	s := plural(len(rows), "repo", "repos") + " where a bot approves and merges a pull request its author can steer"
	if poss := len(rows) - conf; poss > 0 {
		s += fmt.Sprintf(" (%d confirmed, %d possible)", conf, poss)
	}
	return s + ": anyone who can open a pull request there lands code on the default branch with no human review, and gop treats it like push access."
}

// ticks renders text with `code` spans (the Markdown-style backticks of
// graph notes and fixes) as HTML: every segment is escaped, and the ones
// between backticks are wrapped in <code>. An unpaired backtick stays text.
func ticks(s string) template.HTML {
	parts := strings.Split(s, "`")
	if len(parts)%2 == 0 {
		return template.HTML(template.HTMLEscapeString(s))
	}
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			b.WriteString("<code>" + template.HTMLEscapeString(p) + "</code>")
			continue
		}
		b.WriteString(template.HTMLEscapeString(p))
	}
	return template.HTML(b.String())
}
