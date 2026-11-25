package whatif

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sanitize"
)

// ReadOnlyNote is printed with every rendered report.
const ReadOnlyNote = "Hypothetical: gop changed nothing. gop fix-plan prints the steps of one fix."

// WriteJSON prints the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func chain(ids []string, esc func(string) string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = esc(id)
	}
	return strings.Join(out, " -> ")
}

func pathChain(p *graph.Path) []string {
	if p == nil {
		return nil
	}
	return hops(*p)
}

func totalsRows(r Report) [][3]string {
	b, a := r.Before, r.After
	f := func(x float64) string { return fmt.Sprintf("%.1f", x) }
	d := func(x int) string { return fmt.Sprint(x) }
	return [][3]string{
		{"confirmed (principal, repo) pairs", d(b.ConfirmedPairs), d(a.ConfirmedPairs)},
		{"possible (principal, repo) pairs", d(b.PossiblePairs), d(a.PossiblePairs)},
		{"confirmed score", f(b.Score), f(a.Score)},
		{"possible score", f(b.PossibleScore), f(a.PossibleScore)},
	}
}

func shown(r Report) string {
	if len(r.Removed) < r.RemovedTotal {
		return fmt.Sprintf("%d, showing %d", r.RemovedTotal, len(r.Removed))
	}
	return fmt.Sprint(r.RemovedTotal)
}

// WriteText prints the report as plain text. Every name is escaped
// (sanitize.Clean), so no value can start a new line or hide text.
func WriteText(w io.Writer, r Report) {
	c := sanitize.Clean
	fmt.Fprintln(w, sanitize.Line(r.Summary))
	fmt.Fprintln(w, ReadOnlyNote)
	fmt.Fprintf(w, "\nFixes applied (%d):\n", len(r.Fixes))
	for _, f := range r.Fixes {
		fmt.Fprintf(w, "  - %s\n      %s\n", c(f.FixID), c(f.Description))
	}
	fmt.Fprintf(w, "\n%-36s %10s %10s\n", "Totals", "before", "after")
	for _, row := range totalsRows(r) {
		fmt.Fprintf(w, "  %-34s %10s %10s\n", row[0], row[1], row[2])
	}
	fmt.Fprintf(w, "\nPaths that disappear (%s):\n", shown(r))
	if r.RemovedTotal == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, p := range r.Removed {
		fmt.Fprintf(w, "  %s -> %s  [%s -> %s]\n", c(p.Principal), c(p.Target), p.Before, p.After)
		fmt.Fprintf(w, "      was: %s\n", chain(p.Hops, c))
	}
	fmt.Fprintf(w, "\nRemaining top paths (%d):\n", len(r.Remaining))
	if len(r.Remaining) == 0 {
		fmt.Fprintln(w, "  none: no principal has reach left")
	}
	for i, m := range r.Remaining {
		fmt.Fprintf(w, "  %d. %s  score %.1f -> %.1f, confirmed repos %d -> %d, possible repos %d -> %d\n",
			i+1, c(m.Principal), m.Before.Score, m.After.Score, m.Before.Confirmed.Repos, m.After.Confirmed.Repos,
			m.Before.Possible.Repos, m.After.Possible.Repos)
		if m.Path != nil {
			fmt.Fprintf(w, "      %s\n", chain(pathChain(m.Path), c))
		}
	}
	if len(r.Caveats) > 0 {
		fmt.Fprintf(w, "\nCaveats (%d):\n", len(r.Caveats))
		for _, cv := range r.Caveats {
			fmt.Fprintf(w, "  - %s\n", c(cv))
		}
	}
}

// mdCell escapes the characters that end a table cell or open HTML. GitHub
// names never contain them, so only a hostile name shows the escapes.
var mdCell = strings.NewReplacer("|", `\|`, "&", "&amp;", "<", "&lt;", ">", "&gt;")

// WriteMarkdown prints the report as Markdown to paste into a ticket. Names
// sit in code spans with backticks escaped (sanitize.Code); prose has link
// and autolink syntax escaped too (sanitize.NoLinks), and neither can end a
// table cell or open HTML (mdCell).
func WriteMarkdown(w io.Writer, r Report) {
	prose := func(s string) string { return mdCell.Replace(sanitize.NoLinks(sanitize.Clean(s))) }
	code := func(s string) string { return "`" + mdCell.Replace(sanitize.Code(s)) + "`" }
	fmt.Fprintf(w, "## What if\n\n%s\n\n> %s\n\n", sanitize.NoLinks(sanitize.Line(r.Summary)), ReadOnlyNote)
	fmt.Fprintf(w, "### Fixes applied\n\n")
	for _, f := range r.Fixes {
		fmt.Fprintf(w, "- %s: %s\n", code(f.FixID), prose(f.Description))
	}
	fmt.Fprintf(w, "\n### Totals\n\n| | Before | After |\n|---|---:|---:|\n")
	for _, row := range totalsRows(r) {
		fmt.Fprintf(w, "| %s | %s | %s |\n", row[0], row[1], row[2])
	}
	fmt.Fprintf(w, "\n### Paths that disappear (%s)\n\n", shown(r))
	if r.RemovedTotal == 0 {
		fmt.Fprintln(w, "None.")
	} else {
		fmt.Fprintf(w, "| Principal | Target | Change | Path before |\n|---|---|---|---|\n")
		for _, p := range r.Removed {
			fmt.Fprintf(w, "| %s | %s | %s -> %s | %s |\n", code(p.Principal), code(p.Target), p.Before, p.After, chain(p.Hops, code))
		}
	}
	fmt.Fprintf(w, "\n### Remaining top paths\n\n")
	if len(r.Remaining) == 0 {
		fmt.Fprintln(w, "None: no principal has reach left.")
	} else {
		fmt.Fprintf(w, "| # | Principal | Score | Confirmed repos | Possible repos | Remaining path |\n|---:|---|---:|---:|---:|---|\n")
		for i, m := range r.Remaining {
			path := "none confirmed"
			if m.Path != nil {
				path = chain(pathChain(m.Path), code)
			}
			fmt.Fprintf(w, "| %d | %s | %.1f -> %.1f | %d -> %d | %d -> %d | %s |\n", i+1, code(m.Principal),
				m.Before.Score, m.After.Score, m.Before.Confirmed.Repos, m.After.Confirmed.Repos,
				m.Before.Possible.Repos, m.After.Possible.Repos, path)
		}
	}
	if len(r.Caveats) > 0 {
		fmt.Fprintf(w, "\n### Caveats\n\n")
		for _, cv := range r.Caveats {
			fmt.Fprintf(w, "- %s\n", prose(cv))
		}
	}
}
