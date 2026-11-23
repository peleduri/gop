package fixplan

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// ReadOnlyNote is printed with every rendered plan.
const ReadOnlyNote = "gop never runs these steps or calls write APIs: make each change with your own access."

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func pct(before, after int) float64 {
	if before == 0 {
		return 0
	}
	return 100 * float64(before-after) / float64(before)
}

// Summary is the one-line headline of a plan, confirmed numbers first.
func Summary(p Plan) string {
	var edits, settings, unconfirmed int
	repos := map[string]bool{}
	for _, s := range p.Steps {
		switch s.Kind {
		case KindEditWorkflow:
			edits++
			repos[s.Repo] = true
		case KindChangeSetting:
			settings++
		}
		if s.Unconfirmed {
			unconfirmed++
		}
	}
	var parts []string
	if edits > 0 {
		parts = append(parts, plural(edits, "line to edit", "lines to edit")+" across "+plural(len(repos), "repo", "repos"))
	}
	if settings > 0 {
		parts = append(parts, plural(settings, "setting to change", "settings to change"))
	}
	if len(parts) == 0 {
		parts = append(parts, "no change steps")
	}
	b, a := p.Removes.Before.ConfirmedPairs, p.Removes.After.ConfirmedPairs
	out := fmt.Sprintf("%s: %s; removes %d of %d confirmed (principal, repo) pairs (%.0f%%)",
		p.Description, strings.Join(parts, ", "), b-a, b, pct(b, a))
	if bt, at := p.Removes.Before, p.Removes.After; b == a && at.Score < bt.Score {
		// No (principal, repo) pair goes away, but reach inside the repos
		// does (a RestrictToken leaves the repo as CI reach): say so.
		out += fmt.Sprintf("; confirmed workflows %d -> %d, score %.1f -> %.1f", bt.Confirmed.Workflows, at.Confirmed.Workflows, bt.Score, at.Score)
	}
	if unconfirmed > 0 {
		out += fmt.Sprintf("; %s not visible, listed last", plural(unconfirmed, "step is", "steps are"))
	}
	return out
}

func evidenceLabel(ev graph.Evidence) string {
	switch ev {
	case graph.Live, graph.Audit:
		return string(ev)
	case "":
		return ""
	}
	return "not visible"
}

// title is the step's one-line heading, without numbering or checkbox.
func title(s Step, code func(string) string) string {
	switch s.Kind {
	case KindEditWorkflow:
		loc := s.File
		if loc == "" {
			loc = "(file not recorded)"
		}
		out := "Edit " + s.Repo + " " + code(loc)
		if s.Line > 0 {
			out += fmt.Sprintf(" line %d", s.Line)
		}
		if s.FileRef != "" {
			out += " (read at " + s.FileRef + ")"
		}
		return out
	case KindChangeSetting:
		return "Change setting in org " + s.Owner + ": " + s.Setting
	}
	if s.Repo != "" {
		return "Verify " + s.Repo
	}
	return "Verify"
}

func meta(s Step, code func(string) string) []string {
	var out []string
	if s.API != "" {
		out = append(out, "API (text only): "+code(s.API))
	}
	if s.Owner != "" && s.Kind != KindChangeSetting {
		out = append(out, "owner: "+s.Owner)
	}
	if s.Edge != "" {
		e := "evidence: " + code(s.Edge)
		if l := evidenceLabel(s.Evidence); l != "" {
			e += " (" + l + ")"
		}
		out = append(out, e)
	} else if l := evidenceLabel(s.Evidence); l != "" {
		out = append(out, "evidence: "+l)
	}
	if s.Change != "" {
		out = append(out, "change: "+s.Change)
	}
	if s.Note != "" {
		out = append(out, "note: "+s.Note)
	}
	return out
}

func delta(p Plan) string {
	b, a := p.Removes.Before, p.Removes.After
	return fmt.Sprintf("Confirmed (principal, repo) pairs: %d -> %d (%.0f%% removed); possible pairs: %d -> %d.",
		b.ConfirmedPairs, a.ConfirmedPairs, pct(b.ConfirmedPairs, a.ConfirmedPairs), b.PossiblePairs, a.PossiblePairs)
}

// WriteText prints a plan as numbered plain-text steps.
func WriteText(w io.Writer, p Plan) {
	plain := func(s string) string { return s }
	fmt.Fprintln(w, Summary(p))
	fmt.Fprintln(w, delta(p))
	fmt.Fprintln(w, ReadOnlyNote)
	if len(p.Steps) > 0 {
		fmt.Fprintf(w, "\nSteps (%d):\n", len(p.Steps))
	}
	for i, s := range p.Steps {
		fmt.Fprintf(w, "%3d. [%s] %s\n", i+1, s.Kind, title(s, plain))
		for _, m := range meta(s, plain) {
			fmt.Fprintf(w, "       %s\n", m)
		}
		if s.Diff != "" {
			for _, l := range strings.Split(strings.TrimSuffix(s.Diff, "\n"), "\n") {
				fmt.Fprintf(w, "       | %s\n", l)
			}
		}
	}
	if len(p.Caveats) > 0 {
		fmt.Fprintf(w, "\nCaveats (%d):\n", len(p.Caveats))
		for _, c := range p.Caveats {
			fmt.Fprintf(w, "  - %s\n", c)
		}
	}
}

// WriteMarkdown prints a plan as a checklist to paste into a ticket.
func WriteMarkdown(w io.Writer, p Plan) {
	code := func(s string) string { return "`" + s + "`" }
	fmt.Fprintf(w, "## Fix plan: %s\n\n", p.Description)
	fmt.Fprintf(w, "%s\n\n", delta(p))
	fmt.Fprintf(w, "> %s\n", ReadOnlyNote)
	if len(p.Steps) > 0 {
		fmt.Fprintf(w, "\n### Steps\n\n")
	}
	for _, s := range p.Steps {
		fmt.Fprintf(w, "- [ ] %s\n", title(s, code))
		for _, m := range meta(s, code) {
			fmt.Fprintf(w, "  - %s\n", m)
		}
		if s.Diff != "" {
			fmt.Fprintf(w, "\n  ```diff\n")
			for _, l := range strings.Split(strings.TrimSuffix(s.Diff, "\n"), "\n") {
				fmt.Fprintf(w, "  %s\n", l)
			}
			fmt.Fprintf(w, "  ```\n\n")
		}
	}
	if len(p.Caveats) > 0 {
		fmt.Fprintf(w, "\n### Caveats\n\n")
		for _, c := range p.Caveats {
			fmt.Fprintf(w, "- %s\n", c)
		}
	}
}

// WriteJSON prints a plan as indented JSON with its summary.
func WriteJSON(w io.Writer, p Plan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(struct {
		Summary string `json:"summary"`
		Plan    Plan   `json:"plan"`
	}{Summary(p), p})
}
