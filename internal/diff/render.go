package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Sections that Only can keep.
const (
	SectionPaths    = "paths"
	SectionSettings = "settings"
	SectionEdges    = "edges"
	SectionScores   = "scores"
	SectionCoverage = "coverage"
)

// Sections lists every section name accepted by Only.
var Sections = []string{SectionPaths, SectionSettings, SectionEdges, SectionScores, SectionCoverage}

// Only returns a copy of the report with every section not named in keep
// emptied. Meta and Totals are always kept. An empty keep keeps everything.
func (r Report) Only(keep []string) Report {
	if len(keep) == 0 {
		return r
	}
	k := map[string]bool{}
	for _, s := range keep {
		k[s] = true
	}
	if !k[SectionPaths] {
		r.Paths = PathChanges{}
	}
	if !k[SectionSettings] {
		r.Settings = []SettingChange{}
	}
	if !k[SectionEdges] {
		r.Edges = EdgeChanges{Added: []EdgeChange{}, Removed: []EdgeChange{}, Changed: []EdgeChange{}, LostVisibility: []EdgeChange{}}
	}
	if !k[SectionScores] {
		r.Scores = []ScoreDelta{}
	}
	if !k[SectionCoverage] {
		r.Coverage = CoverageChanges{Opened: []graph.Coverage{}, Closed: []graph.Coverage{}}
	}
	return r
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func short(id string) string {
	if _, rest, ok := strings.Cut(id, ":"); ok {
		return rest
	}
	return id
}

func evLabel(ev graph.Evidence) string {
	switch ev {
	case graph.Live:
		return "live"
	case graph.Audit:
		return "audit"
	case graph.Supplied:
		return "supplied file"
	case "":
		return "absent"
	}
	return "not visible"
}

// value renders a setting value; an unknown one is "not visible", never "off".
func value(v string, ev graph.Evidence, known bool) string {
	if known {
		return v
	}
	if v == "" && ev == "" {
		return "absent"
	}
	return "not visible"
}

func (c SettingChange) oldKnown() bool {
	return c.Status == Changed || c.Status == LostVisibility || c.Status == NodeRemoved
}

func (c SettingChange) newKnown() bool {
	return c.Status == Changed || c.Status == GainedVisibility || c.Status == NodeAdded
}

// Phrase describes the change in one line, e.g. "acme-actions default_perm
// read → write"; an unseen value reads "not visible", never off.
func (c SettingChange) Phrase() string { return c.phrase() }

func (c SettingChange) phrase() string {
	o := value(c.Old, c.OldEvidence, c.oldKnown())
	n := value(c.New, c.NewEvidence, c.newKnown())
	switch c.Status {
	case LostVisibility:
		return fmt.Sprintf("%s %s %s → not visible (lost visibility)", short(c.Node), c.Key, o)
	case GainedVisibility:
		return fmt.Sprintf("%s %s now visible: %s", short(c.Node), c.Key, n)
	case NodeAdded:
		return fmt.Sprintf("%s %s %s (new)", short(c.Node), c.Key, n)
	case NodeRemoved:
		return fmt.Sprintf("%s %s %s (node removed)", short(c.Node), c.Key, o)
	}
	return fmt.Sprintf("%s %s %s → %s", short(c.Node), c.Key, o, n)
}

// Headline is the one-sentence summary the text output leads with, e.g.
// "Since 2026-11-13: 2 new confirmed paths (1 to OIDC), 1 removed; acme-actions default_perm read → write."
func (r Report) Headline() string {
	since := "the old snapshot"
	if !r.Old.CollectedAt.IsZero() {
		since = r.Old.CollectedAt.UTC().Format("2006-01-02")
	}
	var parts []string
	if len(r.Paths) > 0 {
		newConf, oidc := 0, 0
		for _, c := range r.Paths {
			if (c.Status == Added && c.New != nil && !c.New.Unverified) || c.Status == Upgraded {
				newConf++
				if c.TargetKind == graph.KindOIDC {
					oidc++
				}
			}
		}
		p := plural(newConf, "new confirmed path", "new confirmed paths")
		if oidc > 0 {
			p += fmt.Sprintf(" (%d to OIDC)", oidc)
		}
		parts = append(parts, p)
		if n := r.Paths.Count(Removed, false); n > 0 {
			parts = append(parts, fmt.Sprintf("%d removed", n))
		}
		if n := r.Paths.Count(Added, false); n > 0 {
			parts = append(parts, plural(n, "new possible path", "new possible paths"))
		}
		if n := r.Paths.Count(Downgraded, false); n > 0 {
			parts = append(parts, fmt.Sprintf("%d downgraded to possible", n))
		}
		if n := r.Paths.Count(LostVisibility, false); n > 0 {
			parts = append(parts, fmt.Sprintf("%d lost visibility", n))
		}
		if n := r.Paths.Count(GainedVisibility, false); n > 0 {
			parts = append(parts, fmt.Sprintf("%d newly visible", n))
		}
	}
	head := strings.Join(parts, ", ")
	var settings []string
	for _, c := range r.Settings {
		if c.Status == NodeAdded || c.Status == NodeRemoved {
			continue
		}
		settings = append(settings, c.phrase())
	}
	if len(settings) > 3 {
		settings = append(settings[:3], fmt.Sprintf("%d more setting changes", len(settings)-3))
	}
	if s := strings.Join(settings, "; "); s != "" {
		if head == "" {
			head = s
		} else {
			head += "; " + s
		}
	}
	if head == "" {
		if r.Empty() {
			return fmt.Sprintf("Since %s: no posture changes.", since)
		}
		head = "no path or setting changes"
	}
	return fmt.Sprintf("Since %s: %s.", since, head)
}

// summary is Summary when set (by Compare), else Headline.
func (r Report) summary() string {
	if r.Summary != "" {
		return r.Summary
	}
	return r.Headline()
}

var pathLabel = map[string]string{
	Added:            "added",
	Removed:          "removed",
	Upgraded:         "upgraded (possible → confirmed)",
	Downgraded:       "downgraded (confirmed → possible: a hop is not visible; not a fix)",
	LostVisibility:   "lost visibility (the newer snapshot cannot see part of this path; reach unknown, not fixed)",
	GainedVisibility: "newly visible (the older snapshot could not see part of this path)",
}

func pathState(p *graph.Path) string {
	if p == nil {
		return "none"
	}
	if p.Unverified {
		return "possible"
	}
	return "confirmed"
}

func writeHops(w io.Writer, indent string, p *graph.Path) {
	if p == nil {
		return
	}
	for _, h := range p.Hops {
		kind := string(h.Kind)
		if h.Reverse {
			kind += " (reversed)"
		}
		fmt.Fprintf(w, "%s%s =[%s, %s]=> %s\n", indent, h.From, kind, evLabel(h.Evidence), h.To)
	}
}

func signed(f float64) string {
	if f >= 0 {
		return fmt.Sprintf("+%g", f)
	}
	return fmt.Sprintf("%g", f)
}

func signedInt(n int) string {
	if n >= 0 {
		return fmt.Sprintf("+%d", n)
	}
	return fmt.Sprintf("%d", n)
}

func (r Report) span() string {
	return fmt.Sprintf("%s (%s): %s → %s", r.New.Enterprise, r.New.Schema,
		r.Old.CollectedAt.UTC().Format("2006-01-02T15:04:05Z"), r.New.CollectedAt.UTC().Format("2006-01-02T15:04:05Z"))
}

func (r Report) totalsLine() string {
	o, n := r.Totals.Old, r.Totals.New
	s := fmt.Sprintf("Confirmed (principal, repo) pairs: %d → %d (%s). Possible pairs: %d → %d (%s).",
		o.ConfirmedPairs, n.ConfirmedPairs, signedInt(n.ConfirmedPairs-o.ConfirmedPairs),
		o.PossiblePairs, n.PossiblePairs, signedInt(n.PossiblePairs-o.PossiblePairs))
	if k := r.unseenConfirmedRepos(); k > 0 {
		s += fmt.Sprintf(" %s lost visibility or became possible: unknown, not fixed.", plural(k, "confirmed pair", "confirmed pairs"))
	}
	return s
}

// unseenConfirmedRepos counts confirmed (principal, repo) pairs that dropped out
// of the confirmed count because of visibility, not because of a fix.
func (r Report) unseenConfirmedRepos() int {
	k := 0
	for _, c := range r.Paths {
		if c.TargetKind == graph.KindRepo && (c.Status == LostVisibility || c.Status == Downgraded) && c.Old != nil && !c.Old.Unverified {
			k++
		}
	}
	return k
}

func edgeLine(c EdgeChange) string {
	s := fmt.Sprintf("%s %s %s", c.From, c.Kind, c.To)
	switch {
	case c.Old != nil && c.New != nil:
		s += fmt.Sprintf("  [%s%s → %s%s]", evLabel(c.Old.Evidence), attrStr(c.Old.Attrs), evLabel(c.New.Evidence), attrStr(c.New.Attrs))
	case c.New != nil:
		s += fmt.Sprintf("  [%s%s]", evLabel(c.New.Evidence), attrStr(c.New.Attrs))
	case c.Old != nil:
		s += fmt.Sprintf("  [was %s%s]", evLabel(c.Old.Evidence), attrStr(c.Old.Attrs))
	}
	return s
}

func attrStr(a map[string]string) string {
	if v, ok := a[graph.AttrRefKind]; ok {
		return ", ref_kind=" + v
	}
	if v, ok := a[graph.AttrVia]; ok {
		return ", via=" + v
	}
	return ""
}

// WriteText writes the report as plain text, leading with Headline.
func WriteText(w io.Writer, r Report) {
	fmt.Fprintln(w, r.summary())
	fmt.Fprintln(w, r.span())
	fmt.Fprintln(w, r.totalsLine())
	if len(r.Paths) > 0 {
		fmt.Fprintf(w, "\nPaths (%d):\n", len(r.Paths))
		for _, c := range r.Paths {
			fmt.Fprintf(w, "  %s -> %s  [%s: %s → %s]\n", c.Principal, c.Target, pathLabel[c.Status], pathState(c.Old), pathState(c.New))
			if c.New != nil {
				writeHops(w, "      ", c.New)
			} else {
				writeHops(w, "      was ", c.Old)
			}
		}
	}
	if len(r.Settings) > 0 {
		fmt.Fprintf(w, "\nSettings (%d):\n", len(r.Settings))
		for _, c := range r.Settings {
			fmt.Fprintf(w, "  %s  [evidence %s → %s]\n", c.phrase(), evLabel(c.OldEvidence), evLabel(c.NewEvidence))
		}
	}
	e := r.Edges
	if n := len(e.Added) + len(e.Removed) + len(e.Changed) + len(e.LostVisibility); n > 0 {
		fmt.Fprintf(w, "\nEdges (%d):\n", n)
		for _, g := range []struct {
			mark string
			l    []EdgeChange
		}{{"+", e.Added}, {"-", e.Removed}, {"~", e.Changed}, {"? lost visibility:", e.LostVisibility}} {
			for _, c := range g.l {
				mark := g.mark
				if c.Status == GainedVisibility {
					mark += " newly visible:"
				}
				fmt.Fprintf(w, "  %s %s\n", mark, edgeLine(c))
			}
		}
	}
	if len(r.Scores) > 0 {
		fmt.Fprintf(w, "\nScores (%d):\n", len(r.Scores))
		for _, s := range r.Scores {
			fmt.Fprintf(w, "  %s  confirmed %g → %g (%s)  possible %g → %g (%s)\n", s.Principal,
				s.Old.Score, s.New.Score, signed(s.DeltaConfirmed), s.Old.PossibleScore, s.New.PossibleScore, signed(s.DeltaPossible))
		}
	}
	if len(r.Coverage.Opened)+len(r.Coverage.Closed) > 0 {
		fmt.Fprintf(w, "\nCoverage:\n")
		for _, c := range r.Coverage.Opened {
			fmt.Fprintf(w, "  gap opened: %s %s: %s (fix: %s)\n", c.Scope, c.Fact, c.Reason, c.NeedsFix)
		}
		for _, c := range r.Coverage.Closed {
			fmt.Fprintf(w, "  gap closed: %s %s\n", c.Scope, c.Fact)
		}
	}
}

func mdEsc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// WriteMarkdown writes the report as GitHub-flavored Markdown.
func WriteMarkdown(w io.Writer, r Report) {
	fmt.Fprintf(w, "# gop posture drift\n\n%s\n\n", r.summary())
	fmt.Fprintf(w, "`%s`\n\n", r.span())
	o, n := r.Totals.Old, r.Totals.New
	fmt.Fprintf(w, "| | Old | New | Change |\n|---|---|---|---|\n")
	fmt.Fprintf(w, "| Confirmed (principal, repo) pairs | %d | %d | %s |\n", o.ConfirmedPairs, n.ConfirmedPairs, signedInt(n.ConfirmedPairs-o.ConfirmedPairs))
	fmt.Fprintf(w, "| Possible (principal, repo) pairs | %d | %d | %s |\n", o.PossiblePairs, n.PossiblePairs, signedInt(n.PossiblePairs-o.PossiblePairs))
	if len(r.Paths) > 0 {
		fmt.Fprintf(w, "\n## Paths\n\n| Status | Principal | Target | Old | New |\n|---|---|---|---|---|\n")
		for _, c := range r.Paths {
			fmt.Fprintf(w, "| %s | `%s` | `%s` | %s | %s |\n", mdEsc(pathLabel[c.Status]), c.Principal, c.Target, pathState(c.Old), pathState(c.New))
		}
	}
	if len(r.Settings) > 0 {
		fmt.Fprintf(w, "\n## Settings\n\n| Change | Old evidence | New evidence |\n|---|---|---|\n")
		for _, c := range r.Settings {
			fmt.Fprintf(w, "| %s | %s | %s |\n", mdEsc(c.phrase()), evLabel(c.OldEvidence), evLabel(c.NewEvidence))
		}
	}
	e := r.Edges
	if len(e.Added)+len(e.Removed)+len(e.Changed)+len(e.LostVisibility) > 0 {
		fmt.Fprintf(w, "\n## Edges\n\n| Status | Edge |\n|---|---|\n")
		for _, l := range [][]EdgeChange{e.Added, e.Removed, e.Changed, e.LostVisibility} {
			for _, c := range l {
				fmt.Fprintf(w, "| %s | `%s` |\n", strings.ReplaceAll(c.Status, "_", " "), mdEsc(edgeLine(c)))
			}
		}
	}
	if len(r.Scores) > 0 {
		fmt.Fprintf(w, "\n## Scores\n\n| Principal | Confirmed | Possible |\n|---|---|---|\n")
		for _, s := range r.Scores {
			fmt.Fprintf(w, "| `%s` | %g → %g (%s) | %g → %g (%s) |\n", s.Principal,
				s.Old.Score, s.New.Score, signed(s.DeltaConfirmed), s.Old.PossibleScore, s.New.PossibleScore, signed(s.DeltaPossible))
		}
	}
	if len(r.Coverage.Opened)+len(r.Coverage.Closed) > 0 {
		fmt.Fprintf(w, "\n## Coverage\n\n| Gap | Scope | Fact | Reason | Needs |\n|---|---|---|---|---|\n")
		for _, c := range r.Coverage.Opened {
			fmt.Fprintf(w, "| opened | `%s` | %s | %s | %s |\n", c.Scope, mdEsc(c.Fact), mdEsc(c.Reason), mdEsc(c.NeedsFix))
		}
		for _, c := range r.Coverage.Closed {
			fmt.Fprintf(w, "| closed | `%s` | %s | %s | %s |\n", c.Scope, mdEsc(c.Fact), mdEsc(c.Reason), mdEsc(c.NeedsFix))
		}
	}
}
