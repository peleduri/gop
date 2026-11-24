// Package report renders a gop graph as one self-contained HTML file or as
// Markdown. Headlines use confirmed reach only; a not_visible fact is always
// labeled "not visible", never shown as off or absent.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/sanitize"
)

// Options tune the report.
type Options struct {
	Format    string // "html" (default) or "md"
	Top       int    // principals in the risks table and paths section (default 10)
	FixBudget int    // suggested fixes (default 5)
	Version   string // gop version for the footer
	// Changes is diff.Compare(previous, current) (gop report --previous):
	// the report opens with a "what changed" banner. Nil means no banner.
	Changes *diff.Report
}

const maxPathsPerPrincipal = 3

// Render writes the report for g to w.
func Render(w io.Writer, g *graph.Graph, opts Options) error {
	if opts.Top <= 0 {
		opts.Top = 10
	}
	if opts.FixBudget <= 0 {
		opts.FixBudget = 5
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	d := build(g, opts)
	switch strings.ToLower(opts.Format) {
	case "", "html":
		if err := addEmbedded(&d, g); err != nil {
			return err
		}
		// html/template escapes markup; sanitize.HTML also turns raw
		// control, bidi and zero-width characters from names into
		// character references.
		var page bytes.Buffer
		if err := pageTmpl.Execute(&page, d); err != nil {
			return err
		}
		_, err := w.Write(sanitize.HTML(page.Bytes()))
		return err
	case "md", "markdown":
		return writeMarkdown(w, d)
	}
	return fmt.Errorf("report: unknown format %q (want html or md)", opts.Format)
}

type data struct {
	Demo        bool // synthetic graph from gop demo: the title says so
	Version     string
	Enterprise  string
	CollectedAt string
	Headline    string
	FixLine     string
	// HasCloud is true when the graph has CAN_ASSUME edges (gop enrich
	// --oidc-trust): the risks table gains a cloud roles column and the
	// notes explain supplied evidence.
	HasCloud bool
	Risks    []riskRow
	Fixes    []fixRow
	PinLine  string
	Pinned   []pinnedRow
	// LockLine counts workflow uses: lines pinned in the workflow file, by
	// an actions.lock, stale in one, and unpinned; set only when the graph
	// has an actions.lock fact.
	LockLine string
	Paths    []principalPaths
	Orgs     []orgRow
	Coverage []graph.Coverage
	Banner   *banner // set only with Options.Changes

	// HTML only: the data the filters and org views read, the org names
	// for the filter bar, and a note when embedded paths were cut.
	DataJSON  template.JS
	OrgNames  []string
	Truncated string

	ix     *graph.Index
	sugg   []graph.FixSuggestion
	budget int
}

// whatIfFixes are the top suggested fixes the Graph tab can simulate: the
// report's own picks when the budget covers them, else a longer greedy run
// (its first picks are the same, the greedy is deterministic).
func (d *data) whatIfFixes() []graph.FixSuggestion {
	if len(d.sugg) >= graphWhatIfFixes || d.budget >= graphWhatIfFixes {
		return d.sugg
	}
	return d.ix.SuggestFixes(graphWhatIfFixes)
}

// addEmbedded fills the HTML-only fields from the graph.
func addEmbedded(d *data, g *graph.Graph) error {
	e := buildEmbedded(d.ix, g, d.ix.Scores(), d.sugg, maxPathsPerOrg)
	e.Graph.WhatIf = whatIfPaths(d.ix, e.Paths, d.whatIfFixes())
	js, err := marshalEmbedded(e)
	if err != nil {
		return err
	}
	d.DataJSON = template.JS(js) // #nosec G203 -- json.Marshal output, checked script-safe by marshalEmbedded
	seen := map[string]bool{}
	for _, o := range d.Orgs {
		seen[o.Org] = true
	}
	for _, p := range e.Paths {
		seen[p.ToOrg] = true
		for _, o := range p.FromOrgs {
			seen[o] = true
		}
	}
	d.OrgNames = sortedSet(seen)
	if n := len(e.Truncated); n > 0 {
		parts := make([]string, 0, n)
		for _, t := range e.Truncated {
			parts = append(parts, fmt.Sprintf("%s (%d)", t.Org, t.Total))
		}
		d.Truncated = fmt.Sprintf("To keep this file small, the filters below hold the top %d paths per target org; %s cut: %s. The sections above are complete.",
			e.MaxPerOrg, plural(n, "org was", "orgs were"), strings.Join(parts, ", "))
	}
	return nil
}

type riskRow struct {
	Principal                    string
	Repos, Orgs                  int
	Cloud                        int
	OIDC, Secrets, Runners       int
	PossibleRepos, PossibleOther int
	Score                        string
	// Advisory is set when the row ranks first for a known advisory: the
	// action's advisories, or the advisory actions its paths run through.
	Advisory string
}

type fixRow struct {
	N             int
	Description   string
	FixID         string
	Removed       int
	CumulativePct string
}

// pinnedRow is a SHA-pinned action that is still controllable through a
// nested mutable action.
type pinnedRow struct {
	Action, Via string
	ViaNote     string // set when Via is only possibly mutable
	Consumers   int
	Path        pathView
	Principal   string
}

type principalPaths struct {
	Principal string
	Paths     []pathView
}

type pathView struct {
	To        string
	Confirmed bool
	Hops      []hopView
	Note      string // supplied-file caveat, "" for paths read only from GitHub
}

type hopView struct {
	From, To, Kind, SourceAPI string
	Reason                    string // why an undecided CAN_ASSUME match is possible only
	Reverse                   bool
	Evidence                  string // live | inferred | audit | audit, stale | supplied file | not visible
	Class                     string // live | audit | supplied | nv
}

type orgRow struct {
	Org   string
	Cells []cell
}

type cell struct {
	Value string
	NV    bool
}

var orgCols = []struct{ Key, Title string }{
	{graph.AttrDefaultPerm, "Default permission"},
	{graph.AttrTwoFactor, "2FA"},
	{graph.AttrSSO, "SSO"},
	{graph.AttrIPAllowList, "IP allow list"},
	{graph.AttrMembers, "Members"},
}

func build(g *graph.Graph, opts Options) data {
	ix := graph.NewIndex(g)
	d := data{Demo: graph.IsDemo(g), Version: opts.Version, Enterprise: g.Enterprise, ix: ix}
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume {
			d.HasCloud = true
			break
		}
	}
	if !g.CollectedAt.IsZero() {
		d.CollectedAt = g.CollectedAt.UTC().Format(time.RFC3339)
	}
	top := ix.TopPaths(opts.Top)
	var pick *graph.Score
	if len(top) > 0 && (top[0].Confirmed.Repos > 0 || top[0].Score > 0) {
		s := headlinePick(ix, top)
		pick = &s
		d.Headline = headline(ix, s)
	} else {
		d.Headline = "No principal has confirmed reach into any repository in this graph."
	}
	for _, s := range top {
		c, p := s.Confirmed, s.Possible
		d.Risks = append(d.Risks, riskRow{Principal: s.Principal, Repos: c.Repos, Orgs: c.Orgs,
			Cloud: c.CloudTargets, OIDC: c.OIDC, Secrets: c.Secrets, Runners: c.Runners,
			PossibleRepos: p.Repos, PossibleOther: p.CloudTargets + p.OIDC + p.Secrets + p.Runners,
			Score: fmt.Sprintf("%.1f", s.Score), Advisory: advisoryNote(ix, s)})
		if pp := pickPaths(ix, s.Principal); len(pp) > 0 {
			d.Paths = append(d.Paths, principalPaths{Principal: s.Principal, Paths: pp})
		}
	}
	d.sugg, d.budget = ix.SuggestFixes(opts.FixBudget), opts.FixBudget
	for i, f := range d.sugg {
		_, desc := mcpserver.DescribeFix(f.Fix)
		d.Fixes = append(d.Fixes, fixRow{N: i + 1, Description: desc, FixID: f.FixID, Removed: f.Removed,
			CumulativePct: fmt.Sprintf("%.0f%%", f.CumulativePct)})
	}
	if len(d.Fixes) > 0 {
		d.FixLine = fmt.Sprintf("%s to remove %s of confirmed reach.", d.Fixes[0].Description, d.Fixes[0].CumulativePct)
	}
	for _, pe := range ix.PinnedExposures() {
		d.Pinned = append(d.Pinned, pinnedRow{Action: strings.TrimPrefix(pe.Action, "action:"),
			Via: strings.TrimPrefix(pe.Via, "action:"), ViaNote: pe.ViaNote, Consumers: pe.Consumers,
			Principal: pe.Path.From, Path: viewPath(pe.Path)})
	}
	if n := len(d.Pinned); n > 0 {
		verb := "run"
		if n == 1 {
			verb = "runs"
		}
		d.PinLine = fmt.Sprintf("Pinning is not enough: %s pinned to a commit SHA still %s a mutable ref that someone can push to.",
			plural(n, "action", "actions"), verb)
	}
	if st := ix.PinStats(); st.HasLock() {
		d.LockLine = lockLine(st)
	}
	for _, n := range g.Nodes {
		if n.Kind != graph.KindOrg {
			continue
		}
		r := orgRow{Org: n.Name}
		if r.Org == "" {
			r.Org = n.ID
		}
		for _, col := range orgCols {
			r.Cells = append(r.Cells, orgCell(n, col.Key))
		}
		d.Orgs = append(d.Orgs, r)
	}
	sort.Slice(d.Orgs, func(i, j int) bool { return d.Orgs[i].Org < d.Orgs[j].Org })
	d.Coverage = g.Coverage
	if opts.Changes != nil {
		d.Banner = buildBanner(opts.Changes, pick)
	}
	return d
}

// orgCell never turns an unseen setting into a value: not_visible evidence or
// an "unknown" value reads "not visible"; a missing attribute reads "unknown".
func orgCell(n graph.Node, key string) cell {
	ev := n.Evidence
	if e, ok := n.AttrEvidence[key]; ok {
		ev = e
	}
	v, ok := n.Attrs[key]
	if ev == graph.NotVisible || v == "unknown" {
		return cell{Value: "not visible", NV: true}
	}
	if !ok || v == "" {
		return cell{Value: "unknown", NV: true}
	}
	return cell{Value: v}
}

// headlinePick is the top-ranked principal; among equal ranks an org's
// members (a whole population) win over a single identity.
func headlinePick(ix *graph.Index, top []graph.Score) graph.Score {
	best := top[0]
	for _, s := range top[1:] {
		if s.Score != best.Score || s.PoutineInjectable != best.PoutineInjectable || (len(s.Advisories) > 0) != (len(best.Advisories) > 0) {
			break
		}
		if ix.Kind(s.Principal) == graph.KindOrgMembers && ix.Kind(best.Principal) != graph.KindOrgMembers {
			best = s
		}
	}
	return best
}

func headline(ix *graph.Index, s graph.Score) string {
	c := s.Confirmed
	who := mcpserver.Display(ix, s.Principal)
	if strings.HasPrefix(who, "members of ") {
		who = "M" + who[1:]
	}
	out := fmt.Sprintf("%s can push code that runs in %s across %s (confirmed)", who,
		plural(c.Repos, "repo", "repos"), plural(c.Orgs, "org", "orgs"))
	if len(s.Advisories) > 0 && s.Advisories[0] == s.Principal {
		out = fmt.Sprintf("%s, a version with a known advisory (%s), runs in %s across %s (confirmed)",
			strings.TrimPrefix(s.Principal, "action:"), advisoryLabel(ix, s.Principal), plural(c.Repos, "repo", "repos"), plural(c.Orgs, "org", "orgs"))
	}
	var term []string
	if c.CloudTargets > 0 {
		term = append(term, plural(c.CloudTargets, "cloud role", "cloud roles"))
	}
	if c.OIDC > 0 {
		term = append(term, plural(c.OIDC, "cloud OIDC trust", "cloud OIDC trusts"))
	}
	if c.Secrets > 0 {
		term = append(term, plural(c.Secrets, "secret scope", "secret scopes"))
	}
	if c.Runners > 0 {
		term = append(term, plural(c.Runners, "self-hosted runner pool", "self-hosted runner pools"))
	}
	if len(term) > 0 {
		out += ", including " + strings.Join(term, ", ")
	}
	out += "."
	if s.Possible.Repos > 0 {
		out += fmt.Sprintf(" %s more possible through facts gop could not see.", plural(s.Possible.Repos, "repo", "repos"))
	}
	if c.CloudTargets > 0 {
		r := ix.Reach(s.Principal, graph.Options{})
		var files []string
		seen := map[string]bool{}
		for _, id := range r.Confirmed.CloudTargets {
			for _, f := range r.Paths[id].SuppliedFiles() {
				if !seen[f] {
					seen[f] = true
					files = append(files, f)
				}
			}
		}
		sort.Strings(files)
		out += " Cloud hops from supplied trust files " + strings.Join(files, ", ") + ", not read from the cloud."
	}
	return out
}

// advisoryLabel is "GHSA-a, GHSA-b; severity critical; fixed in 2.0.1" for
// an action with advisories.
func advisoryLabel(ix *graph.Index, action string) string {
	n, _ := ix.Node(action)
	out := strings.Join(graph.AdvisoryIDs(n), ", ")
	if sev := n.Attrs[graph.AttrAdvisorySeverity]; sev != "" {
		out += "; severity " + sev
	}
	if f := n.Attrs[graph.AttrAdvisoryFixed]; f != "" {
		out += "; fixed in " + f
	} else {
		out += "; no fixed version"
	}
	return out
}

// advisoryNote is the risks-table note for a row with Score.Advisories.
func advisoryNote(ix *graph.Index, s graph.Score) string {
	if len(s.Advisories) == 0 {
		return ""
	}
	if s.Advisories[0] == s.Principal {
		return "known advisory: " + advisoryLabel(ix, s.Principal)
	}
	names := make([]string, len(s.Advisories))
	for i, a := range s.Advisories {
		names[i] = strings.TrimPrefix(a, "action:")
	}
	return "paths run through an action with a known advisory: " + strings.Join(names, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// pickPaths chooses a principal's most telling paths: terminal impact (OIDC,
// secrets, runners) first, confirmed before possible; else the longest
// confirmed repo path; plus one possible path when it has any.
func pickPaths(ix *graph.Index, principal string) []pathView {
	r := ix.Reach(principal, graph.Options{})
	rank := func(id string) int {
		switch ix.Kind(id) {
		case graph.KindCloudTarget:
			return -1
		case graph.KindOIDC:
			return 0
		case graph.KindSecret:
			return 1
		case graph.KindRunner:
			return 2
		}
		return 9
	}
	var terms, repos, possible []graph.Path
	for _, p := range r.Paths {
		switch {
		case rank(p.To) < 9:
			terms = append(terms, p)
		case ix.Kind(p.To) == graph.KindRepo && !p.Unverified:
			repos = append(repos, p)
		}
		if p.Unverified {
			possible = append(possible, p)
		}
	}
	sort.Slice(terms, func(i, j int) bool {
		a, b := terms[i], terms[j]
		if a.Unverified != b.Unverified {
			return !a.Unverified
		}
		if rank(a.To) != rank(b.To) {
			return rank(a.To) < rank(b.To)
		}
		return a.To < b.To
	})
	sort.Slice(repos, func(i, j int) bool {
		if len(repos[i].Hops) != len(repos[j].Hops) {
			return len(repos[i].Hops) > len(repos[j].Hops)
		}
		return repos[i].To < repos[j].To
	})
	sort.Slice(possible, func(i, j int) bool { return possible[i].To < possible[j].To })
	chosen := terms
	if len(chosen) == 0 && len(repos) > 0 {
		chosen = repos[:1]
	}
	if len(chosen) > maxPathsPerPrincipal {
		chosen = chosen[:maxPathsPerPrincipal]
	}
	hasPossible := false
	for _, p := range chosen {
		hasPossible = hasPossible || p.Unverified
	}
	if !hasPossible && len(possible) > 0 {
		chosen = append(chosen, possible[0])
	}
	out := make([]pathView, 0, len(chosen))
	for _, p := range chosen {
		out = append(out, viewPath(p))
	}
	return out
}

func viewPath(p graph.Path) pathView {
	pv := pathView{To: p.To, Confirmed: !p.Unverified, Note: p.SuppliedNote()}
	for _, h := range p.Hops {
		pv.Hops = append(pv.Hops, hopView{From: h.From, To: h.To, Kind: string(h.Kind), SourceAPI: h.SourceAPI, Reason: h.Reason,
			Reverse: h.Reverse, Evidence: mcpserver.HopEvidenceLabel(h), Class: evClass(h.Evidence)})
	}
	return pv
}

func evClass(ev graph.Evidence) string {
	switch ev {
	case graph.Live:
		return "live"
	case graph.Inferred:
		return "inferred"
	case graph.Audit:
		return "audit"
	case graph.Supplied:
		return "supplied"
	}
	return "nv"
}

const footer = "This file maps attack paths in your organization. Treat it as sensitive."

// lockLine is the coverage note that splits workflow uses: lines by how they
// are pinned. A stale actions.lock entry is never counted as pinned.
func lockLine(st graph.PinStats) string {
	return fmt.Sprintf("Action pins (workflow uses: lines): %d pinned in the workflow file, %d pinned by actions.lock (%s), %d with a stale actions.lock entry (counted as unpinned, listed below), %d unpinned.",
		st.InWorkflow, st.ByLock, plural(st.Locks, "repo has a lockfile", "repos have a lockfile"), st.Stale, st.Unpinned)
}
