// Package report renders a gop graph as one self-contained HTML file or as
// Markdown. Headlines use confirmed reach only; a not_visible fact is always
// labeled "not visible", never shown as off or absent.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// Options tune the report.
type Options struct {
	Format    string // "html" (default) or "md"
	Top       int    // principals in the risks table and paths section (default 10)
	FixBudget int    // suggested fixes (default 5)
	Version   string // gop version for the footer
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
		return pageTmpl.Execute(w, d)
	case "md", "markdown":
		return writeMarkdown(w, d)
	}
	return fmt.Errorf("report: unknown format %q (want html or md)", opts.Format)
}

type data struct {
	Version     string
	Enterprise  string
	CollectedAt string
	Headline    string
	FixLine     string
	Risks       []riskRow
	Fixes       []fixRow
	Paths       []principalPaths
	Orgs        []orgRow
	Coverage    []graph.Coverage
}

type riskRow struct {
	Principal                    string
	Repos, Orgs                  int
	OIDC, Secrets, Runners       int
	PossibleRepos, PossibleOther int
	Score                        string
}

type fixRow struct {
	N             int
	Description   string
	FixID         string
	Removed       int
	CumulativePct string
}

type principalPaths struct {
	Principal string
	Paths     []pathView
}

type pathView struct {
	To        string
	Confirmed bool
	Hops      []hopView
}

type hopView struct {
	From, To, Kind, SourceAPI string
	Reverse                   bool
	Evidence                  string // live | audit | not visible
	Class                     string // live | audit | nv
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
	d := data{Version: opts.Version, Enterprise: g.Enterprise}
	if !g.CollectedAt.IsZero() {
		d.CollectedAt = g.CollectedAt.UTC().Format(time.RFC3339)
	}
	top := ix.TopPaths(opts.Top)
	if len(top) > 0 && (top[0].Confirmed.Repos > 0 || top[0].Score > 0) {
		d.Headline = headline(ix, headlinePick(ix, top))
	} else {
		d.Headline = "No principal has confirmed reach into any repository in this graph."
	}
	for _, s := range top {
		c, p := s.Confirmed, s.Possible
		d.Risks = append(d.Risks, riskRow{Principal: s.Principal, Repos: c.Repos, Orgs: c.Orgs,
			OIDC: c.OIDC, Secrets: c.Secrets, Runners: c.Runners,
			PossibleRepos: p.Repos, PossibleOther: p.OIDC + p.Secrets + p.Runners,
			Score: fmt.Sprintf("%.1f", s.Score)})
		if pp := pickPaths(ix, s.Principal); len(pp) > 0 {
			d.Paths = append(d.Paths, principalPaths{Principal: s.Principal, Paths: pp})
		}
	}
	for i, f := range ix.SuggestFixes(opts.FixBudget) {
		_, desc := mcpserver.DescribeFix(f.Fix)
		d.Fixes = append(d.Fixes, fixRow{N: i + 1, Description: desc, FixID: f.FixID, Removed: f.Removed,
			CumulativePct: fmt.Sprintf("%.0f%%", f.CumulativePct)})
	}
	if len(d.Fixes) > 0 {
		d.FixLine = fmt.Sprintf("%s to remove %s of confirmed reach.", d.Fixes[0].Description, d.Fixes[0].CumulativePct)
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

// headlinePick is the top-scored principal; among equal scores an org's
// members (a whole population) win over a single identity.
func headlinePick(ix *graph.Index, top []graph.Score) graph.Score {
	best := top[0]
	for _, s := range top[1:] {
		if s.Score != best.Score {
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
	var term []string
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
	return out
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
		pv := pathView{To: p.To, Confirmed: !p.Unverified}
		for _, h := range p.Hops {
			pv.Hops = append(pv.Hops, hopView{From: h.From, To: h.To, Kind: string(h.Kind), SourceAPI: h.SourceAPI,
				Reverse: h.Reverse, Evidence: mcpserver.EvidenceLabel(h.Evidence), Class: evClass(h.Evidence)})
		}
		out = append(out, pv)
	}
	return out
}

func evClass(ev graph.Evidence) string {
	switch ev {
	case graph.Live:
		return "live"
	case graph.Audit:
		return "audit"
	}
	return "nv"
}

const footer = "This file maps attack paths in your organization. Treat it as sensitive."
