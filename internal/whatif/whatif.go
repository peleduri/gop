// Package whatif re-scores a graph with hypothetical fixes applied and
// reports what changes: the before and after pair totals, the paths that
// disappear and the top paths that remain. The what_if MCP tool and
// gop what-if both compute through Compute, so they report the same numbers.
package whatif

import (
	"fmt"
	"sort"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
)

// Default limits for Options.
const (
	DefaultTop   = 5
	DefaultLimit = 20
)

// Status values of a removed path, before and after the fixes.
const (
	StatusConfirmed = "confirmed"
	StatusPossible  = "possible"
	StatusGone      = "gone"
)

// Options tune Build.
type Options struct {
	// Top is how many remaining principals to list (0 means DefaultTop).
	Top int
	// Limit caps the removed paths listed (0 means DefaultLimit, a negative
	// value lists every one). RemovedTotal always counts all of them.
	Limit int
}

// Fix is one applied fix with its spec and a sentence.
type Fix struct {
	FixID       string          `json:"fix_id"`
	Fix         fixplan.FixSpec `json:"fix"`
	Description string          `json:"description"`
}

// RemovedPath is a path a principal had before the fixes and no longer has
// with the same evidence: confirmed to gone, confirmed to possible, or
// possible to gone. Hops is the node chain of the path before the fixes.
type RemovedPath struct {
	Principal string   `json:"principal"`
	Target    string   `json:"target"`
	Before    string   `json:"before"`
	After     string   `json:"after"`
	Hops      []string `json:"hops"`
}

// Remaining is one of the top principals after the fixes, with its most
// telling remaining path (terminal impact first, else its longest confirmed
// repo path; nil when it reaches nothing confirmed).
type Remaining struct {
	Principal string      `json:"principal"`
	Before    graph.Score `json:"before"`
	After     graph.Score `json:"after"`
	Path      *graph.Path `json:"path"`
}

// Report is the full what-if answer. Its JSON keys are stable.
type Report struct {
	Summary      string        `json:"summary"`
	Fixes        []Fix         `json:"fixes"`
	Before       graph.Totals  `json:"before"`
	After        graph.Totals  `json:"after"`
	Removed      []RemovedPath `json:"removed_paths"`
	RemovedTotal int           `json:"removed_paths_total"`
	Remaining    []Remaining   `json:"remaining_top"`
	Caveats      []string      `json:"caveats"`
}

func pct(before, after int) float64 {
	if before == 0 {
		return 0
	}
	return 100 * float64(before-after) / float64(before)
}

// Summary is the one-line before/after headline of a delta.
func Summary(d graph.Delta) string {
	b, a := d.Before, d.After
	return fmt.Sprintf("confirmed (principal, repo) pairs: %d -> %d (%.0f%% removed); possible pairs: %d -> %d",
		b.ConfirmedPairs, a.ConfirmedPairs, pct(b.ConfirmedPairs, a.ConfirmedPairs), b.PossiblePairs, a.PossiblePairs)
}

// Compute applies fixes hypothetically: the delta and its summary. It is
// the scoring both the what_if tool and gop what-if use.
func Compute(ix *graph.Index, fixes []graph.Fix) (graph.Delta, string) {
	d := ix.WhatIf(fixes)
	return d, Summary(d)
}

// counted are the node kinds that Score counts: a path to one of them is
// reach; a path to an intermediate node (a team, an action) is not listed.
var counted = map[graph.NodeKind]bool{
	graph.KindRepo: true, graph.KindOrg: true, graph.KindWorkflow: true, graph.KindSecret: true,
	graph.KindOIDC: true, graph.KindRunner: true, graph.KindCloudTarget: true,
}

func status(p graph.Path, ok bool) string {
	switch {
	case !ok:
		return StatusGone
	case p.Unverified:
		return StatusPossible
	}
	return StatusConfirmed
}

func hops(p graph.Path) []string {
	out := []string{p.From}
	for _, h := range p.Hops {
		out = append(out, h.To)
	}
	return out
}

// Build computes the delta (Compute) and the paths behind it.
func Build(ix *graph.Index, fixes []graph.Fix, opts Options) Report {
	d, summary := Compute(ix, fixes)
	return FromDelta(ix, fixes, d, summary, opts)
}

// FromDelta builds the report for a delta Compute returned for fixes, with
// summary as its headline (the MCP engine adds its demo and partial markers).
func FromDelta(ix *graph.Index, fixes []graph.Fix, d graph.Delta, summary string, opts Options) Report {
	top, limit := opts.Top, opts.Limit
	if top <= 0 {
		top = DefaultTop
	}
	if limit == 0 {
		limit = DefaultLimit
	}
	r := Report{
		Summary: summary, Before: d.Before, After: d.After,
		Fixes: []Fix{}, Removed: []RemovedPath{}, Remaining: []Remaining{}, Caveats: []string{},
	}
	r.Caveats = append(r.Caveats, d.Caveats...)
	for _, f := range fixes {
		spec, desc := fixplan.Describe(ix, f)
		r.Fixes = append(r.Fixes, Fix{FixID: f.ID(), Fix: spec, Description: desc})
	}

	// Removed paths, principals in before-rank order (the worst first).
	changed := []graph.PrincipalDelta{}
	for _, pd := range d.PerPrincipal {
		if pd.Before.Confirmed != pd.After.Confirmed || pd.Before.Possible != pd.After.Possible {
			changed = append(changed, pd)
		}
	}
	sort.SliceStable(changed, func(i, j int) bool { return graph.RanksAbove(changed[i].Before, changed[j].Before) })
	after := map[string]graph.Result{}
	for _, pd := range changed {
		bef := ix.Reach(pd.Principal, graph.Options{})
		aft := ix.Reach(pd.Principal, graph.Options{Fixes: fixes})
		after[pd.Principal] = aft
		targets := make([]string, 0, len(bef.Paths))
		for t := range bef.Paths {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		for _, t := range targets {
			if !counted[ix.Kind(t)] {
				continue
			}
			bp := bef.Paths[t]
			ap, ok := aft.Paths[t]
			b, a := status(bp, true), status(ap, ok)
			if b == a {
				continue
			}
			r.Removed = append(r.Removed, RemovedPath{Principal: pd.Principal, Target: t, Before: b, After: a, Hops: hops(bp)})
		}
	}
	// Terminal impact first; within a kind, principals keep their rank.
	sort.SliceStable(r.Removed, func(i, j int) bool { return impact(ix, r.Removed[i].Target) < impact(ix, r.Removed[j].Target) })
	r.RemovedTotal = len(r.Removed)
	if limit >= 0 && len(r.Removed) > limit {
		r.Removed = r.Removed[:limit]
	}

	// Remaining top principals after the fixes.
	rest := append([]graph.PrincipalDelta{}, d.PerPrincipal...)
	sort.SliceStable(rest, func(i, j int) bool { return graph.RanksAbove(rest[i].After, rest[j].After) })
	for _, pd := range rest {
		if len(r.Remaining) == top {
			break
		}
		if pd.After.Score == 0 && pd.After.PossibleScore == 0 {
			continue
		}
		aft, ok := after[pd.Principal]
		if !ok {
			aft = ix.Reach(pd.Principal, graph.Options{Fixes: fixes})
		}
		r.Remaining = append(r.Remaining, Remaining{Principal: pd.Principal, Before: pd.Before, After: pd.After, Path: telling(ix, aft)})
	}
	return r
}

// impact orders target kinds for listing: terminal impact first.
func impact(ix *graph.Index, id string) int {
	switch ix.Kind(id) {
	case graph.KindCloudTarget:
		return 0
	case graph.KindOIDC:
		return 1
	case graph.KindSecret:
		return 2
	case graph.KindRunner:
		return 3
	case graph.KindOrg:
		return 4
	case graph.KindRepo:
		return 5
	case graph.KindWorkflow:
		return 6
	}
	return 7
}

// telling picks a principal's most telling confirmed path: terminal impact
// (cloud role, OIDC, secret, runner) first, else its longest repo path.
func telling(ix *graph.Index, r graph.Result) *graph.Path {
	rank := func(id string) int {
		if k := ix.Kind(id); k == graph.KindOrg || k == graph.KindWorkflow {
			return -1
		}
		return impact(ix, id)
	}
	var best *graph.Path
	for _, p := range r.Paths {
		if p.Unverified || rank(p.To) < 0 {
			continue
		}
		if best == nil {
			p := p
			best = &p
			continue
		}
		ra, rb := rank(p.To), rank(best.To)
		switch {
		case ra < rb,
			ra == rb && len(p.Hops) > len(best.Hops),
			ra == rb && len(p.Hops) == len(best.Hops) && p.To < best.To:
			p := p
			best = &p
		}
	}
	return best
}
