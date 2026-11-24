package mcpserver

import (
	"fmt"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
)

// Detail levels of the list-returning tools (who_can_reach, blast_radius,
// paths, top_risks, suggest_fixes, diff and fix_plan).
const (
	DetailBrief = "brief"
	DetailFull  = "full"
	// DefaultBriefLimit caps each list of a brief answer when limit is unset.
	DefaultBriefLimit = 10
)

// detailNote is appended to the description of every list-returning tool.
const detailNote = " detail is brief (the default) or full. Brief caps lists at limit (default 10), leaves out " +
	"bulky per-item fields (path hops, edge attrs, a fix plan's per-principal scores), keeps every listed item's IDs " +
	"and evidence, and adds brief.truncated, brief.total (each list's length before the cut) and brief.omitted. " +
	"For one item's hops call paths with from and to; for one edge's attrs call explain. " +
	"detail full returns every item and field."

// DetailInput is the detail level and list cap shared by the list-returning tools.
type DetailInput struct {
	Detail string `json:"detail,omitempty" jsonschema:"brief (default): capped lists without hops or attrs, with brief.truncated and brief.total; full: every item and field"`
	Limit  int    `json:"limit,omitempty" jsonschema:"brief only: maximum items per list (default 10)"`
}

// detailer is an input with a detail level.
type detailer interface {
	detailOpts() (brief bool, limit int, err error)
}

func (d DetailInput) detailOpts() (bool, int, error) {
	return parseDetail(d.Detail, d.Limit, DefaultBriefLimit)
}

// parseDetail checks detail and limit and returns whether the answer is brief
// and the list cap, def when limit is unset.
func parseDetail(detail string, limit, def int) (bool, int, error) {
	if limit < 0 {
		return false, 0, fmt.Errorf("limit must be positive, got %d", limit)
	}
	if limit == 0 {
		limit = def
	}
	switch detail {
	case "", DetailBrief:
		return true, limit, nil
	case DetailFull:
		return false, limit, nil
	}
	return false, 0, fmt.Errorf("detail must be %s or %s, got %q", DetailBrief, DetailFull, detail)
}

// Brief describes how a brief answer was cut. It is set only on brief answers,
// so a full answer is unchanged.
type Brief struct {
	Truncated bool           `json:"truncated" jsonschema:"true when any list was cut at limit: pass detail full or a larger limit for the rest"`
	Limit     int            `json:"limit"`
	Total     map[string]int `json:"total" jsonschema:"each list's length before the cut, by list name"`
	Omitted   []string       `json:"omitted,omitempty" jsonschema:"fields left out of listed items, e.g. hops (call paths with from and to) or attrs (call explain)"`
}

// trimmer cuts lists for one brief answer and records what it cut.
type trimmer struct {
	b Brief
}

func newTrimmer(limit int) *trimmer {
	return &trimmer{b: Brief{Limit: limit, Total: map[string]int{}}}
}

// omit records a field left out of listed items.
func (t *trimmer) omit(field string) {
	for _, f := range t.b.Omitted {
		if f == field {
			return
		}
	}
	t.b.Omitted = append(t.b.Omitted, field)
}

// brief returns the record of what was cut.
func (t *trimmer) brief() *Brief { b := t.b; return &b }

// trimList records the length of the list name (adding to it when name is
// seen again) and returns at most limit items of s. A nil s stays nil.
func trimList[S ~[]E, E any](t *trimmer, name string, s S) S {
	t.b.Total[name] += len(s)
	return capList(s, t.b.Limit, &t.b.Truncated)
}

// withDetail wraps a tool function: a brief call gets its answer cut by
// brief; a full call gets fn's answer unchanged.
func withDetail[In detailer, Out any](fn func(In) (Out, error), brief func(Out, *trimmer) Out) func(In) (Out, error) {
	return func(in In) (Out, error) {
		isBrief, limit, err := in.detailOpts()
		if err != nil {
			var zero Out
			return zero, err
		}
		out, err := fn(in)
		if err != nil || !isBrief {
			return out, err
		}
		return brief(out, newTrimmer(limit)), nil
	}
}

// pathsWithoutHops returns copies of ps with the hops left out. Each path
// keeps its ends, evidence (the weakest hop), unverified, supplied and stale.
func (t *trimmer) pathsWithoutHops(ps []graph.Path) []graph.Path {
	if ps == nil {
		return nil
	}
	out := make([]graph.Path, len(ps))
	for i, p := range ps {
		if p.Hops != nil {
			t.omit("hops")
		}
		p.Hops = nil
		out[i] = p
	}
	return out
}

func (t *trimmer) pathWithoutHops(p *graph.Path) *graph.Path {
	if p == nil {
		return nil
	}
	return &t.pathsWithoutHops([]graph.Path{*p})[0]
}

func briefWho(o WhoCanReachOutput, t *trimmer) WhoCanReachOutput {
	o.Confirmed = t.pathsWithoutHops(trimList(t, "confirmed", o.Confirmed))
	o.Possible = t.pathsWithoutHops(trimList(t, "possible", o.Possible))
	o.Brief = t.brief()
	return o
}

// briefPaths keeps the hops of a single from-to path: that is the detail call
// a brief list points to.
func briefPaths(o PathsOutput, t *trimmer) PathsOutput {
	o.Confirmed = trimList(t, "confirmed", o.Confirmed)
	o.Possible = trimList(t, "possible", o.Possible)
	if o.To == "" {
		o.Confirmed = t.pathsWithoutHops(o.Confirmed)
		o.Possible = t.pathsWithoutHops(o.Possible)
	}
	o.Brief = t.brief()
	return o
}

func (t *trimmer) reached(prefix string, r graph.Reached) graph.Reached {
	return graph.Reached{
		Repos:        trimList(t, prefix+".repos", r.Repos),
		Workflows:    trimList(t, prefix+".workflows", r.Workflows),
		Actions:      trimList(t, prefix+".actions", r.Actions),
		Secrets:      trimList(t, prefix+".secrets", r.Secrets),
		OIDC:         trimList(t, prefix+".oidc", r.OIDC),
		Runners:      trimList(t, prefix+".runners", r.Runners),
		Orgs:         trimList(t, prefix+".orgs", r.Orgs),
		CloudTargets: trimList(t, prefix+".cloud_targets", r.CloudTargets),
	}
}

func briefBlast(o BlastRadiusOutput, t *trimmer) BlastRadiusOutput {
	o.Confirmed = t.reached("confirmed", o.Confirmed)
	o.Possible = t.reached("possible", o.Possible)
	o.Brief = t.brief()
	return o
}

// briefTop reports every ranked row in total (principals with identical
// reach share a row), so truncated is also true when n alone left rows out.
func (e *Engine) briefTop(o TopRisksOutput, t *trimmer) TopRisksOutput {
	o.Risks = trimList(t, "risks", o.Risks)
	if o.rows > len(o.Risks) {
		t.b.Total["risks"] = o.rows
		t.b.Truncated = true
	}
	o.Brief = t.brief()
	return o
}

func briefSuggest(o SuggestFixesOutput, t *trimmer) SuggestFixesOutput {
	fixes := trimList(t, "fixes", o.Fixes)
	o.Fixes = make([]FixOut, len(fixes))
	for i, f := range fixes {
		f.Edges = trimList(t, "edges", f.Edges)
		o.Fixes[i] = f
	}
	o.Brief = t.brief()
	return o
}

// briefPlan cuts the steps and caveats of a fix plan and leaves out
// removes.per_principal (one before and after score per scoring principal);
// removes.before and removes.after keep the enterprise totals.
func briefPlan(o FixPlanOutput, t *trimmer) FixPlanOutput {
	p := o.Plan
	p.Steps = trimList(t, "steps", p.Steps)
	p.Caveats = trimList(t, "caveats", p.Caveats)
	if n := len(p.Removes.PerPrincipal); n > 0 {
		t.b.Total["per_principal"] = n
		t.b.Truncated = true
		t.omit("per_principal")
		p.Removes.PerPrincipal = []graph.PrincipalDelta{}
	}
	o.Plan = p
	o.Brief = t.brief()
	return o
}

// diffLists names the lists of a diff report in section order.
var diffLists = []string{"paths", "settings", "edges.added", "edges.removed", "edges.changed",
	"edges.lost_visibility", "scores", "coverage.opened", "coverage.closed"}

// shareLimit splits limit entries over lists of the given lengths, one entry
// at a time in list order, so every non-empty list gets an entry before any
// list gets a second.
func shareLimit(lens []int, limit int) []int {
	quota := make([]int, len(lens))
	for left := limit; left > 0; {
		gave := false
		for i, n := range lens {
			if left > 0 && quota[i] < n {
				quota[i]++
				left--
				gave = true
			}
		}
		if !gave {
			break
		}
	}
	return quota
}

// briefReport cuts a diff report to limit entries in all (shared by
// shareLimit, so every section with changes shows at least one when limit
// allows), records each list's length, and leaves out path hops and edge
// attrs. The full-detail per-list limit is applied by truncateReport.
func briefReport(r diff.Report, t *trimmer) diff.Report {
	lens := []int{len(r.Paths), len(r.Settings), len(r.Edges.Added), len(r.Edges.Removed), len(r.Edges.Changed),
		len(r.Edges.LostVisibility), len(r.Scores), len(r.Coverage.Opened), len(r.Coverage.Closed)}
	q := shareLimit(lens, t.b.Limit)
	for i, n := range lens {
		t.b.Total[diffLists[i]] = n
	}
	r.Paths = capList(r.Paths, q[0], &t.b.Truncated)
	r.Settings = capList(r.Settings, q[1], &t.b.Truncated)
	r.Edges.Added = t.edgesWithoutAttrs(capList(r.Edges.Added, q[2], &t.b.Truncated))
	r.Edges.Removed = t.edgesWithoutAttrs(capList(r.Edges.Removed, q[3], &t.b.Truncated))
	r.Edges.Changed = t.edgesWithoutAttrs(capList(r.Edges.Changed, q[4], &t.b.Truncated))
	r.Edges.LostVisibility = t.edgesWithoutAttrs(capList(r.Edges.LostVisibility, q[5], &t.b.Truncated))
	r.Scores = capList(r.Scores, q[6], &t.b.Truncated)
	r.Coverage.Opened = capList(r.Coverage.Opened, q[7], &t.b.Truncated)
	r.Coverage.Closed = capList(r.Coverage.Closed, q[8], &t.b.Truncated)
	if r.Paths != nil {
		paths := make(diff.PathChanges, len(r.Paths))
		for i, c := range r.Paths {
			c.Old = t.pathWithoutHops(c.Old)
			c.New = t.pathWithoutHops(c.New)
			paths[i] = c
		}
		r.Paths = paths
	}
	return r
}

func (t *trimmer) edgesWithoutAttrs(es []diff.EdgeChange) []diff.EdgeChange {
	if es == nil {
		return nil
	}
	out := make([]diff.EdgeChange, len(es))
	for i, e := range es {
		e.Old = t.factWithoutAttrs(e.Old)
		e.New = t.factWithoutAttrs(e.New)
		out[i] = e
	}
	return out
}

func (t *trimmer) factWithoutAttrs(f *diff.EdgeFact) *diff.EdgeFact {
	if f == nil {
		return nil
	}
	c := *f
	if c.Attrs != nil {
		t.omit("attrs")
	}
	c.Attrs = nil
	return &c
}
