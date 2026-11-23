package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
)

// DefaultDiffLimit caps each list in a diff tool answer when limit is unset.
const DefaultDiffLimit = 50

// ServerOptions tune NewServerWith.
type ServerOptions struct {
	// Baseline is the older snapshot the diff tool compares the served graph
	// with. When nil, the diff tool is still listed but returns an error
	// naming the --baseline flag.
	Baseline *graph.Graph
	// Now is the clock for snapshot age in resources and prompts; nil means time.Now.
	Now func() time.Time
}

// NewServer builds an MCP server over g with no baseline.
func NewServer(g *graph.Graph, version string) *mcp.Server {
	return NewServerWith(g, version, ServerOptions{})
}

// ServeWith is Serve with options.
func ServeWith(ctx context.Context, g *graph.Graph, version string, opts ServerOptions) error {
	return NewServerWith(g, version, opts).Run(ctx, &mcp.StdioTransport{})
}

const diffDescription = "Compare the served graph with the baseline snapshot passed to gop serve --baseline: " +
	"new and removed attack paths, setting changes, edge changes, blast radius score deltas and coverage " +
	"gaps opened or closed. Confirmed and possible paths are reported separately (an added path with " +
	"unverified=true is possible). Lost visibility is not a fix: a path, setting or edge the newer " +
	"snapshot cannot see is reported as lost_visibility, never as removed or turned off. " +
	"Optional filters: only (sections: paths, settings, edges, scores, coverage), principal (paths, " +
	"scores and edges touching it), target_kind (cloud_target, oidc, secret, runner or repo; paths only). " +
	"limit caps every list (default 50) and sets truncated when anything was cut. " +
	"summary is the full report's lead line (as gop diff prints it), before filters."

// DiffInput filters the diff tool answer.
type DiffInput struct {
	Only       []string `json:"only,omitempty" jsonschema:"sections to keep: paths, settings, edges, scores, coverage (default all)"`
	Principal  string   `json:"principal,omitempty" jsonschema:"keep only path changes and score deltas of this principal and edges touching it, e.g. members:acme-actions"`
	TargetKind string   `json:"target_kind,omitempty" jsonschema:"keep only path changes to this target kind: cloud_target, oidc, secret, runner or repo"`
	Limit      int      `json:"limit,omitempty" jsonschema:"maximum entries per list (default 50)"`
}

// DiffOutput is the posture drift between the baseline and the served graph.
type DiffOutput struct {
	Summary             string      `json:"summary"`
	BaselineCollectedAt time.Time   `json:"baseline_collected_at"`
	CurrentCollectedAt  time.Time   `json:"current_collected_at"`
	Truncated           bool        `json:"truncated"`
	Report              diff.Report `json:"report"`
}

// differ computes the baseline report once, on first use, and filters it per call.
type differ struct {
	old, cur *graph.Graph
	once     sync.Once
	rep      diff.Report
	err      error
}

func newDiffer(cur, baseline *graph.Graph) *differ { return &differ{old: baseline, cur: cur} }

var diffTargetKinds = []graph.NodeKind{graph.KindCloudTarget, graph.KindOIDC, graph.KindSecret, graph.KindRunner, graph.KindRepo}

// Diff answers the diff tool.
func (d *differ) Diff(in DiffInput) (DiffOutput, error) {
	if d.old == nil {
		return DiffOutput{}, errors.New("diff: no baseline snapshot loaded; restart the server with gop serve --graph NEW.json --baseline OLD.json")
	}
	for _, s := range in.Only {
		if !slices.Contains(diff.Sections, s) {
			return DiffOutput{}, fmt.Errorf("diff: unknown section %q in only (want %s)", s, strings.Join(diff.Sections, ", "))
		}
	}
	kind := graph.NodeKind(in.TargetKind)
	if kind != "" && !slices.Contains(diffTargetKinds, kind) {
		return DiffOutput{}, fmt.Errorf("diff: target_kind must be cloud_target, oidc, secret, runner or repo, got %q", in.TargetKind)
	}
	if in.Limit < 0 {
		return DiffOutput{}, fmt.Errorf("diff: limit must be positive, got %d", in.Limit)
	}
	limit := in.Limit
	if limit == 0 {
		limit = DefaultDiffLimit
	}
	d.once.Do(func() { d.rep, d.err = diff.Compare(d.old, d.cur) })
	if d.err != nil {
		return DiffOutput{}, d.err
	}
	rep := filterReport(d.rep.Only(in.Only), in.Principal, kind)
	rep, truncated := truncateReport(rep, limit)
	summary := rep.Summary
	if graph.IsDemo(d.cur) || graph.IsDemo(d.old) {
		summary = DemoMarker + " " + summary
	}
	return DiffOutput{
		Summary:             summary,
		BaselineCollectedAt: rep.Old.CollectedAt,
		CurrentCollectedAt:  rep.New.CollectedAt,
		Truncated:           truncated,
		Report:              rep,
	}, nil
}

// filterReport keeps the changes of one principal and one target kind. Empty
// filters keep everything. Settings and coverage are not per principal and are
// left as they are.
func filterReport(r diff.Report, principal string, kind graph.NodeKind) diff.Report {
	if principal == "" && kind == "" {
		return r
	}
	paths := diff.PathChanges{}
	for _, c := range r.Paths {
		if (principal == "" || c.Principal == principal) && (kind == "" || c.TargetKind == kind) {
			paths = append(paths, c)
		}
	}
	r.Paths = paths
	if principal == "" {
		return r
	}
	scores := []diff.ScoreDelta{}
	for _, s := range r.Scores {
		if s.Principal == principal {
			scores = append(scores, s)
		}
	}
	r.Scores = scores
	touching := func(in []diff.EdgeChange) []diff.EdgeChange {
		out := []diff.EdgeChange{}
		for _, e := range in {
			if e.From == principal || e.To == principal {
				out = append(out, e)
			}
		}
		return out
	}
	r.Edges = diff.EdgeChanges{
		Added:          touching(r.Edges.Added),
		Removed:        touching(r.Edges.Removed),
		Changed:        touching(r.Edges.Changed),
		LostVisibility: touching(r.Edges.LostVisibility),
	}
	return r
}

// truncateReport caps every list at limit and reports whether anything was cut.
func truncateReport(r diff.Report, limit int) (diff.Report, bool) {
	cut := false
	r.Paths = capList(r.Paths, limit, &cut)
	r.Settings = capList(r.Settings, limit, &cut)
	r.Edges.Added = capList(r.Edges.Added, limit, &cut)
	r.Edges.Removed = capList(r.Edges.Removed, limit, &cut)
	r.Edges.Changed = capList(r.Edges.Changed, limit, &cut)
	r.Edges.LostVisibility = capList(r.Edges.LostVisibility, limit, &cut)
	r.Scores = capList(r.Scores, limit, &cut)
	r.Coverage.Opened = capList(r.Coverage.Opened, limit, &cut)
	r.Coverage.Closed = capList(r.Coverage.Closed, limit, &cut)
	return r, cut
}

func capList[S ~[]E, E any](s S, limit int, cut *bool) S {
	if len(s) <= limit {
		return s
	}
	*cut = true
	return s[:limit:limit]
}
