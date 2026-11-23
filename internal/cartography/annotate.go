package cartography

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/oidc"
)

// AnnotateStats summarizes one Annotate call.
type AnnotateStats struct {
	Observed int // CAN_ASSUME edges marked observed_use=true
	Orphans  int // observations no CAN_ASSUME edge matches
}

// Annotate runs after oidc.Enrich over r.Trusts. It marks what came from the
// export and what CloudTrail saw:
//
//   - CAN_ASSUME edges read from r.File get attrs.source=cartography, and a
//     cloud_target any such edge points to gets it too;
//   - for each observation (repo assumed role), every CAN_ASSUME edge from a
//     workflow of that repo into cloud:aws:<role> (from this export or from a
//     trust file) gets observed_use=true, times_used and last_used. Evidence
//     is not changed. An observation that no edge matches is returned as a
//     warning and never becomes an edge.
//
// Observed-use attrs from earlier runs are cleared first, so the latest
// export's observations replace them. The graph is modified in place in a
// deterministic order.
func Annotate(g *graph.Graph, r *Result) ([]string, AnnotateStats) {
	var st AnnotateStats
	fromExport := map[string]bool{}
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind != graph.CanAssume {
			continue
		}
		for _, k := range []string{graph.AttrObservedUse, graph.AttrTimesUsed, graph.AttrLastUsed} {
			delete(e.Attrs, k)
		}
		if e.Attrs[graph.AttrFile] == r.File {
			e.Attrs[graph.AttrSource] = graph.SourceCartography
		}
		if e.Attrs[graph.AttrSource] == graph.SourceCartography {
			fromExport[e.To] = true
		}
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != graph.KindCloudTarget {
			continue
		}
		if fromExport[n.ID] {
			if n.Attrs == nil {
				n.Attrs = map[string]string{}
			}
			n.Attrs[graph.AttrSource] = graph.SourceCartography
		} else if n.Attrs[graph.AttrSource] == graph.SourceCartography {
			delete(n.Attrs, graph.AttrSource)
		}
	}

	// Merge observations of the same repo and role.
	type key struct{ repo, role string }
	merged := map[key]*Observation{}
	var order []key
	for _, o := range r.Observations {
		k := key{strings.ToLower(o.Repo), o.RoleARN}
		m, ok := merged[k]
		if !ok {
			c := o
			merged[k] = &c
			order = append(order, k)
			continue
		}
		m.TimesUsed += o.TimesUsed
		if o.LastUsed > m.LastUsed {
			m.LastUsed = o.LastUsed
		}
	}

	var warnings []string
	for _, k := range order {
		o := merged[k]
		target := oidc.CloudID(oidc.Trust{Provider: oidc.AWS, Target: o.RoleARN})
		hit := false
		for i := range g.Edges {
			e := &g.Edges[i]
			if e.Kind != graph.CanAssume || e.To != target || !strings.EqualFold(edgeRepo(*e), o.Repo) {
				continue
			}
			if e.Attrs == nil {
				e.Attrs = map[string]string{}
			}
			e.Attrs[graph.AttrObservedUse] = "true"
			if o.TimesUsed > 0 {
				e.Attrs[graph.AttrTimesUsed] = strconv.FormatInt(o.TimesUsed, 10)
			}
			if o.LastUsed != "" {
				e.Attrs[graph.AttrLastUsed] = o.LastUsed
			}
			st.Observed++
			hit = true
		}
		if !hit {
			st.Orphans++
			used := ""
			if o.TimesUsed > 0 {
				used = fmt.Sprintf(" %d times", o.TimesUsed)
			}
			if o.LastUsed != "" {
				used += " (last " + o.LastUsed + ")"
			}
			warnings = append(warnings, fmt.Sprintf("%s: row %d: CloudTrail shows %s assumed %s%s, but no CAN_ASSUME edge from a workflow of that repo matches a trust; not added (the repo may be outside the graph, the trust may be missing from the export, or the workflow uses a custom sub template)",
				r.File, o.Row, o.Repo, o.RoleARN, used))
		}
	}
	return warnings, st
}

// edgeRepo is the owner/repo of a CAN_ASSUME edge's workflow: from its oidc
// attr ("oidc:owner/repo"), else from the workflow ID.
func edgeRepo(e graph.Edge) string {
	if r, ok := strings.CutPrefix(e.Attrs[graph.AttrOIDC], "oidc:"); ok && r != "" {
		return r
	}
	rest, ok := strings.CutPrefix(e.From, "workflow:")
	if !ok {
		return ""
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}
