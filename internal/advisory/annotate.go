package advisory

import (
	"fmt"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Stats summarizes one Annotate run.
type Stats struct {
	Actions  int // action_ref nodes checked
	Affected int // nodes that got advisories
	Unknown  int // nodes with an advisory gop could not decide (coverage entries)
}

// Ref is the parsed reference of an action_ref node.
type Ref struct {
	Owner, Repo, Path, Ref string
}

// RefOf reads owner, repo, path and ref from an action_ref node: its attrs
// when the collector set them, else its ID (action:owner/repo[/path]@ref).
func RefOf(n graph.Node) (Ref, bool) {
	r := Ref{Owner: n.Attrs["owner"], Repo: n.Attrs["repo"], Path: n.Attrs["path"], Ref: n.Attrs[graph.AttrRef]}
	if r.Owner != "" && r.Repo != "" && r.Ref != "" {
		return r, true
	}
	uses := strings.TrimPrefix(n.ID, "action:")
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return Ref{}, false
	}
	parts := strings.Split(uses[:at], "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Ref{}, false
	}
	return Ref{Owner: parts[0], Repo: parts[1], Path: strings.Join(parts[2:], "/"), Ref: uses[at+1:]}, true
}

// Annotate matches every action_ref node of g against db. Affected nodes get
// advisories, advisory_severity and (when known) advisory_fixed; a node gop
// cannot place gets a coverage entry. Advisory attrs and coverage from an
// earlier run are replaced, so annotating twice gives the same graph.
func Annotate(g *graph.Graph, db *DB) Stats {
	clearAdvisories(g)
	var st Stats
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != graph.KindActionRef {
			continue
		}
		ref, ok := RefOf(*n)
		if !ok {
			continue
		}
		st.Actions++
		m := db.Match(ref.Owner, ref.Repo, ref.Path, ref.Ref)
		if len(m.Affected) > 0 {
			st.Affected++
			if n.Attrs == nil {
				n.Attrs = map[string]string{}
			}
			n.Attrs[graph.AttrAdvisories] = strings.Join(m.Affected, ",")
			n.Attrs[graph.AttrAdvisorySeverity] = m.Severity
			if m.Fixed != "" {
				n.Attrs[graph.AttrAdvisoryFixed] = m.Fixed
			}
		}
		if len(m.Unknown) > 0 {
			st.Unknown++
			g.Coverage = append(g.Coverage, graph.Coverage{
				Scope:    n.ID,
				Fact:     graph.CoverageAdvisories,
				Reason:   fmt.Sprintf("unknown, not safe: %s: %s", strings.Join(m.Unknown, ", "), m.Why),
				NeedsFix: "pin to a tag or commit SHA the advisory lists as fixed, or check the advisory by hand",
			})
		}
	}
	return st
}

// Skip records that no advisory check ran: one enterprise coverage entry
// saying why. Advisory attrs from an earlier run are removed, since gop can
// no longer vouch for them.
func Skip(g *graph.Graph, reason string) {
	clearAdvisories(g)
	g.Coverage = append(g.Coverage, graph.Coverage{
		Scope:    "enterprise:" + g.Enterprise,
		Fact:     graph.CoverageAdvisories,
		Reason:   "advisory check skipped: " + reason,
		NeedsFix: "run gop advisories update, or pass --advisories <zip|dir> or --advisories-live",
	})
}

func clearAdvisories(g *graph.Graph) {
	for i := range g.Nodes {
		a := g.Nodes[i].Attrs
		delete(a, graph.AttrAdvisories)
		delete(a, graph.AttrAdvisorySeverity)
		delete(a, graph.AttrAdvisoryFixed)
	}
	kept := g.Coverage[:0]
	for _, c := range g.Coverage {
		if c.Fact != graph.CoverageAdvisories {
			kept = append(kept, c)
		}
	}
	g.Coverage = kept
}
