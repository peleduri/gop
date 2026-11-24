package advisory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Stats summarizes one Annotate run.
type Stats struct {
	Actions  int // action_ref nodes checked
	Affected int // nodes whose ref got advisories
	Unknown  int // nodes with an advisory gop could not decide (coverage entries)
	// LockAffected counts USES edges whose actions.lock commit (locked_sha)
	// an advisory lists as affected.
	LockAffected int
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
// cannot place gets a coverage entry. A USES edge that an actions.lock pins
// (actions_lock=locked) is matched on its locked_sha too: an affected commit
// sets lock_advisories, lock_advisory_severity and lock_advisory_fixed on
// the edge (never on the node, whose attrs stay the ref-level match), and a
// commit the advisory does not list gets a coverage entry. Advisory attrs
// and coverage from an earlier run are replaced, so annotating twice gives
// the same graph.
func Annotate(g *graph.Graph, db *DB) Stats {
	clearAdvisories(g)
	locked := map[string]map[string][]int{} // action -> locked_sha -> edge indexes
	for i, e := range g.Edges {
		sha := e.Attrs[graph.AttrLockedSHA]
		if e.Kind != graph.Uses || e.Attrs[graph.AttrActionsLock] != graph.LockLocked || sha == "" {
			continue
		}
		if locked[e.To] == nil {
			locked[e.To] = map[string][]int{}
		}
		locked[e.To][sha] = append(locked[e.To][sha], i)
	}
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
		unknown := len(m.Unknown) > 0
		if unknown {
			g.Coverage = append(g.Coverage, graph.Coverage{
				Scope:    n.ID,
				Fact:     graph.CoverageAdvisories,
				Reason:   fmt.Sprintf("unknown, not safe: %s: %s", strings.Join(m.Unknown, ", "), m.Why),
				NeedsFix: "pin to a tag or commit SHA the advisory lists as fixed, or check the advisory by hand",
			})
		}
		shas := make([]string, 0, len(locked[n.ID]))
		for sha := range locked[n.ID] {
			shas = append(shas, sha)
		}
		sort.Strings(shas)
		for _, sha := range shas {
			edges := locked[n.ID][sha]
			lm := db.Match(ref.Owner, ref.Repo, ref.Path, sha)
			if len(lm.Affected) > 0 {
				for _, ei := range edges {
					a := g.Edges[ei].Attrs
					a[graph.AttrLockAdvisories] = strings.Join(lm.Affected, ",")
					a[graph.AttrLockAdvisorySeverity] = lm.Severity
					if lm.Fixed != "" {
						a[graph.AttrLockAdvisoryFixed] = lm.Fixed
					}
				}
				st.LockAffected += len(edges)
			}
			if len(lm.Unknown) > 0 {
				unknown = true
				g.Coverage = append(g.Coverage, graph.Coverage{
					Scope:    n.ID,
					Fact:     graph.CoverageAdvisories,
					Reason:   fmt.Sprintf("unknown, not safe: actions.lock pins it to %s (%d uses): %s: %s", sha, len(edges), strings.Join(lm.Unknown, ", "), lm.Why),
					NeedsFix: "check the locked commit against the advisory by hand, or move to a version the advisory lists as fixed and rerun gh actions-lock",
				})
			}
		}
		if unknown {
			st.Unknown++
		}
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
	for i := range g.Edges {
		delete(g.Edges[i].Attrs, graph.AttrLockAdvisories)
		delete(g.Edges[i].Attrs, graph.AttrLockAdvisorySeverity)
		delete(g.Edges[i].Attrs, graph.AttrLockAdvisoryFixed)
	}
	kept := g.Coverage[:0]
	for _, c := range g.Coverage {
		if c.Fact != graph.CoverageAdvisories {
			kept = append(kept, c)
		}
	}
	g.Coverage = kept
}
