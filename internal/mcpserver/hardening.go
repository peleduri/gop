package mcpserver

import (
	"sort"

	"github.com/peleduri/gop/internal/graph"
)

// Hardening context: the SSO and IP allow list settings of the org a path
// ends in, attached after reach is computed. It is context only and never
// feeds evidence, counts, scores or rank order.

// harden returns a copy of ps where each path whose target org is weak or
// unknown carries TargetOrgHardening. The input slice (which may be cached
// by the index) is not modified.
func (e *Engine) harden(ps []graph.Path) []graph.Path {
	if ps == nil {
		return nil
	}
	out := make([]graph.Path, len(ps))
	for i, p := range ps {
		p.TargetOrgHardening = e.ix.TargetOrgHardening(p)
		out[i] = p
	}
	return out
}

// weakTargetOrgs lists, sorted by org ID, the weak or unknown target orgs of
// the confirmed and possible paths of the given principals.
func (e *Engine) weakTargetOrgs(principals []string) []graph.OrgHardening {
	seen := map[string]graph.OrgHardening{}
	for _, pr := range principals {
		for _, p := range e.ix.Reach(pr, graph.Options{}).Paths {
			if h := e.ix.TargetOrgHardening(p); h != nil {
				seen[h.Org] = *h
			}
		}
	}
	out := make([]graph.OrgHardening, 0, len(seen))
	for _, h := range seen {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Org < out[j].Org })
	return out
}
