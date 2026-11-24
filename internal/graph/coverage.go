package graph

import (
	"sort"
	"strings"
)

// OrgCoverage summarizes how much of one org's part of the graph is unknown.
// Org is "org:<login>", or "enterprise:<slug>" for facts that belong to no
// org (the enterprise node, identities, external principals and
// enterprise-scope coverage).
type OrgCoverage struct {
	Org             string         `json:"org"`
	NotVisibleNodes int            `json:"not_visible_nodes"`
	NotVisibleEdges int            `json:"not_visible_edges"`
	NotVisibleAttrs int            `json:"not_visible_attrs"`
	Entries         int            `json:"entries"`         // coverage entries scoped to the org or something in it
	Facts           map[string]int `json:"facts,omitempty"` // coverage entries by fact
}

// CoverageSummary counts not_visible nodes, edges and attributes and coverage
// entries per org, sorted by Org. Nodes, attributes and coverage scopes are
// attributed with OrgOf; an edge goes to the org of its source, else of its
// target. Every org node gets an entry, even when it is fully visible; the
// enterprise entry appears only when something is attributed to it.
func CoverageSummary(g *Graph) []OrgCoverage {
	if g == nil {
		return []OrgCoverage{}
	}
	ent := "enterprise:" + g.Enterprise
	by := map[string]*OrgCoverage{}
	get := func(ids ...string) *OrgCoverage {
		key := ent
		for _, id := range ids {
			if o := OrgOf(id); o != "" {
				key = o
				break
			}
		}
		c, ok := by[key]
		if !ok {
			c = &OrgCoverage{Org: key}
			by[key] = c
		}
		return c
	}
	for _, n := range g.Nodes {
		if n.Kind == KindOrg {
			get(n.ID)
		}
		if n.Evidence == NotVisible {
			get(n.ID).NotVisibleNodes++
		}
		for _, ev := range n.AttrEvidence {
			if ev == NotVisible {
				get(n.ID).NotVisibleAttrs++
			}
		}
	}
	for _, e := range g.Edges {
		if e.Evidence == NotVisible {
			get(e.From, e.To).NotVisibleEdges++
		}
	}
	for _, c := range g.Coverage {
		oc := get(c.Scope)
		oc.Entries++
		if oc.Facts == nil {
			oc.Facts = map[string]int{}
		}
		oc.Facts[c.Fact]++
	}
	out := make([]OrgCoverage, 0, len(by))
	for _, c := range by {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Org < out[j].Org })
	return out
}

// Caveat texts on fix suggestions and what-if results.
const caveatNestedUnknown = "nested references not visible: the pin may not close every path"

// CaveatReduceOwners travels with every ReduceOwners suggestion: owner work
// still needs owners, so the fix is to grant it on demand.
const CaveatReduceOwners = "prefer just-in-time ownership (owner access granted on demand and removed after) over standing ownership; " +
	"the kept owners and anyone with owner access granted later still hold this reach"

// fixCaveat returns what gop could not see that may make f less effective
// than computed: a PinRef on an action whose nested references are unknown
// (nested=unknown) may leave mutable references inside it. A ReduceOwners
// always carries CaveatReduceOwners. "" if none.
func fixCaveat(ix *Index, f Fix) string {
	if _, ok := f.(ReduceOwners); ok {
		return CaveatReduceOwners
	}
	if p, ok := f.(PinRef); ok {
		if n, ok := ix.nodes[p.Action]; ok && n.Attrs["nested"] == "unknown" {
			return caveatNestedUnknown
		}
	}
	return ""
}

// fixCaveats returns "<fix id>: <caveat>" for every fix with a caveat, in order.
func fixCaveats(ix *Index, fixes []Fix) []string {
	var out []string
	for _, f := range fixes {
		if c := fixCaveat(ix, f); c != "" {
			out = append(out, strings.Join([]string{f.ID(), c}, ": "))
		}
	}
	return out
}
