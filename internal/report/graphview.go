package report

import (
	"sort"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// The Graph tab draws the union of the filtered paths as a layered
// left-to-right diagram. The layout is computed here, once, over the union of
// every embedded path: each node gets a layer (longest path from a principal)
// and an order inside its layer (barycenter sweeps to reduce crossings). Any
// subset of the paths keeps every edge pointing right under that layering, so
// the script only drops the nodes it does not show, closes empty layers and
// assigns coordinates. No layout engine runs in the browser.

// graphMaxNodes caps the nodes the Graph tab draws; above it the tab asks the
// reader to narrow the filter.
const graphMaxNodes = 300

// graphWhatIfFixes is how many suggested fixes get precomputed what-if data
// for the "simulate pin" toggle.
const graphWhatIfFixes = 10

// barycenterSweeps is the number of down-then-up ordering passes.
const barycenterSweeps = 4

type embGraph struct {
	MaxNodes int         `json:"max_nodes"`
	Nodes    []embGNode  `json:"nodes"`
	Edges    []embGEdge  `json:"edges"`
	WhatIf   []embWhatIf `json:"what_if"`
}

// embGNode is one node of the union of embedded paths with its layout.
type embGNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Layer int    `json:"layer"`
	Order int    `json:"order"`
}

// embGEdge is one distinct hop of the embedded paths, in control direction,
// with the evidence edge behind it: its API, when it was observed and its
// attrs (file and line for USES and EXECUTES_WITH when the collector saw
// them). Rev says the evidence edge points the other way.
type embGEdge struct {
	From  string            `json:"from"`
	To    string            `json:"to"`
	Kind  string            `json:"kind"`
	Ev    string            `json:"ev"`
	API   string            `json:"api,omitempty"`
	At    string            `json:"at,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
	Rev   bool              `json:"rev,omitempty"`
	// Stale marks an audit fact older than the audit age limit: the engine
	// demoted the hop to not visible, so its paths are possible only.
	Stale bool `json:"stale,omitempty"`
}

// embWhatIf is the precomputed effect of one suggested fix applied on its
// own: the indexes into embedded.Paths of the paths it removes. A confirmed
// path is removed when its target is no longer confirmed reach of its
// principal; a possible path when its target is no longer reached at all.
type embWhatIf struct {
	Fix     string `json:"fix"`
	Kind    string `json:"kind"` // pin | default_perm | restrict_token | harden_trigger
	Node    string `json:"node,omitempty"`
	Desc    string `json:"desc"`
	Removed []int  `json:"removed"`
}

// evLabel is the evidence label the Graph tab shows. A class this build
// does not know (a newer schema) keeps its own name instead of being folded
// into "not visible"; the script styles it as unclassified.
func evLabel(ev graph.Evidence) string {
	switch ev {
	case graph.Live, graph.Inferred, graph.Audit, graph.Supplied, graph.NotVisible, "":
		return mcpserver.EvidenceLabel(ev)
	}
	return string(ev)
}

func buildGraphView(ix *graph.Index, paths []embPath, fixes []graph.FixSuggestion) embGraph {
	gv := embGraph{MaxNodes: graphMaxNodes, Nodes: []embGNode{}, Edges: []embGEdge{}, WhatIf: []embWhatIf{}}
	type key struct{ from, to, kind string }
	seenEdge := map[key]bool{}
	firstPos := map[string]int{}
	var ids []string
	addNode := func(id string) {
		if _, ok := firstPos[id]; !ok {
			firstPos[id] = len(ids)
			ids = append(ids, id)
		}
	}
	var edges []embGEdge
	for _, p := range paths {
		for _, h := range p.Hops {
			addNode(h.From)
			addNode(h.To)
			k := key{h.From, h.To, h.Kind}
			if seenEdge[k] {
				continue
			}
			seenEdge[k] = true
			edges = append(edges, hopEdge(ix, h))
		}
	}
	layer, order := layout(ids, edges)
	for _, id := range ids {
		gv.Nodes = append(gv.Nodes, embGNode{ID: id, Kind: string(ix.Kind(id)), Layer: layer[id], Order: order[id]})
	}
	sort.Slice(gv.Nodes, func(i, j int) bool {
		a, b := gv.Nodes[i], gv.Nodes[j]
		if a.Layer != b.Layer {
			return a.Layer < b.Layer
		}
		return a.Order < b.Order
	})
	if edges != nil {
		gv.Edges = edges
	}
	gv.WhatIf = whatIfPaths(ix, paths, fixes)
	return gv
}

// hopEdge finds the evidence edge behind a hop for its observed_at and
// attrs. The evidence shown is the hop's: the engine may weaken an edge (an
// unknown gate makes it not visible). A hop the engine derives (a ref bypass)
// may have no single edge; it keeps the hop's own fields.
func hopEdge(ix *graph.Index, h embHop) embGEdge {
	ge := embGEdge{From: h.From, To: h.To, Kind: h.Kind, Ev: evLabel(h.raw), API: h.API, Rev: h.Rev, Stale: h.stale}
	if h.stale {
		ge.Ev = h.Ev // "audit, stale"
	}
	from, to := h.From, h.To
	if h.Rev {
		from, to = to, from
	}
	alt := ""
	if h.Kind == string(graph.MemberOf) && ix.Kind(to) == graph.KindOrgMembers {
		alt = graph.OrgOf(to) // the evidence edge is identity MEMBER_OF org:X; the hop is to members:X
	}
	var match *graph.Edge
	for _, e := range ix.Out(from) {
		if (e.To != to && (alt == "" || e.To != alt)) || string(e.Kind) != h.Kind {
			continue
		}
		if match == nil || (match.SourceAPI != h.API && e.SourceAPI == h.API) {
			e := e
			match = &e
		}
	}
	if match == nil {
		return ge
	}
	if ge.API == "" {
		ge.API = match.SourceAPI
	}
	if !match.ObservedAt.IsZero() {
		ge.At = match.ObservedAt.UTC().Format(time.RFC3339)
	}
	if len(match.Attrs) > 0 {
		ge.Attrs = make(map[string]string, len(match.Attrs))
		for k, v := range match.Attrs {
			ge.Attrs[k] = v
		}
	}
	return ge
}

// layout assigns every node a layer and an order inside its layer. ids are
// in first-seen order over the ranked paths, which seeds the order.
//
// Layers: longest path over the union of hops, so every drawn edge points
// right. The union of shortest paths can still hold a cycle (a workflow that
// pushes to the repo that defines it, reached from two principals); Kahn's
// algorithm then breaks it at the earliest-seen remaining node, and the hops
// into that node from later layers are drawn as back edges.
//
// Order: barycenter sweeps, down then up, each node placed at the mean
// order of its neighbours in the layer before (or after); ties keep the
// previous order.
func layout(ids []string, edges []embGEdge) (layer, order map[string]int) {
	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		pos[id] = i
	}
	in := map[string][]string{}
	out := map[string][]string{}
	indeg := make(map[string]int, len(ids))
	for _, e := range edges {
		if e.From == e.To {
			continue
		}
		out[e.From] = append(out[e.From], e.To)
		in[e.To] = append(in[e.To], e.From)
		indeg[e.To]++
	}
	layer = make(map[string]int, len(ids))
	done := make(map[string]bool, len(ids))
	var ready []string
	for _, id := range ids {
		if indeg[id] == 0 {
			ready = append(ready, id)
		}
	}
	byPos := func(s []string) { sort.Slice(s, func(i, j int) bool { return pos[s[i]] < pos[s[j]] }) }
	for len(done) < len(ids) {
		if len(ready) == 0 {
			for _, id := range ids {
				if !done[id] {
					ready = append(ready, id)
					break
				}
			}
		}
		byPos(ready)
		id := ready[0]
		ready = ready[1:]
		if done[id] {
			continue
		}
		done[id] = true
		l := 0
		for _, p := range in[id] {
			if done[p] && p != id && layer[p]+1 > l {
				l = layer[p] + 1
			}
		}
		layer[id] = l
		for _, n := range out[id] {
			if done[n] {
				continue
			}
			indeg[n]--
			if indeg[n] == 0 {
				ready = append(ready, n)
			}
		}
	}

	maxLayer := 0
	for _, l := range layer {
		if l > maxLayer {
			maxLayer = l
		}
	}
	layers := make([][]string, maxLayer+1)
	for _, id := range ids {
		layers[layer[id]] = append(layers[layer[id]], id)
	}
	order = make(map[string]int, len(ids))
	for _, ls := range layers {
		for i, id := range ls {
			order[id] = i
		}
	}
	sweep := func(l int, nb map[string][]string, want func(int) bool) {
		ls := layers[l]
		bary := make(map[string]float64, len(ls))
		for _, id := range ls {
			sum, n := 0.0, 0
			for _, o := range nb[id] {
				if want(layer[o]) {
					sum += float64(order[o])
					n++
				}
			}
			if n == 0 {
				bary[id] = float64(order[id])
			} else {
				bary[id] = sum / float64(n)
			}
		}
		sort.SliceStable(ls, func(i, j int) bool {
			a, b := ls[i], ls[j]
			if bary[a] != bary[b] {
				return bary[a] < bary[b]
			}
			return order[a] < order[b]
		})
		for i, id := range ls {
			order[id] = i
		}
	}
	for s := 0; s < barycenterSweeps; s++ {
		if s%2 == 0 {
			for l := 1; l <= maxLayer; l++ {
				l := l
				sweep(l, in, func(o int) bool { return o < l })
			}
		} else {
			for l := maxLayer - 1; l >= 0; l-- {
				l := l
				sweep(l, out, func(o int) bool { return o > l })
			}
		}
	}
	return layer, order
}

// whatIfPaths applies each of the top suggested fixes on its own and lists
// the embedded paths it removes. The pairs it reports are the engine's: a
// confirmed path is removed exactly when WhatIf counts its target as no
// longer confirmed for that principal.
func whatIfPaths(ix *graph.Index, paths []embPath, fixes []graph.FixSuggestion) []embWhatIf {
	out := []embWhatIf{}
	byPrincipal := map[string][]int{}
	var order []string
	for i, p := range paths {
		if _, ok := byPrincipal[p.From]; !ok {
			order = append(order, p.From)
		}
		byPrincipal[p.From] = append(byPrincipal[p.From], i)
	}
	if len(fixes) > graphWhatIfFixes {
		fixes = fixes[:graphWhatIfFixes]
	}
	for _, f := range fixes {
		kind, node := fixTarget(f.Fix)
		_, desc := mcpserver.DescribeFix(f.Fix)
		w := embWhatIf{Fix: f.FixID, Kind: kind, Node: node, Desc: desc, Removed: []int{}}
		for _, pr := range order {
			after := ix.Reach(pr, graph.Options{Fixes: []graph.Fix{f.Fix}})
			for _, i := range byPrincipal[pr] {
				p := paths[i]
				ap, ok := after.Paths[p.To]
				if !ok || (p.Ev == "confirmed" && ap.Unverified) {
					w.Removed = append(w.Removed, i)
				}
			}
		}
		sort.Ints(w.Removed)
		out = append(out, w)
	}
	return out
}

// fixTarget names a fix's kind and the node the Graph tab attaches it to.
func fixTarget(f graph.Fix) (kind, node string) {
	switch v := f.(type) {
	case graph.PinRef:
		return "pin", v.Action
	case graph.LowerDefaultPerm:
		return "default_perm", v.Org
	case graph.RestrictToken:
		return "restrict_token", v.Workflow
	case graph.HardenTrigger:
		return "harden_trigger", v.Workflow
	}
	return "other", ""
}
