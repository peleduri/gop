package report

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

func acmeEmbedded(t *testing.T) (*graph.Index, embedded) {
	t.Helper()
	var e embedded
	if err := json.Unmarshal([]byte(embeddedJSON(t, render(t, loadAcme(t), "html"))), &e); err != nil {
		t.Fatal(err)
	}
	return graph.NewIndex(loadAcme(t)), e
}

// TestGraphLayoutInput checks the layout the Go side embeds: one node per
// path node, one edge per distinct hop, every edge pointing right, each
// layer's order a permutation, and the evidence edge's details attached.
func TestGraphLayoutInput(t *testing.T) {
	_, e := acmeEmbedded(t)
	gv := e.Graph
	if gv.MaxNodes != graphMaxNodes {
		t.Errorf("max_nodes = %d, want %d", gv.MaxNodes, graphMaxNodes)
	}
	nodes := map[string]embGNode{}
	for _, n := range gv.Nodes {
		if _, dup := nodes[n.ID]; dup {
			t.Errorf("node %s listed twice", n.ID)
		}
		nodes[n.ID] = n
	}
	edges := map[string]embGEdge{}
	for _, ge := range gv.Edges {
		edges[ge.From+" "+ge.Kind+" "+ge.To] = ge
	}
	want := map[string]bool{}
	for _, p := range e.Paths {
		for _, h := range p.Hops {
			want[h.From], want[h.To] = true, true
			ge, ok := edges[h.From+" "+h.Kind+" "+h.To]
			if !ok {
				t.Errorf("hop %s %s %s has no graph edge", h.From, h.Kind, h.To)
				continue
			}
			if ge.Rev != h.Rev || ge.Ev != h.Ev {
				t.Errorf("edge %+v does not match hop %+v", ge, h)
			}
		}
	}
	if len(want) != len(nodes) {
		t.Errorf("%d graph nodes, %d path nodes", len(nodes), len(want))
	}
	perLayer := map[int][]int{}
	for id, n := range nodes {
		if !want[id] {
			t.Errorf("graph node %s is on no path", id)
		}
		perLayer[n.Layer] = append(perLayer[n.Layer], n.Order)
	}
	for l, os := range perLayer {
		sort.Ints(os)
		for i, o := range os {
			if o != i {
				t.Errorf("layer %d orders %v are not 0..%d", l, os, len(os)-1)
				break
			}
		}
	}
	for _, ge := range gv.Edges {
		if nodes[ge.From].Layer >= nodes[ge.To].Layer {
			t.Errorf("edge %s -> %s points left: layers %d -> %d", ge.From, ge.To, nodes[ge.From].Layer, nodes[ge.To].Layer)
		}
	}
	// Principals open the diagram; the planted cross-org path runs right.
	for _, id := range []string{"identity:bob", "members:acme-legacy"} {
		if nodes[id].Layer != 0 {
			t.Errorf("%s in layer %d, want 0", id, nodes[id].Layer)
		}
	}
	chain := []string{"members:acme-actions", "repo:acme-actions/deploy", "action:acme-actions/deploy@main",
		"workflow:acme-app/web/.github/workflows/ci.yml", "oidc:acme-app/web"}
	for i := 1; i < len(chain); i++ {
		if nodes[chain[i-1]].Layer >= nodes[chain[i]].Layer {
			t.Errorf("%s (layer %d) is not left of %s (layer %d)", chain[i-1], nodes[chain[i-1]].Layer, chain[i], nodes[chain[i]].Layer)
		}
	}

	nv := edges["members:acme-legacy CAN_PUSH repo:acme-legacy/old-api"]
	if nv.Ev != "not visible" || nv.API == "" || nv.At == "" {
		t.Errorf("not visible hop = %+v, want evidence not visible with its source", nv)
	}
	rev := edges["repo:acme-actions/deploy RESOLVES_TO action:acme-actions/deploy@main"]
	if !rev.Rev || rev.At == "" {
		t.Errorf("reversed hop = %+v, want rev with observed_at", rev)
	}
	uses := edges["action:acme-actions/deploy@main USES workflow:acme-app/web/.github/workflows/ci.yml"]
	if uses.Attrs["ref_kind"] != "branch" {
		t.Errorf("USES hop attrs = %v, want the evidence edge's attrs", uses.Attrs)
	}

	// Deterministic: the same graph gives the same layout.
	_, again := acmeEmbedded(t)
	if !reflect.DeepEqual(again.Graph, e.Graph) {
		t.Error("layout differs between two renders of the same graph")
	}
}

// TestLayoutBarycenter: a crossing the seed order puts in is removed.
func TestLayoutBarycenter(t *testing.T) {
	ids := []string{"a", "b", "x", "y"}
	edges := []embGEdge{{From: "a", To: "y"}, {From: "b", To: "x"}}
	layer, order := layout(ids, edges)
	if layer["a"] != 0 || layer["b"] != 0 || layer["x"] != 1 || layer["y"] != 1 {
		t.Fatalf("layers %v", layer)
	}
	if (order["a"] < order["b"]) != (order["y"] < order["x"]) {
		t.Errorf("edges still cross: order %v", order)
	}
}

// TestLayoutCycle: a cycle in the union of paths still gets a layer for
// every node, and only the hop that closes the cycle points left.
func TestLayoutCycle(t *testing.T) {
	ids := []string{"p", "q", "repo", "wf", "oidc"}
	edges := []embGEdge{
		{From: "p", To: "repo"}, {From: "repo", To: "wf"}, {From: "wf", To: "oidc"},
		{From: "q", To: "wf"}, {From: "wf", To: "repo"},
	}
	layer, order := layout(ids, edges)
	if len(layer) != len(ids) || len(order) != len(ids) {
		t.Fatalf("layer %v order %v", layer, order)
	}
	left := 0
	for _, e := range edges {
		if layer[e.From] >= layer[e.To] {
			left++
		}
	}
	if left != 1 {
		t.Errorf("%d edges point left, want only the one closing the cycle: %v", left, layer)
	}
}

// TestGraphWhatIfMatchesEngine: for each precomputed fix, the confirmed
// paths it greys are exactly the confirmed pairs WhatIf says it removes,
// per principal and per target kind.
func TestGraphWhatIfMatchesEngine(t *testing.T) {
	for name, g := range map[string]*graph.Graph{
		"acme": loadAcme(t),
		"demo": demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}),
	} {
		t.Run(name, func(t *testing.T) {
			var e embedded
			if err := json.Unmarshal([]byte(embeddedJSON(t, render(t, g, "html"))), &e); err != nil {
				t.Fatal(err)
			}
			if len(e.Truncated) != 0 {
				t.Fatal("paths truncated: the comparison needs every pair embedded")
			}
			ix := graph.NewIndex(g)
			sugg := ix.SuggestFixes(graphWhatIfFixes)
			if len(e.Graph.WhatIf) != len(sugg) {
				t.Fatalf("%d what-if entries, want the top %d suggested fixes", len(e.Graph.WhatIf), len(sugg))
			}
			for i, w := range e.Graph.WhatIf {
				f := sugg[i]
				if w.Fix != f.FixID {
					t.Fatalf("what-if %d is %s, want %s", i, w.Fix, f.FixID)
				}
				got := map[string]*graph.Counts{}
				for _, pi := range w.Removed {
					p := e.Paths[pi]
					if p.Ev != "confirmed" {
						continue
					}
					c := got[p.From]
					if c == nil {
						c = &graph.Counts{}
						got[p.From] = c
					}
					switch p.ToKind {
					case "repo":
						c.Repos++
					case "oidc":
						c.OIDC++
					case "secret":
						c.Secrets++
					case "runner":
						c.Runners++
					case "cloud":
						c.CloudTargets++
					}
				}
				for _, pd := range ix.WhatIf([]graph.Fix{f.Fix}).PerPrincipal {
					b, a := pd.Before.Confirmed, pd.After.Confirmed
					want := graph.Counts{Repos: b.Repos - a.Repos, OIDC: b.OIDC - a.OIDC, Secrets: b.Secrets - a.Secrets,
						Runners: b.Runners - a.Runners, CloudTargets: b.CloudTargets - a.CloudTargets}
					var have graph.Counts
					if c := got[pd.Principal]; c != nil {
						have = *c
					}
					if have.Repos != want.Repos || have.OIDC != want.OIDC || have.Secrets != want.Secrets ||
						have.Runners != want.Runners || have.CloudTargets != want.CloudTargets {
						t.Errorf("%s %s: greyed confirmed %+v, WhatIf removes %+v", w.Fix, pd.Principal, have, want)
					}
				}
			}
		})
	}
}

// TestGraphPinOnDeployMain is the acceptance case: the pin on
// action:acme-actions/deploy@main greys exactly the paths through that ref.
func TestGraphPinOnDeployMain(t *testing.T) {
	_, e := acmeEmbedded(t)
	var w *embWhatIf
	for i := range e.Graph.WhatIf {
		if e.Graph.WhatIf[i].Fix == "pin:action:acme-actions/deploy@main" {
			w = &e.Graph.WhatIf[i]
		}
	}
	if w == nil || w.Kind != "pin" || w.Node != "action:acme-actions/deploy@main" {
		t.Fatalf("pin what-if = %+v", w)
	}
	var through []int
	for i, p := range e.Paths {
		for _, h := range p.Hops {
			if h.From == w.Node || h.To == w.Node {
				through = append(through, i)
				break
			}
		}
	}
	if !reflect.DeepEqual(w.Removed, through) {
		t.Errorf("pin removes paths %v, want the paths through the ref %v", w.Removed, through)
	}
}

// TestGraphUnknownEvidence: an evidence class this build does not know
// (a newer schema's) keeps its name in the Graph tab instead of turning into
// "not visible", and the script draws it as unclassified.
func TestGraphUnknownEvidence(t *testing.T) {
	if got := evLabel("speculative"); got != "speculative" {
		t.Errorf("evLabel(speculative) = %q", got)
	}
	for ev, want := range map[graph.Evidence]string{graph.Live: "live", graph.Inferred: "inferred", graph.Audit: "audit", graph.Supplied: "supplied file", graph.NotVisible: "not visible"} {
		if got := evLabel(ev); got != want {
			t.Errorf("evLabel(%s) = %q, want %q", ev, got, want)
		}
	}
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	g := &graph.Graph{Schema: "gop.graph/v1", CollectedAt: at,
		Nodes: []graph.Node{{ID: "org:acme", Kind: graph.KindOrg}, {ID: "members:acme", Kind: graph.KindOrgMembers}, {ID: "repo:acme/app", Kind: graph.KindRepo}},
		Edges: []graph.Edge{{From: "members:acme", To: "repo:acme/app", Kind: graph.CanPush, Evidence: "speculative", SourceAPI: "rest:/orgs/{org}", ObservedAt: at,
			Attrs: map[string]string{"rule": "default_perm"}}}}
	ix := graph.NewIndex(g)
	e := buildEmbedded(ix, g, ix.Scores(), nil, maxPathsPerOrg)
	if len(e.Graph.Edges) != 1 || e.Graph.Edges[0].Ev != "speculative" || e.Graph.Edges[0].Attrs["rule"] != "default_perm" {
		t.Errorf("graph edges = %+v, want the unknown-class edge with its own label and attrs", e.Graph.Edges)
	}
	for _, want := range []string{`"supplied file":"supplied"}[ev]||"other"`, `other:"•"`} {
		if !strings.Contains(scriptJS, want) {
			t.Errorf("script does not fall back for unknown evidence: missing %q", want)
		}
	}
	if !strings.Contains(styleCSS, ".e-other path{") || !strings.Contains(styleCSS, "\n.other{") {
		t.Error("no style for unknown evidence")
	}
}

// TestGraphStaleAudit: an audit fact older than the audit age limit is a
// stale hop in the Graph tab, labelled "audit, stale", not plain audit.
func TestGraphStaleAudit(t *testing.T) {
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	old := at.AddDate(0, 0, -200)
	g := &graph.Graph{Schema: graph.SchemaVersion, CollectedAt: at,
		Nodes: []graph.Node{{ID: "org:acme", Kind: graph.KindOrg}, {ID: "identity:alice", Kind: graph.KindIdentity}, {ID: "repo:acme/app", Kind: graph.KindRepo}},
		Edges: []graph.Edge{{From: "identity:alice", To: "repo:acme/app", Kind: graph.CanPush, Evidence: graph.Audit, SourceAPI: "audit:repo.add_member", ObservedAt: old}}}
	ix := graph.NewIndex(g)
	e := buildEmbedded(ix, g, ix.Scores(), nil, maxPathsPerOrg)
	if len(e.Graph.Edges) != 1 {
		t.Fatalf("graph edges = %+v", e.Graph.Edges)
	}
	ge := e.Graph.Edges[0]
	if !ge.Stale || ge.Ev != "audit, stale" || ge.At == "" {
		t.Errorf("stale audit edge = %+v, want stale with label audit, stale", ge)
	}
	if len(e.Paths) != 1 || e.Paths[0].Ev != "possible" {
		t.Errorf("paths = %+v, want one possible path", e.Paths)
	}
	if !strings.Contains(styleCSS, ".e-stale path{") {
		t.Error("no style for stale hops")
	}
}

// graphHarness is what epilogue.js prints for the Graph tab.
type graphHarness struct {
	All, Pinned, Picked graphState
	HashAfterPick       string
	FocusedAfterPick    string
	EnterPrevented      bool
	HashAfterEnter      string
	AfterArrow          struct {
		Hash       string
		ListHidden bool
		Focused    bool
	}
	InferredClass string
	UnknownClass  string
	StaleClass    string
	StaleText     string
	ReversedText  string
	CapOver       bool
}

type graphState struct {
	Status      string
	ListHidden  bool
	GraphHidden bool
	TabSelected string
	SVG         *struct{ NS, Role, Label, Describedby string }
	Nodes       []struct{ ID, Cls, Tabindex, Role, Label, Pressed, Text string }
	Edges       []struct{ Title, Cls, Q string }
	Text        []struct {
		I    int
		Text string
	}
	Pins       []string
	PinsHidden bool
}

func (s graphState) edge(from, to string) (cls, q string, ok bool) {
	for _, e := range s.Edges {
		if strings.HasPrefix(e.Title, from+" → "+to+"\n") {
			return e.Cls, e.Q, true
		}
	}
	return "", "", false
}

// checkGraphTab checks the Graph tab as the script rendered it on the acme
// report (TestInlineScriptInNode).
func checkGraphTab(t *testing.T, raw json.RawMessage, data string) {
	t.Helper()
	var h graphHarness
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("graph harness output: %v\n%s", err, raw)
	}
	var e embedded
	if err := json.Unmarshal([]byte(data), &e); err != nil {
		t.Fatal(err)
	}
	a := h.All
	if !a.ListHidden || a.GraphHidden || a.TabSelected != "true" {
		t.Errorf("#view=graph: list hidden %v, graph hidden %v, tab selected %q", a.ListHidden, a.GraphHidden, a.TabSelected)
	}
	if a.SVG == nil {
		t.Fatalf("no SVG drawn; status %q", a.Status)
	}
	if a.SVG.NS != svgNS || a.SVG.Role != "group" || a.SVG.Label == "" || a.SVG.Describedby != "gop-graph-text" {
		t.Errorf("SVG text alternative: %+v", *a.SVG)
	}
	if len(a.Nodes) != len(e.Graph.Nodes) || len(a.Edges) != len(e.Graph.Edges) {
		t.Errorf("drew %d nodes and %d edges, want %d and %d", len(a.Nodes), len(a.Edges), len(e.Graph.Nodes), len(e.Graph.Edges))
	}
	for _, n := range a.Nodes {
		if n.Tabindex != "0" || n.Role != "button" || !strings.HasPrefix(n.Label, n.ID+": ") || n.Pressed != "false" || n.Text == "" {
			t.Errorf("node not keyboard accessible: %+v", n)
		}
	}
	if len(a.Text) != len(e.Paths) {
		t.Errorf("text alternative lists %d paths, want %d", len(a.Text), len(e.Paths))
	}
	// The planted cross-org path, live hops solid.
	// members:acme-actions → deploy is a default-permission push: inferred.
	if cls, _, ok := a.edge("members:acme-actions", "repo:acme-actions/deploy"); !ok || !strings.Contains(cls, "e-inferred") {
		t.Errorf("inferred hop: drawn %v, class %q, want e-inferred", ok, cls)
	}
	for _, hop := range [][2]string{
		{"identity:bob", "repo:acme-actions/deploy"},
		{"repo:acme-actions/deploy", "action:acme-actions/deploy@main"},
		{"action:acme-actions/deploy@main", "workflow:acme-app/web/.github/workflows/ci.yml"},
		{"workflow:acme-app/web/.github/workflows/ci.yml", "oidc:acme-app/web"},
	} {
		if cls, _, ok := a.edge(hop[0], hop[1]); !ok || !strings.Contains(cls, "e-live") {
			t.Errorf("cross-org hop %s → %s: drawn %v, class %q", hop[0], hop[1], ok, cls)
		}
	}
	if cls, q, ok := a.edge("members:acme-legacy", "repo:acme-legacy/old-api"); !ok || !strings.Contains(cls, "e-nv") || q != "?" {
		t.Errorf("not visible hop: drawn %v, class %q, mark %q; want e-nv with ?", ok, cls, q)
	}
	if cls, _, ok := a.edge("repo:acme-legacy/old-api", "workflow:acme-legacy/old-api/.github/workflows/ci.yml"); !ok || !strings.Contains(cls, "e-audit") {
		t.Errorf("audit hop class %q", cls)
	}
	for _, ed := range a.Edges {
		if strings.Contains(ed.Title, "RESOLVES_TO") && !strings.Contains(ed.Title, "Drawn in control direction") {
			t.Errorf("reversed hop tooltip does not explain the reversal: %q", ed.Title)
		}
		if !strings.Contains(ed.Title, "source_api: ") || !strings.Contains(ed.Title, "observed_at: ") {
			t.Errorf("hop tooltip lacks source_api or observed_at: %q", ed.Title)
		}
	}
	if a.PinsHidden || !contains(a.Pins, "pin:action:acme-actions/deploy@main") || !contains(a.Pins, "") {
		t.Errorf("pin options %v (hidden %v)", a.Pins, a.PinsHidden)
	}

	// Simulate pin: the greyed paths are exactly the embedded what-if.
	var want []int
	for _, w := range e.Graph.WhatIf {
		if w.Fix == "pin:action:acme-actions/deploy@main" {
			want = w.Removed
		}
	}
	var greyed []int
	for _, x := range h.Pinned.Text {
		if strings.Contains(x.Text, "Removed by the simulated pin.") {
			greyed = append(greyed, x.I)
		}
	}
	sort.Ints(greyed)
	if len(want) == 0 || !reflect.DeepEqual(greyed, want) {
		t.Errorf("simulated pin greys paths %v, what-if says %v", greyed, want)
	}
	if !strings.Contains(h.Pinned.Status, "Simulating pin:action:acme-actions/deploy@main: "+strconv.Itoa(len(want))+" of ") {
		t.Errorf("pinned status %q", h.Pinned.Status)
	}
	for _, n := range h.Pinned.Nodes {
		if n.ID == "action:acme-actions/deploy@main" && !strings.Contains(n.Cls, "off") {
			t.Errorf("pinned ref node not greyed: %q", n.Cls)
		}
		if n.ID == "members:acme-legacy" && strings.Contains(n.Cls, "off") {
			t.Error("a node the pin does not touch is greyed")
		}
	}

	// Click a node: filter to the paths through it, shareable in the hash.
	if h.HashAfterPick != "#via=action%3Aacme-actions%2Fdeploy%40main&view=graph" {
		t.Errorf("hash after picking a node = %q", h.HashAfterPick)
	}
	for _, x := range h.Picked.Text {
		if !strings.Contains(x.Text, "action:acme-actions/deploy@main") {
			t.Errorf("picked view lists a path not through the node: %q", x.Text)
		}
	}
	if len(h.Picked.Text) != len(want) {
		t.Errorf("picked view lists %d paths, want %d", len(h.Picked.Text), len(want))
	}
	for _, n := range h.Picked.Nodes {
		if (n.ID == "action:acme-actions/deploy@main") != (n.Pressed == "true") {
			t.Errorf("node %s aria-pressed %q after picking", n.ID, n.Pressed)
		}
	}
	if h.FocusedAfterPick != "action:acme-actions/deploy@main" {
		t.Errorf("focus after picking = %q, want the picked node", h.FocusedAfterPick)
	}
	if !h.EnterPrevented || h.HashAfterEnter != "#view=graph" {
		t.Errorf("Enter on the picked node: prevented %v, hash %q; want the pick cleared", h.EnterPrevented, h.HashAfterEnter)
	}
	if h.AfterArrow.Hash != "" || h.AfterArrow.ListHidden || !h.AfterArrow.Focused {
		t.Errorf("ArrowLeft on the Graph tab: %+v", h.AfterArrow)
	}
	if h.InferredClass != "inferred" || h.UnknownClass != "other" {
		t.Errorf("evidence classes: inferred -> %q, unknown -> %q; want inferred and other", h.InferredClass, h.UnknownClass)
	}
	if h.StaleClass != "stale" || !strings.Contains(h.StaleText, "Stale: ") {
		t.Errorf("stale audit hop: class %q, text %q", h.StaleClass, h.StaleText)
	}
	if !strings.Contains(h.ReversedText, "Drawn in control direction") {
		t.Errorf("reversed edge text %q", h.ReversedText)
	}
	if !h.CapOver {
		t.Error("graph model does not report a graph over the node cap")
	}
}

// TestGraphCapInNode renders the medium demo (about 950 path nodes) with the
// Graph tab open: it shows the cap message instead of drawing, quickly.
func TestGraphCapInNode(t *testing.T) {
	if testing.Short() {
		t.Skip("medium demo report in -short mode")
	}
	out := render(t, demo.Generate(demo.Options{Seed: 1, Size: demo.SizeMedium}), "html")
	epi := `function go(hash) { location.hash = hash; winListeners.hashchange(); }
var t0 = Date.now();
go("#view=graph");
var ms = Date.now() - t0;
var t1 = Date.now();
form.elements.q.value = "members:";
form.fire("input");
process.stdout.write(JSON.stringify({ status: ids["gop-graph-status"].textContent, svgs: ids["gop-graph"].find("svg").length, ms: ms, inputMs: Date.now() - t1 }));
`
	var r struct {
		Status   string
		Svgs, Ms int
		InputMs  int `json:"inputMs"`
	}
	if err := json.Unmarshal(runHarness(t, out, epi), &r); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Status, "Too many paths to draw: ") || !strings.Contains(r.Status, "at most 300") || r.Svgs != 0 {
		t.Errorf("over the cap: status %q, %d SVGs", r.Status, r.Svgs)
	}
	if r.Ms > 2000 || r.InputMs > 2000 {
		t.Errorf("Graph tab took %d ms to open and %d ms to refilter over the cap", r.Ms, r.InputMs)
	}
}
