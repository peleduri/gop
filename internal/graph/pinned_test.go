package graph

import (
	"fmt"
	"slices"
	"testing"
)

const (
	pinnedSHA = "action:o/release@0123456789abcdef0123456789abcdef01234567"
	nestedTag = "action:x/deploy@v3"
)

// pinnedGraph is tagGraph with the workflow's USES moved to a SHA-pinned
// o/release action, which itself uses the tag x/deploy@v3 (attrs on v3).
func pinnedGraph(attrs map[string]string) *Graph {
	g := tagGraph(attrs)
	for i, e := range g.Edges {
		if e.Kind == Uses {
			g.Edges[i].To = pinnedSHA
			g.Edges[i].Attrs = map[string]string{AttrRefKind: "sha"}
		}
	}
	g.Edges = append(g.Edges,
		edge(pinnedSHA, "USES", nestedTag, AttrRefKind, "tag"),
		edge(pinnedSHA, "RESOLVES_TO", "repo:o/release"))
	return g
}

func TestRefStateAndPinnedExposures(t *testing.T) {
	cases := []struct {
		name    string
		attrs   map[string]string
		state   RefState
		mutable bool
		// exposure: "" none, "c" confirmed path, "p" possible path
		exposure, note string
	}{
		{"no attr", nil, RefMutable, true, "c", ""},
		{"immutable release", map[string]string{AttrRefImmutable: "true", AttrRefImmutableBy: RefImmutableRelease, AttrBypass: "none"}, RefMutable, true, "c", ""},
		{"unknown", map[string]string{AttrRefImmutable: "unknown"}, RefPossiblyMutable, true, "p", "possibly mutable (immutability not visible)"},
		{"ambiguous", map[string]string{AttrRefImmutable: "true", AttrRefAmbiguous: "true", AttrRefKind: "branch"}, RefMutable, true, "c", ""},
		{"protected branch unknown", map[string]string{AttrRefKind: "branch", AttrRefProtected: "unknown"}, RefPossiblyMutable, true, "p", "possibly mutable (protection not visible)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ix := NewIndex(pinnedGraph(tc.attrs))
			checkExposure(t, ix, tc.state, tc.mutable, tc.exposure, tc.note)
		})
	}

	// team:x/release's bypass edge applies to v3 above, so "immutable release"
	// stays mutable. Without it the tag is locked: not mutable, and the
	// SHA-pinned action that uses it is not an exposure.
	noBypass := func(attrs map[string]string) *Graph {
		g := pinnedGraph(attrs)
		g.Edges = slices.DeleteFunc(g.Edges, func(e Edge) bool { return e.From == "team:x/release" })
		return g
	}
	t.Run("locked", func(t *testing.T) {
		ix := NewIndex(noBypass(map[string]string{AttrRefImmutable: "true", AttrRefImmutableBy: RefImmutableRelease, AttrBypass: "none"}))
		checkExposure(t, ix, RefLocked, false, "", "")
	})
	t.Run("locked bypass unknown", func(t *testing.T) {
		ix := NewIndex(noBypass(map[string]string{AttrRefImmutable: "true", AttrBypass: "unknown"}))
		checkExposure(t, ix, RefPossiblyMutable, true, "p", "possibly mutable (bypass actors not visible)")
	})

	// The exposure through a bypass edge names the nested tag as Via.
	ix := NewIndex(pinnedGraph(map[string]string{AttrRefImmutable: "true", AttrBypass: "none"}))
	ex := ix.PinnedExposures()
	if len(ex) != 1 || ex[0].Via != nestedTag || ex[0].Path.From != "team:x/release" {
		t.Errorf("bypass exposure = %+v", ex)
	}
}

func checkExposure(t *testing.T, ix *Index, state RefState, mutable bool, exposure, note string) {
	t.Helper()
	if got := ix.RefState(nestedTag); got != state {
		t.Errorf("RefState = %q, want %q", got, state)
	}
	if got := ix.MutableRef(nestedTag); got != mutable {
		t.Errorf("MutableRef = %v, want %v", got, mutable)
	}
	if got := ix.RefState(pinnedSHA); got != RefPinned {
		t.Errorf("outer RefState = %q", got)
	}
	ex := ix.PinnedExposures()
	if exposure == "" {
		if len(ex) != 0 {
			t.Errorf("PinnedExposures = %+v, want none", ex)
		}
		return
	}
	if len(ex) != 1 || ex[0].Action != pinnedSHA || ex[0].Via != nestedTag || ex[0].ViaNote != note || ex[0].Consumers != 1 {
		t.Fatalf("PinnedExposures = %+v", ex)
	}
	if got := map[bool]string{false: "c", true: "p"}[ex[0].Path.Unverified]; got != exposure {
		t.Errorf("exposure path %q, want %q", got, exposure)
	}
}

// A locked tag counts as pinned: an immutable o/release@v1 that runs a mutable
// branch is listed like a SHA pin.
func TestPinnedExposuresLockedOuter(t *testing.T) {
	g := pinnedGraph(nil)
	const outer = "action:o/release@v1"
	for i, e := range g.Edges {
		if e.From == pinnedSHA {
			g.Edges[i].From = outer
		}
		if e.To == pinnedSHA {
			g.Edges[i].To = outer
			g.Edges[i].Attrs = map[string]string{AttrRefKind: "tag"}
		}
	}
	g.Nodes = append(g.Nodes, Node{ID: outer, Kind: KindActionRef, Name: "o/release@v1", Evidence: Live,
		Attrs: map[string]string{AttrRefKind: "tag", AttrRefImmutable: "true", AttrBypass: "none"}})
	ix := NewIndex(g)
	if st := ix.RefState(outer); st != RefLocked {
		t.Fatalf("outer RefState = %q", st)
	}
	ex := ix.PinnedExposures()
	if len(ex) != 1 || ex[0].Action != outer || ex[0].Via != nestedTag || ex[0].Path.Unverified {
		t.Errorf("PinnedExposures = %+v", ex)
	}
}

// TestPropertyPinnedExposures checks PinnedExposures against the reference
// reach (refReach) and the reference ref gate (refResolves) on random graphs:
// every exposure is a pinned or locked action that its principal reaches
// (confirmed when the path is verified, else possible only), its Via is a
// mutable or possibly mutable ref with a note exactly when possible, and every
// pinned or locked action that some principal reaches is listed. RefState is
// RefLocked exactly when the reference gate keeps no hop for the action.
func TestPropertyPinnedExposures(t *testing.T) {
	n := propertySeeds(t)
	exposures, possible, locked := 0, 0, 0
	for seed := uint64(0); seed < uint64(n); seed++ {
		g := genGraph(propRand(seed), propSize(seed))
		if err := propPinnedExposures(g); err != nil {
			small := minimizeGraph(g, func(h *Graph) bool { return propPinnedExposures(h) != nil })
			t.Errorf("seed=%d: %v\nminimized graph fails with: %v", seed, err, propPinnedExposures(small))
		}
		ix := NewIndex(g)
		for _, pe := range ix.PinnedExposures() {
			exposures++
			if pe.ViaNote != "" {
				possible++
			}
		}
		for _, nd := range g.Nodes {
			if nd.Kind == KindActionRef && ix.RefState(nd.ID) == RefLocked {
				locked++
			}
		}
	}
	// The generator must exercise the property, not pass it vacuously.
	if n >= defaultPropertySeeds && (exposures == 0 || possible == 0 || locked == 0) {
		t.Errorf("weak generator: %d exposures, %d possible, %d locked refs over %d seeds", exposures, possible, locked, n)
	}
	t.Logf("%d exposures (%d possible), %d locked refs over %d seeds", exposures, possible, locked, n)
}

func propPinnedExposures(g *Graph) error {
	ix := NewIndex(g)
	// RefState agrees with the reference gate.
	for _, nd := range g.Nodes {
		if nd.Kind != KindActionRef {
			continue
		}
		var res []Edge
		for _, e := range g.Edges {
			if e.Kind == ResolvesTo && e.From == nd.ID {
				res = append(res, e)
			}
		}
		if len(res) == 0 {
			continue
		}
		st := ix.RefState(nd.ID)
		if !refMutable(g, nd.ID) {
			if st != RefPinned {
				return fmt.Errorf("%s: RefState %q, reference says SHA-pinned", nd.ID, st)
			}
			continue
		}
		open := false
		for _, e := range res {
			open = open || len(refResolves(g, e, refEdge{from: e.To, to: e.From})) > 0
		}
		if (st == RefLocked) == open {
			return fmt.Errorf("%s: RefState %q, reference gate keeps a hop: %v", nd.ID, st, open)
		}
		if ix.MutableRef(nd.ID) != (st != RefLocked) {
			return fmt.Errorf("%s: MutableRef disagrees with RefState %q", nd.ID, st)
		}
	}

	listed := map[string]bool{}
	for _, pe := range ix.PinnedExposures() {
		listed[pe.Action] = true
		if st := ix.RefState(pe.Action); st != RefPinned && st != RefLocked {
			return fmt.Errorf("exposure %s: RefState %q", pe.Action, st)
		}
		from := pe.Path.From
		conf := refReach(g, from, nil, true)
		all := refReach(g, from, nil, false)
		if _, ok := all[pe.Action]; !ok {
			return fmt.Errorf("exposure %s: reference reach from %s has no path", pe.Action, from)
		}
		if _, ok := conf[pe.Action]; ok == pe.Path.Unverified {
			return fmt.Errorf("exposure %s from %s: confirmed by reference %v, path unverified %v", pe.Action, from, ok, pe.Path.Unverified)
		}
		if pe.Via != "" {
			st := ix.RefState(pe.Via)
			if st != RefMutable && st != RefPossiblyMutable {
				return fmt.Errorf("exposure %s: via %s is %q", pe.Action, pe.Via, st)
			}
			if (pe.ViaNote != "") != (st == RefPossiblyMutable) {
				return fmt.Errorf("exposure %s: via %s is %q, note %q", pe.Action, pe.Via, st, pe.ViaNote)
			}
		}
	}
	// Completeness: a pinned or locked, used action that some principal
	// reaches is listed.
	for _, e := range g.Edges {
		if e.Kind != Uses || ix.Kind(e.From) != KindActionRef || listed[e.From] {
			continue
		}
		if st := ix.RefState(e.From); st != RefPinned && st != RefLocked {
			continue
		}
		for _, p := range ix.Principals() {
			if _, ok := refReach(g, p, nil, false)[e.From]; ok {
				return fmt.Errorf("%s is reached by %s but not listed", e.From, p)
			}
		}
	}
	return nil
}
