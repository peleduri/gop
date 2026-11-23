package graph

import (
	"slices"
	"testing"
)

// protectedGraph: members:x push to repo:x/deploy, which hosts action
// x/deploy@main, used by a workflow in o/app that holds secrets. team:x/release
// may bypass the branch's protection; team:x/other bypasses another branch.
func protectedGraph(protected, bypass string) *Graph {
	attrs := map[string]string{AttrRefKind: "branch", AttrRef: "main"}
	if protected != "" {
		attrs[AttrRefProtected] = protected
	}
	if bypass != "" {
		attrs[AttrBypass] = bypass
	}
	return &Graph{Schema: SchemaVersion,
		Nodes: []Node{
			{ID: "action:x/deploy@main", Kind: KindActionRef, Name: "x/deploy@main", Evidence: Live, Attrs: attrs},
			{ID: "team:x/release", Kind: KindIdentity, Name: "x/release", Evidence: Live},
			{ID: "team:x/other", Kind: KindIdentity, Name: "x/other", Evidence: Live},
		},
		Edges: []Edge{
			edge("members:x", "CAN_PUSH", "repo:x/deploy", AttrVia, ViaDefaultPerm),
			edge("team:x/release", "CAN_PUSH", "repo:x/deploy", AttrVia, ViaRefBypass, AttrRef, "main"),
			edge("team:x/other", "CAN_PUSH", "repo:x/deploy", AttrVia, ViaRefBypass, AttrRef, "release/v1"),
			edge("workflow:o/app/.github/workflows/ci.yml", "DEFINED_IN", "repo:o/app"),
			edge("workflow:o/app/.github/workflows/ci.yml", "USES", "action:x/deploy@main", AttrRefKind, "branch"),
			edge("action:x/deploy@main", "RESOLVES_TO", "repo:x/deploy"),
			edge("workflow:o/app/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:o/app"),
		}}
}

const protSecret = "secret:o/app"

func TestRefProtectedGatesResolvesTo(t *testing.T) {
	cases := []struct {
		protected, bypass string
		// for members:x, team:x/release and team:x/other: "c" confirmed, "p" possible, "" none
		members, release, other string
	}{
		{"", "", "c", "c", "c"}, // missing: today's behavior (bypass edges are CAN_PUSH too)
		{"false", "", "c", "c", "c"},
		{"true", "team:x/release", "", "c", ""},
		{"true", "none", "", "c", ""}, // the attr is informational; edges decide
		{"true", "unknown", "p", "c", "p"},
		{"unknown", "", "p", "p", "p"},
	}
	for _, tc := range cases {
		g := protectedGraph(tc.protected, tc.bypass)
		ix := NewIndex(g)
		for p, want := range map[string]string{"members:x": tc.members, "team:x/release": tc.release, "team:x/other": tc.other} {
			r := ix.Reach(p, Options{})
			got := ""
			switch {
			case slices.Contains(r.Confirmed.Secrets, protSecret):
				got = "c"
			case slices.Contains(r.Possible.Secrets, protSecret):
				got = "p"
			}
			if got != want {
				t.Errorf("ref_protected=%q bypass=%q: %s reach = %q, want %q", tc.protected, tc.bypass, p, got, want)
			}
			// Push to the repo itself is never gated.
			if !slices.Contains(r.Confirmed.Repos, "repo:x/deploy") {
				t.Errorf("ref_protected=%q: %s lost CAN_PUSH to repo:x/deploy", tc.protected, p)
			}
		}
	}
}

func TestRefBypassHop(t *testing.T) {
	g := protectedGraph("true", "team:x/release")
	r := Reach(g, "team:x/release", Options{})
	p := r.Paths["action:x/deploy@main"]
	if len(p.Hops) != 1 || p.Hops[0].Kind != CanPush || p.Hops[0].From != "team:x/release" || p.Hops[0].Reverse || p.Hops[0].Evidence != Live {
		t.Fatalf("bypass path = %+v, want one forward CAN_PUSH hop", p.Hops)
	}
	who := WhoCanReach(g, protSecret)
	var from []string
	for _, w := range who {
		from = append(from, w.From)
	}
	if !slices.Equal(from, []string{"team:x/release"}) {
		t.Errorf("WhoCanReach = %v", from)
	}
	// A PinRef blocks the bypass hop too.
	pinned := Reach(g, "team:x/release", Options{Fixes: []Fix{PinRef{Action: "action:x/deploy@main"}}})
	if slices.Contains(pinned.Confirmed.Secrets, protSecret) {
		t.Error("PinRef must block the bypass hop")
	}
	// An unknown ref_protected hop is reported as not_visible on the RESOLVES_TO hop.
	u := Reach(protectedGraph("unknown", ""), "members:x", Options{})
	up := u.Paths[protSecret]
	if !up.Unverified || up.Hops[1].Kind != ResolvesTo || up.Hops[1].Evidence != NotVisible {
		t.Errorf("unknown path = %+v", up)
	}
}

func TestPinRefCandidateOnlyForBypass(t *testing.T) {
	// Protected with a bypass team: the pin is a candidate and removes only the
	// bypass team's pair; members:x lost the path through protection already.
	ix := NewIndex(protectedGraph("true", "team:x/release"))
	var pin *FixSuggestion
	for _, s := range ix.SuggestFixes(5) {
		if s.FixID == "pin:action:x/deploy@main" {
			pin = &s
		}
	}
	if pin == nil {
		t.Fatal("pin of a ref with a bypass team not suggested")
	}
	if pin.Removed != 1 {
		t.Errorf("pin removes %d pairs, want 1 (team:x/release -> repo:o/app)", pin.Removed)
	}
	// Unprotected: the same pin removes members:x and both teams.
	open := NewIndex(protectedGraph("false", "")).SuggestFixes(5)
	if len(open) == 0 || open[0].FixID != "pin:action:x/deploy@main" || open[0].Removed != 3 {
		t.Errorf("unprotected suggestions = %+v", open)
	}
	// Protected with no bypass edge for main: pinning removes nothing, so it is never picked.
	g := protectedGraph("true", "none")
	g.Edges = slices.DeleteFunc(g.Edges, func(e Edge) bool { return e.From == "team:x/release" })
	for _, s := range NewIndex(g).SuggestFixes(5) {
		if s.FixID == "pin:action:x/deploy@main" {
			t.Errorf("pin of a fully protected ref suggested: %+v", s)
		}
	}
}
