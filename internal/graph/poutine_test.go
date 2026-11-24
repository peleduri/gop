package graph

import "testing"

func setPoutine(t *testing.T, g *Graph, id, rules string) {
	t.Helper()
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			if g.Nodes[i].Attrs == nil {
				g.Nodes[i].Attrs = map[string]string{}
			}
			g.Nodes[i].Attrs[AttrPoutineRules] = rules
			return
		}
	}
	t.Fatalf("no node %s", id)
}

func principals(s []Score) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.Principal
	}
	return out
}

// TestPoutineInjectableRanksFirst: a principal whose confirmed reach includes
// a workflow with an injection-class poutine finding ranks above principals
// with a higher score and no such workflow; its score and counts are unchanged.
func TestPoutineInjectableRanksFirst(t *testing.T) {
	g, err := LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	before := TopPaths(g, 0)
	if before[0].Principal == "identity:alice" || before[0].PoutineInjectable != 0 {
		t.Fatalf("fixture changed: top before = %+v", before[0])
	}
	var aliceBefore Score
	for _, s := range before {
		if s.Principal == "identity:alice" {
			aliceBefore = s
		}
	}

	// A non-injection finding does not change the order.
	setPoutine(t, g, "workflow:acme-app/infra/.github/workflows/ci.yml", "debug_enabled,pr_runs_on_self_hosted")
	if got := principals(TopPaths(g, 0)); got[0] != before[0].Principal {
		t.Errorf("non-injection finding reordered: %v", got)
	}

	for _, rule := range []string{"injection", "untrusted_checkout_exec"} {
		setPoutine(t, g, "workflow:acme-app/infra/.github/workflows/ci.yml", "debug_enabled,"+rule)
		after := TopPaths(g, 0)
		top := after[0]
		if top.Principal != "identity:alice" || top.PoutineInjectable != 1 {
			t.Fatalf("%s: top = %+v, order %v", rule, top, principals(after))
		}
		if top.Score != aliceBefore.Score || top.Confirmed != aliceBefore.Confirmed {
			t.Errorf("%s: score changed: %+v -> %+v", rule, aliceBefore, top)
		}
		if after[1].Principal != before[0].Principal {
			t.Errorf("%s: rest of the order changed: %v", rule, principals(after))
		}
	}

	// Reach into the workflow by every pusher counts: bob reaches web ci.yml.
	setPoutine(t, g, "workflow:acme-app/web/.github/workflows/ci.yml", "injection")
	if s := NewIndex(g).BlastRadius("identity:bob"); s.PoutineInjectable != 1 {
		t.Errorf("bob = %+v", s)
	}
}

func TestRanksAbove(t *testing.T) {
	a := Score{Principal: "a", Score: 1, PoutineInjectable: 1}
	b := Score{Principal: "b", Score: 100}
	if !RanksAbove(a, b) || RanksAbove(b, a) {
		t.Error("injectable does not rank first")
	}
	c := Score{Principal: "c", Score: 100, PossibleScore: 5}
	if !RanksAbove(c, b) || !RanksAbove(b, Score{Principal: "d", Score: 100}) {
		t.Error("score, possible score, ID order broken")
	}
}
