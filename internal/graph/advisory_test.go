package graph

import (
	"reflect"
	"testing"
)

// advisoryGraph: members:acme-app has the largest reach (OIDC and a secret)
// with no advisory; an outside action with a known advisory reaches one
// secret; alice can push to an enterprise action that also has an advisory.
func advisoryGraph() *Graph {
	adv := func(id string) map[string]string {
		return map[string]string{AttrRefKind: "tag", AttrAdvisories: id, AttrAdvisorySeverity: "critical", AttrAdvisoryFixed: "2.4.1"}
	}
	g := &Graph{Schema: SchemaVersion, Enterprise: "acme"}
	n := func(id string, k NodeKind, attrs map[string]string) {
		g.Nodes = append(g.Nodes, Node{ID: id, Kind: k, Name: id, Evidence: Live, Attrs: attrs})
	}
	e := func(from string, k EdgeKind, to string, attrs map[string]string) {
		g.Edges = append(g.Edges, Edge{From: from, To: to, Kind: k, Evidence: Live, SourceAPI: "test", Attrs: attrs})
	}
	n("org:acme-app", KindOrg, nil)
	n("org:acme-actions", KindOrg, nil)
	n("members:acme-app", KindOrgMembers, nil)
	n("identity:alice", KindIdentity, nil)
	for _, r := range []string{"acme-app/big", "acme-app/small", "acme-app/tiny", "acme-actions/lint-ish"} {
		n("repo:"+r, KindRepo, nil)
	}
	n("workflow:acme-app/big/.github/workflows/ci.yml", KindWorkflow, nil)
	n("workflow:acme-app/small/.github/workflows/preview.yml", KindWorkflow, nil)
	n("workflow:acme-app/tiny/.github/workflows/ci.yml", KindWorkflow, nil)
	n("oidc:acme-app/big", KindOIDC, nil)
	n("secret:acme-app/big", KindSecret, nil)
	n("secret:acme-app/small", KindSecret, nil)
	n("action:acme-oss/checkout-ish@v2", KindActionRef, adv("GHSA-acme-test-0001"))
	n("action:acme-actions/lint-ish@v1", KindActionRef, adv("GHSA-acme-test-0002"))

	e("members:acme-app", CanPush, "repo:acme-app/big", map[string]string{AttrVia: ViaDirect})
	e("workflow:acme-app/big/.github/workflows/ci.yml", DefinedIn, "repo:acme-app/big", nil)
	e("workflow:acme-app/big/.github/workflows/ci.yml", ExecutesWith, "oidc:acme-app/big", nil)
	e("workflow:acme-app/big/.github/workflows/ci.yml", ExecutesWith, "secret:acme-app/big", nil)

	e("workflow:acme-app/small/.github/workflows/preview.yml", DefinedIn, "repo:acme-app/small", nil)
	e("workflow:acme-app/small/.github/workflows/preview.yml", Uses, "action:acme-oss/checkout-ish@v2", map[string]string{AttrRefKind: "tag"})
	e("workflow:acme-app/small/.github/workflows/preview.yml", ExecutesWith, "secret:acme-app/small", nil)

	e("identity:alice", CanPush, "repo:acme-actions/lint-ish", map[string]string{AttrVia: ViaDirect})
	e("action:acme-actions/lint-ish@v1", ResolvesTo, "repo:acme-actions/lint-ish", nil)
	e("workflow:acme-app/tiny/.github/workflows/ci.yml", DefinedIn, "repo:acme-app/tiny", nil)
	e("workflow:acme-app/tiny/.github/workflows/ci.yml", Uses, "action:acme-actions/lint-ish@v1", map[string]string{AttrRefKind: "tag"})
	return g
}

func TestTopPathsRanksAdvisoriesFirst(t *testing.T) {
	ix := NewIndex(advisoryGraph())
	top := ix.TopPaths(0)
	var order []string
	for _, s := range top {
		order = append(order, s.Principal)
	}
	want := []string{"action:acme-oss/checkout-ish@v2", "identity:alice", "action:acme-actions/lint-ish@v1", "members:acme-app"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order %v, want %v", order, want)
	}
	if last := top[len(top)-1]; last.Score <= top[0].Score || len(last.Advisories) != 0 {
		t.Errorf("members:acme-app must have the highest score and no advisory: %+v", last)
	}
	if got := top[1].Advisories; !reflect.DeepEqual(got, []string{"action:acme-actions/lint-ish@v1"}) {
		t.Errorf("alice advisories %v", got)
	}
	if got := top[0].Advisories; !reflect.DeepEqual(got, []string{"action:acme-oss/checkout-ish@v2"}) {
		t.Errorf("action entry advisories %v", got)
	}
	if top[0].Confirmed.Secrets != 1 {
		t.Errorf("the compromised action reaches the preview secret: %+v", top[0].Confirmed)
	}
	// Advisory actions join the ranking only: totals, what-if and fixes
	// still score the principals.
	for _, p := range ix.ScoringPrincipals() {
		if KindFromID(p) == KindActionRef {
			t.Errorf("%s must not be a scoring principal", p)
		}
	}
	if len(ix.Scores()) != 2 {
		t.Errorf("Scores: %d, want the 2 principals", len(ix.Scores()))
	}
}

func TestTopPathsNoReachNoAdvisoryTier(t *testing.T) {
	g := advisoryGraph()
	// Drop every USES edge: the advisory actions reach nothing, so they are
	// not listed and alice's score is 0.
	kept := g.Edges[:0]
	for _, e := range g.Edges {
		if e.Kind != Uses {
			kept = append(kept, e)
		}
	}
	g.Edges = kept
	top := NewIndex(g).TopPaths(0)
	if len(top) != 2 || top[0].Principal != "members:acme-app" {
		t.Errorf("top %+v", top)
	}
}

func TestRanksAboveAdvisoryBeforePoutine(t *testing.T) {
	adv := Score{Principal: "action:acme-oss/checkout-ish@v2", Score: 1, Advisories: []string{"action:acme-oss/checkout-ish@v2"}}
	pout := Score{Principal: "members:acme-app", Score: 100, PoutineInjectable: 3}
	plain := Score{Principal: "identity:bob", Score: 500}
	if !RanksAbove(adv, pout) || RanksAbove(pout, adv) {
		t.Error("an advisory must rank above a poutine-injectable entry")
	}
	if !RanksAbove(pout, plain) {
		t.Error("poutine injectable must still rank above a higher score")
	}
}
