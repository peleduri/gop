package graph

import (
	"strings"
	"testing"
)

// envGraph: members:acme-app push to repo acme-app/web, whose deploy
// workflow reaches its secrets and OIDC token only through a production
// environment with required reviewers, and a cloud role through that token.
// gated switches the gate on.
func envGraph(gated bool) *Graph {
	gate := map[string]string{AttrEnvGate: EnvGateNone, AttrEnvProtection: "production:none"}
	if gated {
		gate = map[string]string{AttrEnvGate: EnvGateReviewers, AttrEnvProtection: "production:required_reviewers=1+prevent_self_review"}
	}
	wf := "workflow:acme-app/web/.github/workflows/deploy.yml"
	return &Graph{Schema: SchemaVersion, Enterprise: "acme",
		Nodes: []Node{
			{ID: "org:acme-app", Kind: KindOrg, Name: "acme-app", Evidence: Live},
			{ID: "members:acme-app", Kind: KindOrgMembers, Name: "acme-app members", Evidence: Live},
			{ID: "repo:acme-app/web", Kind: KindRepo, Name: "acme-app/web", Evidence: Live},
			{ID: wf, Kind: KindWorkflow, Name: "deploy", Evidence: Live},
			{ID: "secret:acme-app/web", Kind: KindSecret, Name: "secrets", Evidence: Live},
			{ID: "oidc:acme-app/web", Kind: KindOIDC, Name: "oidc", Evidence: Live},
			{ID: "cloud:aws:role/deploy", Kind: KindCloudTarget, Name: "deploy role", Evidence: Supplied},
		},
		Edges: []Edge{
			{From: "members:acme-app", To: "repo:acme-app/web", Kind: CanPush, Evidence: Live, SourceAPI: "rest"},
			{From: wf, To: "repo:acme-app/web", Kind: DefinedIn, Evidence: Live, SourceAPI: "rest"},
			{From: wf, To: "secret:acme-app/web", Kind: ExecutesWith, Evidence: Live, SourceAPI: "rest", Attrs: gate},
			{From: wf, To: "oidc:acme-app/web", Kind: ExecutesWith, Evidence: Live, SourceAPI: "rest", Attrs: gate},
			{From: wf, To: "cloud:aws:role/deploy", Kind: CanAssume, Evidence: Supplied, SourceAPI: "supplied:trust.json"},
		},
	}
}

func TestEnvGateOnPathsAndScore(t *testing.T) {
	open := NewIndex(envGraph(false))
	gated := NewIndex(envGraph(true))

	r := gated.Reach("members:acme-app", Options{})
	for _, to := range []string{"secret:acme-app/web", "oidc:acme-app/web", "cloud:aws:role/deploy"} {
		p, ok := r.Paths[to]
		if !ok {
			t.Fatalf("gated graph: %s not reached (a gate must not remove reach)", to)
		}
		if !p.Gated || p.Unverified {
			t.Errorf("%s: gated=%v unverified=%v, want gated and confirmed", to, p.Gated, p.Unverified)
		}
		last := p.Hops[len(p.Hops)-1]
		if !strings.Contains(last.Gate, "environment production") {
			t.Errorf("%s: last hop gate = %q", to, last.Gate)
		}
		if n := gated.HopNote(last); n != last.Gate {
			t.Errorf("%s: hop note = %q, want the gate", to, n)
		}
	}
	if p := open.Reach("members:acme-app", Options{}).Paths["secret:acme-app/web"]; p.Gated {
		t.Error("ungated graph: path is gated")
	}

	so, sg := open.BlastRadius("members:acme-app"), gated.BlastRadius("members:acme-app")
	if sg.Confirmed != so.Confirmed {
		t.Errorf("gated counts %+v differ from ungated %+v: a gate must not remove reach", sg.Confirmed, so.Confirmed)
	}
	if sg.EnvGated != 3 || so.EnvGated != 0 {
		t.Errorf("env_gated = %d (gated) / %d (open), want 3 / 0", sg.EnvGated, so.EnvGated)
	}
	want := so.Score - (1-gatedFactor)*(wSecret+wOIDC+wCloud)*so.Multiplier
	if sg.Score != want {
		t.Errorf("gated score = %v, want %v (open %v)", sg.Score, want, so.Score)
	}
	if !RanksAbove(so, sg) {
		t.Error("the ungated principal should rank above the gated one")
	}
}

func TestEnvGateNeedsEveryWorkflow(t *testing.T) {
	g := envGraph(true)
	wf2 := "workflow:acme-app/web/.github/workflows/nightly.yml"
	g.Nodes = append(g.Nodes, Node{ID: wf2, Kind: KindWorkflow, Name: "nightly", Evidence: Live})
	g.Edges = append(g.Edges,
		Edge{From: wf2, To: "repo:acme-app/web", Kind: DefinedIn, Evidence: Live, SourceAPI: "rest"},
		Edge{From: wf2, To: "secret:acme-app/web", Kind: ExecutesWith, Evidence: Live, SourceAPI: "rest"})
	s := NewIndex(g).BlastRadius("members:acme-app")
	// The secret is reached ungated through nightly.yml; the OIDC token and
	// the cloud role stay gated.
	if s.EnvGated != 2 {
		t.Errorf("env_gated = %d, want 2", s.EnvGated)
	}
}

func TestEnvGateUnknownIsNotGated(t *testing.T) {
	g := envGraph(false)
	for i := range g.Edges {
		if g.Edges[i].Kind == ExecutesWith {
			g.Edges[i].Attrs = map[string]string{AttrEnvGate: EnvGateUnknown, AttrEnvGateReason: "could not read"}
		}
	}
	ix := NewIndex(g)
	if s := ix.BlastRadius("members:acme-app"); s.EnvGated != 0 {
		t.Errorf("unknown gate counted as gated: %d", s.EnvGated)
	}
	if p := ix.Reach("members:acme-app", Options{}).Paths["oidc:acme-app/web"]; p.Gated {
		t.Error("unknown gate marks the path gated")
	}
}
