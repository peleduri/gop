package graph

import (
	"strings"
	"testing"
)

const (
	agentClaude  = "workflow:acme-app/docs/.github/workflows/claude.yml"
	agentCodex   = "workflow:acme-actions/setup/.github/workflows/codex-review.yml"
	agentGemini  = "workflow:acme-app/docs/.github/workflows/gemini-review.yml"
	agentLabeler = "workflow:acme-app/docs/.github/workflows/ai-labeler.yml"
)

func loadAgents(t *testing.T) *Graph {
	t.Helper()
	g, err := LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// stripAgents removes every agent attr and, with edges, the CAN_TRIGGER
// edges that only an agent exec created.
func stripAgents(g *Graph, edges bool) *Graph {
	out := *g
	out.Nodes = make([]Node, len(g.Nodes))
	for i, n := range g.Nodes {
		a := map[string]string{}
		for k, v := range n.Attrs {
			if !strings.HasPrefix(k, "agent") {
				a[k] = v
			}
		}
		n.Attrs = a
		out.Nodes[i] = n
	}
	out.Edges = nil
	for _, e := range g.Edges {
		if edges && e.Kind == CanTrigger && e.Attrs["exec"] == "agent" {
			continue
		}
		out.Edges = append(out.Edges, e)
	}
	return &out
}

func TestAgentNodes(t *testing.T) {
	ix := NewIndex(loadAgents(t))
	if got := ix.AgentWorkflows(); len(got) != 4 {
		t.Fatalf("agent workflows = %v", got)
	}
	for id, want := range map[string]bool{agentClaude: true, agentCodex: true, agentGemini: false, agentLabeler: false} {
		n, _ := ix.Node(id)
		if AgentExposed(n) != want {
			t.Errorf("AgentExposed(%s) = %v, want %v (attrs %v)", id, !want, want, n.Attrs)
		}
	}
	lab, _ := ix.Node(agentLabeler)
	if !IsAgent(lab) || AgentConfirmed(lab) || AgentFixes(lab) != nil {
		t.Errorf("name-only labeler: IsAgent %v, AgentConfirmed %v, fixes %v", IsAgent(lab), AgentConfirmed(lab), AgentFixes(lab))
	}
	c, _ := ix.Node(agentClaude)
	fixes := strings.Join(AgentFixes(c), "\n")
	for _, w := range []string{"Restrict who can start it", "issue_comment", "read-only token", "contents:write", "Pin the agent action", "dangerously_skip_permissions", "Scope the allowed tools"} {
		if !strings.Contains(fixes, w) {
			t.Errorf("claude fixes lack %q:\n%s", w, fixes)
		}
	}
	if imp := AgentImpact(c); strings.Join(imp, ",") != "contents:write,issues:write,pull-requests:write,secrets" {
		t.Errorf("impact = %v", imp)
	}
}

// TestAgentExposedRanksFirst: the principal that can start an outsider-
// triggerable agent workflow with a write token ranks first; its score is
// what the same reach scores without the agent rank factor.
func TestAgentExposedRanksFirst(t *testing.T) {
	g := loadAgents(t)
	top := TopPaths(g, 0)
	if top[0].AgentExposed == 0 {
		t.Fatalf("top = %+v, order %v", top[0], principals(top[:5]))
	}
	exposed := map[string]int{}
	for _, s := range top {
		if s.AgentExposed > 0 {
			exposed[s.Principal] = s.AgentExposed
		}
	}
	// Members of the orgs that can fork acme-actions/setup reach the Codex
	// workflow through their own CAN_TRIGGER edge; acme-actions members push
	// to it and are not counted.
	// bob (an acme-app member) starts it through that edge too; alice pushes
	// to acme-actions/setup. Anyone on the internet starts the Claude
	// workflow in public acme-app/docs.
	if exposed["external:anyone"] != 1 || exposed["members:acme-app"] != 1 || exposed["identity:bob"] != 1 ||
		exposed["identity:alice"] != 0 || exposed["members:acme-actions"] != 0 {
		t.Errorf("exposed = %v", exposed)
	}
	for i, s := range top {
		if s.AgentExposed == 0 {
			for _, r := range top[i:] {
				if r.AgentExposed > 0 {
					t.Errorf("%s (agent exposed) ranks below %s", r.Principal, s.Principal)
				}
			}
			break
		}
	}

	// Without the agent attrs nobody is agent exposed, and every score,
	// count and possible figure is the same.
	plain := map[string]Score{}
	for _, s := range TopPaths(stripAgents(g, false), 0) {
		if s.AgentExposed != 0 {
			t.Errorf("stripped: %s agent exposed", s.Principal)
		}
		plain[s.Principal] = s
	}
	for _, s := range top {
		p := plain[s.Principal]
		if p.Score != s.Score || p.Confirmed != s.Confirmed || p.Possible != s.Possible || p.PossibleScore != s.PossibleScore {
			t.Errorf("%s score changed: %+v -> %+v", s.Principal, p, s)
		}
	}

	// Without the agent's own CAN_TRIGGER edges, every principal that had
	// none keeps its score exactly: agent detection adds reach only through
	// the principals who can start an agent.
	agentSources := map[string]bool{}
	for _, e := range g.Edges {
		if e.Kind == CanTrigger && e.Attrs["exec"] == "agent" {
			agentSources[e.From] = true
		}
	}
	if !agentSources["external:anyone"] {
		t.Fatalf("no agent CAN_TRIGGER from external:anyone")
	}
	base := map[string]Score{}
	for _, s := range TopPaths(stripAgents(g, true), 0) {
		base[s.Principal] = s
	}
	for _, s := range top {
		if agentSources[s.Principal] {
			continue
		}
		b := base[s.Principal]
		if b.Score != s.Score || b.Confirmed != s.Confirmed || b.Possible != s.Possible {
			t.Errorf("non-agent principal %s changed: %+v -> %+v", s.Principal, b, s)
		}
	}
}

func TestRanksAboveAgent(t *testing.T) {
	a := Score{Principal: "a", Score: 1, AgentExposed: 1}
	b := Score{Principal: "b", Score: 100}
	if !RanksAbove(a, b) || RanksAbove(b, a) {
		t.Error("agent exposed does not rank above score")
	}
	p := Score{Principal: "p", Score: 1, PoutineInjectable: 1}
	if !RanksAbove(p, a) {
		t.Error("poutine must rank above agent exposed")
	}
	adv := Score{Principal: "z", Score: 1, Advisories: []string{"action:x@v1"}}
	if !RanksAbove(adv, a) {
		t.Error("advisory must rank above agent exposed")
	}
}
