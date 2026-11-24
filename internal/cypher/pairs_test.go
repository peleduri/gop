package cypher

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// GOP_REACHES follows the pair model of the totals and the SQL reach table:
// reach an identity holds only through its org membership is one edge from
// members:X, not one more per member who qualifies for another reason (here
// alice's team, which grants nothing). Reach through a member's own grant
// stays on the member.
func TestReachFollowsPairModel(t *testing.T) {
	edge := func(from string, kind graph.EdgeKind, to string, attrs ...string) graph.Edge {
		e := graph.Edge{From: from, To: to, Kind: kind, Evidence: graph.Live}
		if len(attrs) == 2 {
			e.Attrs = map[string]string{attrs[0]: attrs[1]}
		}
		return e
	}
	node := func(id string, k graph.NodeKind) graph.Node {
		return graph.Node{ID: id, Kind: k, Evidence: graph.Live}
	}
	g := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme",
		Nodes: []graph.Node{
			{ID: "org:acme", Kind: graph.KindOrg, Evidence: graph.Live, Attrs: map[string]string{graph.AttrDefaultPerm: "write"}},
			node("members:acme", graph.KindOrgMembers),
			node("team:acme/readers", graph.KindIdentity),
			node("identity:alice", graph.KindIdentity),
			node("repo:acme/web", graph.KindRepo),
			node("repo:acme/api", graph.KindRepo),
			node("workflow:acme/web/.github/workflows/ci.yml", graph.KindWorkflow),
			node("workflow:acme/api/.github/workflows/ci.yml", graph.KindWorkflow),
			node("secret:acme/web", graph.KindSecret),
			node("secret:acme/api", graph.KindSecret),
		},
		Edges: []graph.Edge{
			edge("members:acme", graph.CanPush, "repo:acme/web", graph.AttrVia, graph.ViaDefaultPerm),
			edge("identity:alice", graph.MemberOf, "org:acme"),
			edge("identity:alice", graph.MemberOf, "team:acme/readers"),
			edge("identity:alice", graph.CanPush, "repo:acme/api"),
			edge("workflow:acme/web/.github/workflows/ci.yml", graph.DefinedIn, "repo:acme/web"),
			edge("workflow:acme/api/.github/workflows/ci.yml", graph.DefinedIn, "repo:acme/api"),
			edge("workflow:acme/web/.github/workflows/ci.yml", graph.ExecutesWith, "secret:acme/web"),
			edge("workflow:acme/api/.github/workflows/ci.yml", graph.ExecutesWith, "secret:acme/api"),
		},
	}
	if s := graph.NewIndex(g).Reach("identity:alice", graph.Options{}); s.Paths["secret:acme/web"].From == "" {
		t.Fatal("fixture: alice's full reach should include secret:acme/web through members:acme")
	}
	out := export(t, g, Options{})
	for _, want := range []string{
		"{from: 'members:acme', to: 'secret:acme/web'",
		"{from: 'identity:alice', to: 'secret:acme/api'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing GOP_REACHES row %s", want)
		}
	}
	if strings.Contains(out, "{from: 'identity:alice', to: 'secret:acme/web'") {
		t.Error("alice repeats members:acme's reach to secret:acme/web")
	}
}
