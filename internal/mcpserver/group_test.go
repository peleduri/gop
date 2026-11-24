package mcpserver

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func loadOwners(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/owners/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// top_risks folds the 14 owners of acme-security into one row: n counts
// rows, the JSON lists every member, the text truncates, and explain and
// blast_radius still answer for any member.
func TestTopRisksGroupsIdenticalReach(t *testing.T) {
	cs := connectGraph(t, loadOwners(t))
	var tr TopRisksOutput
	res := call(t, cs, "top_risks", map[string]any{"n": 10}, &tr)
	if len(tr.Risks) != 4 {
		t.Fatalf("rows = %d, want 4 (1 group + 3 principals): %+v", len(tr.Risks), tr.Risks)
	}
	g := tr.Risks[0]
	if g.Principal != "identity:owner01" || len(g.Members) != 14 || g.Members[13] != "identity:owner14" {
		t.Errorf("group = %s, members %v", g.Principal, g.Members)
	}
	if g.Via != graph.ViaOrgOwner || len(g.ViaScope) != 1 || g.ViaScope[0] != "org:acme-security" {
		t.Errorf("via = %q %v", g.Via, g.ViaScope)
	}
	if g.Score == 0 || g.Confirmed.Repos != 3 {
		t.Errorf("score fields must stay flat in JSON: %+v", g.GroupScore)
	}
	for i, want := range []string{"identity:alice", "identity:bob", "identity:carol"} {
		if r := tr.Risks[i+1]; r.Principal != want || r.Members != nil {
			t.Errorf("row %d = %s %v, want %s alone", i+1, r.Principal, r.Members, want)
		}
	}
	want := "top risk: `the 14 owners of acme-security (identity:owner01, identity:owner02, identity:owner03 and 11 more)` can control 3 repos"
	if !strings.HasPrefix(tr.Summary, want) || !strings.HasPrefix(text(res), want) {
		t.Errorf("summary = %q, want prefix %q", tr.Summary, want)
	}
	var two TopRisksOutput
	call(t, cs, "top_risks", map[string]any{"n": 2}, &two)
	if len(two.Risks) != 2 || len(two.Risks[0].Members) != 14 {
		t.Errorf("n=2 should return 2 rows, the first the whole group: %+v", two.Risks)
	}
	// brief.total counts rows, not principals.
	if tr.Brief == nil || tr.Brief.Truncated || tr.Brief.Total["risks"] != 4 {
		t.Errorf("n=10 brief = %+v, want 4 rows, not truncated", tr.Brief)
	}
	if two.Brief == nil || !two.Brief.Truncated || two.Brief.Total["risks"] != 4 {
		t.Errorf("n=2 brief = %+v, want truncated with 4 rows in total", two.Brief)
	}

	var ex ExplainOutput
	call(t, cs, "explain", map[string]any{"from": "identity:owner07", "to": "repo:acme-security/vault"}, &ex)
	if len(ex.Edges) != 1 || ex.Edges[0].Evidence != string(graph.Inferred) {
		t.Errorf("explain on a member = %+v", ex)
	}
	var br BlastRadiusOutput
	call(t, cs, "blast_radius", map[string]any{"principal": "identity:owner07"}, &br)
	if br.Score.Score != g.Score {
		t.Errorf("member score %v, group score %v", br.Score.Score, g.Score)
	}
}

func TestGroupPhrases(t *testing.T) {
	ix := graph.NewIndex(loadOwners(t))
	one := graph.RiskGroup{GroupScore: graph.Score{Principal: "members:acme-app"}}
	team := graph.RiskGroup{Members: []string{"identity:alice", "identity:bob"}, Via: graph.ViaTeam, ViaScope: []string{"team:acme-app/web"}}
	plain := graph.RiskGroup{Members: []string{"identity:alice", "identity:bob", "identity:carol"}}
	for _, c := range []struct{ got, want string }{
		{GroupWho(ix, one), "members of acme-app"},
		{GroupKind(one), ""},
		{GroupWho(ix, team), "the 2 principals of team:acme-app/web"},
		{GroupKind(team), "2 principals (team:acme-app/web)"},
		{GroupWho(ix, plain), "3 principals with identical reach"},
		{GroupKind(plain), "3 principals (identical reach)"},
		{MembersText(plain.Members, 2), "identity:alice, identity:bob and 1 more"},
		{MembersText(plain.Members, 3), "identity:alice, identity:bob, identity:carol"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
