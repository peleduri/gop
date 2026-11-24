package mcpserver

import (
	"strings"
	"testing"
	"time"

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

func loadCauses(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/causes/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// top_risks folds the 4 owners of many orgs into one cause row: the summary
// names the cause and the range, brief leaves out member_scores, full lists
// them; what_if, suggest_fixes and fix_plan model reduce_owners; the
// summary resource carries the ownership histogram.
func TestCauseGroupsAndReduceOwnersOverMCP(t *testing.T) {
	cs := connectGraph(t, loadCauses(t))
	var tr TopRisksOutput
	call(t, cs, "top_risks", map[string]any{"n": 3}, &tr)
	g := tr.Risks[0]
	if g.Cause != graph.CauseOrgOwner || len(g.Members) != 4 || g.Range == nil || g.MemberScores != nil {
		t.Fatalf("brief cause row = %+v", g)
	}
	want := "top risk: `4 accounts that own 18 or more orgs (identity:admin-a, identity:admin-b, identity:admin-c and 1 more)` can each control 54 to 56 repos across 18 to 20 orgs (confirmed)"
	if !strings.HasPrefix(tr.Summary, want) {
		t.Errorf("summary = %q, want prefix %q", tr.Summary, want)
	}
	if tr.Brief == nil || tr.Brief.Total["member_scores"] != 4 {
		t.Errorf("brief = %+v, want member_scores counted", tr.Brief)
	}
	var full TopRisksOutput
	call(t, cs, "top_risks", map[string]any{"n": 3, "detail": "full"}, &full)
	if len(full.Risks[0].MemberScores) != 4 || full.Risks[0].MemberScores[3].Principal != "identity:admin-d" {
		t.Errorf("full member scores = %+v", full.Risks[0].MemberScores)
	}

	var wi WhatIfOutput
	call(t, cs, "what_if", map[string]any{"fixes": []map[string]any{{"type": "reduce_owners"}}}, &wi)
	if len(wi.Delta.Fixes) != 1 || wi.Delta.Fixes[0] != "reduce_owners:>=5" || wi.Delta.After.ConfirmedPairs >= wi.Delta.Before.ConfirmedPairs {
		t.Errorf("what_if = %+v", wi.Delta.Fixes)
	}
	var sf SuggestFixesOutput
	call(t, cs, "suggest_fixes", map[string]any{"owner_threshold": 19, "detail": "full"}, &sf)
	if len(sf.Fixes) == 0 || sf.Fixes[0].Fix.Type != "reduce_owners" || sf.Fixes[0].Fix.Threshold != 19 || sf.Fixes[0].Caveat == "" {
		t.Errorf("suggest_fixes = %+v", sf.Fixes)
	}
	var fp FixPlanOutput
	call(t, cs, "fix_plan", map[string]any{"fix": map[string]any{"type": "reduce_owners", "threshold": 5}, "detail": "full"}, &fp)
	if len(fp.Plan.Steps) != 13 || !strings.Contains(fp.Summary, "13 settings to change") {
		t.Errorf("fix_plan: %d steps, summary %q", len(fp.Plan.Steps), fp.Summary)
	}
	kept := false
	for _, c := range fp.Plan.Caveats {
		kept = kept || strings.Contains(c, "acme-o15 (admin-a, admin-b)")
	}
	if !kept {
		t.Errorf("caveats should name the kept owners: %v", fp.Plan.Caveats)
	}

	s := NewEngine(loadCauses(t)).Summary(time.Now())
	if s.OrgOwnership == nil || s.OrgOwnership.Owners != 25 || s.OrgOwnership.Buckets[3].Accounts != 4 {
		t.Errorf("summary org_ownership = %+v", s.OrgOwnership)
	}
	if NewEngine(loadOwners(t)).Summary(time.Now()).OrgOwnership == nil {
		t.Error("the owners fixture has owners")
	}
}

func TestCausePhrases(t *testing.T) {
	ix := graph.NewIndex(loadOwners(t))
	two := []string{"identity:alice", "identity:bob"}
	own := graph.RiskGroup{Members: two, Cause: graph.CauseOrgOwner, Range: &graph.GroupRange{OwnedOrgs: &graph.MinMax{Min: 1009, Max: 1079}}}
	same := graph.RiskGroup{Members: two, Cause: graph.CauseOrgOwner, Range: &graph.GroupRange{OwnedOrgs: &graph.MinMax{Min: 6, Max: 6}}}
	team := graph.RiskGroup{Members: two, Cause: graph.CauseTeam, CauseScope: []string{"team:acme-app/web"}}
	mem := graph.RiskGroup{Members: two, Cause: graph.CauseOrgMembers, CauseScope: []string{"members:acme-app"}}
	for _, c := range []struct{ got, want string }{
		{GroupWho(ix, own), "2 accounts that own 1,009 or more orgs"},
		{GroupKind(own), "2 owners of 1,009 to 1,079 orgs"},
		{GroupWho(ix, same), "2 accounts that each own 6 orgs"},
		{GroupKind(same), "2 owners of 6 orgs"},
		{GroupWho(ix, team), "2 principals that reach mostly through team:acme-app/web"},
		{GroupKind(team), "2 principals (mostly through team:acme-app/web)"},
		{GroupWho(ix, mem), "2 members of acme-app"},
		{GroupKind(mem), "2 principals (mostly as members of acme-app)"},
		{Num(1234567), "1,234,567"}, {Num(-1000), "-1,000"}, {Num(999), "999"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
