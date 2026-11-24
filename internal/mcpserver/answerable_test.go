package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

var answerT0 = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// answerGraph is a small fully visible enterprise: members of acme-app push
// to acme-app/web, whose ci workflow uses acme-actions/deploy@main (a branch
// with branch protection) and mints an OIDC token.
func answerGraph() *graph.Graph {
	live := func(from, to string, kind graph.EdgeKind, attrs map[string]string) graph.Edge {
		return graph.Edge{From: from, To: to, Kind: kind, Evidence: graph.Live, SourceAPI: "test", ObservedAt: answerT0, Attrs: attrs}
	}
	node := func(id string, kind graph.NodeKind, attrs map[string]string) graph.Node {
		return graph.Node{ID: id, Kind: kind, Name: id, Evidence: graph.Live, Attrs: attrs}
	}
	wf := "workflow:acme-app/web/.github/workflows/ci.yml"
	act := "action:acme-actions/deploy@main"
	return &graph.Graph{
		Schema: graph.SchemaVersion, CollectedAt: answerT0, Enterprise: "acme",
		Nodes: []graph.Node{
			node("enterprise:acme", graph.KindEnterprise, nil),
			node("org:acme-app", graph.KindOrg, map[string]string{graph.AttrDefaultPerm: "write"}),
			node("org:acme-actions", graph.KindOrg, map[string]string{graph.AttrDefaultPerm: "read"}),
			node("members:acme-app", graph.KindOrgMembers, nil),
			node("identity:alice", graph.KindIdentity, nil),
			node("identity:bob", graph.KindIdentity, nil),
			node("repo:acme-app/web", graph.KindRepo, nil),
			node("repo:acme-actions/deploy", graph.KindRepo, nil),
			node(wf, graph.KindWorkflow, nil),
			node(act, graph.KindActionRef, map[string]string{graph.AttrRefKind: "branch", graph.AttrRef: "main",
				graph.AttrRefProtected: "false"}),
			node("oidc:acme-app/web", graph.KindOIDC, nil),
		},
		Edges: []graph.Edge{
			live("identity:alice", "org:acme-app", graph.MemberOf, nil),
			live("members:acme-app", "repo:acme-app/web", graph.CanPush, map[string]string{graph.AttrVia: graph.ViaDefaultPerm}),
			live("identity:bob", "repo:acme-actions/deploy", graph.CanPush, map[string]string{graph.AttrVia: graph.ViaDirect}),
			live(wf, "repo:acme-app/web", graph.DefinedIn, nil),
			live(wf, act, graph.Uses, map[string]string{graph.AttrRefKind: "branch"}),
			live(act, "repo:acme-actions/deploy", graph.ResolvesTo, nil),
			live(wf, "oidc:acme-app/web", graph.ExecutesWith, nil),
		},
		Coverage: []graph.Coverage{},
	}
}

func checkAnswerable(t *testing.T, g *graph.Graph, kind, subject string) CheckAnswerableOutput {
	t.Helper()
	out, err := NewEngine(g).CheckAnswerable(CheckAnswerableInput{QuestionKind: kind, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCheckAnswerableFullCoverage(t *testing.T) {
	g := answerGraph()
	for _, r := range requiredFacts {
		out := checkAnswerable(t, g, r.Kind, "repo:acme-app/web")
		if out.Answerable != AnswerYes || len(out.Missing) != 0 {
			t.Errorf("%s: %s %+v, want yes", r.Kind, out.Answerable, out.Missing)
		}
	}
}

func TestCheckAnswerableBranchProtectionNotVisible(t *testing.T) {
	g := answerGraph()
	for i, n := range g.Nodes {
		if n.ID == "action:acme-actions/deploy@main" {
			g.Nodes[i].Attrs[graph.AttrRefProtected] = "unknown"
			g.Nodes[i].AttrEvidence = map[string]graph.Evidence{graph.AttrRefProtected: graph.NotVisible}
		}
	}
	g.Coverage = append(g.Coverage, graph.Coverage{Scope: "action:acme-actions/deploy@main", Fact: graph.AttrRefProtection,
		Reason: "token cannot read branch protection", NeedsFix: "admin on acme-actions/deploy"})
	out := checkAnswerable(t, g, "who_can_reach", "repo:acme-actions/deploy")
	if out.Answerable != AnswerPartial {
		t.Fatalf("answerable %s, want partial: %+v", out.Answerable, out)
	}
	want := MissingFact{Fact: factBranchProtection, Scope: "repo:acme-actions/deploy",
		Reason: "token cannot read branch protection; not visible attribute ref_protected: 1", NeedsFix: "admin on acme-actions/deploy"}
	if len(out.Missing) != 1 || out.Missing[0] != want {
		t.Errorf("missing %+v, want [%+v]", out.Missing, want)
	}
	// bob pushes to the host repo, so his blast radius goes through the gate.
	if b := checkAnswerable(t, g, "blast_radius", "identity:bob"); b.Answerable != AnswerPartial {
		t.Errorf("blast_radius bob: %s, want partial", b.Answerable)
	}
	// Control of acme-app's members (alice) does not depend on the gate.
	if p := checkAnswerable(t, g, "who_can_reach", "members:acme-app"); p.Answerable != AnswerYes {
		t.Errorf("who_can_reach members:acme-app: %s %+v, want yes", p.Answerable, p.Missing)
	}
}

func TestCheckAnswerableOrgWithNoData(t *testing.T) {
	g := answerGraph()
	g.Nodes = append(g.Nodes, graph.Node{ID: "org:acme-legacy", Kind: graph.KindOrg, Name: "acme-legacy", Evidence: graph.Live,
		Attrs: map[string]string{"repositories": "unknown"}, AttrEvidence: map[string]graph.Evidence{"repositories": graph.NotVisible}})
	g.Coverage = append(g.Coverage, graph.Coverage{Scope: "org:acme-legacy", Fact: "repositories",
		Reason: "token is not an org owner", NeedsFix: "org owner on acme-legacy"})
	for _, kind := range []string{"who_can_reach", "blast_radius", "paths"} {
		out := checkAnswerable(t, g, kind, "acme-legacy")
		if out.Answerable != AnswerNo || out.Subject != "org:acme-legacy" {
			t.Errorf("%s: %s about %s, want no about org:acme-legacy", kind, out.Answerable, out.Subject)
		}
		if len(out.Missing) == 0 || out.Missing[0].Fact != factRepositories || out.Missing[0].NeedsFix != "org owner on acme-legacy" {
			t.Errorf("%s: missing %+v", kind, out.Missing)
		}
	}
	// The other orgs still answer, and the whole enterprise is partial.
	if out := checkAnswerable(t, g, "who_can_reach", "repo:acme-app/web"); out.Answerable != AnswerYes {
		t.Errorf("web: %s %+v", out.Answerable, out.Missing)
	}
	if out := checkAnswerable(t, g, "top_risks", ""); out.Answerable != AnswerPartial || out.Subject != "enterprise:acme" {
		t.Errorf("top_risks: %s about %s", out.Answerable, out.Subject)
	}
}

func TestCheckAnswerableNotVisibleSubject(t *testing.T) {
	g := answerGraph()
	g.Nodes = append(g.Nodes, graph.Node{ID: "repo:acme-app/old", Kind: graph.KindRepo, Evidence: graph.NotVisible})
	if out := checkAnswerable(t, g, "who_can_reach", "repo:acme-app/old"); out.Answerable != AnswerNo {
		t.Errorf("not_visible subject: %s", out.Answerable)
	}
}

func TestCheckAnswerableEvidenceLevels(t *testing.T) {
	setPush := func(g *graph.Graph, ev graph.Evidence, at time.Time) {
		for i, e := range g.Edges {
			if e.Kind == graph.CanPush && e.From == "members:acme-app" {
				g.Edges[i].Evidence, g.Edges[i].ObservedAt = ev, at
			}
		}
	}
	for _, tc := range []struct {
		name      string
		ev        graph.Evidence
		at        time.Time
		retention int
		want      string
	}{
		{"inferred is visible", graph.Inferred, answerT0, 0, AnswerYes},
		{"recent audit is visible", graph.Audit, answerT0.Add(-30 * 24 * time.Hour), 0, AnswerYes},
		{"stale audit is not visible", graph.Audit, answerT0.Add(-120 * 24 * time.Hour), 0, AnswerPartial},
		{"audit stale under audit_retention_days", graph.Audit, answerT0.Add(-45 * 24 * time.Hour), 60, AnswerPartial},
		{"audit fresh under audit_retention_days", graph.Audit, answerT0.Add(-100 * 24 * time.Hour), 400, AnswerYes},
		{"not_visible", graph.NotVisible, answerT0, 0, AnswerPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := answerGraph()
			g.AuditRetentionDays = tc.retention
			setPush(g, tc.ev, tc.at)
			out := checkAnswerable(t, g, "who_can_reach", "repo:acme-app/web")
			if out.Answerable != tc.want {
				t.Fatalf("%s %+v, want %s", out.Answerable, out.Missing, tc.want)
			}
			if tc.want == AnswerPartial && (out.Missing[0].Fact != factDefaultPerm || out.Missing[0].Scope != "repo:acme-app/web") {
				t.Errorf("missing %+v", out.Missing)
			}
		})
	}
}

func TestCheckAnswerableNotRequiredFactIgnored(t *testing.T) {
	g := answerGraph()
	g.Coverage = append(g.Coverage, graph.Coverage{Scope: "org:acme-app", Fact: graph.AttrIPAllowList, Reason: "token is not an org owner"})
	if out := checkAnswerable(t, g, "who_can_reach", "repo:acme-app/web"); out.Answerable != AnswerYes {
		t.Errorf("who_can_reach: %s; ip_allow_list is not required", out.Answerable)
	}
	if out := checkAnswerable(t, g, "blast_radius", "members:acme-app"); out.Answerable != AnswerPartial || out.Missing[0].Fact != factOrgSettings {
		t.Errorf("blast_radius: %s %+v; org settings weight the score", out.Answerable, out.Missing)
	}
	g.Coverage = append(g.Coverage, graph.Coverage{Scope: "repo:acme-app/web", Fact: "something_new", Reason: "new gap"})
	if out := checkAnswerable(t, g, "who_can_reach", "repo:acme-app/web"); out.Answerable != AnswerPartial || out.Missing[0].Fact != factOther {
		t.Errorf("unclassified gap: %s %+v, want partial with fact other", out.Answerable, out.Missing)
	}
}

func TestCheckAnswerableErrors(t *testing.T) {
	e := NewEngine(answerGraph())
	for _, tc := range []struct {
		in   CheckAnswerableInput
		want string
	}{
		{CheckAnswerableInput{QuestionKind: "explain", Subject: "repo:acme-app/web"}, "question_kind must be one of who_can_reach, blast_radius, paths, top_risks, what_if, fix_plan"},
		{CheckAnswerableInput{QuestionKind: "who_can_reach"}, "subject is required"},
		{CheckAnswerableInput{QuestionKind: "paths", Subject: "repo:acme-app/wbe"}, `unknown subject "repo:acme-app/wbe"`},
	} {
		if _, err := e.CheckAnswerable(tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: error %v, want %q", tc.in, err, tc.want)
		}
	}
}

// TestUpstreamMatchesReach checks Upstream against Reach on the acme fixture
// and on random graphs with not_visible, inferred, audit and stale audit hops.
func TestUpstreamMatchesReach(t *testing.T) {
	check := func(name string, g *graph.Graph, targets []string) {
		ix := graph.NewIndex(g)
		for _, target := range targets {
			up := map[string]bool{}
			for _, id := range ix.Upstream(target) {
				up[id] = true
			}
			for _, n := range g.Nodes {
				if n.ID == target {
					continue
				}
				_, reaches := ix.Reach(n.ID, graph.Options{}).Paths[target]
				if reaches != up[n.ID] {
					t.Errorf("%s: %s: %s reaches=%v upstream=%v", name, target, n.ID, reaches, up[n.ID])
				}
			}
		}
	}
	check("acme", loadAcme(t), []string{"repo:acme-app/web", "oidc:acme-app/web", "action:acme-actions/deploy@main"})
	for seed := int64(1); seed <= 20; seed++ {
		g := randomAnswerGraph(rand.New(rand.NewSource(seed)))
		for i := range g.Edges {
			if i%7 == 0 && g.Edges[i].Evidence == graph.Live {
				g.Edges[i].Evidence = graph.Inferred
			}
		}
		var targets []string
		for _, n := range g.Nodes {
			targets = append(targets, n.ID)
		}
		check(fmt.Sprintf("seed %d", seed), g, targets)
	}
}

// randomAnswerGraph builds a random two-org enterprise in which each edge is
// present or not and live, not_visible, audit or stale audit at random.
func randomAnswerGraph(r *rand.Rand) *graph.Graph {
	g := &graph.Graph{Schema: graph.SchemaVersion, CollectedAt: answerT0, Enterprise: "acme", Coverage: []graph.Coverage{}}
	g.Nodes = append(g.Nodes, graph.Node{ID: "enterprise:acme", Kind: graph.KindEnterprise, Evidence: graph.Live})
	edge := func(from, to string, kind graph.EdgeKind, attrs map[string]string) {
		if r.Intn(10) < 3 {
			return
		}
		e := graph.Edge{From: from, To: to, Kind: kind, Evidence: graph.Live, SourceAPI: "test", ObservedAt: answerT0, Attrs: attrs}
		switch r.Intn(10) {
		case 0, 1:
			e.Evidence = graph.NotVisible
		case 2:
			e.Evidence = graph.Audit
			if r.Intn(2) == 0 {
				e.ObservedAt = answerT0.Add(-200 * 24 * time.Hour)
			}
		}
		g.Edges = append(g.Edges, e)
	}
	node := func(id string, kind graph.NodeKind, attrs map[string]string) {
		g.Nodes = append(g.Nodes, graph.Node{ID: id, Kind: kind, Name: id, Evidence: graph.Live, Attrs: attrs})
	}
	node("identity:alice", graph.KindIdentity, nil)
	node("identity:bob", graph.KindIdentity, nil)
	node("external:anyone", graph.KindExternal, nil)
	for _, org := range []string{"acme-app", "acme-actions"} {
		node("org:"+org, graph.KindOrg, map[string]string{graph.AttrDefaultPerm: "write"})
		node("members:"+org, graph.KindOrgMembers, nil)
		node("team:"+org+"/devs", graph.KindIdentity, nil)
		edge("identity:alice", "org:"+org, graph.MemberOf, nil)
		edge("identity:bob", "team:"+org+"/devs", graph.MemberOf, nil)
		for _, name := range []string{"one", "two"} {
			repo := "repo:" + org + "/" + name
			wf := "workflow:" + org + "/" + name + "/.github/workflows/ci.yml"
			act := "action:" + org + "/" + name + "@main"
			node(repo, graph.KindRepo, nil)
			node(wf, graph.KindWorkflow, nil)
			node(act, graph.KindActionRef, map[string]string{graph.AttrRefKind: "branch", graph.AttrRef: "main"})
			node("oidc:"+org+"/"+name, graph.KindOIDC, nil)
			edge("members:"+org, repo, graph.CanPush, map[string]string{graph.AttrVia: graph.ViaDefaultPerm})
			edge("team:"+org+"/devs", repo, graph.CanPush, map[string]string{graph.AttrVia: graph.ViaTeam})
			edge("identity:bob", repo, graph.CanPush, map[string]string{graph.AttrVia: graph.ViaDirect})
			edge(wf, repo, graph.DefinedIn, nil)
			edge(wf, repo, graph.CanPush, map[string]string{graph.AttrVia: graph.ViaTokenWrite})
			edge(wf, "oidc:"+org+"/"+name, graph.ExecutesWith, nil)
			edge(act, repo, graph.ResolvesTo, nil)
			edge("external:anyone", wf, graph.CanTrigger, map[string]string{"trigger": "pull_request_target"})
		}
	}
	// Workflows use actions across both orgs.
	for _, o1 := range []string{"acme-app", "acme-actions"} {
		for _, n1 := range []string{"one", "two"} {
			for _, o2 := range []string{"acme-app", "acme-actions"} {
				for _, n2 := range []string{"one", "two"} {
					if r.Intn(4) == 0 {
						edge("workflow:"+o1+"/"+n1+"/.github/workflows/ci.yml", "action:"+o2+"/"+n2+"@main", graph.Uses,
							map[string]string{graph.AttrRefKind: "branch"})
					}
				}
			}
		}
	}
	return g
}

// flipAll makes every not_visible edge and node live and every audit edge
// fresh: it flips every gap check_answerable could have reported.
func flipAll(g *graph.Graph) (*graph.Graph, int) {
	ix := graph.NewIndex(g)
	f := *g
	f.Edges = append([]graph.Edge{}, g.Edges...)
	f.Nodes = append([]graph.Node{}, g.Nodes...)
	n := 0
	for i, e := range f.Edges {
		if !ix.EdgeVerified(e) {
			f.Edges[i].Evidence, f.Edges[i].ObservedAt = graph.Live, g.CollectedAt
			n++
		}
	}
	for i, nd := range f.Nodes {
		if nd.Evidence == graph.NotVisible {
			f.Nodes[i].Evidence = graph.Live
			n++
		}
	}
	return &f, n
}

// answerFor computes the named tool's answer about subject, as JSON.
func answerFor(t *testing.T, e *Engine, kind, subject string) string {
	t.Helper()
	var outs []any
	add := func(v any, err error) {
		if err != nil {
			t.Fatalf("%s %s: %v", kind, subject, err)
		}
		outs = append(outs, v)
	}
	principal := subject
	if m := membersID(subject); m != subject {
		principal = m
	}
	switch kind {
	case "who_can_reach":
		targets := []string{subject}
		if graph.KindFromID(subject) == graph.KindOrg {
			for _, n := range e.ix.Graph().Nodes {
				if n.Kind == graph.KindRepo && graph.OrgOf(n.ID) == subject {
					targets = append(targets, n.ID)
				}
			}
		}
		for _, tg := range targets {
			add(e.WhoCanReach(WhoCanReachInput{Target: tg}))
		}
	case "blast_radius":
		add(e.BlastRadius(BlastRadiusInput{Principal: principal}))
	case "paths":
		add(e.Paths(PathsInput{From: principal}))
	case "top_risks":
		add(e.TopRisks(TopRisksInput{N: 100}))
	case "what_if":
		add(e.WhatIf(WhatIfInput{Fixes: []FixSpec{{Type: "pin_ref", Action: "action:acme-actions/one@main"},
			{Type: "lower_default_perm", Org: "org:acme-app", To: "read"}}}))
	case "fix_plan":
		for _, f := range []FixSpec{{Type: "pin_ref", Action: "action:acme-app/two@main"},
			{Type: "lower_default_perm", Org: "org:acme-actions", To: "none"},
			{Type: "restrict_token", Workflow: "workflow:acme-app/one/.github/workflows/ci.yml"}} {
			add(e.FixPlan(FixPlanInput{Fix: &f}))
		}
	default:
		t.Fatalf("no answer for %s", kind)
	}
	b, err := json.Marshal(outs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestCheckAnswerableRequiredFactsComplete is the property: when
// check_answerable says yes, flipping every gap it did not report (all of
// them, since it reported none) leaves the answer unchanged.
func TestCheckAnswerableRequiredFactsComplete(t *testing.T) {
	yes, flipped := 0, 0
	for seed := int64(1); seed <= 60; seed++ {
		g := randomAnswerGraph(rand.New(rand.NewSource(seed)))
		f, n := flipAll(g)
		e, ef := NewEngine(g), NewEngine(f)
		subjects := append([]string{"acme-app"}, e.ids...)
		for _, r := range requiredFacts {
			for _, s := range subjects {
				if r.Region == regionAll && s != "acme-app" {
					continue // one subject is enough: the region is the whole graph
				}
				out, err := e.CheckAnswerable(CheckAnswerableInput{QuestionKind: r.Kind, Subject: s})
				if err != nil {
					t.Fatal(err)
				}
				if out.Answerable != AnswerYes {
					continue
				}
				yes++
				if n > 0 {
					flipped++
				}
				if a, b := answerFor(t, e, r.Kind, out.Subject), answerFor(t, ef, r.Kind, out.Subject); a != b {
					t.Errorf("seed %d: %s about %s is yes, but flipping %d gaps changed the answer:\n%s\n%s", seed, r.Kind, s, n, a, b)
				}
			}
		}
	}
	if yes == 0 || flipped == 0 {
		t.Fatalf("property never exercised: %d yes answers, %d with gaps flipped", yes, flipped)
	}
}

func TestCheckAnswerableGolden(t *testing.T) {
	cs := connect(t)
	for _, tc := range []struct{ golden, kind, subject string }{
		{"check_answerable_partial.txt", "top_risks", ""},
		{"check_answerable_yes.txt", "who_can_reach", "repo:acme-app/web"},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "check_answerable",
			Arguments: map[string]any{"question_kind": tc.kind, "subject": tc.subject}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool error: %s", text(res))
		}
		testutil.Golden(t, tc.golden, []byte(text(res)))
	}
}

func TestServerInstructionsNameCheckAnswerable(t *testing.T) {
	ir := connect(t).InitializeResult()
	if ir == nil || !strings.Contains(ir.Instructions, "call check_answerable") {
		t.Errorf("instructions do not ask for check_answerable: %+v", ir)
	}
	p, err := NewEngine(loadAcme(t)).RenderPrompt("explain_path", map[string]string{"from": "members:acme-actions", "to": "oidc:acme-app/web"}, answerT0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "call check_answerable") {
		t.Error("explain_path prompt does not ask for check_answerable")
	}
}

// TestRequiredFactsDoc keeps the table in docs/mcp-clients.md equal to
// requiredFacts.
func TestRequiredFactsDoc(t *testing.T) {
	b, err := os.ReadFile("../../docs/mcp-clients.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- check_answerable table: generated from requiredFacts -->\n", "<!-- end check_answerable table -->"
	doc := string(b)
	i, j := strings.Index(doc, begin), strings.Index(doc, end)
	if i < 0 || j < i {
		t.Fatalf("docs/mcp-clients.md: markers %q and %q not found", begin, end)
	}
	if got, want := doc[i+len(begin):j], requirementsMarkdown(); got != want {
		t.Errorf("docs/mcp-clients.md table differs from requiredFacts; replace it with:\n%s", want)
	}
}

func TestEveryFactDocumented(t *testing.T) {
	doc := map[string]bool{}
	for _, f := range factDocs {
		doc[f.Fact] = true
	}
	check := func(where, f string) {
		if !doc[f] {
			t.Errorf("%s: fact %q has no factDocs entry", where, f)
		}
	}
	for _, r := range requiredFacts {
		for _, f := range r.Facts {
			check(r.Kind, f)
		}
	}
	for name, f := range nameFacts {
		check(name, f)
	}
	for _, kind := range []graph.EdgeKind{graph.CanPush, graph.Uses, graph.ResolvesTo, graph.DefinedIn, graph.ExecutesWith,
		graph.MemberOf, graph.CanTrigger, graph.CanAssume} {
		if f := factOfEdge(graph.Edge{Kind: kind, To: "repo:acme-app/web"}); f == factOther {
			t.Errorf("edge kind %s is unclassified", kind)
		}
	}
}
