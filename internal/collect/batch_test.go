package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// collectBatch runs Collect against f with the same 502 injection as
// collectAcme and returns the stable JSON of the graph.
func collectBatch(t *testing.T, f *fakeGitHub, cfg Config) (*graph.Graph, []byte) {
	t.Helper()
	f.failures["/orgs/acme-app/repos"] = 1
	cfg.Enterprise = "acme"
	cfg.Client = f.client(t)
	g, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return g, stableGraphJSON(t, g)
}

// workflowDirHits counts REST listings of .github/workflows, per repo.
func workflowDirHits(f *fakeGitHub) map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, n := range f.hits {
		if repo, ok := strings.CutSuffix(k, "/contents/.github/workflows"); ok {
			out[strings.TrimPrefix(repo, "/repos/")] += n
		}
	}
	return out
}

// liveRepos counts collected, non-archived repositories in g.
func liveRepos(g *graph.Graph) int {
	n := 0
	for _, x := range g.Nodes {
		if x.Kind == graph.KindRepo && x.Attrs["collected"] != "false" && x.Attrs[graph.AttrArchived] == "false" {
			n++
		}
	}
	return n
}

func TestBatchEquivalentToREST(t *testing.T) {
	rest := newFakeGitHub(t)
	_, restJSON := collectBatch(t, rest, Config{DisableGraphQLBatch: true})
	if len(rest.batchSizes) != 0 {
		t.Errorf("DisableGraphQLBatch sent %d batched queries", len(rest.batchSizes))
	}

	batched := newFakeGitHub(t)
	g, batchJSON := collectBatch(t, batched, Config{})
	testutil.Golden(t, "collect_acme.json", restJSON)
	testutil.Golden(t, "collect_acme.json", batchJSON)
	if string(restJSON) != string(batchJSON) {
		t.Fatalf("batched graph differs from REST:\n%s", testutil.UnifiedDiff(string(restJSON), string(batchJSON)))
	}

	if hits := workflowDirHits(batched); len(hits) != 0 {
		t.Errorf("REST workflow listings with batching on: %v", hits)
	}
	if hits := workflowDirHits(rest); len(hits) != liveRepos(g) {
		t.Errorf("REST path listed %d repos, want %d", len(hits), liveRepos(g))
	}
	// One query for the 13 live repositories, then one per nested wave with
	// something to read. Every enterprise reference the fixture's nested
	// files make (setup@main, deploy@sha, deploy@main) is already queued from
	// a workflow at depth 1, so only the first wave reads anything.
	repos := liveRepos(g)
	wantWorkflowQueries := (repos + DefaultBatchSize - 1) / DefaultBatchSize
	const nestedWaves = 1
	if got := len(batched.batchSizes); got != wantWorkflowQueries+nestedWaves {
		t.Errorf("batched queries = %d %v, want %d workflow + %d nested", got, batched.batchSizes, wantWorkflowQueries, nestedWaves)
	}
	if len(batched.batchSizes) > 0 && batched.batchSizes[0] != repos {
		t.Errorf("first batch has %d aliases, want %d repos", batched.batchSizes[0], repos)
	}
}

func TestBatchAliasErrorFallsBackToREST(t *testing.T) {
	f := newFakeGitHub(t)
	f.objectErrors["acme-app/api"] = "FORBIDDEN"
	// Priority keeps the fixture's org order (the default puts larger orgs
	// first), which the alias check below relies on.
	_, got := collectBatch(t, f, Config{Priority: []string{"acme-actions", "acme-app"}})
	testutil.Golden(t, "collect_acme.json", got)
	hits := workflowDirHits(f)
	if len(hits) != 1 || hits["acme-app/api"] != 1 {
		t.Errorf("REST workflow listings = %v, want only acme-app/api once", hits)
	}
	// The refused alias is r3 of the first batch: acme-actions/deploy, setup,
	// acme-app/web, api in fixture order.
	var body struct {
		Variables map[string]any `json:"variables"`
	}
	f.mu.Lock()
	first := f.gqlBodies[0]
	f.mu.Unlock()
	if err := json.Unmarshal([]byte(first), &body); err != nil {
		t.Fatal(err)
	}
	if body.Variables["o3"] != "acme-app" || body.Variables["n3"] != "api" {
		t.Errorf("acme-app/api is not alias r3: %v/%v", body.Variables["o3"], body.Variables["n3"])
	}
}

func TestBatchTruncatedBlobIsCoverage(t *testing.T) {
	f := newFakeGitHub(t)
	const path = ".github/workflows/deploy.yml"
	f.truncated["acme-app/api/"+path] = true
	g, _ := collectBatch(t, f, Config{})
	ix := newIndex(g)
	c, ok := hasCoverage(g, "repo:acme-app/api", "workflow:"+path)
	if !ok || c.Reason != "file too large or binary" {
		t.Errorf("coverage = %+v, %v", c, ok)
	}
	if _, ok := ix.nodes["workflow:acme-app/api/"+path]; ok {
		t.Error("truncated workflow was parsed")
	}
	if got := ix.node(t, "repo:acme-app/api").Attrs["workflows"]; got != "1" {
		t.Errorf("workflows = %q, want 1 (release.yml only)", got)
	}
	if hits := workflowDirHits(f); len(hits) != 0 {
		t.Errorf("truncation fell back to REST: %v", hits)
	}
}

// batchCollector is a collector on f's client, enough to drive fetchObjects.
func batchCollector(t *testing.T, f *fakeGitHub) *collector {
	t.Helper()
	cfg := Config{Enterprise: "acme"}
	return &collector{c: f.client(t), cfg: cfg, batch: newBatchState(cfg)}
}

func TestBatchHalvesOnResourceLimits(t *testing.T) {
	f := newFakeGitHub(t)
	f.limitAbove = 24
	k := batchCollector(t, f)
	var logs []string
	k.c.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	reqs := make([]objReq, 25)
	for i := range reqs {
		reqs[i] = objReq{owner: "acme-app", name: "web", exprs: []string{workflowDirExpr}}
	}
	res, err := k.fetchObjects(context.Background(), k.c, reqs)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.batchSizes) != "[25 13 12]" {
		t.Errorf("batch sizes = %v, want [25 13 12]", f.batchSizes)
	}
	for i, r := range res {
		if !r.ok || r.objs[0] == nil || r.objs[0].Typename != "Tree" {
			t.Fatalf("result %d = %+v", i, r)
		}
	}
	if k.batch.size != 13 {
		t.Errorf("batch size = %d, want 13", k.batch.size)
	}
	if len(logs) != 1 {
		t.Errorf("logged %d size changes, want 1: %v", len(logs), logs)
	}

	// A single request that is still too expensive falls back to REST.
	f.limitAbove = -1
	res, err = k.fetchObjects(context.Background(), k.c, reqs[:1])
	if err != nil {
		t.Fatal(err)
	}
	if res[0].ok {
		t.Error("over-limit single request should fall back to REST")
	}
}

func TestBatchUnsupportedSchemaDisablesBatching(t *testing.T) {
	f := newFakeGitHub(t)
	k := batchCollector(t, f)
	// The fake answers any query it does not know with errors and no data,
	// like an older GHES schema without the requested fields.
	q := []objReq{{owner: "acme-app", name: "web"}}
	res, err := k.fetchObjects(context.Background(), k.c, q)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].ok || !k.batch.off {
		t.Errorf("ok=%v off=%v, want REST fallback and batching off", res[0].ok, k.batch.off)
	}
}

// hostile strings: quotes, braces, a GraphQL comment and a fake alias.
var hostile = []string{`"}{`, `x") { viewer { login } } #`, "a\nr9: repository(owner: \"evil\""}

func TestBuildObjectQueryKeepsValuesOutOfText(t *testing.T) {
	var reqs []objReq
	for _, h := range hostile {
		reqs = append(reqs, objReq{owner: h, name: h, exprs: []string{h + ":" + h + "/action.yml"}})
	}
	q, vars := buildObjectQuery(reqs)
	for _, h := range hostile {
		if strings.Contains(q, h) {
			t.Errorf("query text contains %q", h)
		}
	}
	if strings.ContainsAny(q, `"#`) {
		t.Errorf("query text has a string literal or comment:\n%s", q)
	}
	if vars["o0"] != hostile[0] || vars["n1"] != hostile[1] || vars["e2_0"] != hostile[2]+":"+hostile[2]+"/action.yml" {
		t.Errorf("variables = %v", vars)
	}
	if isMutation(q) {
		t.Error("batched query is not a query")
	}
}

func TestBatchHostileWorkflowRefs(t *testing.T) {
	f := newFakeGitHub(t)
	f.extraWorkflows["acme-app/web/hostile.yml"] = `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: 'acme-actions/x"}{@"}{'
      - uses: 'acme-actions/deploy/p"){viewer{login}}#@v1"}{'
`
	g, _ := collectBatch(t, f, Config{})
	ix := newIndex(g)
	ix.node(t, `action:acme-actions/x"}{@"}{`)
	f.mu.Lock()
	bodies := append([]string(nil), f.gqlBodies...)
	f.mu.Unlock()
	sawRef := false
	for _, b := range bodies {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal([]byte(b), &req); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{`"}{`, `x"`, "viewer", `p")`} {
			if strings.Contains(req.Query, bad) {
				t.Errorf("query text contains attacker string %q:\n%s", bad, req.Query)
			}
		}
		for _, v := range req.Variables {
			if s, _ := v.(string); strings.HasPrefix(s, `"}{:`) {
				sawRef = true
			}
		}
	}
	if !sawRef {
		t.Error(`the "}{ ref was never sent as a variable`)
	}
}

func TestProgressCallback(t *testing.T) {
	f := newFakeGitHub(t)
	var events []Progress
	g, _ := collectBatch(t, f, Config{Progress: func(p Progress) { events = append(events, p) }})
	last := map[string]int{}
	var workflowTotal, workflowDone int
	for _, p := range events {
		if p.Done < last[p.Phase] {
			t.Errorf("%s: Done went back from %d to %d", p.Phase, last[p.Phase], p.Done)
		}
		if p.Done > p.Total {
			t.Errorf("%s: Done %d > Total %d", p.Phase, p.Done, p.Total)
		}
		last[p.Phase] = p.Done
		if p.Phase == PhaseWorkflows {
			if workflowTotal != 0 && p.Total != workflowTotal {
				t.Errorf("workflows Total changed from %d to %d", workflowTotal, p.Total)
			}
			workflowTotal, workflowDone = p.Total, p.Done
		}
	}
	for _, ph := range []string{PhaseOrgs, PhaseSettings, PhaseMembers, PhaseRepos, PhaseWorkflows, PhaseNested} {
		if _, ok := last[ph]; !ok {
			t.Errorf("no %s progress", ph)
		}
	}
	if want := liveRepos(g); workflowTotal != want || workflowDone != want {
		t.Errorf("workflows progress ended at %d/%d, want %d/%d", workflowDone, workflowTotal, want, want)
	}
	if lastEv := events[len(events)-1]; lastEv.GraphQLRemaining != 4900 {
		t.Errorf("GraphQLRemaining = %d, want 4900 from rateLimit", lastEv.GraphQLRemaining)
	}
}

func TestProgressLoggerThrottles(t *testing.T) {
	now := time.Date(2030, 1, 1, 14, 0, 0, 0, time.UTC)
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	p := newProgressLogger(logf, func() time.Time { return now })
	ev := Progress{Phase: PhaseWorkflows, Done: 1200, Total: 3000, RESTRemaining: 4870, GraphQLRemaining: 4100,
		ResetAt: time.Date(2030, 1, 1, 14, 5, 0, 0, time.UTC)}
	p(ev)
	now = now.Add(4 * time.Second)
	p(ev)
	now = now.Add(time.Second)
	ev.RESTRemaining, ev.GraphQLRemaining = -1, -1
	p(ev)
	want := []string{
		"collect: workflows 1200/3000 repos | graphql 4100 left | rest 4870 left, resets 14:05Z",
		"collect: workflows 1200/3000 repos",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestProgressDefaultsToLogf(t *testing.T) {
	if progressFunc(Config{}) != nil {
		t.Error("no Logf and no Progress should mean no progress output")
	}
	if progressFunc(Config{Logf: func(string, ...any) {}}) == nil {
		t.Error("Logf should enable the default progress logger")
	}
}
