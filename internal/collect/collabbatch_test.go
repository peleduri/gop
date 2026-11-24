package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// collabRun is one collection of the acme fixture: its stable graph JSON,
// its not-visible log lines and the fake that served it.
type collabRun struct {
	f      *fakeGitHub
	g      *graph.Graph
	json   string
	notVis []string
}

func runCollab(t *testing.T, setup func(*fakeGitHub), disable bool) collabRun {
	t.Helper()
	f := newFakeGitHub(t)
	if setup != nil {
		setup(f)
	}
	var mu sync.Mutex
	var notVis []string
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		if strings.Contains(line, "not visible") {
			mu.Lock()
			notVis = append(notVis, line)
			mu.Unlock()
		}
	}
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), DisableGraphQLBatch: disable, Logf: logf})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return collabRun{f: f, g: g, json: string(stableGraphJSON(t, g)), notVis: notVis}
}

// restCollabHits counts REST collaborator listings, per repo.
func restCollabHits(f *fakeGitHub) map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, n := range f.hits {
		path, _, _ := strings.Cut(k, "?")
		if repo, ok := strings.CutSuffix(path, "/collaborators"); ok && strings.HasPrefix(repo, "/repos/") {
			out[strings.TrimPrefix(repo, "/repos/")] += n
		}
	}
	return out
}

// restRequests counts every REST request the fake served (GraphQL excluded).
func restRequests(f *fakeGitHub) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, c := range f.hits {
		if k != "/graphql" && !strings.HasPrefix(k, "/api/graphql") && !strings.HasPrefix(k, "graphql:") {
			n += c
		}
	}
	return n
}

// The batched and REST collaborator reads give the same graph, coverage and
// not-visible summary, including for repositories and orgs the token cannot
// read and for every reason a repository falls back to REST.
func TestCollabBatchEquivalentToREST(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*fakeGitHub)
	}{
		{"fixture", nil},
		{"forbidden repo", func(f *fakeGitHub) { f.forbidCollab["acme-actions/deploy"] = true }},
		{"not found repo", func(f *fakeGitHub) { f.collabStatus["acme-app/web"] = 404 }},
		{"alias error", func(f *fakeGitHub) { f.objectErrors["acme-app/api"] = "FORBIDDEN" }},
		{"more than one page", func(f *fakeGitHub) { f.collabPageMax = 1 }},
		{"no permission sources", func(f *fakeGitHub) { f.noPermSources = true }},
		{"unsupported schema", func(f *fakeGitHub) { f.collabUnsupported = true }},
		{"resource limits", func(f *fakeGitHub) { f.limitAbove = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest := runCollab(t, tc.setup, true)
			batched := runCollab(t, tc.setup, false)
			if rest.json != batched.json {
				t.Fatalf("batched graph differs from REST:\n%s", testutil.UnifiedDiff(rest.json, batched.json))
			}
			if !slices.Equal(rest.notVis, batched.notVis) {
				t.Errorf("not-visible lines differ:\nREST:    %q\nbatched: %q", rest.notVis, batched.notVis)
			}
			if rest.f.collabQueries != 0 {
				t.Errorf("DisableGraphQLBatch sent %d collaborator queries", rest.f.collabQueries)
			}
		})
	}
}

// On the acme fixture the batch replaces every REST collaborator listing
// except the ones that must fall back: acme-app/api (a custom role, which
// only REST names) and acme-legacy/old-site (the token cannot list it).
func TestCollabBatchRequestCount(t *testing.T) {
	before := runCollab(t, func(f *fakeGitHub) { f.collabUnsupported = true }, false)
	after := runCollab(t, nil, false)
	if before.json != after.json {
		t.Fatalf("graphs differ:\n%s", testutil.UnifiedDiff(before.json, after.json))
	}
	bh, ah := restCollabHits(before.f), restCollabHits(after.f)
	want := map[string]int{"acme-app/api": 1, "acme-legacy/old-site": 1}
	if fmt.Sprint(ah) != fmt.Sprint(want) {
		t.Errorf("REST collaborator listings with batching = %v, want %v", ah, want)
	}
	if len(bh) != liveRepos(before.g) {
		t.Errorf("REST collaborator listings without the batch = %d, want one per live repo (%d)", len(bh), liveRepos(before.g))
	}
	// One query per org with live repositories: acme-actions, acme-app,
	// acme-legacy, acme-secure (acme-archive is archived).
	if after.f.collabQueries != 4 {
		t.Errorf("collaborator queries = %d, want 4", after.f.collabQueries)
	}
	rb, ra := restRequests(before.f), restRequests(after.f)
	t.Logf("acme fixture REST requests: %d before, %d after (collaborator listings %d -> %d)",
		rb, ra, sumCounts(bh), sumCounts(ah))
	if rb-ra != sumCounts(bh)-sumCounts(ah) {
		t.Errorf("REST requests dropped by %d, want %d (the collaborator listings saved)", rb-ra, sumCounts(bh)-sumCounts(ah))
	}
	// The custom role's base role still comes from the REST role list.
	e := newIndex(after.g).mustEdge(t, "identity:frank", "repo:acme-app/api", graph.CanPush)
	if e.Attrs["permission"] != "deployer" || e.Attrs[attrBaseRole] != "write" {
		t.Errorf("frank edge = %+v", e.Attrs)
	}
}

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func TestGQLCollaborators(t *testing.T) {
	type src = struct {
		RoleName *string `json:"roleName"`
	}
	str := func(s string) *string { return &s }
	srcs := func(names ...*string) *[]src {
		out := []src{}
		for _, n := range names {
			out = append(out, src{RoleName: n})
		}
		return &out
	}
	cases := []struct {
		name    string
		perm    string
		sources *[]src
		ok      bool
		role    string
		push    bool
	}{
		{"built-in write", "WRITE", srcs(str("write")), true, "write", true},
		{"capitalized built-in names", "ADMIN", srcs(str("Write"), str("Admin")), true, "admin", true},
		{"sources without names", "MAINTAIN", srcs(nil), true, "maintain", true},
		{"custom role", "WRITE", srcs(str("deployer")), false, "", false},
		{"organization role", "WRITE", srcs(str("all_repo_write")), false, "", false},
		{"pusher without sources", "WRITE", nil, false, "", false},
		{"reader without sources", "READ", nil, true, "read", false},
		{"moderate", "MODERATE", srcs(str("custom-mod")), true, "moderate", false},
		{"unknown permission", "OWNER", srcs(), false, "", false},
	}
	for _, tc := range cases {
		gr := &gqlCollabRepo{}
		js := fmt.Sprintf(`{"collaborators":{"pageInfo":{"hasNextPage":false},"edges":[{"permission":%q,"node":{"login":"alice"}}]}}`, tc.perm)
		if err := json.Unmarshal([]byte(js), gr); err != nil {
			t.Fatal(err)
		}
		gr.Collaborators.Edges[0].PermissionSources = tc.sources
		got, ok := gqlCollaborators(gr)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if len(got) != 1 || got[0].Login != "alice" || got[0].RoleName != tc.role || got[0].Permissions.canPush() != tc.push {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if tc.push && pushRole(got[0].RoleName, got[0].Permissions) != tc.role {
			t.Errorf("%s: pushRole = %q", tc.name, pushRole(got[0].RoleName, got[0].Permissions))
		}
	}
	// More than one page, or no collaborators field: REST.
	for _, js := range []string{`{"collaborators":{"pageInfo":{"hasNextPage":true},"edges":[]}}`, `{"collaborators":null}`} {
		gr := &gqlCollabRepo{}
		if err := json.Unmarshal([]byte(js), gr); err != nil {
			t.Fatal(err)
		}
		if _, ok := gqlCollaborators(gr); ok {
			t.Errorf("%s: batched answer accepted", js)
		}
	}
}

func TestBuildCollabQueryKeepsValuesOutOfText(t *testing.T) {
	o := &orgState{login: hostile[0]}
	var repos []*graph.Node
	for _, h := range hostile {
		repos = append(repos, &graph.Node{ID: "repo:" + o.login + "/" + h})
	}
	q, vars := buildCollabQuery(o, repos)
	for _, h := range hostile {
		if strings.Contains(q, h) {
			t.Errorf("query text contains %q", h)
		}
	}
	if strings.ContainsAny(q, `"#`) {
		t.Errorf("query text has a string literal or comment:\n%s", q)
	}
	if vars["o0"] != hostile[0] || vars["n1"] != hostile[1] || vars["n2"] != hostile[2] {
		t.Errorf("variables = %v", vars)
	}
	if isMutation(q) {
		t.Error("batched query is not a query")
	}
}

// GraphQL points are counted from each query's rateLimit { cost } (else 1)
// and reported in progress.
func TestGraphQLPointsInProgress(t *testing.T) {
	f := newFakeGitHub(t)
	var last Progress
	if _, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), Progress: func(p Progress) { last = p }}); err != nil {
		t.Fatal(err)
	}
	if last.GraphQLPoints <= 0 {
		t.Fatalf("GraphQLPoints = %d, want > 0", last.GraphQLPoints)
	}
	if s := last.String(); !strings.Contains(s, fmt.Sprintf("%d points used", last.GraphQLPoints)) {
		t.Errorf("progress line %q does not show points", s)
	}
	c := f.client(t)
	var data map[string]any
	if _, err := c.GraphQL(context.Background(), "query { viewer { login } }", nil, &data); err != nil {
		t.Fatal(err)
	}
	if st := c.RateState(); st.GraphQLQueries != 1 || st.GraphQLPoints != 1 {
		t.Errorf("a query without rateLimit: queries %d, points %d, want 1 and 1", st.GraphQLQueries, st.GraphQLPoints)
	}
}

func TestBatchCost(t *testing.T) {
	cases := []struct{ repos, perRepo, queries, points int }{
		{0, 52, 0, 0},
		{25, 52, 1, 13},
		{26, 52, 2, 14}, // the second query's one repo still costs a point
		{25, 1, 1, 1},
		{60, 1, 3, 3},
	}
	for _, tc := range cases {
		q, p := batchCost(tc.repos, tc.perRepo)
		if q != tc.queries || p != tc.points {
			t.Errorf("batchCost(%d, %d) = %d, %d, want %d, %d", tc.repos, tc.perRepo, q, p, tc.queries, tc.points)
		}
	}
}
