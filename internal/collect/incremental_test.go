package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// incRun is one collection against a fake: the graph, the logs and the
// requests it sent.
type incRun struct {
	g        *graph.Graph
	logs     []string
	hits     map[string]int // REST path?query -> count
	gql      []string       // GraphQL request bodies
	requests int
}

func (r incRun) logged(sub string) bool {
	return slices.ContainsFunc(r.logs, func(l string) bool { return strings.Contains(l, sub) })
}

// collectRun runs Collect against f (counters reset first) with cfg's
// cache and incremental settings.
func collectRun(t *testing.T, f *fakeGitHub, cfg Config) incRun {
	t.Helper()
	f.resetCounts()
	f.mu.Lock()
	f.gqlAll = nil
	f.mu.Unlock()
	var run incRun
	c := f.client(t)
	c.logf = func(format string, args ...any) { run.logs = append(run.logs, fmt.Sprintf(format, args...)) }
	cfg.Enterprise, cfg.Client = "acme", c
	g, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	run.g, run.hits, run.gql, run.requests = g, map[string]int{}, f.gqlAll, f.requests
	for k, v := range f.hits {
		if k != "/graphql" {
			run.hits[k] = v
		}
	}
	return run
}

// listedRepos returns the lower "owner/repo" of every repo the collector
// lists (the repos of non-archived orgs), less skip.
func listedRepos(f *fakeGitHub, skip ...string) map[string]bool {
	out := map[string]bool{}
	for _, o := range f.fx.Orgs {
		if o.ArchivedAt != "" {
			continue
		}
		for _, raw := range o.Repos {
			var r struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &r)
			full := strings.ToLower(o.Login + "/" + r.Name)
			if !slices.Contains(skip, full) {
				out[full] = true
			}
		}
	}
	return out
}

// gqlRepos returns the lower "owner/repo" every batched alias of the
// GraphQL bodies names.
func gqlRepos(t *testing.T, bodies []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, b := range bodies {
		var req struct {
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal([]byte(b), &req); err != nil {
			t.Fatal(err)
		}
		for i := 0; ; i++ {
			o, ok1 := req.Variables[fmt.Sprintf("o%d", i)].(string)
			n, ok2 := req.Variables[fmt.Sprintf("n%d", i)].(string)
			if !ok1 || !ok2 {
				break
			}
			out[strings.ToLower(o+"/"+n)] = true
		}
	}
	return out
}

// removeRepo deletes owner/name from the fake's fixture.
func removeRepo(f *fakeGitHub, owner, name string) {
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login != owner {
			continue
		}
		f.fx.Orgs[i].Repos = slices.DeleteFunc(f.fx.Orgs[i].Repos, func(raw json.RawMessage) bool {
			var r struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &r)
			return r.Name == name
		})
	}
}

const (
	incPushRepo = "acme-app/api" // a push: a new CODEOWNERS file
	incWFRepo   = "acme-app/web" // one workflow file changed
	incDelRepo  = "acme-app/docs"
	incPushedAt = "2026-02-01T00:00:00Z"
)

// mutate applies the incremental test's changes to f.
func mutate(f *fakeGitHub) {
	f.mu.Lock()
	f.pushedAt = map[string]string{incPushRepo: incPushedAt, incWFRepo: incPushedAt}
	f.extraFiles[incPushRepo+"/.github/CODEOWNERS"] = "* @acme-app/admins\n"
	f.extraWorkflows[incWFRepo+"/ci.yml"] = cacheWorkflow("acme-other/tool2@main")
	f.mu.Unlock()
	removeRepo(f, "acme-app", "docs")
}

func TestIncrementalCollect(t *testing.T) {
	f := newFakeGitHub(t)
	dir := filepath.Join(t.TempDir(), "gop-cache")
	cfg := Config{CacheDir: dir, Incremental: true}

	first := collectRun(t, f, cfg)
	if !first.logged("incremental: full run (no previous incremental run") || !first.logged("repos read (full run)") {
		t.Fatalf("first run is not a full run: %q", first.logs)
	}
	// Without changes, nothing per repository is requested again.
	same := collectRun(t, f, cfg)
	if normalized(t, same.g) != normalized(t, first.g) {
		t.Error("an unchanged incremental run's graph differs from the full run's")
	}
	unchangedAll := listedRepos(f)
	for k := range same.hits {
		if unchangedAll[repoScope(k)] {
			t.Errorf("unchanged run requested %s", k)
		}
	}
	for r := range gqlRepos(t, same.gql) {
		if unchangedAll[r] {
			t.Errorf("unchanged run sent a batched alias for %s", r)
		}
	}

	mutate(f)
	inc := collectRun(t, f, cfg)

	// Reference: a fresh full collection of the mutated fake, without a cache.
	ref := newFakeGitHub(t)
	mutate(ref)
	full := collectRun(t, ref, Config{})

	if normalized(t, inc.g) != normalized(t, full.g) {
		t.Error("the incremental graph differs from a full collection of the changed enterprise")
	}
	if !graphMentions(inc.g, "acme-other/tool2") || graphMentions(inc.g, incDelRepo) {
		t.Error("the incremental graph misses the changed workflow or keeps the deleted repo")
	}
	if inc.logged("does not match its plan") {
		t.Errorf("a batched query plan does not match its query: %q", inc.logs)
	}
	unchanged := listedRepos(f, incPushRepo, incWFRepo)
	if !inc.logged(fmt.Sprintf("incremental: 2 repos re-read, %d reused", len(unchanged))) {
		t.Errorf("no re-read/reused count line in %q", inc.logs)
	}

	// REST: exactly the full run's requests that are not about an unchanged
	// repository (org-level calls, the changed repos, uncollected repos).
	want := map[string]int{}
	for k, v := range full.hits {
		if !unchanged[repoScope(k)] {
			want[k] = v
		}
	}
	for k, v := range inc.hits {
		if want[k] != v {
			t.Errorf("incremental run: %s requested %d times, want %d", k, v, want[k])
		}
		if strings.Contains(k, "/repos/"+incDelRepo+"/") {
			t.Errorf("the deleted repo was requested: %s", k)
		}
	}
	for k, v := range want {
		if _, ok := inc.hits[k]; !ok {
			t.Errorf("incremental run: %s not requested, want %d", k, v)
		}
	}
	// GraphQL: batched aliases only for changed or uncollected repos.
	sent := gqlRepos(t, inc.gql)
	for r := range sent {
		if unchanged[r] {
			t.Errorf("incremental run sent a batched alias for unchanged %s", r)
		}
	}
	if !sent[incPushRepo] || !sent[incWFRepo] {
		t.Errorf("changed repos were not read again: %v", sent)
	}
	if inc.requests >= full.requests {
		t.Errorf("incremental run sent %d requests, the full run %d", inc.requests, full.requests)
	}
	t.Logf("requests: full %d (graphql %d), unchanged incremental %d (graphql %d), incremental after 2 changes and 1 deletion %d (graphql %d), fresh full of the changed fake %d (graphql %d)",
		first.requests, len(first.gql), same.requests, len(same.gql), inc.requests, len(inc.gql), full.requests, len(full.gql))

	// observed_at: facts read from reused answers keep the first run's time;
	// facts of the changed repos get this run's.
	prev := map[string]graph.Edge{}
	for _, e := range first.g.Edges {
		prev[edgeKey(e)] = e
	}
	kept, fresh := 0, 0
	for _, e := range inc.g.Edges {
		if !strings.HasPrefix(e.SourceAPI, "rest:GET /repos/") {
			if !e.ObservedAt.Equal(inc.g.CollectedAt) {
				t.Errorf("org-level edge %s -%s-> %s: observed_at %s, want the run time", e.From, e.Kind, e.To, e.ObservedAt)
			}
			continue
		}
		switch repo := edgeRepo(e); {
		case repo == strings.ToLower(incPushRepo) || repo == strings.ToLower(incWFRepo):
			fresh++
			if !e.ObservedAt.Equal(inc.g.CollectedAt) {
				t.Errorf("re-read edge %s -%s-> %s: observed_at %s, want the run time", e.From, e.Kind, e.To, e.ObservedAt)
			}
		case unchanged[repo]:
			p, ok := prev[edgeKey(e)]
			if ok && p.ObservedAt.Equal(first.g.CollectedAt) {
				kept++
				if !e.ObservedAt.Equal(p.ObservedAt) {
					t.Errorf("reused edge %s -%s-> %s: observed_at %s, want %s", e.From, e.Kind, e.To, e.ObservedAt, p.ObservedAt)
				}
			}
		}
	}
	if kept == 0 || fresh == 0 {
		t.Errorf("%d reused edges kept their time, %d re-read edges checked", kept, fresh)
	}
	if !first.g.CollectedAt.Before(inc.g.CollectedAt) {
		t.Fatal("runs share a timestamp")
	}

	checkCacheModes(t, dir)
	grepCache(t, dir, testToken)
	// The deleted repo's records are gone.
	grepCache(t, dir, `"repo":"`+incDelRepo+`"`)
}

func TestIncrementalFullEvery(t *testing.T) {
	f := newFakeGitHub(t)
	dir := filepath.Join(t.TempDir(), "gop-cache")
	cfg := Config{CacheDir: dir, Incremental: true}
	first := collectRun(t, f, cfg)

	second := collectRun(t, f, cfg)
	if !second.logged("incremental: reusing unchanged repositories") || second.requests >= first.requests {
		t.Fatalf("second run is not incremental (%d requests, full %d): %q", second.requests, first.requests, second.logs)
	}

	// A short threshold makes the next run a full run.
	cfgShort := cfg
	cfgShort.FullEvery = time.Nanosecond
	short := collectRun(t, f, cfgShort)
	if !short.logged("incremental: full run (the last full run was") || short.requests != first.requests {
		t.Errorf("FullEvery=1ns: %d requests, want %d; logs %q", short.requests, first.requests, short.logs)
	}

	// Default threshold: a last full run 8 days ago forces a full run.
	path := filepath.Join(dir, incStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st incState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if !st.LastAt.Equal(st.FullAt) {
		t.Errorf("after a full run full_at %s != last_at %s", st.FullAt, st.LastAt)
	}
	st.FullAt = time.Now().Add(-8 * 24 * time.Hour)
	data, _ = json.Marshal(st)
	if err := writeFileAtomic(dir, incStateFile, data); err != nil {
		t.Fatal(err)
	}
	aged := collectRun(t, f, cfg)
	if !aged.logged("full runs every 168h0m0s") || aged.requests != first.requests {
		t.Errorf("8 days after the full run: %d requests, want %d; logs %q", aged.requests, first.requests, aged.logs)
	}
	// It is still incremental within the threshold.
	again := collectRun(t, f, cfg)
	if !again.logged("incremental: reusing") {
		t.Errorf("run after the forced full run is not incremental: %q", again.logs)
	}
}

func TestIncrementalFullRunWhenStateDiffers(t *testing.T) {
	f := newFakeGitHub(t)
	dir := filepath.Join(t.TempDir(), "gop-cache")
	collectRun(t, f, Config{CacheDir: dir, Incremental: true})
	for name, tc := range map[string]struct {
		cfg    Config
		mutate func(*incState)
		want   string
	}{
		"orgs":      {cfg: Config{Orgs: []string{"acme-app"}}, want: "the org selection changed"},
		"token":     {mutate: func(s *incState) { s.Auth = "token:0000000000000000" }, want: "the previous run used another token or App"},
		"schema":    {mutate: func(s *incState) { s.Schema = "gop.graph/v1" }, want: "the graph schema changed"},
		"ent":       {mutate: func(s *incState) { s.Enterprise = "other" }, want: "the previous run collected another enterprise"},
		"corrupted": {mutate: func(s *incState) { s.FullAt = time.Time{} }, want: "unreadable"},
	} {
		t.Run(name, func(t *testing.T) {
			sub := filepath.Join(t.TempDir(), "gop-cache")
			collectRun(t, f, Config{CacheDir: sub, Incremental: true})
			if tc.mutate != nil {
				data, _ := os.ReadFile(filepath.Join(sub, incStateFile))
				var st incState
				_ = json.Unmarshal(data, &st)
				tc.mutate(&st)
				data, _ = json.Marshal(st)
				if err := writeFileAtomic(sub, incStateFile, data); err != nil {
					t.Fatal(err)
				}
			}
			cfg := tc.cfg
			cfg.CacheDir, cfg.Incremental = sub, true
			r := collectRun(t, f, cfg)
			if !r.logged("incremental: full run (" + tc.want) {
				t.Errorf("want a full run because %q: %q", tc.want, r.logs)
			}
		})
	}
	// A missing previous graph also forces a full run.
	if err := os.Remove(filepath.Join(dir, incGraphFile)); err != nil {
		t.Fatal(err)
	}
	if r := collectRun(t, f, Config{CacheDir: dir, Incremental: true}); !r.logged("full run (previous graph unreadable)") {
		t.Errorf("missing previous graph: %q", r.logs)
	}
}

func TestIncrementalWorkflowBlobReuse(t *testing.T) {
	// REST mode: a changed repo's unchanged workflow files are not
	// downloaded again when the listing reports the same blob SHA.
	setup := func(f *fakeGitHub) {
		f.extraWorkflows["acme-app/web/keep.yml"] = cacheWorkflow("acme-other/keep@main")
		f.extraWorkflows["acme-app/web/edit.yml"] = cacheWorkflow("acme-other/edit@main")
	}
	change := func(f *fakeGitHub) {
		f.mu.Lock()
		f.pushedAt = map[string]string{"acme-app/web": incPushedAt}
		f.extraWorkflows["acme-app/web/edit.yml"] = cacheWorkflow("acme-other/edit2@main")
		f.mu.Unlock()
	}
	f := newFakeGitHub(t)
	setup(f)
	dir := filepath.Join(t.TempDir(), "gop-cache")
	cfg := Config{CacheDir: dir, Incremental: true, DisableGraphQLBatch: true}
	collectRun(t, f, cfg)
	change(f)
	inc := collectRun(t, f, cfg)

	ref := newFakeGitHub(t)
	setup(ref)
	change(ref)
	full := collectRun(t, ref, Config{DisableGraphQLBatch: true})
	if normalized(t, inc.g) != normalized(t, full.g) {
		t.Error("incremental REST-mode graph differs from a full collection")
	}
	const base = "/repos/acme-app/web/contents/.github/workflows"
	if inc.hits[base] != 1 || inc.hits[base+"/edit.yml"] != 1 {
		t.Errorf("the listing and the changed file must be read: %v", inc.hits)
	}
	if n := inc.hits[base+"/keep.yml"]; n != 0 {
		t.Errorf("unchanged workflow blob requested %d times", n)
	}
	if !graphMentions(inc.g, "acme-other/edit2@main") || !graphMentions(inc.g, "acme-other/keep@main") {
		t.Error("graph misses the changed or the reused workflow")
	}
	if inc.requests >= full.requests {
		t.Errorf("incremental REST run sent %d requests, full %d", inc.requests, full.requests)
	}
}

func TestIncrementalNeedsCacheDir(t *testing.T) {
	f := newFakeGitHub(t)
	_, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), Incremental: true})
	if err == nil || !strings.Contains(err.Error(), "CacheDir") {
		t.Errorf("Incremental without CacheDir: %v", err)
	}
	_, err = Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), CacheDir: t.TempDir(), Incremental: true, FullEvery: -time.Hour})
	if err == nil {
		t.Error("negative FullEvery accepted")
	}
}

func TestSourceRepo(t *testing.T) {
	for id, want := range map[string]string{
		"repo:Acme-App/Web":                         "acme-app/web",
		"workflow:acme-app/web/.github/workflows/x": "acme-app/web",
		"action:acme-actions/setup/sub@v1.2/x":      "acme-actions/setup",
		"action:acme-actions/setup@main":            "acme-actions/setup",
		"oidc:acme-app/web":                         "acme-app/web",
		"identity:alice":                            "",
		"members:acme-app":                          "",
		"repo:broken":                               "",
	} {
		if got := sourceRepo(id); got != want {
			t.Errorf("sourceRepo(%q) = %q, want %q", id, got, want)
		}
	}
	for rel, want := range map[string]string{
		"/repos/Acme-App/Web/collaborators": "acme-app/web",
		"/repos/acme-app/web":               "acme-app/web",
		"/repos/acme-app":                   "",
		"/orgs/acme-app/repos":              "",
	} {
		if got := repoScope(rel); got != want {
			t.Errorf("repoScope(%q) = %q, want %q", rel, got, want)
		}
	}
}

func TestIncrementalAppMode(t *testing.T) {
	// Installation tokens change on every run; the App ID ties the runs.
	f, c, _ := appFake(t, nil)
	dir := filepath.Join(t.TempDir(), "gop-cache")
	run := func() (*graph.Graph, []string, int) {
		f.resetCounts()
		var logs []string
		cp := *c
		cp.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
		cfg := appConfig(&cp, t, "acme-actions", "acme-app")
		cfg.CacheDir, cfg.Incremental = dir, true
		g, err := Collect(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		var repoHits []string
		for k := range f.hits {
			if repoScope(k) != "" {
				repoHits = append(repoHits, k)
			}
		}
		return g, logs, len(repoHits)
	}
	g1, logs1, hits1 := run()
	g2, logs2, hits2 := run()
	if !slices.ContainsFunc(logs1, func(l string) bool { return strings.Contains(l, "full run (no previous") }) ||
		!slices.ContainsFunc(logs2, func(l string) bool { return strings.Contains(l, "incremental: reusing") }) {
		t.Fatalf("logs: %q / %q", logs1, logs2)
	}
	if hits1 == 0 || hits2 != 0 {
		t.Errorf("per-repository requests: full %d, incremental %d (want 0)", hits1, hits2)
	}
	if normalized(t, g1) != normalized(t, g2) {
		t.Error("App-mode incremental graph differs from the full run's")
	}
}
