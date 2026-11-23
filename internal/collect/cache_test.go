package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

func TestCacheKey(t *testing.T) {
	u1, _ := url.Parse("https://api.github.com/orgs/acme-app/repos?per_page=100")
	u2, _ := url.Parse("https://github.acme.example/api/v3/orgs/acme-app/repos?per_page=100")
	base := cacheKey("GET", u1, jsonAccept, "tok-a")
	if len(base) != 64 {
		t.Fatalf("key %q is not a hex sha256", base)
	}
	if cacheKey("GET", u1, jsonAccept, "tok-a") != base {
		t.Error("key is not deterministic")
	}
	for name, k := range map[string]string{
		"host":   cacheKey("GET", u2, jsonAccept, "tok-a"),
		"token":  cacheKey("GET", u1, jsonAccept, "tok-b"),
		"accept": cacheKey("GET", u1, "application/vnd.github.raw", "tok-a"),
		"method": cacheKey("HEAD", u1, jsonAccept, "tok-a"),
	} {
		if k == base {
			t.Errorf("a different %s gives the same key", name)
		}
	}
	if fp := tokenFingerprint("tok-a"); len(fp) != 16 || strings.Contains(fp, "tok-a") {
		t.Errorf("fingerprint %q", fp)
	}
}

func TestCacheWriteAtomicAndModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gop-cache")
	rc, err := openCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("ab", 32)
	e := &cacheEntry{URLRedacted: "/orgs/acme-app", ETag: `"x"`, Status: 200, Body: []byte(`{"login":"acme-app"}`), FetchedAt: time.Now().UTC()}
	if err := rc.store(key, e); err != nil {
		t.Fatal(err)
	}
	e.Body = []byte(`{"login":"acme-app","v":2}`)
	if err := rc.store(key, e); err != nil {
		t.Fatal(err)
	}
	got := rc.load(key)
	if got == nil || string(got.Body) != `{"login":"acme-app","v":2}` || got.ETag != `"x"` {
		t.Fatalf("load = %+v", got)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, key[:2]))
	if len(ents) != 1 || ents[0].Name() != key+".json" {
		t.Errorf("stray files after atomic writes: %v", ents)
	}
	checkCacheModes(t, dir)

	if runtime.GOOS != "windows" {
		open := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(open, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := openCache(open); err == nil || !strings.Contains(err.Error(), "chmod 700") {
			t.Errorf("a world-readable cache dir must be refused, got %v", err)
		}
	}
}

// checkCacheModes fails unless every directory under dir is 0700 and every
// file 0600 (skipped on Windows).
func checkCacheModes(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %04o, want %04o", p, fi.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// grepCache fails if any file under dir contains needle.
func grepCache(t *testing.T, dir, needle string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(needle)) {
			t.Errorf("%s contains %q", p, needle)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCacheTokenIsolation(t *testing.T) {
	var (
		mu    sync.Mutex
		auths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization")+"|"+r.Header.Get("If-None-Match"))
		mu.Unlock()
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeJSON(w, 200, map[string]string{"login": "acme"})
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "gop-cache")
	rc, err := openCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewClient(ClientOptions{BaseURL: srv.URL, Token: "token-alice-synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	base = base.withCache(rc)
	get := func(c *Client) string {
		var out map[string]string
		if err := c.GetJSON(context.Background(), "/orgs/acme", &out); err != nil {
			t.Fatal(err)
		}
		return out["login"]
	}
	alice, bob := base, base.WithToken("token-bob-synthetic")
	if get(alice) != "acme" || get(bob) != "acme" {
		t.Fatal("unexpected bodies")
	}
	if get(alice) != "acme" {
		t.Fatal("cached body not served")
	}
	want := []string{
		"Bearer token-alice-synthetic|",
		"Bearer token-bob-synthetic|", // bob never revalidates alice's entry
		`Bearer token-alice-synthetic|"v1"`,
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(auths, ",") != strings.Join(want, ",") {
		t.Errorf("requests = %q, want %q", auths, want)
	}
	if st := rc.Stats(); st.Hits != 1 || st.Fetched != 2 {
		t.Errorf("stats = %+v", st)
	}
	files := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			files++
		}
		return nil
	})
	if files != 2 {
		t.Errorf("%d cache files, want one per token", files)
	}
	grepCache(t, dir, "token-alice-synthetic")
	grepCache(t, dir, "token-bob-synthetic")
}

func TestCacheSkipsUncacheable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/no-validator":
			writeJSON(w, 200, map[string]string{})
		case "/missing":
			w.Header().Set("ETag", `"e"`)
			writeJSON(w, 404, map[string]string{"message": "Not Found"})
		case "/graphql":
			w.Header().Set("ETag", `"g"`)
			writeJSON(w, 200, map[string]any{"data": map[string]any{}})
		}
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "gop-cache")
	rc, err := openCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientOptions{BaseURL: srv.URL, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	c = c.withCache(rc)
	ctx := context.Background()
	if err := c.GetJSON(ctx, "/no-validator", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.GetJSON(ctx, "/missing", nil); !IsNotFound(err) {
		t.Fatalf("want 404, got %v", err)
	}
	if _, err := c.GraphQL(ctx, "query { viewer { login } }", nil, nil); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("uncacheable responses were stored: %v", ents)
	}
}

// collectCached runs Collect against f with a cache in dir.
func collectCached(t *testing.T, ctx context.Context, f *fakeGitHub, dir string, resume bool) (*graph.Graph, error) {
	t.Helper()
	return Collect(ctx, Config{Enterprise: "acme", Client: f.client(t), CacheDir: dir, Resume: resume, DisableGraphQLBatch: true})
}

// resetCounts clears the fake's per-request counters between runs.
func (f *fakeGitHub) resetCounts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits, f.conditional, f.notModified, f.ok200 = map[string]int{}, map[string]int{}, map[string]int{}, map[string]bool{}
	f.requests = 0
}

// normalized returns g as JSON with collected_at and every observed_at zeroed.
func normalized(t *testing.T, g *graph.Graph) string {
	t.Helper()
	cp := *g
	cp.CollectedAt = time.Time{}
	cp.Edges = append([]graph.Edge(nil), g.Edges...)
	for i := range cp.Edges {
		cp.Edges[i].ObservedAt = time.Time{}
	}
	b, err := json.Marshal(&cp)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const cacheWorkflowKey = "/repos/acme-app/web/contents/.github/workflows/cache.yml"

func cacheWorkflow(action string) string {
	return "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + action + "\n"
}

func TestCollectCachedRerun(t *testing.T) {
	f := newFakeGitHub(t)
	f.etags = true
	f.extraWorkflows["acme-app/web/cache.yml"] = cacheWorkflow("acme-other/tool@main")
	dir := filepath.Join(t.TempDir(), "gop-cache")
	ctx := context.Background()

	g1, err := collectCached(t, ctx, f, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, cacheRunFile)); !os.IsNotExist(err) {
		t.Errorf("run.json must be removed after a successful run: %v", err)
	}
	cached := map[string]bool{}
	for k := range f.ok200 {
		cached[k] = true
	}
	if len(cached) == 0 || !cached[cacheWorkflowKey] {
		t.Fatalf("first run fetched %d GETs, want the planted workflow among them", len(cached))
	}

	f.resetCounts()
	var logs []string
	c2 := f.client(t)
	c2.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	g2, err := Collect(ctx, Config{Enterprise: "acme", Client: c2, CacheDir: dir, DisableGraphQLBatch: true})
	if err != nil {
		t.Fatal(err)
	}
	revalidated := 0
	for k := range cached {
		if f.hits[k] == 0 {
			continue
		}
		revalidated++
		if f.conditional[k] != f.hits[k] || f.notModified[k] != f.hits[k] {
			t.Errorf("%s: %d requests, %d with If-None-Match, %d answered 304", k, f.hits[k], f.conditional[k], f.notModified[k])
		}
	}
	if revalidated < len(cached)/2 {
		t.Errorf("only %d of %d cached GETs were requested again", revalidated, len(cached))
	}
	if normalized(t, g1) != normalized(t, g2) {
		t.Error("the cached re-run's graph differs from the first run's")
	}
	if !slices.ContainsFunc(logs, func(l string) bool {
		return strings.HasPrefix(l, "collect: cache ") && strings.Contains(l, " hits (304), ")
	}) {
		t.Errorf("no cache summary line in %q", logs)
	}
	for _, e := range g2.Edges {
		if !e.ObservedAt.Equal(g2.CollectedAt) {
			t.Errorf("revalidated edge %s -> %s: observed_at %s, want the run time", e.From, e.To, e.ObservedAt)
			break
		}
	}

	// Change one workflow: only that file is downloaded again.
	f.resetCounts()
	f.mu.Lock()
	f.extraWorkflows["acme-app/web/cache.yml"] = cacheWorkflow("acme-other/tool2@main")
	f.mu.Unlock()
	g3, err := collectCached(t, ctx, f, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	for k := range cached {
		if f.hits[k] == 0 {
			continue
		}
		changed := f.notModified[k] == 0
		if changed != (k == cacheWorkflowKey) {
			t.Errorf("%s: %d requests, %d answered 304", k, f.hits[k], f.notModified[k])
		}
	}
	if !graphMentions(g3, "acme-other/tool2") || graphMentions(g3, "acme-other/tool@") {
		t.Error("the graph does not reflect the changed workflow")
	}
	checkCacheModes(t, dir)
	grepCache(t, dir, testToken)
}

// graphMentions reports whether any node ID contains s.
func graphMentions(g *graph.Graph, s string) bool {
	for _, n := range g.Nodes {
		if strings.Contains(n.ID, s) {
			return true
		}
	}
	return false
}

func TestCollectResume(t *testing.T) {
	// Reference: an uninterrupted run without a cache.
	ref := newFakeGitHub(t)
	ref.etags = true
	want, err := Collect(context.Background(), Config{Enterprise: "acme", Client: ref.client(t), DisableGraphQLBatch: true})
	if err != nil {
		t.Fatal(err)
	}
	total := ref.requests

	f := newFakeGitHub(t)
	f.etags = true
	dir := filepath.Join(t.TempDir(), "gop-cache")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancelAfter, f.cancel = total/2, cancel
	if _, err := collectCached(t, ctx, f, dir, true); err == nil {
		t.Fatal("the interrupted run succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, cacheRunFile)); err != nil {
		t.Fatalf("run.json must survive an interrupted run: %v", err)
	}
	fetched := map[string]bool{}
	for k := range f.ok200 {
		fetched[k] = true
	}
	if len(fetched) == 0 {
		t.Fatal("the interrupted run fetched nothing")
	}

	f.resetCounts()
	f.mu.Lock()
	f.cancelAfter = 0
	f.mu.Unlock()
	got, err := collectCached(t, context.Background(), f, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ok200) == 0 {
		t.Error("the resumed run fetched nothing new; the interruption came too late to test resume")
	}
	for k := range fetched {
		if f.hits[k] != 0 {
			t.Errorf("%s was fetched by the interrupted run but requested again (%d)", k, f.hits[k])
		}
	}
	if normalized(t, got) != normalized(t, want) {
		t.Error("the resumed graph differs from an uninterrupted run's")
	}

	// Edges built from resumed bodies keep the entry's fetched_at.
	fetchedAt := map[time.Time]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == cacheRunFile {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		var e cacheEntry
		if json.Unmarshal(b, &e) == nil && strings.HasPrefix(e.URLRedacted, "/enterprises/acme/consumed-licenses") {
			fetchedAt[e.FetchedAt] = true
		}
		return nil
	})
	if len(fetchedAt) == 0 {
		t.Fatal("no consumed-licenses entries in the cache")
	}
	n := 0
	for _, e := range got.Edges {
		if e.SourceAPI != srcLicenses || e.Kind != graph.MemberOf {
			continue
		}
		n++
		if !fetchedAt[e.ObservedAt] || !e.ObservedAt.Before(got.CollectedAt) {
			t.Errorf("edge %s -> %s: observed_at %s is not a cache entry's fetched_at", e.From, e.To, e.ObservedAt)
		}
	}
	if n == 0 {
		t.Fatal("no consumed-licenses edges")
	}
	if _, err := os.Stat(filepath.Join(dir, cacheRunFile)); !os.IsNotExist(err) {
		t.Errorf("run.json must be removed after the resumed run succeeds: %v", err)
	}
	checkCacheModes(t, dir)
	grepCache(t, dir, testToken)
}

func TestCacheResumeNeedsMatchingRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gop-cache")
	rc, err := openCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if resumed, err := rc.beginRun("acme", []string{"acme-app"}, true, start); err != nil || resumed {
		t.Fatalf("first run: resumed=%v err=%v", resumed, err)
	}
	for _, tc := range []struct {
		ent    string
		orgs   []string
		resume bool
		want   bool
	}{
		{"acme", []string{"ACME-APP"}, true, true},
		{"acme", []string{"acme-app"}, false, false},
		{"acme", []string{"acme-actions"}, true, false},
		{"other", []string{"acme-app"}, true, false},
	} {
		rc := &responseCache{dir: dir}
		// Restore the interrupted run's run.json for each case.
		if _, err := (&responseCache{dir: dir}).beginRun("acme", []string{"acme-app"}, false, start); err != nil {
			t.Fatal(err)
		}
		resumed, err := rc.beginRun(tc.ent, tc.orgs, tc.resume, start.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if resumed != tc.want || (resumed && !rc.resumeSince.Equal(start)) {
			t.Errorf("%+v: resumed=%v since=%s", tc, resumed, rc.resumeSince)
		}
	}
}
