package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Incremental collection (Config.Incremental) re-reads only what changed
// since the previous run that used the same cache directory.
//
// It works on the API answers, not on the graph: every answer gop gets about
// one repository (a REST GET under /repos/{owner}/{repo}/, or one
// repository's alias of a batched GraphQL query) is recorded in
// <cache-dir>/replay together with the repository's stamp: its id,
// pushed_at, updated_at, default branch, archived flag and visibility from
// this run's org repository listing. The next incremental run lists every
// org again (org-level reads are never reused), and a per-repository request
// whose recorded stamp equals the repository's current stamp is answered from
// the record without a request. A workflow file of a changed repository is
// also answered from the record when the .github/workflows listing reports
// the same blob SHA. Everything else goes to GitHub and is recorded.
//
// Because the collector runs exactly as in a full run, on the same answers,
// the graph equals a full collection's whenever unchanged stamps mean
// unchanged answers. Deleted repositories and workflow files drop out because
// they are no longer listed or requested. Facts read only from reused answers
// keep the observed_at of the previous graph (<cache-dir>/incremental-graph.json).
//
// A full run (record only, nothing reused) happens when there is no previous
// incremental run in the directory, when FullEvery has passed since the last
// full run, or when the schema, enterprise, host, org selection or token
// differ from the previous run's.

const (
	incStateFile  = "incremental.json"
	incGraphFile  = "incremental-graph.json"
	replayDirName = "replay"
	// incVersion is bumped when the replay record format or the way requests
	// are keyed changes: the next run is then a full run.
	incVersion = 1
	// DefaultFullEvery is how often an incremental collection does a full run
	// anyway (Config.FullEvery).
	DefaultFullEvery = 7 * 24 * time.Hour
)

// incState is <cache-dir>/incremental.json, written after every successful
// incremental-mode run.
type incState struct {
	Version    int       `json:"version"`
	Schema     string    `json:"schema"`
	Enterprise string    `json:"enterprise"`
	Host       string    `json:"host"`
	Orgs       []string  `json:"orgs"`
	Auth       string    `json:"auth"`
	FullAt     time.Time `json:"full_at"`
	LastAt     time.Time `json:"last_at"`
}

// incremental is one run's incremental state.
type incremental struct {
	cacheDir string
	want     incState
	prev     *incState
	prevG    *graph.Graph
	full     bool
	reason   string
	store    *replayStore
}

// authID identifies what read the previous run: an App ID, or a fingerprint
// of the token (the same 16 hex digits of its SHA-256 the cache keys use).
// "" means unknown, which always forces a full run.
func authID(cfg Config, c *Client) string {
	if cfg.appMode() {
		return "app:" + strconv.FormatInt(cfg.AppID, 10)
	}
	if c.token != "" {
		return "token:" + tokenFingerprint(c.token)
	}
	return ""
}

// startIncremental decides between a full and an incremental run and returns
// the client to collect with. It is a no-op unless cfg.Incremental is set.
func startIncremental(cfg Config, c *Client) (*incremental, *Client, error) {
	if !cfg.Incremental {
		return nil, c, nil
	}
	every := cfg.FullEvery
	if every == 0 {
		every = DefaultFullEvery
	}
	inc := &incremental{cacheDir: cfg.CacheDir, want: incState{
		Version: incVersion, Schema: graph.SchemaVersion, Enterprise: cfg.Enterprise,
		Host: cfg.host(), Orgs: normOrgs(cfg.Orgs), Auth: authID(cfg, c),
	}}
	inc.full, inc.reason = inc.decide(time.Now().UTC(), every)
	st := &replayStore{
		dir: filepath.Join(cfg.CacheDir, replayDirName), serve: !inc.full, logf: c.logf,
		stamps: map[string]string{}, blobs: map[string]map[string]string{}, touched: map[string]bool{},
		fetched: map[string]bool{}, served: map[string]bool{},
	}
	if err := os.MkdirAll(st.dir, cacheDirMode); err != nil {
		return nil, nil, fmt.Errorf("collect: creating %s: %w", st.dir, err)
	}
	inc.store = st
	if inc.full {
		c.logf("collect: incremental: full run (%s)", inc.reason)
	} else {
		c.logf("collect: incremental: reusing unchanged repositories from the run of %s (last full run %s)",
			inc.prev.LastAt.Format(time.RFC3339), inc.prev.FullAt.Format(time.RFC3339))
	}
	return inc, c.withReplay(st), nil
}

// decide reports whether this run must be a full run, and why.
func (inc *incremental) decide(now time.Time, every time.Duration) (bool, string) {
	data, err := os.ReadFile(filepath.Join(inc.cacheDir, incStateFile))
	if err != nil {
		return true, "no previous incremental run in the cache directory"
	}
	var prev incState
	if json.Unmarshal(data, &prev) != nil || prev.FullAt.IsZero() {
		return true, "unreadable " + incStateFile
	}
	w := inc.want
	switch {
	case prev.Version != w.Version:
		return true, "the incremental record format changed"
	case prev.Schema != w.Schema:
		return true, "the graph schema changed from " + prev.Schema + " to " + w.Schema
	case !strings.EqualFold(prev.Enterprise, w.Enterprise):
		return true, "the previous run collected another enterprise"
	case prev.Host != w.Host:
		return true, "the previous run collected another host"
	case strings.Join(prev.Orgs, ",") != strings.Join(w.Orgs, ","):
		return true, "the org selection changed"
	case w.Auth == "" || prev.Auth != w.Auth:
		return true, "the previous run used another token or App"
	case now.Sub(prev.FullAt) >= every:
		return true, fmt.Sprintf("the last full run was %s ago, full runs every %s",
			now.Sub(prev.FullAt).Round(time.Minute), every)
	}
	g, err := graph.LoadFile(filepath.Join(inc.cacheDir, incGraphFile))
	if err != nil {
		return true, "previous graph unreadable"
	}
	if !strings.EqualFold(g.Enterprise, w.Enterprise) {
		return true, "the previous graph is of another enterprise"
	}
	inc.prev, inc.prevG = &prev, g
	return false, ""
}

// finish carries observed_at over for reused facts, logs the counts, saves
// the graph and the state, and drops replay records this run did not use.
// Failures are logged: the next run is then a full run, never a wrong one.
func (inc *incremental) finish(k *collector, g *graph.Graph) {
	st := inc.store
	reread, reused := st.counts()
	if inc.full {
		k.logf("collect: incremental: %d repos read (full run)", reread+reused)
	} else {
		inc.carryObserved(g, st.reusedRepos())
		k.logf("collect: incremental: %d repos re-read, %d reused (%d requests answered from the previous run)",
			reread, reused, st.nServed)
	}
	var buf bytes.Buffer
	if err := WriteGraph(&buf, g); err != nil {
		k.logf("collect: incremental: saving the graph: %v", err)
		return
	}
	if err := writeFileAtomic(inc.cacheDir, incGraphFile, buf.Bytes()); err != nil {
		k.logf("collect: incremental: saving the graph: %v", err)
		return
	}
	state := inc.want
	state.LastAt = k.now
	state.FullAt = k.now
	if !inc.full {
		state.FullAt = inc.prev.FullAt
	}
	data, err := json.Marshal(state)
	if err == nil {
		err = writeFileAtomic(inc.cacheDir, incStateFile, data)
	}
	if err != nil {
		k.logf("collect: incremental: saving %s: %v", incStateFile, err)
		return
	}
	if err := st.prune(); err != nil {
		k.logf("collect: incremental: removing unused replay records: %v", err)
	}
}

// carryObserved gives every edge read from a reused repository's answers,
// and identical to the previous graph's edge, the previous observed_at.
func (inc *incremental) carryObserved(g *graph.Graph, reused map[string]bool) {
	prev := make(map[string]graph.Edge, len(inc.prevG.Edges))
	for _, e := range inc.prevG.Edges {
		prev[edgeKey(e)] = e
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		if !strings.HasPrefix(e.SourceAPI, "rest:GET /repos/") || !reused[edgeRepo(*e)] {
			continue
		}
		p, ok := prev[edgeKey(*e)]
		if ok && p.From == e.From && p.To == e.To && p.Kind == e.Kind && p.Evidence == e.Evidence &&
			p.SourceAPI == e.SourceAPI && maps.Equal(p.Attrs, e.Attrs) {
			e.ObservedAt = p.ObservedAt
		}
	}
}

// edgeRepo is the repository (lower "owner/repo") whose answers an edge with
// a per-repository source was built from: the workflow's or action's
// repository for USES, DEFINED_IN and EXECUTES_WITH, otherwise the target's.
func edgeRepo(e graph.Edge) string {
	switch e.Kind {
	case graph.Uses, graph.DefinedIn, graph.ExecutesWith:
		return sourceRepo(e.From)
	}
	if r := sourceRepo(e.To); r != "" {
		return r
	}
	return sourceRepo(e.From)
}

// sourceRepo returns the lower "owner/repo" a node ID names, or "".
func sourceRepo(id string) string {
	prefix, rest, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	switch prefix {
	case "action":
		rest, _, _ = strings.Cut(rest, "@")
	case "repo", "workflow", "secret", "oidc", "runner":
	default:
		return ""
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return strings.ToLower(parts[0] + "/" + parts[1])
}

// ---- replay store ----

// replayEntry is one recorded answer, <cache-dir>/replay/<key[:2]>/<key>.json.
type replayEntry struct {
	Kind  string `json:"kind"` // "rest" or "graphql"
	URL   string `json:"url_redacted,omitempty"`
	Repo  string `json:"repo"`
	Stamp string `json:"stamp"`
	// Blob is the blob SHA of a REST contents file answer.
	Blob   string `json:"blob,omitempty"`
	Status int    `json:"status,omitempty"`
	// Message is a REST error answer's message.
	Message string `json:"message,omitempty"`
	Link    string `json:"link,omitempty"`
	SSO     string `json:"sso,omitempty"`
	// Body is the REST body, or the GraphQL alias's data.
	Body      json.RawMessage `json:"body,omitempty"`
	Errors    GraphQLErrors   `json:"errors,omitempty"`
	FetchedAt time.Time       `json:"fetched_at"`
}

// replayStore records per-repository answers and, in an incremental run,
// serves the unchanged ones. Copies of a Client share it.
type replayStore struct {
	dir   string
	serve bool
	logf  func(string, ...any)

	mu sync.Mutex
	// stamps holds this run's stamp per lower "owner/repo", from the org
	// repository listings; blobs the .github/workflows blob SHAs by path.
	stamps  map[string]string
	blobs   map[string]map[string]string
	touched map[string]bool // record keys served or written this run
	fetched map[string]bool // repos with at least one request sent this run
	served  map[string]bool // repos with at least one answer served
	nServed int
	warned  bool
}

type replayBypassKey struct{}

// replayBypass marks a request the replay store already handled.
func replayBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, replayBypassKey{}, true)
}

func replayBypassed(ctx context.Context) bool {
	b, _ := ctx.Value(replayBypassKey{}).(bool)
	return b
}

// withReplay returns a copy of c that records and serves through rs.
func (c *Client) withReplay(rs *replayStore) *Client {
	cp := *c
	cp.replay = rs
	return &cp
}

func replayKey(kind, a, b string) string {
	s := sha256.Sum256([]byte(kind + "\x00" + a + "\x00" + b))
	return hex.EncodeToString(s[:])
}

func (rs *replayStore) path(key string) string {
	return filepath.Join(rs.dir, key[:2], key+".json")
}

func (rs *replayStore) load(key, kind string) *replayEntry {
	data, err := os.ReadFile(rs.path(key))
	if err != nil {
		return nil
	}
	var e replayEntry
	if json.Unmarshal(data, &e) != nil || e.Kind != kind {
		return nil
	}
	return &e
}

func (rs *replayStore) store(key string, e *replayEntry) {
	data, err := json.Marshal(e)
	if err == nil {
		err = writeFileAtomic(filepath.Join(rs.dir, key[:2]), key+".json", data)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if err == nil {
		rs.touched[key] = true
		return
	}
	if !rs.warned {
		rs.warned = true
		rs.logf("collect: incremental: writing a replay record failed, continuing without it: %v", err)
	}
}

func (rs *replayStore) stamp(repo string) string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.stamps[repo]
}

func (rs *replayStore) markServed(key, repo string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.touched[key] = true
	rs.served[repo] = true
	rs.nServed++
}

func (rs *replayStore) markFetched(repo string) {
	if repo == "" {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.fetched[repo] = true
}

// counts returns how many listed repositories had a request sent this run
// and how many were answered only from records (or needed no request).
func (rs *replayStore) counts() (reread, reused int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for repo := range rs.stamps {
		if rs.fetched[repo] {
			reread++
		} else {
			reused++
		}
	}
	return reread, reused
}

// reusedRepos are the listed repositories answered only from records.
func (rs *replayStore) reusedRepos() map[string]bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := map[string]bool{}
	for repo := range rs.served {
		if !rs.fetched[repo] && rs.stamps[repo] != "" {
			out[repo] = true
		}
	}
	return out
}

// prune removes every record this run neither served nor wrote: deleted
// repositories and files, and answers whose source changed.
func (rs *replayStore) prune() error {
	rs.mu.Lock()
	touched := maps.Clone(rs.touched)
	rs.mu.Unlock()
	return filepath.WalkDir(rs.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if key, ok := strings.CutSuffix(d.Name(), ".json"); ok && touched[key] {
			return nil
		}
		return os.Remove(p)
	})
}

// relPath is u's path below the client's REST base path ("/api/v3" on GHES).
func (c *Client) relPath(u *url.URL) string {
	if base := strings.TrimSuffix(c.base.Path, "/"); base != "" {
		if p, ok := strings.CutPrefix(u.Path, base); ok {
			return p
		}
	}
	return u.Path
}

// repoScope returns the lower "owner/repo" of a /repos/{owner}/{repo}/...
// path, or "" for any other path.
func repoScope(rel string) string {
	rest, ok := strings.CutPrefix(rel, "/repos/")
	if !ok {
		return ""
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return strings.ToLower(parts[0] + "/" + parts[1])
}

// contentsFile returns the file path of a ref-less contents GET, or "".
func contentsFile(rel string, u *url.URL) string {
	if u.RawQuery != "" {
		return ""
	}
	rest, ok := strings.CutPrefix(rel, "/repos/")
	if !ok {
		return ""
	}
	parts := strings.SplitN(rest, "/", 4)
	if len(parts) != 4 || parts[2] != "contents" {
		return ""
	}
	return parts[3]
}

// get answers one REST GET: from a record when its repository is unchanged
// (or, for a workflow file, its blob is), otherwise from GitHub, recording
// per-repository answers.
func (rs *replayStore) get(ctx context.Context, c *Client, u *url.URL, accept string) (*response, error) {
	if u.Host != c.base.Host {
		return c.doAccept(replayBypass(ctx), http.MethodGet, u, nil, accept)
	}
	rel := c.relPath(u)
	repo := repoScope(rel)
	key := replayKey("rest", u.String(), accept)
	file := ""
	if repo != "" {
		file = contentsFile(rel, u)
		if r, err, ok := rs.serveREST(key, repo, file, u); ok {
			return r, err
		}
		rs.markFetched(repo)
	}
	r, err := c.doAccept(replayBypass(ctx), http.MethodGet, u, nil, accept)
	if ctx.Err() != nil {
		return r, err
	}
	if err == nil {
		rs.observe(rel, r)
	}
	if repo != "" {
		rs.recordREST(key, repo, file, u, r, err)
	}
	return r, err
}

// serveREST returns the recorded answer for key when it may be reused.
func (rs *replayStore) serveREST(key, repo, file string, u *url.URL) (*response, error, bool) {
	if !rs.serve {
		return nil, nil, false
	}
	rs.mu.Lock()
	stamp := rs.stamps[repo]
	blob := ""
	if file != "" {
		blob = rs.blobs[repo][file]
	}
	rs.mu.Unlock()
	if stamp == "" && blob == "" {
		return nil, nil, false
	}
	e := rs.load(key, "rest")
	if e == nil {
		return nil, nil, false
	}
	sameStamp := stamp != "" && e.Stamp == stamp
	sameBlob := blob != "" && e.Blob == blob
	if !sameStamp && !sameBlob {
		return nil, nil, false
	}
	rs.markServed(key, repo)
	h := http.Header{}
	if e.Link != "" {
		h.Set("Link", e.Link)
	}
	if e.SSO != "" {
		h.Set(headerSSO, e.SSO)
	}
	if e.Status >= 200 && e.Status < 300 {
		return &response{status: e.Status, header: h, body: e.Body}, nil, true
	}
	return nil, &APIError{Method: http.MethodGet, Path: redactedPath(u), StatusCode: e.Status, Message: e.Message, header: h}, true
}

// recordREST stores a final answer for a listed repository: a success, or a
// 4xx other than a rate limit. Transport errors, 5xx and exhausted retries
// are never recorded.
func (rs *replayStore) recordREST(key, repo, file string, u *url.URL, r *response, err error) {
	stamp := rs.stamp(repo)
	if stamp == "" {
		return
	}
	e := &replayEntry{Kind: "rest", URL: redactedPath(u), Repo: repo, Stamp: stamp, FetchedAt: time.Now().UTC()}
	var h http.Header
	switch ae, ok := err.(*APIError); {
	case err == nil && r != nil:
		e.Status, e.Body, h = r.status, r.body, r.header
		if file != "" {
			var f struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			}
			if json.Unmarshal(r.body, &f) == nil && f.Type == "file" {
				e.Blob = f.SHA
			}
		}
	case ok && ae.StatusCode >= 400 && ae.StatusCode < 500 && ae.StatusCode != http.StatusTooManyRequests:
		e.Status, e.Message, h = ae.StatusCode, ae.Message, ae.header
	default:
		return
	}
	if h != nil {
		e.Link, e.SSO = h.Get("Link"), h.Get(headerSSO)
	}
	rs.store(key, e)
}

// observe learns repository stamps from org repository listings and blob
// SHAs from .github/workflows listings.
func (rs *replayStore) observe(rel string, r *response) {
	if r.status != http.StatusOK {
		return
	}
	if rest, ok := strings.CutPrefix(rel, "/orgs/"); ok {
		if org, tail, _ := strings.Cut(rest, "/"); org != "" && tail == "repos" {
			rs.observeRepos(r.body)
		}
		return
	}
	repo := repoScope(rel)
	if repo == "" || !strings.EqualFold(rel, "/repos/"+repo+"/contents/.github/workflows") {
		return
	}
	var entries []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	if json.Unmarshal(r.body, &entries) != nil {
		return
	}
	shas := map[string]string{}
	for _, e := range entries {
		if e.Type == "file" && e.SHA != "" {
			shas[e.Path] = e.SHA
		}
	}
	rs.mu.Lock()
	rs.blobs[repo] = shas
	rs.mu.Unlock()
}

func (rs *replayStore) observeRepos(body []byte) {
	var repos []struct {
		ID            int64  `json:"id"`
		FullName      string `json:"full_name"`
		PushedAt      string `json:"pushed_at"`
		UpdatedAt     string `json:"updated_at"`
		DefaultBranch string `json:"default_branch"`
		Archived      bool   `json:"archived"`
		Visibility    string `json:"visibility"`
		Private       bool   `json:"private"`
	}
	if json.Unmarshal(body, &repos) != nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, r := range repos {
		if r.FullName == "" || (r.PushedAt == "" && r.UpdatedAt == "") {
			continue // nothing tells whether it changed: always read it
		}
		rs.stamps[strings.ToLower(r.FullName)] = strings.Join([]string{
			strconv.FormatInt(r.ID, 10), r.PushedAt, r.UpdatedAt, r.DefaultBranch,
			strconv.FormatBool(r.Archived), r.Visibility, strconv.FormatBool(r.Private)}, "|")
	}
}

// ---- batched GraphQL ----

// aliasPlan describes a batched GraphQL query whose aliases r0..rN-1 each
// read one repository, so the replay store can answer some aliases from
// records and send the rest. build returns the query for a subset of the
// aliases, renumbered from r0; build of every alias must be the query sent.
type aliasPlan struct {
	repos []string // "owner/name" per alias
	build func(idx []int) (string, map[string]any)
}

type aliasPlanKey struct{}

// withAliasPlan attaches p to a GraphQL call's context. Without a replay
// store it changes nothing.
func withAliasPlan(ctx context.Context, p *aliasPlan) context.Context {
	return context.WithValue(ctx, aliasPlanKey{}, p)
}

func aliasPlanFrom(ctx context.Context) *aliasPlan {
	p, _ := ctx.Value(aliasPlanKey{}).(*aliasPlan)
	return p
}

// objectsPlan is the plan of a batched object query (batch.go).
func objectsPlan(reqs []objReq) *aliasPlan {
	repos := make([]string, len(reqs))
	for i, r := range reqs {
		repos[i] = r.owner + "/" + r.name
	}
	return &aliasPlan{repos: repos, build: func(idx []int) (string, map[string]any) {
		sub := make([]objReq, len(idx))
		for j, i := range idx {
			sub[j] = reqs[i]
		}
		return buildObjectQuery(sub)
	}}
}

// protectionPlan is the plan of a batched branch protection query (hardening.go).
func protectionPlan(repos []hardenRepo, withRules bool) *aliasPlan {
	names := make([]string, len(repos))
	for i, hr := range repos {
		names[i] = hr.o.login + "/" + repoName(hr.o, hr.repo)
	}
	return &aliasPlan{repos: names, build: func(idx []int) (string, map[string]any) {
		sub := make([]hardenRepo, len(idx))
		for j, i := range idx {
			sub[j] = repos[i]
		}
		return buildProtectionQuery(sub, withRules)
	}}
}

// collabPlan is the plan of a batched direct-collaborator query (collabbatch.go).
func collabPlan(o *orgState, repos []*graph.Node) *aliasPlan {
	names := make([]string, len(repos))
	for i, r := range repos {
		names[i] = o.login + "/" + repoName(o, r)
	}
	return &aliasPlan{repos: names, build: func(idx []int) (string, map[string]any) {
		sub := make([]*graph.Node, len(idx))
		for j, i := range idx {
			sub[j] = repos[i]
		}
		return buildCollabQuery(o, sub)
	}}
}

// refsPlan is the plan of a batched ref lookup (refs.go).
func refsPlan(ts []*refTarget) *aliasPlan {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = strings.TrimPrefix(t.repoID, "repo:")
	}
	return &aliasPlan{repos: names, build: func(idx []int) (string, map[string]any) {
		sub := make([]*refTarget, len(idx))
		for j, i := range idx {
			sub[j] = ts[i]
		}
		return refBatchQuery(len(sub)), refBatchVars(sub)
	}}
}

// sameQuery reports whether a plan's query is the one the caller sends.
func sameQuery(q1 string, v1 map[string]any, q2 string, v2 map[string]any) bool {
	if q1 != q2 {
		return false
	}
	b1, e1 := json.Marshal(v1)
	b2, e2 := json.Marshal(v2)
	return e1 == nil && e2 == nil && bytes.Equal(b1, b2)
}

// renameAlias returns errs with error paths under alias from moved to alias to.
func renameAlias(errs GraphQLErrors, from, to string) GraphQLErrors {
	out := make(GraphQLErrors, 0, len(errs))
	for _, e := range errs {
		if len(e.Path) > 0 && e.Path[0] == from {
			p := append([]any{to}, e.Path[1:]...)
			e.Path = p
		}
		out = append(out, e)
	}
	return out
}

// recordableAlias reports whether an alias answer is stable enough to
// reuse: no errors, or only NOT_FOUND and FORBIDDEN ones.
func recordableAlias(errs GraphQLErrors) bool {
	for _, e := range errs {
		if e.Type != "NOT_FOUND" && e.Type != "FORBIDDEN" {
			return false
		}
	}
	return true
}

// graphql answers a batched query: aliases of unchanged repositories from
// records, the others in one query to GitHub (recorded), merged under the
// caller's alias names. A query-level failure is returned as GitHub sent
// it, so the caller falls back exactly as without the store.
func (rs *replayStore) graphql(ctx context.Context, c *Client, p *aliasPlan, query string, vars map[string]any, out any) (GraphQLErrors, error) {
	inner := withAliasPlan(ctx, nil)
	n := len(p.repos)
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	if q, v := p.build(all); n == 0 || !sameQuery(q, v, query, vars) {
		rs.mu.Lock()
		if !rs.warned {
			rs.warned = true
			rs.logf("collect: incremental: a batched query does not match its plan; sending it unchanged")
		}
		rs.mu.Unlock()
		return c.GraphQL(inner, query, vars, out)
	}
	merged := map[string]json.RawMessage{}
	var errs GraphQLErrors
	keys := make([]string, n)
	stamps := make([]string, n)
	var miss []int
	for i := range n {
		q1, v1 := p.build([]int{i})
		vb, _ := json.Marshal(v1)
		keys[i] = replayKey("graphql", c.graphqlURL+"\x00"+q1, string(vb))
		repo := strings.ToLower(p.repos[i])
		stamps[i] = rs.stamp(repo)
		if rs.serve && stamps[i] != "" {
			if e := rs.load(keys[i], "graphql"); e != nil && e.Stamp == stamps[i] {
				rs.markServed(keys[i], repo)
				merged["r"+strconv.Itoa(i)] = e.Body
				errs = append(errs, renameAlias(e.Errors, "r0", "r"+strconv.Itoa(i))...)
				continue
			}
		}
		miss = append(miss, i)
	}
	if len(miss) > 0 {
		q, v := query, vars
		if len(miss) < n {
			q, v = p.build(miss)
		}
		for _, i := range miss {
			rs.markFetched(strings.ToLower(p.repos[i]))
		}
		var data map[string]json.RawMessage
		gerrs, err := c.GraphQL(inner, q, v, &data)
		if err != nil {
			return gerrs, err
		}
		global := false
		perAlias := make([]GraphQLErrors, len(miss))
		for _, e := range gerrs {
			j := aliasIndex(e.Path)
			if j < 0 || j >= len(miss) {
				global = true
				errs = append(errs, e)
				continue
			}
			perAlias[j] = append(perAlias[j], e)
			errs = append(errs, renameAlias(GraphQLErrors{e}, "r"+strconv.Itoa(j), "r"+strconv.Itoa(miss[j]))...)
		}
		if data == nil {
			// No data at all: the caller must see the query fail as a whole.
			return errs, nil
		}
		record := !global && !isLimitError(gerrs)
		now := time.Now().UTC()
		for j, i := range miss {
			raw, ok := data["r"+strconv.Itoa(j)]
			if !ok {
				continue
			}
			merged["r"+strconv.Itoa(i)] = raw
			if record && stamps[i] != "" && recordableAlias(perAlias[j]) {
				rs.store(keys[i], &replayEntry{Kind: "graphql", Repo: strings.ToLower(p.repos[i]), Stamp: stamps[i],
					Body: raw, Errors: renameAlias(perAlias[j], "r"+strconv.Itoa(j), "r0"), FetchedAt: now})
			}
		}
		if rl, ok := data["rateLimit"]; ok {
			merged["rateLimit"] = rl
		}
	}
	if out != nil {
		b, err := json.Marshal(merged)
		if err == nil {
			err = json.Unmarshal(b, out)
		}
		if err != nil {
			return errs, fmt.Errorf("graphql: decoding data: %w", err)
		}
	}
	return errs, nil
}
