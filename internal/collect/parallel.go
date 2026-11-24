package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// This file holds parallel org collection in GitHub App mode. Each org
// installation has its own hourly rate-limit budget, so reading orgs at the
// same time multiplies the budget a run can spend per hour.
//
// The graph must not depend on how many workers ran or in which order they
// finished. The collector itself stays sequential; parallelism happens one
// level below it, in two passes:
//
//  1. Prefetch: a bounded pool of workers (Config.Parallel) runs a complete,
//     throwaway collection of one org each, through the shared installation
//     clients. Every final response (2xx, or an error that is not retried)
//     is recorded in a memo on the installation client that fetched it.
//  2. The sequential pass is the normal run over every selected org. Each
//     request is answered from its installation's memo when the worker
//     already fetched it, and goes to GitHub otherwise (cross-org reads the
//     workers could not predict, such as nested references batched across
//     orgs).
//
// The sequential pass is the same code with the same responses as a run with
// Parallel 1, so the graph is identical byte for byte. Rate limits are
// tracked per installation: a primary or secondary rate limit pauses only
// the requests of the installation that hit it, honoring Retry-After.

const (
	// DefaultParallel is the default number of org workers in App mode.
	DefaultParallel = 4
	// MaxParallel caps Config.Parallel. GitHub's secondary rate limits
	// discourage many concurrent requests even across installations.
	MaxParallel = 16
)

// parallel returns how many orgs App mode reads at once.
func (cfg Config) parallel() int {
	switch {
	case cfg.Parallel <= 0:
		return DefaultParallel
	case cfg.Parallel > MaxParallel:
		return MaxParallel
	}
	return cfg.Parallel
}

// lockedLogf serializes logf; nil stays nil.
func lockedLogf(logf func(string, ...any)) func(string, ...any) {
	if logf == nil {
		return nil
	}
	var mu sync.Mutex
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logf(format, args...)
	}
}

// withLockedLog returns a copy of c whose logger is serialized.
func (c *Client) withLockedLog() *Client {
	cp := *c
	cp.logf = lockedLogf(c.logf)
	return &cp
}

// withLogf returns a copy of c that logs to logf (nil: nowhere).
func (c *Client) withLogf(logf func(string, ...any)) *Client {
	cp := *c
	if logf == nil {
		logf = func(string, ...any) {}
	}
	cp.logf = logf
	return &cp
}

// ---- per-installation rate limits ----

// newInstallRateTracker is the rate tracker of one GitHub App installation.
func newInstallRateTracker() *rateTracker {
	t := newRateTracker()
	t.gate = true
	return t
}

// pauseFor holds back the installation's other requests for d after one of
// them was rate limited. It is a no-op outside App mode.
func (c *Client) pauseFor(d time.Duration) {
	if c.rate == nil || !c.rate.gate {
		return
	}
	until := c.now().Add(d)
	c.rate.mu.Lock()
	defer c.rate.mu.Unlock()
	if until.After(c.rate.pausedUntil) {
		c.rate.pausedUntil = until
	}
}

// waitPaused waits out a pause set by pauseFor before a new request.
func (c *Client) waitPaused(ctx context.Context) error {
	if c.rate == nil || !c.rate.gate {
		return nil
	}
	c.rate.mu.Lock()
	d := c.rate.pausedUntil.Sub(c.now())
	c.rate.mu.Unlock()
	if d <= 0 {
		return nil
	}
	return c.sleep(ctx, d)
}

// InstallationBudget is the last rate-limit budget seen for one GitHub App
// installation. A remaining count of -1 means no response has reported it.
type InstallationBudget struct {
	Login            string
	RESTRemaining    int
	GraphQLRemaining int
	// ResetAt is when the REST budget resets (zero when unknown).
	ResetAt time.Time
}

// budgets returns the budget of every installation that has sent a request,
// sorted by login.
func (a *appAuth) budgets() []InstallationBudget {
	var out []InstallationBudget
	for _, in := range a.installs {
		in.mu.Lock()
		c := in.client
		in.mu.Unlock()
		if c == nil {
			continue
		}
		rs := c.RateState()
		if rs.RESTRemaining < 0 && rs.GraphQLRemaining < 0 {
			continue
		}
		out = append(out, InstallationBudget{Login: in.login, RESTRemaining: rs.RESTRemaining,
			GraphQLRemaining: rs.GraphQLRemaining, ResetAt: rs.RESTReset})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Login < out[j].Login })
	return out
}

// progressMaxInstalls is how many installation budgets a progress line shows.
const progressMaxInstalls = 4

// installationsString renders the installations closest to running out of
// REST budget, for Progress.String.
func installationsString(ins []InstallationBudget) string {
	sorted := append([]InstallationBudget(nil), ins...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := sorted[i].RESTRemaining, sorted[j].RESTRemaining
		if (ri < 0) != (rj < 0) {
			return rj < 0 // unknown budgets last
		}
		return ri < rj
	})
	var b strings.Builder
	for i, in := range sorted {
		if i == progressMaxInstalls {
			b.WriteString(" | +" + strconv.Itoa(len(sorted)-i) + " more installations")
			break
		}
		b.WriteString(" | " + in.Login)
		if in.RESTRemaining >= 0 {
			b.WriteString(" rest " + strconv.Itoa(in.RESTRemaining) + " left")
			if !in.ResetAt.IsZero() {
				b.WriteString(", resets " + in.ResetAt.UTC().Format("15:04") + "Z")
			}
		} else {
			b.WriteString(" graphql " + strconv.Itoa(in.GraphQLRemaining) + " left")
		}
	}
	return b.String()
}

// ---- response memo ----

// responseMemo holds the responses org workers fetched through one
// installation client until the sequential pass asks for them. Bodies are
// kept gzip-compressed: a large enterprise fetches many thousands of them.
type responseMemo struct {
	mu      sync.Mutex
	replay  bool
	entries map[string][]memoEntry
	// recorded, replayed and missed count responses stored by workers,
	// served to the sequential pass, and fetched by it from GitHub.
	recorded, replayed, missed int
}

type memoEntry struct {
	status   int
	header   http.Header
	body     []byte // gzip, for a 2xx
	message  string // for an error
	servedAt time.Time
}

func newResponseMemo() *responseMemo { return &responseMemo{entries: map[string][]memoEntry{}} }

// memoKey identifies a request by method, URL, Accept and body. The token is
// not part of it: each installation client has its own memo.
func memoKey(method string, u *url.URL, accept string, body []byte) string {
	h := sha256.New()
	_, _ = io.WriteString(h, method+" "+u.String()+"\x00"+accept+"\x00")
	_, _ = h.Write(body)
	return string(h.Sum(nil))
}

// memoDo answers a request from the memo in the sequential pass, and records
// what the request returns while workers prefetch.
func (c *Client) memoDo(ctx context.Context, method string, u *url.URL, body []byte, accept string) (*response, error) {
	m := c.memo
	key := memoKey(method, u, accept, body)
	if e, ok := m.take(key); ok {
		c.observed.set(e.servedAt)
		return e.result(method, u)
	}
	cp := *c
	cp.memo = nil
	r, err := cp.doAccept(ctx, method, u, body, accept)
	m.record(key, r, err)
	return r, err
}

// take removes and returns the first entry for key in the sequential pass.
func (m *responseMemo) take(key string) (memoEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.replay {
		return memoEntry{}, false
	}
	es := m.entries[key]
	if len(es) == 0 {
		m.missed++
		return memoEntry{}, false
	}
	if len(es) == 1 {
		delete(m.entries, key)
	} else {
		m.entries[key] = es[1:]
	}
	m.replayed++
	return es[0], true
}

// record stores a final result while workers prefetch: a 2xx, or an
// *APIError that was not retried. Exhausted retries, rate-limit waits and
// GraphQL RATE_LIMITED answers are not stored, so the sequential pass asks
// GitHub again rather than replaying a failure.
func (m *responseMemo) record(key string, r *response, err error) {
	var e memoEntry
	switch ae, isAPI := err.(*APIError); {
	case err == nil && r != nil:
		if bytes.Contains(r.body, []byte(`"RATE_LIMITED"`)) {
			return
		}
		e = memoEntry{status: r.status, header: r.header, body: gzipBytes(r.body), servedAt: r.servedAt}
	case isAPI:
		e = memoEntry{status: ae.StatusCode, header: ae.header, message: ae.Message}
	default:
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.replay {
		return
	}
	m.entries[key] = append(m.entries[key], e)
	m.recorded++
}

// result rebuilds what doAccept returned for the recorded request.
func (e memoEntry) result(method string, u *url.URL) (*response, error) {
	if e.status >= 200 && e.status < 300 {
		body, err := gunzipBytes(e.body)
		if err != nil {
			return nil, err
		}
		return &response{status: e.status, header: e.header, body: body, servedAt: e.servedAt}, nil
	}
	return nil, &APIError{Method: method, Path: redactedPath(u), StatusCode: e.status, Message: e.message, header: e.header}
}

// startReplay ends recording; take answers from now on.
func (m *responseMemo) startReplay() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replay = true
}

// drop frees the remaining entries and returns the counts.
func (m *responseMemo) drop() (recorded, replayed, missed int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = map[string][]memoEntry{}
	return m.recorded, m.replayed, m.missed
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func gunzipBytes(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// memos returns the memo of every installation client, sorted by login.
func (a *appAuth) memos() []*responseMemo {
	logins := make([]string, 0, len(a.installs))
	for l := range a.installs {
		logins = append(logins, l)
	}
	sort.Strings(logins)
	var out []*responseMemo
	for _, l := range logins {
		in := a.installs[l]
		in.mu.Lock()
		if in.client != nil && in.client.memo != nil {
			out = append(out, in.client.memo)
		}
		in.mu.Unlock()
	}
	return out
}

// ---- the prefetch ----

// prefetchOrgs runs the parallel prefetch in GitHub App mode when more than
// one org is selected and Config.Parallel allows it. Only the context's
// error is returned: a worker that fails leaves the rest of its org to the
// sequential pass, which reports the failure the way a sequential run does.
func (k *collector) prefetchOrgs(ctx context.Context) error {
	if k.app == nil || k.cfg.parallel() < 2 {
		return nil
	}
	if err := k.app.listInstallations(ctx); err != nil {
		return ctx.Err() // collectOrgsApp lists again and reports the error
	}
	orgs := k.prefetchSelection()
	if len(orgs) < 2 {
		return nil
	}
	k.app.memo = true
	workers := min(k.cfg.parallel(), len(orgs))
	k.logf("collect: GitHub App mode: reading %d orgs with %d workers, one installation budget each", len(orgs), workers)
	k.fetchTotal = len(orgs)
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for org := range jobs {
				k.prefetchOrg(ctx, org)
				k.fetchDone.Add(1)
				k.fetchProgress()
			}
		})
	}
feed:
	for _, org := range orgs {
		select {
		case jobs <- org:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, m := range k.app.memos() {
		m.startReplay()
	}
	return nil
}

// prefetchSelection returns the installed orgs collectOrgsApp will collect,
// in its order.
func (k *collector) prefetchSelection() []string {
	logins := k.app.logins()
	if len(k.cfg.Orgs) > 0 {
		logins = dedupe(k.cfg.Orgs)
	}
	var out []string
	for _, l := range logins {
		if in, ok := k.app.installation(l); ok {
			out = append(out, in.login)
		}
	}
	return out
}

// prefetchOrg runs one worker's throwaway collection of org. Its graph is
// discarded; what it leaves behind is the responses in the memos.
func (k *collector) prefetchOrg(ctx context.Context, org string) {
	cfg := k.cfg
	cfg.Orgs = []string{org}
	cfg.MergeInto, cfg.MergeForce, cfg.Verbose, cfg.Progress = nil, false, false, nil
	app := *k.app
	app.fallback = nil
	w := newCollector(cfg, k.c.withLogf(nil), &app)
	w.progressFn = func(Progress) { k.fetchProgress() }
	if err := w.run(ctx); err != nil && ctx.Err() == nil {
		k.logf("collect: worker for %s stopped early; the sequential pass reads the rest: %v", org, err)
	}
}

// fetchProgress reports the prefetch, serialized across workers.
func (k *collector) fetchProgress() {
	k.fetchMu.Lock()
	defer k.fetchMu.Unlock()
	k.progress(PhaseFetch, int(k.fetchDone.Load()), k.fetchTotal)
}

// endPrefetch frees the memos and logs how much the sequential pass replayed.
func (k *collector) endPrefetch() {
	if k.app == nil || !k.app.memo {
		return
	}
	var rec, rep, miss int
	for _, m := range k.app.memos() {
		a, b, c := m.drop()
		rec, rep, miss = rec+a, rep+b, miss+c
	}
	k.logf("collect: GitHub App mode: workers fetched %d responses; the sequential pass replayed %d and fetched %d more", rec, rep, miss)
}

// prefetchCounters is embedded in collector for the prefetch progress.
type prefetchCounters struct {
	fetchMu    sync.Mutex
	fetchDone  atomic.Int64
	fetchTotal int
}
