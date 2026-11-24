package collect

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// parallelFake is a GitHub App host with four org installations, each with
// its own budget, and a client on the fake's clock that records its waits.
func parallelFake(t *testing.T, latency time.Duration) (*fakeGitHub, *Client, *sleepLog) {
	t.Helper()
	clk := newTestClock()
	f := newFakeGitHub(t)
	f.enterpriseForbidden = true
	f.latency = latency
	f.app = newFakeApp(t, clk.now, map[string]int64{"acme-actions": 101, "acme-app": 102, "acme-legacy": 103, "acme-secure": 104})
	c, err := newClient(ClientOptions{BaseURL: f.srv.URL, MaxAttempts: 3, Logf: func(format string, args ...any) {
		if strings.Contains(format, "GitHub App mode") {
			t.Logf(format, args...)
		}
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	sl := &sleepLog{}
	c.sleep = sl.sleep
	c.now = clk.now
	return f, c, sl
}

// sleepLog records the waits a client asks for, without waiting.
type sleepLog struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleepLog) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

func (s *sleepLog) has(d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.d, d)
}

// progressLog records progress updates; Collect serializes the calls, the
// mutex is for the race detector's benefit when the test reads them.
type progressLog struct {
	mu sync.Mutex
	p  []Progress
}

func (l *progressLog) add(p Progress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.p = append(l.p, p)
}

func (l *progressLog) phase(name string) []Progress {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Progress
	for _, p := range l.p {
		if p.Phase == name {
			out = append(out, p)
		}
	}
	return out
}

func collectParallel(t *testing.T, c *Client, parallel int, pl *progressLog) (*graph.Graph, time.Duration) {
	t.Helper()
	cfg := appConfig(c, t)
	cfg.Parallel = parallel
	if pl != nil {
		cfg.Progress = pl.add
	}
	start := time.Now()
	g, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect (parallel %d): %v", parallel, err)
	}
	return g, time.Since(start)
}

func TestCollectAppParallelMatchesSequential(t *testing.T) {
	const latency = 4 * time.Millisecond
	fs, cs, _ := parallelFake(t, latency)
	seq, seqTime := collectParallel(t, cs, 1, nil)
	fp, cp, _ := parallelFake(t, latency)
	pl := &progressLog{}
	par, parTime := collectParallel(t, cp, 4, pl)

	if a, b := normalized(t, seq), normalized(t, par); a != b {
		t.Fatalf("parallel graph differs from the sequential graph:\nsequential %d bytes\nparallel   %d bytes", len(a), len(b))
	}
	var orgs []string
	for _, n := range par.Nodes {
		if n.Kind == graph.KindOrg && n.Evidence == graph.Live {
			orgs = append(orgs, n.ID)
		}
	}
	if len(orgs) != 4 {
		t.Errorf("collected orgs = %v, want 4", orgs)
	}
	t.Logf("sequential %s (%d requests), parallel %s (%d requests): %.1fx",
		seqTime.Round(time.Millisecond), fs.requests, parTime.Round(time.Millisecond), fp.requests,
		float64(seqTime)/float64(parTime))
	if !raceEnabled && parTime >= seqTime {
		t.Errorf("parallel run took %s, sequential %s: want faster", parTime, seqTime)
	}
	fetch := pl.phase(PhaseFetch)
	if len(fetch) == 0 {
		t.Fatal("no fetch progress")
	}
	if last := fetch[len(fetch)-1]; last.Done != 4 || last.Total != 4 {
		t.Errorf("last fetch progress = %d/%d, want 4/4", last.Done, last.Total)
	}
}

func TestCollectAppParallelBudgetsAndRetries(t *testing.T) {
	base, cb, _ := parallelFake(t, 0)
	want, _ := collectParallel(t, cb, 4, nil)
	if len(base.app.limited) != 0 {
		t.Fatalf("baseline was rate limited: %v", base.app.limited)
	}

	f, c, sl := parallelFake(t, 0)
	f.app.budget = 5000
	f.app.limitOnce["/orgs/acme-app/teams"] = limitReply{http.StatusForbidden, 7}
	f.app.limitOnce["/orgs/acme-secure/outside_collaborators"] = limitReply{http.StatusTooManyRequests, 9}
	pl := &progressLog{}
	got, _ := collectParallel(t, c, 4, pl)

	if a, b := normalized(t, want), normalized(t, got); a != b {
		t.Fatal("graph after rate-limit retries differs from the graph without them")
	}
	slices.Sort(f.app.limited)
	if !slices.Equal(f.app.limited, []string{"acme-app /orgs/acme-app/teams", "acme-secure /orgs/acme-secure/outside_collaborators"}) {
		t.Errorf("rate-limited answers = %v", f.app.limited)
	}
	if !sl.has(7*time.Second) || !sl.has(9*time.Second) {
		t.Errorf("waits = %v, want the Retry-After values 7s and 9s", sl.d)
	}

	t.Run("progress shows each installation's own budget", func(t *testing.T) {
		all := pl.phase(PhaseProtection)
		if len(all) == 0 {
			t.Fatal("no protection progress")
		}
		last := all[len(all)-1]
		if last.RESTRemaining != -1 {
			t.Errorf("App-mode RESTRemaining = %d, want -1 (budgets are per installation)", last.RESTRemaining)
		}
		var logins []string
		f.app.mu.Lock()
		defer f.app.mu.Unlock()
		for _, in := range last.Installations {
			logins = append(logins, in.Login)
			if in.RESTRemaining >= 5000 || in.RESTRemaining < 5000-f.app.used[in.Login] {
				t.Errorf("%s REST remaining = %d after %d requests", in.Login, in.RESTRemaining, f.app.used[in.Login])
			}
		}
		if !slices.Equal(logins, []string{"acme-actions", "acme-app", "acme-legacy", "acme-secure"}) {
			t.Errorf("installations = %v", logins)
		}
		if s := last.String(); !strings.Contains(s, "acme-app rest ") {
			t.Errorf("progress line %q lacks the acme-app budget", s)
		}
	})
}

func TestInstallationPauseIsPerInstallation(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	base, err := newClient(ClientOptions{BaseURL: "https://api.github.com"}, false)
	if err != nil {
		t.Fatal(err)
	}
	base.now = func() time.Time { return now }
	mk := func() (*Client, *sleepLog) {
		c := base.WithTokenSource(noTokenSource{})
		c.rate = newInstallRateTracker()
		sl := &sleepLog{}
		c.sleep = sl.sleep
		return c, sl
	}
	a, as := mk()
	b, bs := mk()
	a.pauseFor(30 * time.Second)
	a.pauseFor(10 * time.Second) // a shorter pause never shortens a longer one
	if err := a.waitPaused(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.waitPaused(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(as.d, []time.Duration{30 * time.Second}) || len(bs.d) != 0 {
		t.Errorf("waits: paused installation %v, other installation %v", as.d, bs.d)
	}
	// A token-mode client has one budget and no gate.
	tc, ts := base.WithToken("x"), &sleepLog{}
	tc.sleep = ts.sleep
	tc.pauseFor(time.Minute)
	_ = tc.waitPaused(context.Background())
	if len(ts.d) != 0 {
		t.Errorf("token-mode client waited %v", ts.d)
	}
}

func TestResponseMemo(t *testing.T) {
	u, _ := url.Parse("https://api.github.com/repos/acme/web/collaborators")
	m := newResponseMemo()
	ok := memoKey(http.MethodGet, u, jsonAccept, nil)
	notFound := memoKey(http.MethodGet, u, "application/vnd.github.raw", nil)
	limited := memoKey(http.MethodPost, u, jsonAccept, []byte("q"))
	gaveUp := memoKey(http.MethodGet, u, jsonAccept, []byte("x"))
	h := http.Header{"Link": {`<https://api.github.com/next>; rel="next"`}}
	m.record(ok, &response{status: 200, header: h, body: []byte(`[{"login":"alice"}]`)}, nil)
	m.record(notFound, nil, &APIError{Method: "GET", Path: "/x", StatusCode: 404, Message: "Not Found"})
	m.record(limited, &response{status: 200, body: []byte(`{"errors":[{"type":"RATE_LIMITED"}]}`)}, nil)
	m.record(gaveUp, nil, errors.New("gave up after 3 attempts"))

	if _, hit := m.take(ok); hit {
		t.Fatal("take answered while recording")
	}
	m.startReplay()
	m.record(gaveUp, &response{status: 200}, nil) // ignored in replay
	e, hit := m.take(ok)
	if !hit {
		t.Fatal("recorded 200 not replayed")
	}
	r, err := e.result(http.MethodGet, u)
	if err != nil || string(r.body) != `[{"login":"alice"}]` || r.header.Get("Link") == "" {
		t.Errorf("replayed 200 = %+v, %v", r, err)
	}
	if _, hit := m.take(ok); hit {
		t.Error("an entry was replayed twice")
	}
	e, hit = m.take(notFound)
	if !hit {
		t.Fatal("recorded 404 not replayed")
	}
	if _, err := e.result(http.MethodGet, u); !IsNotFound(err) || !strings.Contains(err.Error(), "/repos/acme/web/collaborators") {
		t.Errorf("replayed 404 = %v", err)
	}
	for _, k := range []string{limited, gaveUp} {
		if _, hit := m.take(k); hit {
			t.Error("a rate-limited or failed answer was replayed")
		}
	}
	if rec, rep, miss := m.drop(); rec != 2 || rep != 2 || miss != 3 {
		t.Errorf("counts recorded %d replayed %d missed %d", rec, rep, miss)
	}
}

func TestConfigParallel(t *testing.T) {
	for in, want := range map[int]int{-1: DefaultParallel, 0: DefaultParallel, 1: 1, 8: 8, 99: MaxParallel} {
		if got := (Config{Parallel: in}).parallel(); got != want {
			t.Errorf("parallel(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestProgressStringInstallations(t *testing.T) {
	reset := time.Date(2026, 1, 2, 14, 5, 0, 0, time.UTC)
	p := Progress{Phase: PhaseFetch, Done: 1, Total: 6, RESTRemaining: -1, GraphQLRemaining: -1, Installations: []InstallationBudget{
		{Login: "acme-a", RESTRemaining: 4000, ResetAt: reset},
		{Login: "acme-b", RESTRemaining: 120, ResetAt: reset},
		{Login: "acme-c", RESTRemaining: -1, GraphQLRemaining: 4990},
		{Login: "acme-d", RESTRemaining: 4500},
		{Login: "acme-e", RESTRemaining: 4999},
		{Login: "acme-f", RESTRemaining: 3000},
	}}
	want := "fetch 1/6 orgs | acme-b rest 120 left, resets 14:05Z | acme-f rest 3000 left | acme-a rest 4000 left, resets 14:05Z" +
		" | acme-d rest 4500 left | +2 more installations"
	if got := p.String(); got != want {
		t.Errorf("String() =\n%q\nwant\n%q", got, want)
	}
}
