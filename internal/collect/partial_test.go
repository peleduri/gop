package collect

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/report"
	"github.com/peleduri/gop/internal/schema"
)

// wrapFake routes every request to f through mw first; when mw returns
// true it has answered the request and f does not see it.
func wrapFake(f *fakeGitHub, mw func(w http.ResponseWriter, r *http.Request) bool) {
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mw(w, r) {
			f.handle(w, r)
		}
	})
}

// fullRunRequests is how many requests an uninterrupted collection of the
// fixture sends.
func fullRunRequests(t *testing.T, cfg Config) (*graph.Graph, int) {
	t.Helper()
	f := newFakeGitHub(t)
	f.etags = true
	cfg.Enterprise, cfg.Client = "acme", f.client(t)
	g, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g, f.requests
}

func wantPartial(t *testing.T, g *graph.Graph, err error, reason string) {
	t.Helper()
	var pe *PartialError
	if !errors.As(err, &pe) || pe.Reason != reason {
		t.Fatalf("err = %v, want a *PartialError with reason %s", err, reason)
	}
	if g == nil {
		t.Fatal("a stopped run returned no graph")
	}
	if !g.Partial || g.PartialReason != reason {
		t.Fatalf("partial = %v, reason %q; want true, %q", g.Partial, g.PartialReason, reason)
	}
	n := 0
	for _, c := range g.Coverage {
		if strings.HasPrefix(c.Reason, graph.CoverageNotCollected) {
			n++
			if !strings.HasPrefix(c.Fact, "phase:") || c.NeedsFix == "" {
				t.Errorf("stopped coverage %+v: want a phase: fact and a fix", c)
			}
		}
	}
	if n == 0 {
		t.Error("no coverage entry says what the stopped run did not collect")
	}
}

func TestCollectInterruptedWritesPartialGraph(t *testing.T) {
	_, total := fullRunRequests(t, Config{})
	for _, after := range []int{1, total / 4, total / 2, total - 2} {
		t.Run(strconv.Itoa(after), func(t *testing.T) {
			f := newFakeGitHub(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancelAfter, f.cancel = after, cancel
			g, err := Collect(ctx, Config{Enterprise: "acme", Client: f.client(t)})
			wantPartial(t, g, err, graph.PartialInterrupted)

			var buf bytes.Buffer
			if err := WriteGraph(&buf, g); err != nil {
				t.Fatal(err)
			}
			res, err := schema.Validate(buf.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if !res.Valid || !res.Partial || res.PartialReason != graph.PartialInterrupted {
				t.Fatalf("validate: valid %v partial %v %q, errors %v", res.Valid, res.Partial, res.PartialReason, res.Errors)
			}
			if !slices.ContainsFunc(res.Warnings, func(p schema.Problem) bool { return p.Pointer == "/partial" }) {
				t.Errorf("validate warnings %v: want one at /partial", res.Warnings)
			}
			for _, p := range res.Warnings {
				if strings.Contains(p.Message, "no coverage entry") {
					t.Errorf("not_visible fact without coverage: %s", p)
				}
			}
			loaded, err := graph.Load(&buf)
			if err != nil {
				t.Fatal(err)
			}
			for format, want := range map[string]string{"html": `class="partial"`, "md": "**Warning:** Partial graph: the run was interrupted"} {
				var out bytes.Buffer
				if err := report.Render(&out, loaded, report.Options{Format: format}); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), want) {
					t.Errorf("%s report lacks the partial banner %q", format, want)
				}
			}
		})
	}
}

func TestCollectStopsAtMaxRequests(t *testing.T) {
	want, total := fullRunRequests(t, Config{})
	for _, max := range []int{1, 7, total / 2, total - 1} {
		t.Run(strconv.Itoa(max), func(t *testing.T) {
			f := newFakeGitHub(t)
			g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), MaxRequests: max})
			wantPartial(t, g, err, graph.PartialMaxRequests)
			if f.requests != max {
				t.Errorf("sent %d requests, want exactly the budget %d", f.requests, max)
			}
		})
	}
	f := newFakeGitHub(t)
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), MaxRequests: total})
	if err != nil || g.Partial {
		t.Fatalf("a budget of the whole run stopped it: %v (partial %v)", err, g != nil && g.Partial)
	}
	if normalized(t, g) != normalized(t, want) {
		t.Error("a run within its budget differs from an unbudgeted run")
	}
}

var reposPathRe = regexp.MustCompile(`^/orgs/([^/]+)/repos$`)

// repoListOrder collects the fixture with cfg and returns the orgs in the
// order their repositories were first listed.
func repoListOrder(t *testing.T, cfg Config) (*graph.Graph, []string) {
	t.Helper()
	f := newFakeGitHub(t)
	var (
		mu    sync.Mutex
		order []string
	)
	wrapFake(f, func(_ http.ResponseWriter, r *http.Request) bool {
		if m := reposPathRe.FindStringSubmatch(r.URL.Path); m != nil {
			mu.Lock()
			if !slices.Contains(order, m[1]) {
				order = append(order, m[1])
			}
			mu.Unlock()
		}
		return false
	})
	cfg.Enterprise, cfg.Client = "acme", f.client(t)
	g, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g, order
}

func TestCollectPriorityOrgsFirst(t *testing.T) {
	g, order := repoListOrder(t, Config{Priority: []string{"ACME-secure", "acme-legacy", "acme-nonexistent"}})
	if len(order) < 3 || order[0] != "acme-secure" || order[1] != "acme-legacy" {
		t.Fatalf("repo listing order %v: want acme-secure, acme-legacy first", order)
	}
	// The rest go by member count, largest first.
	def, dorder := repoListOrder(t, Config{})
	members := func(org string) int {
		for _, n := range def.Nodes {
			if n.ID == "org:"+org {
				m, err := strconv.Atoi(n.Attrs[graph.AttrMembers])
				if err != nil {
					return -1
				}
				return m
			}
		}
		return -1
	}
	if !slices.IsSortedFunc(dorder, func(a, b string) int { return members(b) - members(a) }) {
		t.Errorf("default order %v is not by member count, largest first", dorder)
	}
	// Coverage is listed in collection order; everything else is sorted.
	if sortedCoverage(t, g) != sortedCoverage(t, def) {
		t.Error("the collection order changed the graph")
	}
}

// sortedCoverage is normalized with the coverage entries sorted.
func sortedCoverage(t *testing.T, g *graph.Graph) string {
	t.Helper()
	cp := *g
	cp.Coverage = slices.Clone(g.Coverage)
	slices.SortFunc(cp.Coverage, func(a, b graph.Coverage) int {
		return strings.Compare(a.Scope+"\x00"+a.Fact, b.Scope+"\x00"+b.Fact)
	})
	return normalized(t, &cp)
}

// rateFake makes f report a per-API remaining count that every request
// lowers, resetting to start when the client sleeps for the reset. lowest
// is the smallest count a request left. With noReset the reset time is
// never sent.
type rateFake struct {
	mu        sync.Mutex
	remaining map[bool]int
	lowest    int
	start     int
	resets    int
}

func newRateFake(t *testing.T, f *fakeGitHub, start int, noReset bool) (*rateFake, *Client) {
	rf := &rateFake{remaining: map[bool]int{false: start, true: start}, lowest: start, start: start}
	resetAt := time.Now().Add(30 * time.Minute).Unix()
	wrapFake(f, func(w http.ResponseWriter, r *http.Request) bool {
		gql := strings.HasSuffix(r.URL.Path, "/graphql")
		rf.mu.Lock()
		rf.remaining[gql]--
		rem := rf.remaining[gql]
		rf.lowest = min(rf.lowest, rem)
		rf.mu.Unlock()
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(rem))
		if !noReset {
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))
		}
		return false
	})
	c := f.client(t)
	c.sleep = func(ctx context.Context, d time.Duration) error {
		if d > 20*time.Minute { // the reserve wait, not a retry backoff
			rf.mu.Lock()
			rf.remaining = map[bool]int{false: rf.start, true: rf.start}
			rf.resets++
			rf.mu.Unlock()
		}
		return ctx.Err()
	}
	return rf, c
}

func TestCollectReserveWaitsForReset(t *testing.T) {
	want, _ := fullRunRequests(t, Config{})
	const reserve = 15
	f := newFakeGitHub(t)
	rf, c := newRateFake(t, f, 40, false)
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: c, Reserve: reserve})
	if err != nil {
		t.Fatal(err)
	}
	if rf.lowest < reserve {
		t.Errorf("a request left %d remaining, below the reserve %d", rf.lowest, reserve)
	}
	if rf.resets == 0 {
		t.Error("the run never waited for a reset; the fixture is too small for the test")
	}
	if g.Partial || normalized(t, g) != normalized(t, want) {
		t.Error("waiting for resets changed the graph")
	}
}

func TestCollectReserveStopsWhenItCannotWait(t *testing.T) {
	const reserve = 15
	f := newFakeGitHub(t)
	rf, c := newRateFake(t, f, 40, true)
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: c, Reserve: reserve})
	wantPartial(t, g, err, graph.PartialReserve)
	if rf.lowest < reserve {
		t.Errorf("a request left %d remaining, below the reserve %d", rf.lowest, reserve)
	}
}

func TestCollectRateLimitExhaustedWritesPartial(t *testing.T) {
	f := newFakeGitHub(t)
	reset := strconv.FormatInt(time.Now().Add(2*time.Hour).Unix(), 10)
	var (
		mu sync.Mutex
		n  int
	)
	wrapFake(f, func(w http.ResponseWriter, _ *http.Request) bool {
		mu.Lock()
		n++
		limited := n > 10
		mu.Unlock()
		if !limited {
			return false
		}
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", reset)
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "API rate limit exceeded"})
		return true
	})
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
	wantPartial(t, g, err, graph.PartialRateLimit)
	if n > 12 {
		t.Errorf("sent %d requests after the rate limit ran out, want the run to stop at once", n-10)
	}
}

func TestResumeCompletesPartialRun(t *testing.T) {
	want, total := fullRunRequests(t, Config{DisableGraphQLBatch: true})
	f := newFakeGitHub(t)
	f.etags = true
	dir := filepath.Join(t.TempDir(), "gop-cache")
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), CacheDir: dir,
		DisableGraphQLBatch: true, MaxRequests: total / 2})
	wantPartial(t, g, err, graph.PartialMaxRequests)
	f.resetCounts()
	got, err := collectCached(t, context.Background(), f, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Partial {
		t.Error("the resumed run is still partial")
	}
	if f.requests >= total {
		t.Errorf("the resumed run sent %d requests, the whole run takes %d: nothing was resumed", f.requests, total)
	}
	if normalized(t, got) != normalized(t, want) {
		t.Error("the resumed graph differs from an uninterrupted run's")
	}
}

func TestMergeKeepsPartial(t *testing.T) {
	base, _ := fullRunRequests(t, Config{})
	f := newFakeGitHub(t)
	fresh, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), Orgs: []string{"acme-app"}, MaxRequests: 5})
	wantPartial(t, fresh, err, graph.PartialMaxRequests)
	merged, err := MergeWith(base, fresh, []string{"acme-app"}, MergeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Partial || merged.PartialReason != graph.PartialMaxRequests {
		t.Errorf("merged: partial %v reason %q, want the partial re-collection's", merged.Partial, merged.PartialReason)
	}
}
