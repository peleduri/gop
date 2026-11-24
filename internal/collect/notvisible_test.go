package collect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// collectLogged runs Collect against f with verbose set and returns the
// logged lines and the graph.
func collectLogged(t *testing.T, f *fakeGitHub, verbose bool) ([]string, *graph.Graph) {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	c, err := NewClient(ClientOptions{BaseURL: f.srv.URL, Token: testToken, MaxAttempts: 1, Logf: func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: c, Verbose: verbose})
	if err != nil {
		t.Fatal(err)
	}
	return lines, g
}

func grepLines(lines []string, sub string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

// TestNotVisibleSummary: collaborators that 404 (and one 403) on every
// non-archived repo of acme-app log one summary line for the org, not one line
// per repo; the coverage is the same as a verbose run, which logs every repo.
func TestNotVisibleSummary(t *testing.T) {
	appRepos := []string{"web", "api", "worker", "billing", "mobile", "docs", "infra", "search", "notify"}
	setup := func(t *testing.T) *fakeGitHub {
		f := newFakeGitHub(t)
		for _, r := range appRepos {
			f.collabStatus["acme-app/"+r] = 404
		}
		f.collabStatus["acme-app/billing"] = 403
		return f
	}

	lines, g := collectLogged(t, setup(t), false)
	if got := grepLines(lines, "/collaborators"); len(got) != 0 {
		t.Errorf("default run logged per-repo collaborator errors: %q", got)
	}
	want := []string{
		"collect: org acme-app: collaborators not visible on 9 repos (HTTP 404: 8, HTTP 403: 1); see coverage",
		"collect: org acme-legacy: collaborators not visible on 1 repo (HTTP 403: 1); see coverage",
	}
	if got := grepLines(lines, "collaborators not visible"); !slices.Equal(got, want) {
		t.Errorf("summary lines = %q\nwant %q", got, want)
	}
	c, ok := hasCoverage(g, "org:acme-app", "can_push:collaborators")
	if !ok || c.Reason != "could not list collaborators on 9 repos (needs push access)" {
		t.Errorf("coverage = %+v (found %v)", c, ok)
	}

	vlines, vg := collectLogged(t, setup(t), true)
	per := grepLines(vlines, "collaborators not visible: github api GET /repos/acme-app/")
	if len(per) != len(appRepos) {
		t.Errorf("verbose run logged %d acme-app repo lines, want %d: %q", len(per), len(appRepos), per)
	}
	if got := grepLines(vlines, "collect: org acme-app: collaborators not visible on 9 repos"); len(got) != 1 {
		t.Errorf("verbose run summary lines = %q, want one", got)
	}
	if !slices.Equal(g.Coverage, vg.Coverage) {
		t.Errorf("coverage differs between default and verbose runs:\n%+v\n%+v", g.Coverage, vg.Coverage)
	}
}

func TestNotVisibleLine(t *testing.T) {
	tl := &notVisibleTally{repos: 4, byStatus: map[int]int{403: 1, 404: 1, 0: 2}}
	got := notVisibleLine("acme", "collaborators", tl)
	want := "org acme: collaborators not visible on 4 repos (other: 2, HTTP 403: 1, HTTP 404: 1); see coverage"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestFlushNotVisibleResets(t *testing.T) {
	var lines []string
	c, err := NewClient(ClientOptions{BaseURL: "http://127.0.0.1:1", Token: testToken, Logf: func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}})
	if err != nil {
		t.Fatal(err)
	}
	k := &collector{c: c}
	o := &orgState{login: "acme"}
	k.flushNotVisible(o) // nothing counted: no line
	k.repoNotVisible(o, "collaborators", "repo:acme/web", &APIError{Method: "GET", Path: "/x", StatusCode: 404})
	k.repoNotVisible(o, "collaborators", "repo:acme/api", errors.New("decoding collaborators: bad json"))
	k.flushNotVisible(o)
	k.flushNotVisible(o)
	want := []string{"collect: org acme: collaborators not visible on 2 repos (other: 1, HTTP 404: 1); see coverage"}
	if !slices.Equal(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}
}
