package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/testutil"
)

const (
	pinToken = "test-token-pin-do-not-print"
	pinSHA   = "1111111111111111111111111111111111111111"
	tagSHA   = "2222222222222222222222222222222222222222"
)

// methodGuard fails the test on any request that is not a GET.
type methodGuard struct {
	t    *testing.T
	next http.RoundTripper
}

func (g methodGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		g.t.Errorf("gop pin sent %s %s: only GET is allowed", r.Method, r.URL.Path)
	}
	return g.next.RoundTrip(r)
}

// fakeGitHub serves synthetic refs and the workflow fixtures under testdata/pin.
type fakeGitHub struct {
	mu       sync.Mutex
	requests []string
	// tagMessage, when set, makes the tag lookup fail with 403 and this message.
	tagMessage string
	// mainTag makes main a tag as well as a branch.
	mainTag bool
}

func (f *fakeGitHub) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+pinToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p := r.URL.Path
		switch {
		case p == "/repos/acme-actions/deploy/commits/main":
			if r.Header.Get("Accept") != "application/vnd.github.sha" {
				t.Errorf("commit lookup Accept = %q", r.Header.Get("Accept"))
			}
			_, _ = w.Write([]byte(pinSHA))
		case p == "/repos/acme-actions/deploy/commits/v1":
			_, _ = w.Write([]byte(tagSHA))
		case p == "/repos/acme-actions/deploy/git/ref/tags/v1":
			_, _ = w.Write([]byte(`{"ref":"refs/tags/v1"}`))
		case p == "/repos/acme-actions/deploy/git/ref/tags/main" && f.mainTag:
			_, _ = w.Write([]byte(`{"ref":"refs/tags/main"}`))
		case p == "/repos/acme-actions/deploy/git/ref/tags/main" && f.tagMessage != "":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"` + f.tagMessage + `"}`))
		case p == "/repos/acme-actions/deploy/git/ref/heads/main":
			_, _ = w.Write([]byte(`{"ref":"refs/heads/main"}`))
		case strings.HasPrefix(p, "/repos/") && strings.Contains(p, "/contents/"):
			if r.Header.Get("Accept") != "application/vnd.github.raw" {
				t.Errorf("contents Accept = %q", r.Header.Get("Accept"))
			}
			rest := strings.TrimPrefix(p, "/repos/")
			repo, file, _ := strings.Cut(rest, "/contents/")
			data, err := os.ReadFile(filepath.Join("testdata", "pin", repo, file))
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				return
			}
			_, _ = w.Write(data)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}
}

func runPin(t *testing.T, f *fakeGitHub, args ...string) result {
	t.Helper()
	if f == nil {
		f = &fakeGitHub{}
	}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	var out, errb bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
		getenv: func(k string) string {
			if k == "GITHUB_TOKEN" {
				return pinToken
			}
			return ""
		},
		collect: func(context.Context, collect.Config) (*graph.Graph, error) {
			t.Fatal("collect must not run")
			return nil, nil
		},
		serve:     func(context.Context, *graph.Graph, string, mcpserver.ServerOptions) error { return nil },
		apiURL:    srv.URL,
		transport: methodGuard{t, http.DefaultTransport},
	}
	code := a.run(append([]string{"pin"}, args...))
	r := result{code, out.String(), errb.String()}
	if strings.Contains(r.stdout, pinToken) || strings.Contains(r.stderr, pinToken) {
		t.Errorf("token printed: %+v", r)
	}
	return r
}

func TestPinNoGraph(t *testing.T) {
	f := &fakeGitHub{}
	r := runPin(t, f, "--action", "acme-actions/deploy@main")
	if r.code != exitOK || r.stderr != "" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.stdout, "sha: "+pinSHA) || !strings.Contains(r.stdout, "ref kind: branch") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
	testutil.Golden(t, "pin_nograph.txt", []byte(r.stdout))
	want := []string{
		"GET /repos/acme-actions/deploy/commits/main",
		"GET /repos/acme-actions/deploy/git/ref/tags/main",
		"GET /repos/acme-actions/deploy/git/ref/heads/main",
	}
	if strings.Join(f.requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s", strings.Join(f.requests, "\n"))
	}
}

func TestPinTag(t *testing.T) {
	r := runPin(t, nil, "--action", "action:acme-actions/deploy@v1", "--format", "text")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	for _, want := range []string{"sha: " + tagSHA, "ref kind: tag", "with:    uses: acme-actions/deploy@" + tagSHA + " # v1", "can be moved"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
}

func TestPinAmbiguousRef(t *testing.T) {
	r := runPin(t, &fakeGitHub{mainTag: true}, "--action", "acme-actions/deploy@main", "--format", "text")
	if r.code != exitOK || !strings.Contains(r.stdout, "ref kind: branch") || !strings.Contains(r.stdout, "both a tag and a branch") {
		t.Fatalf("%+v", r)
	}
}

func TestPinAlreadySHA(t *testing.T) {
	f := &fakeGitHub{}
	r := runPin(t, f, "--action", "acme-actions/deploy@"+pinSHA)
	if r.code != exitOK || !strings.Contains(r.stdout, "already pinned") || len(f.requests) != 0 {
		t.Fatalf("%+v requests=%v", r, f.requests)
	}
}

func TestPinGraphGolden(t *testing.T) {
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"pin_graph.diff", []string{"--action", "acme-actions/deploy@main", "--graph", linesFixture}},
		{"pin_graph.txt", []string{"--action", "acme-actions/deploy@main", "--graph", linesFixture, "--format", "text"}},
		{"pin_offline.diff", []string{"--action", "acme-actions/deploy@main", "--graph", linesFixture, "--offline"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			r := runPin(t, nil, tc.args...)
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%+v", r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

// TestPinDiffApplies checks each repo's output applies with git apply --check
// to copies of the fixture workflows, header comments included.
func TestPinDiffApplies(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	for _, repo := range []string{"acme-app/web", "acme-app/api", "acme-actions/tools"} {
		t.Run(repo, func(t *testing.T) {
			r := runPin(t, nil, "--action", "acme-actions/deploy@main", "--graph", linesFixture, "--repo", repo)
			if r.code != exitOK || !strings.Contains(r.stdout, "diff --git") {
				t.Fatalf("%+v", r)
			}
			dir := t.TempDir()
			copyTree(t, filepath.Join("testdata", "pin", repo), dir)
			for _, args := range [][]string{{"apply", "--check", "-v"}, {"apply"}} {
				cmd := exec.Command(git, args...)
				cmd.Dir = dir
				cmd.Stdin = strings.NewReader(r.stdout)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s\npatch:\n%s", args, err, out, r.stdout)
				}
			}
			// After applying, every uses: line is pinned.
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				data, _ := os.ReadFile(p)
				if strings.Contains(string(data), "deploy@main") {
					t.Errorf("%s still uses deploy@main:\n%s", p, data)
				}
				if !strings.Contains(string(data), "acme-actions/deploy@"+pinSHA) {
					t.Errorf("%s not pinned:\n%s", p, data)
				}
				return nil
			})
		})
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPinJSON(t *testing.T) {
	r := runPin(t, nil, "--action", "acme-actions/deploy@main", "--graph", linesFixture, "--format", "json")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	var out pinResult
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.SHA != pinSHA || out.RefKind != "branch" || len(out.Files) != 4 || len(out.Skipped) != 1 {
		t.Errorf("%+v", out)
	}
	if out.Skipped[0].Repo != "acme-legacy/old-site" {
		t.Errorf("skipped = %+v", out.Skipped)
	}
}

func TestPinUnknownRef(t *testing.T) {
	r := runPin(t, nil, "--action", "acme-actions/deploy@nope")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "ref not found") || strings.Contains(r.stderr, "goroutine") {
		t.Fatalf("%+v", r)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestPinRedactsTokenInWarnings(t *testing.T) {
	r := runPin(t, &fakeGitHub{tagMessage: "bad credentials " + pinToken}, "--action", "acme-actions/deploy@main")
	if r.code != exitOK || !strings.Contains(r.stdout, "could not tell whether main is a tag or a branch") || !strings.Contains(r.stdout, "[redacted]") {
		t.Fatalf("%+v", r)
	}
}

func TestPinUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "--action is required"},
		{[]string{"--action", "deploy"}, "owner/repo"},
		{[]string{"--action", "./local"}, "owner/repo"},
		{[]string{"--action", "acme-actions/deploy@main", "--format", "yaml"}, "--format"},
		{[]string{"--action", "acme-actions/deploy@main", "--repo", "acme-app/web"}, "need --graph"},
		{[]string{"--action", "acme-actions/deploy@main", "--offline"}, "need --graph"},
	} {
		r := runPin(t, nil, tc.args...)
		if r.code != exitUsage || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v: code %d stderr %q", tc.args, r.code, r.stderr)
		}
	}
	// No token in the environment.
	r := runApp(t, nil, nil, "pin", "--action", "acme-actions/deploy@main")
	if r.code != exitUsage || !strings.Contains(r.stderr, "GITHUB_TOKEN") {
		t.Errorf("no token: %+v", r)
	}
}

func TestPinSkipsMissingAndChangedFiles(t *testing.T) {
	g, err := graph.LoadFile(linesFixture)
	if err != nil {
		t.Fatal(err)
	}
	// Point one consumer at a file the fake does not serve and another at a
	// line that no longer holds the uses: entry.
	for i, e := range g.Edges {
		if e.Kind != graph.Uses {
			continue
		}
		switch e.From {
		case "workflow:acme-app/api/.github/workflows/deploy.yml":
			g.Edges[i].Attrs[graph.AttrFile] = ".github/workflows/gone.yml"
		case "workflow:acme-app/web/.github/workflows/ci.yml":
			g.Edges[i].Attrs[graph.AttrLine] = "3"
		}
	}
	path := filepath.Join(t.TempDir(), "g.json")
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := collect.WriteGraph(fh, g); err != nil {
		t.Fatal(err)
	}
	_ = fh.Close()
	r := runPin(t, nil, "--action", "acme-actions/deploy@main", "--graph", path, "--format", "text")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	for _, want := range []string{
		"skipped: acme-app/api .github/workflows/gone.yml: file not found",
		"skipped: acme-app/web .github/workflows/ci.yml:3: the line no longer reads uses: acme-actions/deploy@main",
		"acme-app/web .github/workflows/release.yml line 12",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
}

func TestReadOnlyTransportRefusesWrites(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request reached the server: %s", r.Method)
	}))
	defer srv.Close()
	c := &http.Client{Transport: readOnlyTransport{http.DefaultTransport}}
	for _, m := range []string{http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(m, srv.URL+"/repos/acme-app/web", nil)
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: no error", m)
		} else if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("%s: %v", m, err)
		}
	}
}
