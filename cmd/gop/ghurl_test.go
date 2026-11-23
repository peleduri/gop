package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

func resolveURLs(t *testing.T, env map[string]string, args ...string) (endpoints, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	uf := addURLFlags(fs, "collect")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return uf.resolve(func(k string) string { return env[k] })
}

func TestResolveURLs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want endpoints
	}{
		{nil, nil, endpoints{host: "github.com"}},
		{[]string{"--github-url", "https://github.com"}, nil, endpoints{host: "github.com"}},
		{[]string{"--github-url", "https://github.com/"}, nil, endpoints{host: "github.com"}},
		{[]string{"--github-url", "https://api.github.com"}, nil, endpoints{host: "github.com"}},
		{[]string{"--github-url", "https://ghes.example"}, nil,
			endpoints{"https://ghes.example/api/v3", "https://ghes.example/api/graphql", "ghes.example"}},
		{[]string{"--github-url", "https://GHES.example/"}, nil,
			endpoints{"https://GHES.example/api/v3", "https://GHES.example/api/graphql", "ghes.example"}},
		// The REST root form --github-url took before it named the instance.
		{[]string{"--github-url", "https://ghes.example/api/v3/"}, nil,
			endpoints{"https://ghes.example/api/v3", "https://ghes.example/api/graphql", "ghes.example"}},
		{nil, map[string]string{"GOP_GITHUB_URL": "https://ghes.example"}, endpoints{"https://ghes.example/api/v3", "https://ghes.example/api/graphql", "ghes.example"}},
		// The flag wins over the environment.
		{[]string{"--github-url", "https://github.com"}, map[string]string{"GOP_GITHUB_URL": "https://ghes.example"}, endpoints{host: "github.com"}},
		// Proxy overrides keep the instance's host.
		{[]string{"--github-url", "https://ghes.example", "--api-url", "https://proxy.example/rest", "--graphql-url", "https://proxy.example/gql"}, nil,
			endpoints{"https://proxy.example/rest", "https://proxy.example/gql", "ghes.example"}},
		{[]string{"--api-url", "https://proxy.example/rest/"}, nil, endpoints{rest: "https://proxy.example/rest", host: "github.com"}},
		{[]string{"--github-url", "http://127.0.0.1:8080", "--insecure-http"}, nil,
			endpoints{"http://127.0.0.1:8080/api/v3", "http://127.0.0.1:8080/api/graphql", "127.0.0.1:8080"}},
	} {
		got, err := resolveURLs(t, tc.env, tc.args...)
		if err != nil || got != tc.want {
			t.Errorf("%v %v: %+v, %v; want %+v", tc.args, tc.env, got, err, tc.want)
		}
	}
}

func TestResolveURLsRejects(t *testing.T) {
	for _, args := range [][]string{
		{"--github-url", "http://ghes.example"},
		{"--github-url", "ghes.example"},
		{"--github-url", "ftp://ghes.example"},
		{"--github-url", "https://ghes.example/some/path"},
		{"--github-url", "https://github.com/acme"},
		{"--github-url", "https://user:secret@ghes.example"},
		{"--github-url", "https://ghes.example?x=1"},
		{"--api-url", "http://proxy.example"},
		{"--github-url", "https://ghes.example", "--graphql-url", "http://proxy.example/graphql"},
	} {
		_, err := resolveURLs(t, nil, args...)
		var ue usageError
		if err == nil || !errors.As(err, &ue) {
			t.Errorf("%v: %v, want a usage error", args, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%v: error echoes credentials: %v", args, err)
		}
	}
	if _, err := resolveURLs(t, map[string]string{"GOP_GITHUB_URL": "http://ghes.example"}); err == nil {
		t.Error("GOP_GITHUB_URL with http:// accepted without --insecure-http")
	}
}

func TestCollectPassesGitHubURL(t *testing.T) {
	var got collect.Config
	c := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		return &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme"}, nil
	}
	out := filepath.Join(t.TempDir(), "g.json")
	r := runApp(t, map[string]string{"GITHUB_TOKEN": "ghp_synthetic"}, c,
		"collect", "--enterprise", "acme", "--out", out, "--github-url", "https://ghes.example")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	if got.BaseURL != "https://ghes.example/api/v3" || got.GraphQLURL != "https://ghes.example/api/graphql" || got.Host != "ghes.example" {
		t.Errorf("config = BaseURL %q GraphQLURL %q Host %q", got.BaseURL, got.GraphQLURL, got.Host)
	}
	r = runApp(t, map[string]string{"GITHUB_TOKEN": "ghp_synthetic"}, nil,
		"collect", "--enterprise", "acme", "--out", out, "--github-url", "http://ghes.example")
	if r.code != exitUsage || !strings.Contains(r.stderr, "--insecure-http") {
		t.Errorf("http:// without --insecure-http: %+v", r)
	}
}

// TestPinGitHubURL: gop pin --github-url reads through /api/v3 of that host.
func TestPinGitHubURL(t *testing.T) {
	f := &fakeGitHub{}
	inner := f.handler(t)
	var mu sync.Mutex
	var paths, hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		hosts = append(hosts, r.Host)
		mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, "/api/v3/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/v3")
		inner(w, r)
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
		getenv: func(k string) string {
			if k == "GITHUB_TOKEN" {
				return pinToken
			}
			return ""
		},
		serve:     func(context.Context, *graph.Graph, string, mcpserver.ServerOptions) error { return nil },
		apiURL:    "https://must-not-be-used.example",
		transport: methodGuard{t, http.DefaultTransport},
	}
	code := a.run([]string{"pin", "--action", "acme-actions/deploy@main", "--github-url", srv.URL, "--insecure-http"})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) == 0 {
		t.Fatal("no requests")
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	for i, p := range paths {
		if !strings.HasPrefix(p, "/api/v3/") || hosts[i] != host {
			t.Errorf("request %s to host %s", p, hosts[i])
		}
	}
}

func TestDiffRefusesDifferentHosts(t *testing.T) {
	o, n := diffCase("identical")
	dir := t.TempDir()
	withHost := func(src, name, host string) string {
		g, err := graph.LoadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for i := range g.Nodes {
			if g.Nodes[i].ID == "enterprise:"+g.Enterprise {
				if g.Nodes[i].Attrs == nil {
					g.Nodes[i].Attrs = map[string]string{}
				}
				g.Nodes[i].Attrs[graph.AttrHost] = host
			}
		}
		var b bytes.Buffer
		if err := collect.WriteGraph(&b, g); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	dotcom := withHost(o, "dotcom.json", "github.com")
	ghes := withHost(n, "ghes.json", "ghes.example")
	r := runApp(t, nil, nil, "diff", dotcom, ghes)
	if r.code != exitUsage || !strings.Contains(r.stderr, "different GitHub hosts") || !strings.Contains(r.stderr, `"github.com" vs "ghes.example"`) {
		t.Errorf("host mismatch: %+v", r)
	}
	if r := runApp(t, nil, nil, "diff", "--force", dotcom, ghes); r.code != exitOK {
		t.Errorf("--force: %+v", r)
	}
	// A graph that does not record its host compares with any host.
	if r := runApp(t, nil, nil, "diff", o, ghes); r.code != exitOK {
		t.Errorf("hostless old graph: %+v", r)
	}
	if r := runApp(t, nil, nil, "diff", dotcom, withHost(n, "dotcom2.json", "github.com")); r.code != exitOK {
		t.Errorf("same host: %+v", r)
	}
}

// TestEnrichCartographyMatchesHostIssuer: Cartography trusts go through the
// same issuer check as trust files: a github.com-issuer export opens paths
// in a github.com graph and none in a GHES graph.
func TestEnrichCartographyMatchesHostIssuer(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	dir := t.TempDir()
	for host, want := range map[string]bool{"github.com": true, "ghes.example": false} {
		g, err := graph.LoadFile("testdata/acme/graph.json")
		if err != nil {
			t.Fatal(err)
		}
		for i := range g.Nodes {
			if g.Nodes[i].Kind == graph.KindEnterprise {
				if g.Nodes[i].Attrs == nil {
					g.Nodes[i].Attrs = map[string]string{}
				}
				g.Nodes[i].Attrs[graph.AttrHost] = host
			}
		}
		in := filepath.Join(dir, host+".json")
		var b bytes.Buffer
		if err := collect.WriteGraph(&b, g); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(in, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, host+"-out.json")
		r := runApp(t, nil, nil, "enrich", "--graph", in, "--cartography", "testdata/cartography/deploy-only.json", "--out", out)
		if r.code != exitOK {
			t.Fatalf("%s: %+v", host, r)
		}
		got, err := graph.LoadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range got.Edges {
			if e.Kind == graph.CanAssume {
				n++
			}
		}
		if (n > 0) != want {
			t.Errorf("%s: %d CAN_ASSUME edges, want any=%v", host, n, want)
		}
	}
}
