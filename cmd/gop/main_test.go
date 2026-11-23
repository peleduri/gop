package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

const fixture = "../../testdata/acme/graph.json"

type result struct {
	code           int
	stdout, stderr string
}

func runApp(t *testing.T, env map[string]string, c collector, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	if c == nil {
		c = func(context.Context, collect.Config) (*graph.Graph, error) {
			t.Fatal("collect must not run")
			return nil, nil
		}
	}
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, getenv: func(k string) string { return env[k] }, collect: c,
		serve: func(context.Context, *graph.Graph, string, mcpserver.ServerOptions) error { return nil }}
	code := a.run(args)
	return result{code, out.String(), errb.String()}
}

func TestVersion(t *testing.T) {
	r := runApp(t, nil, nil, "version")
	if r.code != 0 || r.stdout != "gop dev (commit dev, built dev)\n" {
		t.Fatalf("version: %+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"report", "--graph", fixture}, // missing --out
		{"report", "--graph", fixture, "--out", "x", "--format", "pdf"},
		{"report", "--nope"},
		{"paths", "--graph", fixture},                    // missing --from
		{"who", "--graph", fixture, "extra", "--target"}, // positional arg
		{"serve"},
		{"collect", "--enterprise", "acme"}, // missing --out
		{"validate"},                        // missing --graph
		{"validate", "--graph", fixture, "--format", "yaml"},
		{"validate", "--graph", fixture, "extra"},
		{"demo", "--size", "huge"},
		{"demo", "extra"},
		{"serve", "--demo", "--graph", fixture},
		{"serve", "--graph", "-"},
		{"serve", "--graph", fixture, "--baseline", "-"},
		{"serve", "--graph", fixture, "--baseline", "does-not-exist.json"},
		{"report", "--out", "-"}, // neither --graph nor --demo
	} {
		if r := runApp(t, nil, nil, args...); r.code != exitUsage {
			t.Errorf("%v: code %d, want 2 (stderr %q)", args, r.code, r.stderr)
		}
	}
}

func TestReportWritesFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"report.html", "report.md"} {
		out := filepath.Join(dir, name)
		r := runApp(t, nil, nil, "report", "--graph", fixture, "--out", out, "--top", "5")
		if r.code != 0 {
			t.Fatalf("report: %+v", r)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "Treat it as sensitive.") {
			t.Errorf("%s: footer missing", name)
		}
		if strings.HasSuffix(name, ".html") != strings.Contains(string(b), "<!doctype html>") {
			t.Errorf("%s: wrong format inferred", name)
		}
		if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want 0600", name, fi.Mode().Perm())
		}
	}
}

func TestPathsAndWho(t *testing.T) {
	r := runApp(t, nil, nil, "who", "--graph", fixture, "--target", "repo:acme-app/web")
	if r.code != 0 || !strings.Contains(r.stdout, "members:acme-actions") || !strings.Contains(r.stdout, ", live]") {
		t.Fatalf("who: %+v", r)
	}
	r = runApp(t, nil, nil, "paths", "--graph", fixture, "--from", "members:acme-legacy")
	if r.code != 0 || !strings.Contains(r.stdout, "not visible") {
		t.Fatalf("paths: %+v", r)
	}
	r = runApp(t, nil, nil, "paths", "--graph", fixture, "--from", "members:acme-act")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "members:acme-actions") {
		t.Fatalf("unknown id: %+v", r)
	}
}

func TestCollectTokenFromEnvOnly(t *testing.T) {
	r := runApp(t, nil, nil, "collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json"))
	if r.code != exitUsage || !strings.Contains(r.stderr, "GITHUB_TOKEN") {
		t.Fatalf("no token: %+v", r)
	}
	const tok = "test-token-value-123"
	out := filepath.Join(t.TempDir(), "g.json")
	var got collect.Config
	fake := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		return graph.LoadFile(fixture)
	}
	r = runApp(t, map[string]string{"GH_TOKEN": tok}, fake, "collect", "--enterprise", "acme", "--out", out, "--orgs", "acme-app, acme-actions")
	if r.code != 0 {
		t.Fatalf("collect: %+v", r)
	}
	if got.Token != tok || got.Enterprise != "acme" || len(got.Orgs) != 2 || got.Orgs[1] != "acme-actions" {
		t.Errorf("config = %+v", got)
	}
	if _, err := graph.LoadFile(out); err != nil {
		t.Errorf("written graph does not load: %v", err)
	}
	failing := func(context.Context, collect.Config) (*graph.Graph, error) {
		return nil, errors.New("auth failed for " + tok)
	}
	r = runApp(t, map[string]string{"GITHUB_TOKEN": tok}, failing, "collect", "--enterprise", "acme", "--out", out)
	if r.code != exitRuntime || strings.Contains(r.stderr+r.stdout, tok) {
		t.Fatalf("token leaked or wrong code: %+v", r)
	}
}

func TestValidate(t *testing.T) {
	r := runApp(t, nil, nil, "validate", "--graph", fixture)
	if r.code != exitOK || !strings.Contains(r.stdout, ": valid (gop.graph/v1, 0 errors, 0 warnings)") {
		t.Fatalf("valid fixture: %+v", r)
	}

	bad := "../../internal/schema/testdata/invalid/missing-node.json"
	r = runApp(t, nil, nil, "validate", "--graph", bad)
	if r.code != exitRuntime || !strings.Contains(r.stdout, "error   /edges/0/to: ") || !strings.Contains(r.stderr, "invalid") {
		t.Fatalf("invalid fixture: %+v", r)
	}

	r = runApp(t, nil, nil, "validate", "--graph", "../../internal/schema/testdata/invalid/wrong-schema.json", "--format", "json")
	if r.code != exitRuntime {
		t.Fatalf("wrong schema: %+v", r)
	}
	var res struct {
		Valid  bool `json:"valid"`
		Errors []struct {
			Pointer string `json:"pointer"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil {
		t.Fatalf("json output: %v\n%s", err, r.stdout)
	}
	if res.Valid || len(res.Errors) != 1 || res.Errors[0].Pointer != "/schema" {
		t.Fatalf("json result: %+v", res)
	}

	// Warnings alone keep the exit code 0.
	r = runApp(t, nil, nil, "validate", "--graph", "../../internal/schema/testdata/valid/uncovered.json")
	if r.code != exitOK || !strings.Contains(r.stdout, "warning /nodes/1/evidence") {
		t.Fatalf("warnings only: %+v", r)
	}

	if r = runApp(t, nil, nil, "validate", "--graph", filepath.Join(t.TempDir(), "missing.json")); r.code != exitRuntime {
		t.Fatalf("missing file: %+v", r)
	}
}
func TestDemoDeterministicAndHint(t *testing.T) {
	a := runApp(t, nil, nil, "demo", "--size", "small", "--seed", "1")
	b := runApp(t, nil, nil, "demo")
	if a.code != 0 || a.stdout != b.stdout {
		t.Fatalf("demo not deterministic or failed: code %d stderr %q", a.code, a.stderr)
	}
	if a.stderr != "next: gop serve --graph graph.json\n" {
		t.Errorf("hint = %q", a.stderr)
	}
	out := filepath.Join(t.TempDir(), "demo.json")
	r := runApp(t, nil, nil, "demo", "--out", out)
	if r.code != 0 || !strings.Contains(r.stderr, "--graph "+out) {
		t.Fatalf("demo --out: %+v", r)
	}
	g, err := graph.LoadFile(out)
	if err != nil || !graph.IsDemo(g) {
		t.Fatalf("demo file: demo=%v err=%v", g != nil && graph.IsDemo(g), err)
	}
}

// runStdin runs the app with stdin set.
func runStdin(t *testing.T, stdin string, serve func(context.Context, *graph.Graph, string, mcpserver.ServerOptions) error, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	if serve == nil {
		serve = func(context.Context, *graph.Graph, string, mcpserver.ServerOptions) error { return nil }
	}
	a := &app{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, getenv: func(string) string { return "" },
		collect: func(context.Context, collect.Config) (*graph.Graph, error) {
			t.Fatal("collect must not run")
			return nil, nil
		},
		serve: serve}
	code := a.run(args)
	return result{code, out.String(), errb.String()}
}

func TestDemoPipeToReport(t *testing.T) {
	d := runApp(t, nil, nil, "demo")
	piped := runStdin(t, d.stdout, nil, "report", "--graph", "-", "--out", "-", "--format", "md")
	direct := runApp(t, nil, nil, "report", "--demo", "--out", "-", "--format", "md")
	if piped.code != 0 || direct.code != 0 {
		t.Fatalf("report: piped %+v direct %+v", piped, direct)
	}
	if piped.stdout != direct.stdout {
		t.Error("gop demo | gop report --graph - differs from gop report --demo")
	}
	for _, want := range []string{"# [demo data] gop:", "Pinning is not enough", "## Pinned, still reachable",
		"acme-actions/setup@main", "org:acme-legacy"} {
		if !strings.Contains(piped.stdout, want) {
			t.Errorf("report missing %q", want)
		}
	}
	w := runStdin(t, d.stdout, nil, "who", "--graph", "-", "--target", "repo:acme-app/web")
	if w.code != 0 || !strings.HasPrefix(w.stdout, "[demo data] ") || !strings.Contains(w.stdout, "members:acme-actions") {
		t.Fatalf("who from stdin: %+v", w)
	}
}

func TestDemoServeMCP(t *testing.T) {
	out := filepath.Join(t.TempDir(), "graph.json")
	if r := runApp(t, nil, nil, "demo", "--out", out); r.code != 0 {
		t.Fatalf("demo: %+v", r)
	}
	check := func(args ...string) {
		t.Helper()
		var served *graph.Graph
		r := runStdin(t, "", func(_ context.Context, g *graph.Graph, _ string, _ mcpserver.ServerOptions) error {
			served = g
			return nil
		}, args...)
		if r.code != 0 || served == nil {
			t.Fatalf("%v: %+v", args, r)
		}
		ctx := context.Background()
		st, ct := mcp.NewInMemoryTransports()
		ss, err := mcpserver.NewServer(served, "test").Connect(ctx, st, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ss.Close() }()
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cs.Close() }()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "top_risks", Arguments: map[string]any{"n": 3}})
		if err != nil || res.IsError {
			t.Fatalf("top_risks: %v %+v", err, res)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		if !strings.HasPrefix(text, "[demo data] top risk: ") {
			t.Errorf("%v: top_risks text = %q", args, text[:min(len(text), 120)])
		}
	}
	check("serve", "--graph", out)
	check("serve", "--demo")
}

func TestServeBaseline(t *testing.T) {
	var opts mcpserver.ServerOptions
	serve := func(_ context.Context, _ *graph.Graph, _ string, o mcpserver.ServerOptions) error {
		opts = o
		return nil
	}
	old := "../../internal/diff/testdata/ref-unpinned/old.json"
	cur := "../../internal/diff/testdata/ref-unpinned/new.json"
	if r := runStdin(t, "", serve, "serve", "--graph", cur, "--baseline", old); r.code != 0 || opts.Baseline == nil {
		t.Fatalf("serve --baseline: %+v baseline=%v", r, opts.Baseline != nil)
	}
	if r := runStdin(t, "", serve, "serve", "--graph", cur); r.code != 0 || opts.Baseline != nil {
		t.Fatalf("serve without --baseline: %+v baseline=%v", r, opts.Baseline != nil)
	}
}
