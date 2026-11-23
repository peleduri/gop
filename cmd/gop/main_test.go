package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
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
	a := &app{stdout: &out, stderr: &errb, getenv: func(k string) string { return env[k] }, collect: c,
		serve: func(context.Context, *graph.Graph, string) error { return nil }}
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
