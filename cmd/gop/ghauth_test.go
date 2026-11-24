package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// Synthetic tokens. The test fails if any of them reaches stdout or stderr.
const (
	ghLoginToken = "gho_synthetic0ghlogin"
	envToken     = "ghp_synthetic0env"
	ghEnvToken   = "ghp_synthetic0ghenv"
)

// fakeGH stands in for `gh auth token`: it records the hosts it was asked
// for and never runs gh.
type fakeGH struct {
	token string
	err   error
	hosts []string
}

func (f *fakeGH) Token(_ context.Context, host string) (string, error) {
	f.hosts = append(f.hosts, host)
	return f.token, f.err
}

func newGHApp(env map[string]string, gh ghTokener, c collector) (*app, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, getenv: func(k string) string { return env[k] }, collect: c,
		serve: func(context.Context, *graph.Graph, string, mcpserver.ServerOptions) error { return nil }, gh: gh}, &out, &errb
}

func assertNoToken(t *testing.T, where string, texts ...string) {
	t.Helper()
	for _, s := range texts {
		for _, tok := range []string{ghLoginToken, envToken, ghEnvToken} {
			if strings.Contains(s, tok) {
				t.Errorf("%s leaks a token: %q", where, s)
			}
		}
	}
}

// TestResolveTokenOrder: the explicit --use-gh-auth flag beats the
// environment variables, which beat the gh fallback; the fallback runs only
// when gh started gop as an extension.
func TestResolveTokenOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		useGH  bool
		env    map[string]string
		want   string
		wantGH bool
	}{
		{"flag beats env", true, map[string]string{"GITHUB_TOKEN": envToken, "GH_TOKEN": ghEnvToken, "GH_EXTENSION": "1"}, ghLoginToken, true},
		{"flag outside gh", true, nil, ghLoginToken, true},
		{"GITHUB_TOKEN beats gh fallback", false, map[string]string{"GITHUB_TOKEN": envToken, "GH_TOKEN": ghEnvToken, "GH_EXTENSION": "1"}, envToken, false},
		{"GH_TOKEN beats gh fallback", false, map[string]string{"GH_TOKEN": ghEnvToken, "GH_EXTENSION": "1"}, ghEnvToken, false},
		{"gh fallback as gh gop", false, map[string]string{"GH_EXTENSION": "1"}, ghLoginToken, true},
		{"no gh call outside gh without the flag", false, nil, "", false},
		{"GH_EXTENSION must be 1", false, map[string]string{"GH_EXTENSION": "0"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gh := &fakeGH{token: ghLoginToken}
			a, out, errb := newGHApp(tc.env, gh, nil)
			got, err := a.resolveToken("collect", tc.useGH, graph.GitHubDotCom)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("token from the wrong source (got %d bytes, want %d)", len(got), len(tc.want))
			}
			if called := len(gh.hosts) > 0; called != tc.wantGH {
				t.Errorf("gh called = %v, want %v", called, tc.wantGH)
			}
			if tc.wantGH && !strings.Contains(errb.String(), "using the token of the gh login for github.com") {
				t.Errorf("stderr = %q, want the source note", errb.String())
			}
			assertNoToken(t, "output", out.String(), errb.String())
		})
	}
}

// TestGHHost: the gh login is asked for the --github-url host, else GH_HOST,
// else github.com.
func TestGHHost(t *testing.T) {
	for _, tc := range []struct {
		ep   endpoints
		env  map[string]string
		want string
	}{
		{endpoints{}, nil, "github.com"},
		{endpoints{host: "github.com"}, map[string]string{"GH_HOST": "GitHub.Acme.Example"}, "github.acme.example"},
		{endpoints{host: "ghes.acme.example"}, map[string]string{"GH_HOST": "other.acme.example"}, "ghes.acme.example"},
	} {
		if got := ghHost(tc.ep, func(k string) string { return tc.env[k] }); got != tc.want {
			t.Errorf("ghHost(%+v, %v) = %q, want %q", tc.ep, tc.env, got, tc.want)
		}
	}
}

// TestCollectAsGHExtension: `gh gop collect` with no token variable uses the
// gh login, follows GH_HOST to a GitHub Enterprise Server, and never prints
// the token.
func TestCollectAsGHExtension(t *testing.T) {
	var got collect.Config
	c := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		return &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme"}, nil
	}
	gh := &fakeGH{token: ghLoginToken}
	env := map[string]string{"GH_EXTENSION": "1", "GH_PATH": "/nonexistent/gh", "GH_HOST": "github.acme.example"}
	a, out, errb := newGHApp(env, gh, c)
	code := a.run([]string{"collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json")})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if got.Token != ghLoginToken {
		t.Error("collect did not get the gh login token")
	}
	if got.BaseURL != "https://github.acme.example/api/v3" || got.Host != "github.acme.example" {
		t.Errorf("BaseURL %q Host %q, want the GH_HOST instance", got.BaseURL, got.Host)
	}
	if len(gh.hosts) != 1 || gh.hosts[0] != "github.acme.example" {
		t.Errorf("gh asked for %v, want [github.acme.example]", gh.hosts)
	}
	assertNoToken(t, "output", out.String(), errb.String())

	// --github-url wins over GH_HOST, for the endpoints and the gh host.
	gh.hosts = nil
	code = a.run([]string{"collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json"),
		"--github-url", "https://ghes.acme.example"})
	if code != exitOK || got.Host != "ghes.acme.example" || len(gh.hosts) != 1 || gh.hosts[0] != "ghes.acme.example" {
		t.Errorf("exit %d, Host %q, gh hosts %v", code, got.Host, gh.hosts)
	}
}

// TestGHHostIgnoredWithoutGH: plain gop (no --use-gh-auth, not run by gh)
// ignores GH_HOST, as before.
func TestGHHostIgnoredWithoutGH(t *testing.T) {
	var got collect.Config
	c := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		return &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme"}, nil
	}
	gh := &fakeGH{token: ghLoginToken}
	a, _, errb := newGHApp(map[string]string{"GITHUB_TOKEN": envToken, "GH_HOST": "github.acme.example"}, gh, c)
	if code := a.run([]string{"collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json")}); code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if got.BaseURL != "" || got.Token != envToken || len(gh.hosts) != 0 {
		t.Errorf("BaseURL %q, env token used %v, gh hosts %v", got.BaseURL, got.Token == envToken, gh.hosts)
	}
}

// TestUseGHAuthErrors: a failing or empty gh login and App mode with
// --use-gh-auth are usage errors that name the fix and never the token.
func TestUseGHAuthErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		gh   *fakeGH
		env  map[string]string
		args []string
		want string
	}{
		{"gh fails", &fakeGH{err: errors.New("no oauth token found for github.com")}, nil,
			[]string{"collect", "--enterprise", "acme", "--out", "g.json", "--use-gh-auth"}, "gh auth login --hostname github.com"},
		{"gh has no login", &fakeGH{}, map[string]string{"GH_EXTENSION": "1"},
			[]string{"doctor", "--enterprise", "acme"}, "gh has no login for github.com"},
		{"App mode", &fakeGH{token: ghLoginToken}, map[string]string{"GOP_APP_ID": "123"},
			[]string{"collect", "--enterprise", "acme", "--out", "g.json", "--use-gh-auth"}, "mutually exclusive"},
		{"pin gh fails", &fakeGH{err: errors.New("not logged in")}, nil,
			[]string{"pin", "--action", "acme-actions/deploy@main", "--use-gh-auth"}, "pin: --use-gh-auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, out, errb := newGHApp(tc.env, tc.gh, nil)
			if code := a.run(tc.args); code != exitUsage || !strings.Contains(errb.String(), tc.want) {
				t.Errorf("exit %d, stderr %q, want %q", code, errb.String(), tc.want)
			}
			assertNoToken(t, "output", out.String(), errb.String())
		})
	}
}

// TestExecGHScrubsToken runs a stand-in gh script (never the real gh) that
// prints a token and fails: the error must not carry the token.
func TestExecGHScrubsToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script stand-in")
	}
	dir := t.TempDir()
	ok := filepath.Join(dir, "gh-ok")
	bad := filepath.Join(dir, "gh-bad")
	if err := os.WriteFile(ok, []byte("#!/bin/sh\n[ \"$1 $2 $3 $4\" = \"auth token --hostname github.acme.example\" ] || exit 9\necho "+ghLoginToken+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho "+ghLoginToken+"\necho \"bad state "+ghLoginToken+"\" >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	tok, err := execGH{path: ok}.Token(context.Background(), "github.acme.example")
	if err != nil || tok != ghLoginToken {
		t.Errorf("ok: err %v, token matches %v", err, tok == ghLoginToken)
	}
	_, err = execGH{path: bad}.Token(context.Background(), "github.com")
	if err == nil || !strings.Contains(err.Error(), "bad state [redacted]") {
		t.Errorf("bad: err %v", err)
	}
	assertNoToken(t, "error", err.Error())
	if _, err := (execGH{path: filepath.Join(dir, "missing")}).Token(context.Background(), "github.com"); err == nil {
		t.Error("missing gh: no error")
	}
}
