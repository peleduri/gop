package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// ghTokener returns the token of the GitHub CLI login for a host. The real
// one runs `gh auth token --hostname HOST`; tests replace it with a fake, so
// no test ever runs gh.
type ghTokener interface {
	Token(ctx context.Context, host string) (string, error)
}

// execGH runs the gh binary. path is GH_PATH (set by gh when it runs an
// extension) or empty for the gh on PATH.
type execGH struct{ path string }

func (e execGH) Token(ctx context.Context, host string) (string, error) {
	bin := e.path
	if bin == "" {
		p, err := exec.LookPath("gh")
		if err != nil {
			return "", errors.New("gh (the GitHub CLI) is not on PATH")
		}
		bin = p
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "auth", "token", "--hostname", host)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// gh prints the reason (for example "no oauth token found") on
		// stderr. Keep its first line, with anything gh wrote to stdout
		// scrubbed out of it in case that was a token.
		msg := strings.TrimSpace(strings.SplitN(stderr.String(), "\n", 2)[0])
		msg = scrub(msg, strings.TrimSpace(stdout.String()))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("gh auth token: %s", msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// ghExtension reports whether gh started gop as an extension (`gh gop ...`):
// gh sets GH_EXTENSION=1 and GH_PATH in the extension's environment.
func ghExtension(getenv func(string) string) bool {
	return getenv("GH_EXTENSION") == "1"
}

// ghHost is the gh host a gh-login token is asked for: the instance
// --github-url names, else GH_HOST, else github.com.
func ghHost(ep endpoints, getenv func(string) string) string {
	if ep.host != "" && ep.host != graph.GitHubDotCom {
		return ep.host
	}
	if h := strings.ToLower(strings.TrimSpace(getenv("GH_HOST"))); h != "" {
		return h
	}
	return graph.GitHubDotCom
}

// resolveToken picks the personal token for cmd, in this order:
//
//  1. --use-gh-auth (explicit flag): the token of the gh login for host;
//  2. GITHUB_TOKEN, then GH_TOKEN;
//  3. only when gh started gop as an extension (`gh gop ...`) and neither
//     variable is set: the gh login, as with --use-gh-auth.
//
// It returns "" with no error when there is no token. The token is never
// printed; a note on stderr names only its source and host.
func (a *app) resolveToken(cmd string, useGH bool, host string) (string, error) {
	if useGH {
		return a.ghLoginToken(cmd, "--use-gh-auth", host)
	}
	if t := a.getenv("GITHUB_TOKEN"); t != "" {
		return t, nil
	}
	if t := a.getenv("GH_TOKEN"); t != "" {
		return t, nil
	}
	if ghExtension(a.getenv) {
		return a.ghLoginToken(cmd, "gh gop", host)
	}
	return "", nil
}

// ghLoginToken asks gh for the token of its login on host.
func (a *app) ghLoginToken(cmd, why, host string) (string, error) {
	gh := a.gh
	if gh == nil {
		gh = execGH{path: strings.TrimSpace(a.getenv("GH_PATH"))}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := gh.Token(ctx, host)
	if err != nil {
		return "", usagef("%s: %s: reading the gh login for %s failed: %v; run gh auth login --hostname %s, or set GITHUB_TOKEN",
			cmd, why, host, err, host)
	}
	if tok == "" {
		return "", usagef("%s: %s: gh has no login for %s; run gh auth login --hostname %s, or set GITHUB_TOKEN", cmd, why, host, host)
	}
	fmt.Fprintf(a.stderr, "gop %s: using the token of the gh login for %s\n", cmd, host)
	return tok, nil
}
