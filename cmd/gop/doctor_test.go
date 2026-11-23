package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

var doctorClock = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// doctorServer is a small fake GitHub for gop doctor. It fails the test on
// any request that is not a GET or a GraphQL query.
type doctorServer struct {
	token   string
	scopes  string // "" means no X-OAuth-Scopes header
	owner   bool
	orgs    []string
	sso     map[string]bool
	install []string // installation repository full names
}

func (d doctorServer) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			body, _ := io.ReadAll(r.Body)
			var q struct {
				Query string `json:"query"`
			}
			if r.Method != http.MethodPost || r.URL.Path != "/graphql" || json.Unmarshal(body, &q) != nil ||
				!strings.HasPrefix(strings.TrimSpace(q.Query), "query") {
				t.Errorf("non-read request: %s %s %s", r.Method, r.URL.Path, body)
			}
		}
		if r.Header.Get("Authorization") != "Bearer "+d.token {
			reply(w, 401, map[string]string{"message": "Bad credentials"})
			return
		}
		app := strings.HasPrefix(d.token, "ghs_")
		switch p := r.URL.Path; {
		case p == "/user" && app:
			reply(w, 403, map[string]string{"message": "Resource not accessible by integration"})
		case p == "/user":
			if d.scopes != "" {
				w.Header().Set("X-OAuth-Scopes", d.scopes)
			}
			w.Header().Set("GitHub-Authentication-Token-Expiration", "2027-02-01 00:00:00 UTC")
			reply(w, 200, map[string]any{"login": "alice"})
		case p == "/installation/repositories":
			var repos []map[string]any
			for _, full := range d.install {
				owner, _, _ := strings.Cut(full, "/")
				repos = append(repos, map[string]any{"full_name": full, "owner": map[string]any{"login": owner}})
			}
			reply(w, 200, map[string]any{"total_count": len(repos), "repositories": repos})
		case strings.HasPrefix(p, "/orgs/"):
			org := strings.TrimPrefix(p, "/orgs/")
			if d.sso[org] {
				w.Header().Set("X-GitHub-SSO", "required; url=https://github.example/orgs/"+org+"/sso?authorization_request=SYNTHETIC")
				reply(w, 403, map[string]string{"message": "Resource protected by organization SAML enforcement."})
				return
			}
			reply(w, 200, map[string]any{"login": org, "public_repos": 4, "total_private_repos": 10 * len(org)})
		case p == "/rate_limit":
			reset := doctorClock.Add(40 * time.Minute).Unix()
			reply(w, 200, map[string]any{"resources": map[string]any{
				"core":    map[string]any{"limit": 5000, "remaining": 4980, "reset": reset},
				"graphql": map[string]any{"limit": 5000, "remaining": 4995, "reset": reset},
			}})
		case p == "/graphql" && app:
			reply(w, 200, map[string]any{"data": map[string]any{"enterprise": nil},
				"errors": []map[string]any{{"type": "FORBIDDEN", "message": "must be an enterprise owner"}}})
		case p == "/graphql":
			nodes := []map[string]any{}
			for _, o := range d.orgs {
				nodes = append(nodes, map[string]any{"login": o})
			}
			var oi any
			if d.owner {
				oi = map[string]any{"admins": map[string]any{"totalCount": 1}}
			}
			reply(w, 200, map[string]any{"data": map[string]any{"enterprise": map[string]any{"slug": "acme", "ownerInfo": oi,
				"organizations": map[string]any{"totalCount": len(d.orgs), "nodes": nodes}}}})
		default:
			reply(w, 404, map[string]string{"message": "Not Found"})
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func runDoctorApp(t *testing.T, token string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
		getenv: func(k string) string {
			if k == "GITHUB_TOKEN" {
				return token
			}
			return ""
		},
		collect: func(context.Context, collect.Config) (*graph.Graph, error) {
			t.Fatal("collect must not run")
			return nil, nil
		},
		now: func() time.Time { return doctorClock },
	}
	r := result{a.run(append([]string{"doctor"}, args...)), out.String(), errb.String()}
	if (token != "" && strings.Contains(r.stdout+r.stderr, token)) || strings.Contains(r.stdout+r.stderr, "SYNTHETIC") {
		t.Fatalf("doctor output leaks the token or a header value:\n%s%s", r.stdout, r.stderr)
	}
	return r
}

var ownerServer = doctorServer{
	token:  "ghp_synthetic0owner",
	scopes: "repo, read:org, read:enterprise, read:audit_log",
	owner:  true,
	orgs:   []string{"acme", "acme-actions", "acme-app"},
}

func TestGoldenDoctor(t *testing.T) {
	sso := ownerServer
	sso.scopes = "repo, read:org, read:enterprise"
	sso.orgs = []string{"acme", "acme-app", "acme-legacy"}
	sso.sso = map[string]bool{"acme-legacy": true}
	app := doctorServer{token: "ghs_synthetic0app", install: []string{"acme-actions/deploy", "acme-app/web", "acme-app/api"}}
	for _, tc := range []struct {
		golden string
		srv    doctorServer
		code   int
		extra  []string
	}{
		{"doctor_owner.txt", ownerServer, exitOK, nil},
		{"doctor_owner.json", ownerServer, exitOK, []string{"--format", "json"}},
		{"doctor_app.txt", app, exitWarn, nil},
		{"doctor_sso.txt", sso, exitRuntime, nil},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			url := tc.srv.start(t)
			args := append([]string{"--enterprise", "acme", "--github-url", url}, tc.extra...)
			r := runDoctorApp(t, tc.srv.token, args...)
			if r.code != tc.code {
				t.Fatalf("exit %d, want %d: %+v", r.code, tc.code, r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

func TestDoctorUsage(t *testing.T) {
	for _, tc := range []struct {
		token string
		args  []string
	}{
		{"ghp_synthetic0owner", nil},
		{"ghp_synthetic0owner", []string{"--enterprise", "acme", "--format", "yaml"}},
		{"", []string{"--enterprise", "acme"}},
		{"ghp_synthetic0owner", []string{"--enterprise", "acme", "extra"}},
	} {
		if r := runDoctorApp(t, tc.token, tc.args...); r.code != exitUsage {
			t.Errorf("%v: exit %d, want 2", tc.args, r.code)
		}
	}
}

func TestGraphQLURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "",
		"https://api.github.com":       "",
		"https://ghes.example/api/v3":  "https://ghes.example/api/graphql",
		"https://ghes.example/api/v3/": "https://ghes.example/api/graphql",
	} {
		if got := graphQLURL(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
