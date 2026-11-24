package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
	"github.com/peleduri/gop/internal/testutil"
)

// The App key is generated at runtime and never committed. Tests write it
// only to t.TempDir().
var (
	appKeyOnce sync.Once
	appKey     *rsa.PrivateKey
)

const fakeAppID = 4242

func testAppKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	appKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		appKey = k
	})
	return appKey
}

func testAppPEM(t *testing.T) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testAppKey(t))})
}

// writeKey writes the test key to a temp file with the given mode.
func writeKey(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, testAppPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// appGitHub is a small fake GitHub host for App mode: /app/* takes the App
// JWT, every other path an installation token of the org it is about. It
// fails the test on any write request except the token mint.
type appGitHub struct {
	t        *testing.T
	installs map[string]int64             // org -> installation id
	granted  map[string]map[string]string // org -> granted permissions (default: all read)

	mu     sync.Mutex
	tokens map[string]string // installation token -> org
	jwts   []string
	srv    *httptest.Server
}

var appMintRe = regexp.MustCompile(`^/app/installations/([0-9]+)/access_tokens$`)

func newAppGitHub(t *testing.T, installs map[string]int64) *appGitHub {
	f := &appGitHub{t: t, installs: installs, granted: map[string]map[string]string{}, tokens: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *appGitHub) perms(org string) map[string]string {
	if p, ok := f.granted[org]; ok {
		return p
	}
	out := map[string]string{}
	for k := range collect.DefaultAppPermissions {
		out[k] = "read"
	}
	return out
}

// secrets returns every credential the fake handed out or saw.
func (f *appGitHub) secrets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.jwts...)
	for tok := range f.tokens {
		out = append(out, tok)
	}
	return out
}

func (f *appGitHub) verifyJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&testAppKey(f.t).PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c struct{ ISS int64 }
	return json.Unmarshal(cb, &c) == nil && c.ISS == fakeAppID
}

func (f *appGitHub) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	mint := appMintRe.FindStringSubmatch(p)
	var gql struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if r.Method == http.MethodPost && p == "/graphql" {
		if json.NewDecoder(r.Body).Decode(&gql) != nil || !strings.HasPrefix(strings.TrimSpace(gql.Query), "query") {
			f.t.Errorf("GraphQL request that is not a query: %q", gql.Query)
		}
	} else if r.Method != http.MethodGet && (r.Method != http.MethodPost || mint == nil) {
		f.t.Errorf("write request: %s %s", r.Method, p)
		reply(w, 405, map[string]string{"message": "write refused by the test"})
		return
	}
	auth, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.HasPrefix(p, "/app/") {
		if !f.verifyJWT(auth) {
			f.t.Errorf("%s %s: bad App JWT", r.Method, p)
			reply(w, 401, map[string]string{"message": "A JSON web token could not be decoded"})
			return
		}
		f.mu.Lock()
		f.jwts = append(f.jwts, auth)
		f.mu.Unlock()
		f.serveApp(w, r, mint)
		return
	}
	f.mu.Lock()
	org, ok := f.tokens[auth]
	f.mu.Unlock()
	if !ok {
		f.t.Errorf("%s %s: not an installation token", r.Method, p)
		reply(w, 401, map[string]string{"message": "Bad credentials"})
		return
	}
	for _, pre := range []string{"/orgs/", "/repos/"} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			owner, _, _ := strings.Cut(rest, "/")
			if _, installed := f.installs[owner]; installed && owner != org {
				f.t.Errorf("%s %s: carries the %s installation token", r.Method, p, org)
			}
		}
	}
	if p == "/graphql" && (strings.Contains(gql.Query, "object(expression:") || strings.Contains(gql.Query, "...gopProtection") ||
		strings.Contains(gql.Query, "...gopCollaborators")) {
		// Batched file, branch protection and collaborator reads: every repository owner must be the token's org
		// (or an org without an installation, read through a fallback token).
		for name, v := range gql.Variables {
			owner, _ := v.(string)
			if _, installed := f.installs[owner]; strings.HasPrefix(name, "o") && installed && owner != org {
				f.t.Errorf("batched GraphQL about %q carries the %s installation token", owner, org)
			}
		}
		// No repository aliases in the answer: the collector reads over REST.
		reply(w, 200, map[string]any{"data": map[string]any{}})
		return
	}
	if p == "/graphql" {
		login, _ := gql.Variables["login"].(string)
		if login != org {
			f.t.Errorf("GraphQL about %q carries the %s installation token", login, org)
		}
		reply(w, 200, map[string]any{"data": map[string]any{"organization": map[string]any{
			"ipAllowListEnabledSetting": "DISABLED", "ipAllowListEntries": map[string]any{"totalCount": 0}}}})
		return
	}
	f.serveData(w, r)
}

func (f *appGitHub) serveApp(w http.ResponseWriter, r *http.Request, mint []string) {
	if r.URL.Path == "/app/installations" {
		orgs := make([]string, 0, len(f.installs))
		for o := range f.installs {
			orgs = append(orgs, o)
		}
		sort.Strings(orgs)
		var items []map[string]any
		for _, o := range orgs {
			items = append(items, map[string]any{"id": f.installs[o], "permissions": f.perms(o),
				"account": map[string]any{"login": o, "type": "Organization"}})
		}
		reply(w, 200, items)
		return
	}
	if mint == nil {
		reply(w, 404, map[string]string{"message": "Not Found"})
		return
	}
	id, _ := strconv.ParseInt(mint[1], 10, 64)
	var body struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		reply(w, 400, map[string]string{"message": "bad json"})
		return
	}
	for org, iid := range f.installs {
		if iid != id {
			continue
		}
		granted := f.perms(org)
		for p, v := range body.Permissions {
			if v != "read" {
				f.t.Errorf("mint for %s requested %s:%s", org, p, v)
			}
			if granted[p] == "" {
				reply(w, 422, map[string]string{"message": "The permissions requested are not granted to this installation."})
				return
			}
		}
		f.mu.Lock()
		tok := fmt.Sprintf("ghs_synthetic%s%d", strings.ReplaceAll(org, "-", ""), len(f.tokens)+1)
		f.tokens[tok] = org
		f.mu.Unlock()
		reply(w, 201, map[string]any{"token": tok, "permissions": body.Permissions,
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		return
	}
	reply(w, 404, map[string]string{"message": "Not Found"})
}

const (
	appWorkflow = "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme-actions/deploy@main\n"
	appAction   = "name: deploy\nruns:\n  using: composite\n  steps:\n    - run: echo deploy\n      shell: bash\n"
)

func fileBody(path, data string) map[string]any {
	return map[string]any{"type": "file", "name": filepath.Base(path), "path": path,
		"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(data))}
}

// serveData serves the org and repo endpoints for acme-actions/deploy and
// acme-app/web. Anything else is a 404, which collect records as coverage.
func (f *appGitHub) serveData(w http.ResponseWriter, r *http.Request) {
	repos := map[string]string{"acme-actions": "deploy", "acme-app": "web"}
	members := map[string]string{"acme-actions": "alice", "acme-app": "bob"}
	switch p := r.URL.Path; {
	case p == "/rate_limit":
		reset := doctorClock.Add(40 * time.Minute).Unix()
		reply(w, 200, map[string]any{"resources": map[string]any{
			"core":    map[string]any{"limit": 5000, "remaining": 4990, "reset": reset},
			"graphql": map[string]any{"limit": 5000, "remaining": 5000, "reset": reset},
		}})
	case strings.HasPrefix(p, "/orgs/") && strings.Count(p, "/") == 2:
		org := strings.TrimPrefix(p, "/orgs/")
		if _, ok := repos[org]; !ok {
			reply(w, 404, map[string]string{"message": "Not Found"})
			return
		}
		reply(w, 200, map[string]any{"login": org, "public_repos": 1, "total_private_repos": 2,
			"default_repository_permission": "write", "two_factor_requirement_enabled": true})
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/repos"):
		org := strings.Split(p, "/")[2]
		reply(w, 200, []map[string]any{{"name": repos[org], "full_name": org + "/" + repos[org],
			"visibility": "private", "private": true, "default_branch": "main"}})
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/members"):
		org := strings.Split(p, "/")[2]
		reply(w, 200, []map[string]any{{"login": members[org], "type": "User"}})
	case p == "/repos/acme-app/web/contents/.github/workflows":
		reply(w, 200, []map[string]any{{"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml"}})
	case p == "/repos/acme-app/web/contents/.github/workflows/ci.yml":
		reply(w, 200, fileBody(".github/workflows/ci.yml", appWorkflow))
	case p == "/repos/acme-actions/deploy/contents/action.yml":
		reply(w, 200, fileBody("action.yml", appAction))
	default:
		reply(w, 404, map[string]string{"message": "Not Found"})
	}
}

// runAppEnv runs the CLI with env; collect runs the real collector against
// base (the fake GitHub) and records the config it got.
func runAppEnv(t *testing.T, env map[string]string, base string, got *collect.Config, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, getenv: func(k string) string { return env[k] },
		collect: func(ctx context.Context, cfg collect.Config) (*graph.Graph, error) {
			if got != nil {
				*got = cfg
			}
			cfg.BaseURL, cfg.MaxAttempts = base, 1
			return collect.Collect(ctx, cfg)
		},
		now: func() time.Time { return doctorClock },
	}
	return result{a.run(args), out.String(), errb.String()}
}

// assertNoSecret fails when the App key (any line of it), a JWT or an
// installation token appears in any of texts.
func assertNoSecret(t *testing.T, f *appGitHub, texts ...string) {
	t.Helper()
	secrets := f.secrets()
	for _, line := range strings.Split(string(testAppPEM(t)), "\n") {
		if len(line) >= 16 && !strings.HasPrefix(line, "-----") {
			secrets = append(secrets, line)
		}
	}
	all := strings.Join(texts, "\n")
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Fatalf("output leaks a secret (%d chars)", len(s))
		}
	}
	if strings.Contains(all, "PRIVATE KEY") || strings.Contains(all, "ghs_synthetic") {
		t.Fatal("output leaks key or token material")
	}
}

func TestCollectAppModeCLI(t *testing.T) {
	f := newAppGitHub(t, map[string]int64{"acme-actions": 101, "acme-app": 102})
	keyFile := writeKey(t, 0o600)
	out := filepath.Join(t.TempDir(), "graph.json")
	var got collect.Config
	r := runAppEnv(t, nil, f.srv.URL, &got, "collect", "--enterprise", "acme", "--out", out,
		"--app-id", "4242", "--app-key-file", keyFile)
	if r.code != exitOK {
		t.Fatalf("collect: %+v", r)
	}
	if got.AppID != fakeAppID || !bytes.Equal(got.AppPrivateKeyPEM, testAppPEM(t)) || got.Token != "" {
		t.Errorf("config: app id %d, key set %v, token set %v", got.AppID, len(got.AppPrivateKeyPEM) > 0, got.Token != "")
	}
	if strings.Contains(r.stderr, "warning") {
		t.Errorf("0600 key file warned: %s", r.stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, f, r.stdout, r.stderr, string(data))
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	for _, id := range []string{"org:acme-actions", "org:acme-app", "repo:acme-actions/deploy", "repo:acme-app/web"} {
		if !ids[id] {
			t.Errorf("graph lacks %s", id)
		}
	}
	uses := false
	for _, e := range g.Edges {
		uses = uses || (e.Kind == graph.Uses && e.From == "workflow:acme-app/web/.github/workflows/ci.yml" &&
			e.To == "action:acme-actions/deploy@main")
	}
	if !uses {
		t.Error("graph lacks the cross-org USES edge into acme-actions/deploy@main")
	}
	res, err := schema.Validate(data)
	if err != nil || !res.Valid {
		t.Fatalf("graph.json does not validate: %v %+v", err, res)
	}
}

func TestCollectAppModeEnvAndKeyWarning(t *testing.T) {
	f := newAppGitHub(t, map[string]int64{"acme-actions": 101, "acme-app": 102})
	out := filepath.Join(t.TempDir(), "graph.json")
	env := map[string]string{"GOP_APP_ID": "4242", "GOP_APP_PRIVATE_KEY": string(testAppPEM(t))}
	r := runAppEnv(t, env, f.srv.URL, nil, "collect", "--enterprise", "acme", "--out", out)
	if r.code != exitOK {
		t.Fatalf("collect from env: %+v", r)
	}
	data, _ := os.ReadFile(out)
	assertNoSecret(t, f, r.stdout, r.stderr, string(data))

	keyFile := writeKey(t, 0o644)
	r = runAppEnv(t, nil, f.srv.URL, nil, "collect", "--enterprise", "acme", "--out", out,
		"--app-id", "4242", "--app-key-file", keyFile)
	if r.code != exitOK || !strings.Contains(r.stderr, "has mode 0644, wider than 0600") {
		t.Fatalf("0644 key file: %+v", r)
	}
	assertNoSecret(t, f, r.stdout, r.stderr)
}

func TestAppModeUsageErrors(t *testing.T) {
	keyFile := writeKey(t, 0o600)
	tok := map[string]string{"GITHUB_TOKEN": "ghp_synthetic0token"}
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"token and app flags", tok, []string{"--app-id", "4242", "--app-key-file", keyFile}, "mutually exclusive"},
		{"gh token and app env", map[string]string{"GH_TOKEN": "x", "GOP_APP_ID": "4242", "GOP_APP_PRIVATE_KEY": "k"}, nil, "mutually exclusive"},
		{"id without key", nil, []string{"--app-id", "4242"}, "needs the private key"},
		{"key without id", nil, []string{"--app-key-file", keyFile}, "needs the App ID"},
		{"bad id", nil, []string{"--app-id", "abc", "--app-key-file", keyFile}, "positive integer"},
		{"zero id", map[string]string{"GOP_APP_ID": "0", "GOP_APP_PRIVATE_KEY": "k"}, nil, "positive integer"},
		{"nothing", nil, nil, "GITHUB_TOKEN"},
	} {
		for _, cmd := range []string{"collect", "doctor"} {
			args := []string{cmd, "--enterprise", "acme"}
			if cmd == "collect" {
				args = append(args, "--out", filepath.Join(t.TempDir(), "g.json"))
			}
			r := runAppEnv(t, tc.env, "http://127.0.0.1:1", nil, append(args, tc.args...)...)
			if r.code != exitUsage || !strings.Contains(r.stderr, tc.want) {
				t.Errorf("%s %s: exit %d, want 2 with %q: %s", cmd, tc.name, r.code, tc.want, r.stderr)
			}
		}
	}
	// A missing key file is a runtime error naming the path, not the key.
	r := runAppEnv(t, nil, "http://127.0.0.1:1", nil, "collect", "--enterprise", "acme", "--out", "x.json",
		"--app-id", "4242", "--app-key-file", filepath.Join(t.TempDir(), "missing.pem"))
	if r.code != exitRuntime || !strings.Contains(r.stderr, "missing.pem") {
		t.Errorf("missing key file: %+v", r)
	}
	// A key that is not PEM fails without echoing it.
	r = runAppEnv(t, map[string]string{"GOP_APP_ID": "4242", "GOP_APP_PRIVATE_KEY": "not-a-key-SYNTHETICSECRET"}, "http://127.0.0.1:1", nil,
		"collect", "--enterprise", "acme", "--out", "x.json")
	if r.code != exitRuntime || strings.Contains(r.stderr, "SYNTHETICSECRET") || !strings.Contains(r.stderr, "not PEM encoded") {
		t.Errorf("bad key: %+v", r)
	}
}

func TestGoldenDoctorApp(t *testing.T) {
	f := newAppGitHub(t, map[string]int64{"acme-actions": 101, "acme-app": 102})
	write := f.perms("acme-app")
	write["contents"] = "write"
	f.granted["acme-app"] = write
	keyFile := writeKey(t, 0o600)
	for _, tc := range []struct {
		golden string
		extra  []string
	}{
		{"doctor_app_mode.txt", nil},
		{"doctor_app_mode.json", []string{"--format", "json"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			args := append([]string{"doctor", "--enterprise", "acme", "--api-url", f.srv.URL, "--insecure-http",
				"--orgs", "acme-actions,acme-app,acme-legacy", "--app-id", "4242", "--app-key-file", keyFile}, tc.extra...)
			r := runAppEnv(t, nil, f.srv.URL, nil, args...)
			if r.code != exitWarn {
				t.Fatalf("exit %d, want %d: %+v", r.code, exitWarn, r)
			}
			assertNoSecret(t, f, r.stdout, r.stderr)
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

func TestDoctorAppMissingPermission(t *testing.T) {
	f := newAppGitHub(t, map[string]int64{"acme-actions": 101, "acme-app": 102})
	p := f.perms("acme-actions")
	delete(p, "members")
	f.granted["acme-actions"] = p
	env := map[string]string{"GOP_APP_ID": "4242", "GOP_APP_PRIVATE_KEY": string(testAppPEM(t))}
	r := runAppEnv(t, env, f.srv.URL, nil, "doctor", "--enterprise", "acme", "--api-url", f.srv.URL, "--insecure-http")
	if r.code != exitRuntime {
		t.Fatalf("exit %d, want 1: %+v", r.code, r)
	}
	for _, want := range []string{
		"WARN  permissions acme-actions",
		"the App is not granted members:read, which collect requests",
		"fix: grant the App members:read",
		"FAIL  token acme-actions",
		"could not mint a read-only installation token: HTTP 422",
		"org acme-actions: org members, teams and outside collaborators (CAN_PUSH edges) (App lacks members:read)",
		"1 of 2 organizations readable (from App installations)",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("doctor output lacks %q:\n%s", want, r.stdout)
		}
	}
	assertNoSecret(t, f, r.stdout, r.stderr)
}

func TestDoctorAppBadKey(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemOther := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	env := map[string]string{"GOP_APP_ID": "4242", "GOP_APP_PRIVATE_KEY": string(pemOther)}
	// The fake reports a bad JWT as a test error; run it on a server that
	// answers 401 without checking instead.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 401, map[string]string{"message": "A JSON web token could not be decoded"})
	}))
	t.Cleanup(srv.Close)
	r := runAppEnv(t, env, srv.URL, nil, "doctor", "--enterprise", "acme", "--api-url", srv.URL, "--insecure-http")
	if r.code != exitRuntime || !strings.Contains(r.stdout, "FAIL  app  App JWT rejected (HTTP 401)") {
		t.Fatalf("bad key: %+v", r)
	}
	if strings.Contains(r.stdout+r.stderr, "PRIVATE KEY") {
		t.Fatal("key material in output")
	}
}
