package collect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

// testClock is a settable clock shared by the fake server and the client.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// appFake returns a fakeGitHub with the App installed on acme-actions and
// acme-app (not acme-legacy) and a client with no token on the shared clock.
func appFake(t *testing.T, logf func(string, ...any)) (*fakeGitHub, *Client, *testClock) {
	t.Helper()
	clk := newTestClock()
	f := newFakeGitHub(t)
	f.enterpriseForbidden = true // an installation token can never read the enterprise
	f.app = newFakeApp(t, clk.now, map[string]int64{"acme-actions": 101, "acme-app": 102})
	c, err := newClient(ClientOptions{BaseURL: f.srv.URL, MaxAttempts: 3, Logf: logf}, false)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	c.now = clk.now
	return f, c, clk
}

func appConfig(c *Client, t *testing.T, orgs ...string) Config {
	return Config{Enterprise: "acme", Orgs: orgs, Client: c, AppID: testAppID, AppPrivateKeyPEM: appTestPEM(t)}
}

func TestSignAppJWT(t *testing.T) {
	key := appTestKey(t)
	now := time.Unix(1_700_000_000, 0)
	tok, err := signAppJWT(key, testAppID, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts", len(parts))
	}
	enc := base64.RawURLEncoding
	hb, _ := enc.DecodeString(parts[0])
	if string(hb) != `{"alg":"RS256","typ":"JWT"}` {
		t.Errorf("header = %s", hb)
	}
	cb, _ := enc.DecodeString(parts[1])
	var c map[string]int64
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatal(err)
	}
	if c["iat"] != now.Unix()-60 || c["exp"] != now.Unix()+540 || c["iss"] != testAppID {
		t.Errorf("claims = %s", cb)
	}
	sig, _ := enc.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("signature does not verify with the public key: %v", err)
	}
}

func TestParseAppKey(t *testing.T) {
	key := appTestKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string][]byte{
		"pkcs1": appTestPEM(t),
		"pkcs8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		got, err := parseAppKey(p)
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: key = %v, err = %v", name, got != nil, err)
		}
	}
	// Corrupt keys fail without echoing any key material.
	good := appTestPEM(t)
	body := strings.Split(string(good), "\n")[1]
	bad := bytes.Replace(good, []byte(body), []byte(strings.Repeat("A", len(body))), 1)
	for name, p := range map[string][]byte{"not pem": []byte("secret-not-a-key"), "corrupt": bad} {
		_, err := parseAppKey(p)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "secret-not-a-key") || strings.Contains(err.Error(), body[:16]) {
			t.Errorf("%s: error carries key material: %v", name, err)
		}
	}
}

func TestConfigAuthValidation(t *testing.T) {
	pemKey := appTestPEM(t)
	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"token and app":   {Config{Token: "x", AppID: 1, AppPrivateKeyPEM: pemKey}, "mutually exclusive"},
		"app without key": {Config{AppID: 1}, "private key"},
		"key without id":  {Config{AppPrivateKeyPEM: pemKey}, "App ID"},
		"write permission": {Config{AppID: 1, AppPrivateKeyPEM: pemKey, AppPermissions: map[string]string{"contents": "write"}},
			`"read"`},
	}
	for name, tc := range cases {
		tc.cfg.Enterprise = "acme"
		_, err := Collect(context.Background(), tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestAppInstallationsAndMint(t *testing.T) {
	f, c, _ := appFake(t, nil)
	f.pageSize = 1 // paginate the installation list
	a, err := newAppAuth(Config{AppID: testAppID, AppPrivateKeyPEM: appTestPEM(t)}, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.listInstallations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.logins(); !slices.Equal(got, []string{"acme-actions", "acme-app"}) {
		t.Fatalf("installations = %v", got)
	}
	if _, ok := a.client("acme-legacy"); ok {
		t.Error("acme-legacy has no installation")
	}
	ac, ok := a.client("ACME-APP") // logins match case-insensitively
	if !ok {
		t.Fatal("no client for acme-app")
	}
	if err := ac.GetJSON(context.Background(), "/orgs/acme-app", nil); err != nil {
		t.Fatal(err)
	}
	if f.app.mintCount("acme-app") != 1 || f.app.mintCount("acme-actions") != 0 {
		t.Errorf("mints = %v", f.app.mints)
	}
	for _, p := range f.app.perms {
		if fmt.Sprint(p) != fmt.Sprint(DefaultAppPermissions) {
			t.Errorf("mint requested %v, want %v", p, DefaultAppPermissions)
		}
	}
	// The JWT client refuses anything outside /app/*.
	if err := a.jwt.GetJSON(context.Background(), "/orgs/acme-app", nil); err == nil || !strings.Contains(err.Error(), "/app/") {
		t.Errorf("JWT client outside /app/: err = %v", err)
	}
}

func TestAppTokenRefresh(t *testing.T) {
	f, c, clk := appFake(t, nil)
	a, err := newAppAuth(Config{AppID: testAppID, AppPrivateKeyPEM: appTestPEM(t)}, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.listInstallations(context.Background()); err != nil {
		t.Fatal(err)
	}
	ac, _ := a.client("acme-app")
	get := func() {
		t.Helper()
		if err := ac.GetJSON(context.Background(), "/orgs/acme-app", nil); err != nil {
			t.Fatal(err)
		}
	}
	get()
	clk.advance(50 * time.Minute) // 10 minutes left: reuse
	get()
	if n := f.app.mintCount("acme-app"); n != 1 {
		t.Fatalf("mints after 50m = %d, want 1", n)
	}
	clk.advance(6 * time.Minute) // 4 minutes left: re-mint before the request
	get()
	if n := f.app.mintCount("acme-app"); n != 2 {
		t.Fatalf("mints after 56m = %d, want 2", n)
	}
	in, _ := a.installation("acme-app")
	if in.token != "ghs_synthetic_acme-app_2" {
		t.Errorf("token not replaced by the re-minted one")
	}
}

func TestAppRefusesWriteGrant(t *testing.T) {
	f, c, _ := appFake(t, nil)
	f.app.grant = map[string]string{"contents": "write", "metadata": "read"}
	_, err := Collect(context.Background(), appConfig(c, t, "acme-app"))
	if err == nil {
		// Collection continues with coverage; the write token must never be used.
		for _, req := range f.app.allRequests() {
			if !strings.HasPrefix(req, "GET /app/") && !strings.HasPrefix(req, "POST /app/") {
				t.Errorf("request sent with a write-scoped token: %s", req)
			}
		}
		return
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("err = %v", err)
	}
}

// allowedRequest is the read-only contract: GET anywhere, POST only to
// GraphQL and the installation-token mint.
var allowedPost = regexp.MustCompile(`^POST (/graphql|/app/installations/[0-9]+/access_tokens)$`)

func TestCollectAppMode(t *testing.T) {
	var logMu sync.Mutex
	var logs []string
	logf := func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	f, c, _ := appFake(t, logf)
	f.app.forbid["/orgs/acme-app/outside_collaborators"] = true
	g, err := Collect(context.Background(), appConfig(c, t, "acme-actions", "acme-app", "acme-legacy"))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	ix := newIndex(g)

	t.Run("planted cross-org path exists", func(t *testing.T) {
		e := ix.mustEdge(t, "members:acme-actions", "repo:acme-actions/deploy", graph.CanPush)
		if e.Evidence != graph.Live || e.Attrs[graph.AttrVia] != graph.ViaDefaultPerm {
			t.Errorf("CAN_PUSH = %+v", e)
		}
		r := ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
		if r.SourceAPI != "derived:workflow.uses+"+srcAppInstalls {
			t.Errorf("RESOLVES_TO source = %q", r.SourceAPI)
		}
		ix.mustEdge(t, "workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main", graph.Uses)
		res := graph.NewIndex(g).Reach("members:acme-actions", graph.Options{})
		if !slices.Contains(res.Confirmed.Repos, "repo:acme-app/web") {
			t.Errorf("members:acme-actions should reach repo:acme-app/web, confirmed = %v", res.Confirmed.Repos)
		}
		// The nested action.yml in acme-actions was read with acme-actions' token
		// (the fake fails the test otherwise) and expanded.
		if v := ix.node(t, "action:acme-actions/deploy@main").Attrs[attrNested]; v == "" || v == "unknown" {
			t.Errorf("deploy@main nested = %q, want expanded", v)
		}
	})

	t.Run("uninstalled org is not_visible with coverage", func(t *testing.T) {
		c, ok := hasCoverage(g, "org:acme-legacy", "installation")
		if !ok {
			t.Fatalf("missing org:acme-legacy / installation coverage: %+v", g.Coverage)
		}
		if c.Reason != "GitHub App not installed on acme-legacy" || c.NeedsFix != "install the App on acme-legacy with read-only permissions" {
			t.Errorf("coverage = %+v", c)
		}
		if n := ix.node(t, "org:acme-legacy"); n.Evidence != graph.NotVisible {
			t.Errorf("acme-legacy evidence = %q", n.Evidence)
		}
		for _, req := range f.app.allRequests() {
			if strings.Contains(req, "/orgs/acme-legacy") {
				t.Errorf("collector read the uninstalled org: %s", req)
			}
		}
	})

	t.Run("enterprise facts are not_visible, members from org lists", func(t *testing.T) {
		ce, ok := hasCoverage(g, "enterprise:acme", "enterprise")
		if !ok || !strings.HasPrefix(ce.Reason, "GitHub App mode") {
			t.Errorf("enterprise coverage = %+v", ce)
		}
		app := ix.node(t, "org:acme-app")
		if app.AttrEvidence[graph.AttrSSO] != graph.NotVisible {
			t.Errorf("sso evidence = %q", app.AttrEvidence[graph.AttrSSO])
		}
		if app.Attrs[graph.AttrMembers] != "3" {
			t.Errorf("acme-app members = %q", app.Attrs[graph.AttrMembers])
		}
		for _, req := range f.app.allRequests() {
			if strings.Contains(req, "/enterprises/") || strings.HasPrefix(req, "GET /user/orgs") || strings.Contains(req, "/installation/repositories") {
				t.Errorf("enterprise or discovery call in App mode: %s", req)
			}
		}
	})

	t.Run("a 403 names the missing App permission", func(t *testing.T) {
		c, ok := hasCoverage(g, "org:acme-app", "outside_collaborators")
		if !ok || c.NeedsFix != "grant the App members:read" {
			t.Errorf("coverage = %+v (found %v)", c, ok)
		}
	})

	t.Run("one mint per installed org", func(t *testing.T) {
		if f.app.mintCount("acme-actions") != 1 || f.app.mintCount("acme-app") != 1 {
			t.Errorf("mints = %v", f.app.mints)
		}
	})

	t.Run("read-only: every request is GET or an allowlisted POST", func(t *testing.T) {
		reqs := f.app.allRequests()
		if len(reqs) < 20 {
			t.Fatalf("only %d requests recorded", len(reqs))
		}
		mints := 0
		for _, req := range reqs {
			if strings.HasPrefix(req, "GET /") {
				continue
			}
			if !allowedPost.MatchString(req) {
				t.Errorf("non-GET request outside the allowlist: %s", req)
			}
			if strings.Contains(req, "/access_tokens") {
				mints++
			}
		}
		if mints != 2 {
			t.Errorf("mint POSTs = %d, want 2", mints)
		}
	})

	t.Run("no key, JWT or token in logs or graph.json", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteGraph(&buf, g); err != nil {
			t.Fatal(err)
		}
		logMu.Lock()
		hay := buf.String() + strings.Join(logs, "\n")
		logMu.Unlock()
		secrets := append(f.app.allTokens(), "PRIVATE KEY", "eyJhbGciOiJSUzI1NiIs") // JWT header prefix
		keyBody := strings.Split(string(appTestPEM(t)), "\n")[1]
		secrets = append(secrets, keyBody[:32])
		for _, s := range secrets {
			if strings.Contains(hay, s) {
				t.Errorf("secret %q leaked into logs or graph", s[:min(len(s), 12)])
			}
		}
		res, err := schema.Validate(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !res.Valid {
			t.Fatalf("graph does not validate: %v", res.Errors)
		}
	})
}

func TestCollectAppModeNoInstalledOrg(t *testing.T) {
	_, c, _ := appFake(t, nil)
	_, err := Collect(context.Background(), appConfig(c, t, "acme-legacy"))
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectAppModeAllInstallations(t *testing.T) {
	_, c, _ := appFake(t, nil)
	g, err := Collect(context.Background(), appConfig(c, t))
	if err != nil {
		t.Fatal(err)
	}
	var orgs []string
	for _, n := range g.Nodes {
		if n.Kind == graph.KindOrg {
			orgs = append(orgs, n.ID)
		}
	}
	if !slices.Equal(orgs, []string{"org:acme-actions", "org:acme-app"}) {
		t.Errorf("orgs = %v", orgs)
	}
}

// TestReadOnlyGuard sends every write method to REST paths and checks that
// only the installation-token mint reaches the server.
func TestReadOnlyGuard(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		writeJSON(w, 201, map[string]any{"token": "x", "data": map[string]any{}})
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientOptions{BaseURL: srv.URL, Token: testToken, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		for _, p := range []string{"/repos/acme-app/web/contents/x", "/orgs/acme-app/members/bob", "/app/installations/1",
			"/app/installations/1/access_tokens/x", "/app/installations/abc/access_tokens", "/graphql/x"} {
			u, _ := c.resolve(p)
			if _, err := c.do(ctx, m, u, []byte("{}")); err == nil || !strings.Contains(err.Error(), "read-only") {
				t.Errorf("%s %s: err = %v, want refusal", m, p, err)
			}
		}
	}
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		u, _ := c.resolve("/app/installations/1/access_tokens")
		if _, err := c.do(ctx, m, u, nil); err == nil {
			t.Errorf("%s on the mint path was allowed", m)
		}
	}
	if _, err := c.GraphQL(ctx, "  mutation { addStar(input: {}) { clientMutationId } }", nil, nil); err == nil {
		t.Error("GraphQL mutation was allowed")
	}
	if _, err := c.GraphQL(ctx, "# c\nsubscription { x }", nil, nil); err == nil {
		t.Error("GraphQL subscription was allowed")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d refused requests reached the server", n)
	}
	// The allowlisted calls go out.
	if err := c.postJSON(ctx, "/app/installations/7/access_tokens", map[string]any{}, nil); err != nil {
		t.Errorf("mint POST refused: %v", err)
	}
	if _, err := c.GraphQL(ctx, "query { viewer { login } }", nil, nil); err != nil {
		t.Errorf("GraphQL query refused: %v", err)
	}
	if err := c.GetJSON(ctx, "/orgs/acme-app", nil); err != nil {
		t.Errorf("GET refused: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("allowed requests = %d, want 3", n)
	}
}

// TestAppErrorsCarryNoSecret: a failed mint and a failed installation list
// produce errors without the JWT, key or token.
func TestAppErrorsCarryNoSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"message": "A JSON web token could not be decoded"})
	}))
	t.Cleanup(srv.Close)
	c, err := newClient(ClientOptions{BaseURL: srv.URL, MaxAttempts: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Collect(context.Background(), appConfig(c, t, "acme-app"))
	if err == nil {
		t.Fatal("no error")
	}
	keyBody := strings.Split(string(appTestPEM(t)), "\n")[1]
	if strings.Contains(err.Error(), "eyJ") || strings.Contains(err.Error(), keyBody[:32]) || strings.Contains(err.Error(), "PRIVATE") {
		t.Errorf("error carries a secret: %v", err)
	}
	a, err := newAppAuth(Config{AppID: testAppID, AppPrivateKeyPEM: appTestPEM(t)}, c)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.mint(context.Background(), &appInstallation{id: 1, login: "acme-app"})
	if err == nil || strings.Contains(err.Error(), "eyJ") || !strings.Contains(err.Error(), "acme-app") {
		t.Errorf("mint err = %v", err)
	}
}

func TestAppPermissionFor(t *testing.T) {
	for path, want := range map[string]string{
		"/repos/acme-app/web/contents/.github/workflows":          "contents",
		"/repos/acme-app/web/collaborators?affiliation=direct":    "metadata",
		"/repos/acme-app/web/branches/main/protection":            "administration",
		"/repos/acme-app/web/branches/main":                       "metadata",
		"/repos/acme-app/web/actions/permissions/access":          "administration",
		"/orgs/acme-app/outside_collaborators":                    "members",
		"/orgs/acme-app/teams/release/members":                    "members",
		"/orgs/acme-app/actions/permissions/workflow":             "organization_administration",
		"/orgs/acme-app/custom-repository-roles":                  "organization_custom_roles",
		"/api/v3/repos/acme-app/web/contents/action.yml?ref=main": "contents",
		"/orgs/acme-app": "",
		"/user/42":       "",
	} {
		if got := appPermissionFor(path); got != want {
			t.Errorf("appPermissionFor(%q) = %q, want %q", path, got, want)
		}
	}
}
