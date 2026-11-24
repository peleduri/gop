package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// doctorNow is the fixed clock for estimates; rate limits reset 30 minutes later.
var doctorNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

const ssoHeaderSecret = "required; url=https://github.example/orgs/acme-legacy/sso?authorization_request=SYNTHETICREQUESTID"

// doctorFake is a configurable fake GitHub for gop doctor.
type doctorFake struct {
	token        string
	scopes       *string // X-OAuth-Scopes; nil means no header (fine-grained or App)
	expiry       string
	owner        bool     // ownerInfo readable
	entVisible   bool     // enterprise(slug) returns non-null
	orgs         []string // enterprise orgs, and /user/orgs
	ssoOrgs      map[string]bool
	repos        map[string]int
	installRepos []string // full names served by /installation/repositories
	partialSSO   string   // X-GitHub-SSO on /user/orgs
	coreLeft     int
	// notOwned are orgs the token user does not own: the enterprise query
	// says so and /orgs/{org}/memberships/{user} is 404. gqlRepos, when
	// set, is the enterprise query's repositories totalCount per org.
	notOwned map[string]bool
	gqlRepos map[string]int

	mu   sync.Mutex
	hits []string
}

func strp(s string) *string { return &s }

func ownerFake() *doctorFake {
	return &doctorFake{
		token:      "ghp_synthetic0owner",
		scopes:     strp("repo, read:org, read:enterprise, read:audit_log"),
		expiry:     "2027-02-01 00:00:00 UTC",
		owner:      true,
		entVisible: true,
		orgs:       []string{"acme", "acme-actions", "acme-app"},
		repos:      map[string]int{"acme": 12, "acme-actions": 5, "acme-app": 30},
		coreLeft:   4990,
	}
}

func (f *doctorFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits = append(f.hits, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
			return
		}
		installation := strings.HasPrefix(f.token, "ghs_")
		p := r.URL.Path
		switch {
		case p == "/user" && installation:
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
		case p == "/user":
			if f.scopes != nil {
				w.Header().Set("X-OAuth-Scopes", *f.scopes)
			}
			if f.expiry != "" {
				w.Header().Set("GitHub-Authentication-Token-Expiration", f.expiry)
			}
			writeJSON(w, 200, map[string]any{"login": "alice"})
		case p == "/installation/repositories" && installation:
			var repos []map[string]any
			for _, full := range f.installRepos {
				owner, _, _ := strings.Cut(full, "/")
				repos = append(repos, map[string]any{"full_name": full, "owner": map[string]any{"login": owner}})
			}
			writeJSON(w, 200, map[string]any{"total_count": len(repos), "repositories": repos})
		case p == "/user/orgs" && !installation:
			if f.partialSSO != "" {
				w.Header().Set("X-GitHub-SSO", f.partialSSO)
			}
			var out []map[string]any
			for _, o := range f.orgs {
				out = append(out, map[string]any{"login": o})
			}
			writeJSON(w, 200, out)
		case strings.HasPrefix(p, "/orgs/") && strings.Contains(p, "/memberships/"):
			org, _, _ := strings.Cut(strings.TrimPrefix(p, "/orgs/"), "/")
			if f.notOwned[org] {
				writeJSON(w, 404, map[string]string{"message": "Not Found"})
				return
			}
			writeJSON(w, 200, map[string]any{"role": "admin", "state": "active"})
		case strings.HasPrefix(p, "/orgs/"):
			org := strings.TrimPrefix(p, "/orgs/")
			if f.ssoOrgs[org] {
				w.Header().Set("X-GitHub-SSO", ssoHeaderSecret)
				writeJSON(w, 403, map[string]string{"message": "Resource protected by organization SAML enforcement."})
				return
			}
			n, ok := f.repos[org]
			if !ok {
				writeJSON(w, 404, map[string]string{"message": "Not Found"})
				return
			}
			public := min(n, 2)
			body := map[string]any{"login": org, "public_repos": public}
			switch {
			case installation:
				body["public_repos"] = n
			case !f.notOwned[org]:
				// GitHub returns total_private_repos to org owners only.
				body["total_private_repos"] = n - public
			}
			writeJSON(w, 200, body)
		case p == "/rate_limit":
			reset := doctorNow.Add(30 * time.Minute).Unix()
			writeJSON(w, 200, map[string]any{"resources": map[string]any{
				"core":    map[string]any{"limit": 5000, "remaining": f.coreLeft, "reset": reset},
				"graphql": map[string]any{"limit": 5000, "remaining": 4999, "reset": reset},
			}})
		case p == "/graphql":
			var ent any
			if f.entVisible {
				nodes := []map[string]any{}
				for _, o := range f.orgs {
					n := map[string]any{"login": o, "viewerCanAdminister": !f.notOwned[o], "viewerIsAMember": !f.notOwned[o]}
					if c, ok := f.gqlRepos[o]; ok {
						n["repositories"] = map[string]any{"totalCount": c}
					}
					nodes = append(nodes, n)
				}
				var oi any
				if f.owner {
					oi = map[string]any{"admins": map[string]any{"totalCount": 1}}
				}
				ent = map[string]any{"slug": "acme", "ownerInfo": oi,
					"organizations": map[string]any{"totalCount": len(f.orgs), "nodes": nodes}}
			}
			resp := map[string]any{"data": map[string]any{"enterprise": ent}}
			if !f.entVisible {
				resp["errors"] = []map[string]any{{"type": "FORBIDDEN", "path": []string{"enterprise"}, "message": "must be an enterprise owner"}}
			}
			writeJSON(w, 200, resp)
		default:
			writeJSON(w, 404, map[string]string{"message": "Not Found"})
		}
	}
}

// readOnlyTransport fails the test on any request that is not a GET or a
// GraphQL query (no mutations).
type readOnlyTransport struct {
	errorf func(format string, args ...any)
	base   http.RoundTripper
}

func (rt readOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case r.Method == http.MethodGet:
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/graphql"):
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		var q struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(body, &q); err != nil || !strings.HasPrefix(strings.TrimSpace(q.Query), "query") {
			rt.errorf("non-query GraphQL request: %s", body)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	default:
		rt.errorf("non-read request: %s %s", r.Method, r.URL.Path)
	}
	return rt.base.RoundTrip(r)
}

func runDoctor(t *testing.T, f *doctorFake, orgs ...string) (*DoctorReport, string) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientOptions{BaseURL: srv.URL, Token: f.token, MaxAttempts: 1,
		HTTPClient: &http.Client{Transport: readOnlyTransport{t.Errorf, http.DefaultTransport}}})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Doctor(context.Background(), DoctorConfig{Enterprise: "acme", Token: f.token, Orgs: orgs, Client: c,
		Now: func() time.Time { return doctorNow }})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteDoctor(&b, rep); err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(rep)
	for _, out := range []string{b.String(), string(js)} {
		if strings.Contains(out, f.token) || strings.Contains(out, "SYNTHETICREQUESTID") {
			t.Fatalf("output leaks the token or a header value:\n%s", out)
		}
	}
	return rep, b.String()
}

func findCheck(r *DoctorReport, name string) *DoctorCheck {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			return &r.Checks[i]
		}
	}
	return nil
}

func TestDoctorOwnerAllPass(t *testing.T) {
	rep, out := runDoctor(t, ownerFake())
	if rep.Mode != ModeOwner || rep.Token.Kind != KindClassicPAT || rep.Token.Login != "alice" {
		t.Fatalf("mode %q kind %q login %q", rep.Mode, rep.Token.Kind, rep.Token.Login)
	}
	if f, w := rep.Counts(); f != 0 || w != 0 {
		t.Fatalf("want all pass, got %d fails %d warns:\n%s", f, w, out)
	}
	if len(rep.NotVisible) != 0 || len(rep.Predicted) != 0 {
		t.Fatalf("not_visible: %v predicted: %v", rep.NotVisible, rep.Predicted)
	}
	e := rep.Estimate
	if e == nil || e.Orgs != 3 || e.Repos != 47 || e.Requests == 0 || e.RateLimitWaits != 0 {
		t.Fatalf("estimate: %+v", e)
	}
	if !strings.Contains(out, "Result: all checks pass") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestDoctorInstallationToken(t *testing.T) {
	f := &doctorFake{
		token:        "ghs_synthetic0app",
		orgs:         []string{"acme-actions", "acme-app"},
		repos:        map[string]int{"acme-actions": 5, "acme-app": 30},
		installRepos: []string{"acme-actions/deploy", "acme-app/web", "acme-app/api"},
		coreLeft:     4990,
	}
	rep, _ := runDoctor(t, f)
	if rep.Mode != ModePerOrg || rep.Token.Kind != KindInstallation {
		t.Fatalf("mode %q kind %q", rep.Mode, rep.Token.Kind)
	}
	if c := findCheck(rep, "enterprise"); c == nil || c.Status != StatusWarn {
		t.Fatalf("enterprise check: %+v", c)
	}
	if len(rep.NotVisible) == 0 || !strings.Contains(rep.NotVisible[0], "enterprise settings") {
		t.Fatalf("not_visible: %v", rep.NotVisible)
	}
	if len(rep.Orgs) != 2 || rep.Orgs[0].Login != "acme-actions" {
		t.Fatalf("orgs from installation repositories: %+v", rep.Orgs)
	}
	for _, h := range f.hits {
		if h == "GET /user/orgs" {
			t.Errorf("installation token must not list /user/orgs")
		}
	}
}

func TestDoctorOneRepoToken(t *testing.T) {
	f := &doctorFake{token: "ghs_synthetic0repo", installRepos: []string{"acme-app/web"}, coreLeft: 900}
	rep, _ := runDoctor(t, f)
	if rep.Mode != ModeOneRepo {
		t.Fatalf("mode %q", rep.Mode)
	}
	if fails, _ := rep.Counts(); fails == 0 {
		t.Fatalf("mode (c) must fail: %+v", rep.Checks)
	}
	if rep.Estimate != nil {
		t.Fatalf("no estimate in mode (c)")
	}
}

func TestDoctorMissingAuditLog(t *testing.T) {
	f := ownerFake()
	f.scopes = strp("repo, read:org, read:enterprise")
	rep, _ := runDoctor(t, f)
	c := findCheck(rep, "scope read:audit_log")
	if c == nil || c.Status != StatusWarn || c.Fix != "add the read:audit_log scope to the token" {
		t.Fatalf("audit log check: %+v", c)
	}
	if fails, warns := rep.Counts(); fails != 0 || warns != 1 {
		t.Fatalf("want 1 warning, got %d fails %d warns", fails, warns)
	}
}

func TestDoctorSSOUnauthorizedOrg(t *testing.T) {
	f := ownerFake()
	f.orgs = append(f.orgs, "acme-legacy")
	f.ssoOrgs = map[string]bool{"acme-legacy": true}
	rep, out := runDoctor(t, f)
	c := findCheck(rep, "sso acme-legacy")
	if c == nil || c.Status != StatusFail || !strings.Contains(c.Fix, "authorize this token for SSO in acme-legacy") {
		t.Fatalf("sso check: %+v\n%s", c, out)
	}
	if rep.Orgs[3].Status != "sso_unauthorized" {
		t.Fatalf("org status: %+v", rep.Orgs[3])
	}
}

func TestDoctorWriteScopesNoExpiry(t *testing.T) {
	f := ownerFake()
	f.scopes = strp("repo, admin:org, read:enterprise, read:audit_log, delete_repo")
	f.expiry = ""
	rep, _ := runDoctor(t, f)
	if c := findCheck(rep, "write scopes"); c == nil || c.Status != StatusWarn || c.Detail != "broader than gop needs: admin:org, delete_repo" {
		t.Fatalf("write scopes: %+v", c)
	}
	if c := findCheck(rep, "scope read:org"); c == nil || c.Status != StatusPass {
		t.Fatalf("admin:org implies read:org: %+v", c)
	}
	if c := findCheck(rep, "expiry"); c == nil || c.Status != StatusWarn {
		t.Fatalf("expiry: %+v", c)
	}
}

func TestDoctorNonOwnerPartialSSO(t *testing.T) {
	f := ownerFake()
	f.owner, f.entVisible = false, false
	f.scopes = strp("repo, read:org")
	f.partialSSO = "partial-results; organizations=1001,1002"
	rep, _ := runDoctor(t, f)
	if rep.Mode != ModePerOrg {
		t.Fatalf("mode %q", rep.Mode)
	}
	if c := findCheck(rep, "sso hidden orgs"); c == nil || c.Status != StatusFail || !strings.HasPrefix(c.Detail, "2 organizations") {
		t.Fatalf("partial sso: %+v", c)
	}
	if c := findCheck(rep, "scope read:enterprise"); c == nil || c.Status != StatusWarn {
		t.Fatalf("read:enterprise: %+v", c)
	}
}

func TestDoctorRateLimitShort(t *testing.T) {
	f := ownerFake()
	f.coreLeft = 10
	rep, _ := runDoctor(t, f)
	c := findCheck(rep, "rate limit")
	if c == nil || c.Status != StatusWarn || rep.Estimate.RateLimitWaits != 1 || rep.Estimate.Minutes < 30 {
		t.Fatalf("rate limit: %+v %+v", c, rep.Estimate)
	}
}

func TestDoctorBadToken(t *testing.T) {
	f := ownerFake()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientOptions{BaseURL: srv.URL, Token: "ghp_synthetic0wrong", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Doctor(context.Background(), DoctorConfig{Enterprise: "acme", Token: "ghp_synthetic0wrong", Client: c})
	if err != nil {
		t.Fatal(err)
	}
	if fails, _ := rep.Counts(); fails != 1 || rep.Mode != ModeUnknown || len(f.hits) != 1 {
		t.Fatalf("bad token: %+v hits %v", rep.Checks, f.hits)
	}
}

func TestReadOnlyTransportCatchesWrites(t *testing.T) {
	rt := readOnlyTransport{nil, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPatch, "https://api.github.example/orgs/acme", nil),
		httptest.NewRequest(http.MethodPost, "https://api.github.example/graphql", strings.NewReader(`{"query":"mutation { x }"}`)),
	} {
		flagged := false
		rt.errorf = func(string, ...any) { flagged = true }
		resp, _ := rt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !flagged {
			t.Errorf("%s %s was not flagged", req.Method, req.URL.Path)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTokenKind(t *testing.T) {
	for tok, want := range map[string]string{
		"ghp_x": KindClassicPAT, "github_pat_x": KindFineGrainedPAT, "gho_x": KindOAuth,
		"ghu_x": KindAppUser, "ghs_x": KindInstallation, "x": KindUnknown,
	} {
		if got := TokenKind(tok); got != want {
			t.Errorf("%s: %s, want %s", tok, got, want)
		}
	}
}

// predictedVsCollected runs gop doctor and gop collect against the same fake
// and returns, per org scope, the coverage entries doctor predicted and the
// ones collect recorded.
func predictedVsCollected(t *testing.T, f *fakeGitHub) (*DoctorReport, string, map[string][]PredictedCoverage, map[string][]PredictedCoverage) {
	t.Helper()
	rep, err := Doctor(context.Background(), DoctorConfig{Enterprise: "acme", Token: testToken, Client: f.client(t),
		Now: func() time.Time { return doctorNow }})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteDoctor(&b, rep); err != nil {
		t.Fatal(err)
	}
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), DisableGraphQLBatch: true})
	if err != nil {
		t.Fatal(err)
	}
	predicted := map[string][]PredictedCoverage{}
	for _, p := range rep.Predicted {
		predicted[p.Scope] = append(predicted[p.Scope], p)
	}
	collected := map[string][]PredictedCoverage{}
	for _, c := range g.Coverage {
		if strings.HasPrefix(c.Scope, "org:") {
			collected[c.Scope] = append(collected[c.Scope], PredictedCoverage{Scope: c.Scope, Fact: c.Fact, NeedsFix: c.NeedsFix})
		}
	}
	return rep, b.String(), predicted, collected
}

func coverageSet(cs []PredictedCoverage) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.Fact+" | "+c.NeedsFix] = true
	}
	return out
}

func assertSameCoverage(t *testing.T, scope string, predicted, collected map[string][]PredictedCoverage) {
	t.Helper()
	p, c := coverageSet(predicted[scope]), coverageSet(collected[scope])
	if len(p) == 0 {
		t.Fatalf("%s: nothing predicted; collect recorded %v", scope, c)
	}
	for k := range c {
		if !p[k] {
			t.Errorf("%s: collect recorded %q, doctor did not predict it", scope, k)
		}
	}
	for k := range p {
		if !c[k] {
			t.Errorf("%s: doctor predicted %q, collect did not record it", scope, k)
		}
	}
}

// An enterprise-owner token that is not a member of acme-legacy: doctor
// predicts exactly the org coverage collect records there, takes the repo
// count from the enterprise GraphQL query and predicts nothing for owned orgs.
func TestDoctorPredictsCollectCoverageForNotOwnedOrg(t *testing.T) {
	f := newFakeGitHub(t)
	f.gqlRepoTotals = map[string]int{"acme-legacy": 28}
	rep, out, predicted, collected := predictedVsCollected(t, f)
	if rep.Mode != ModeOwner {
		t.Fatalf("mode %q", rep.Mode)
	}
	assertSameCoverage(t, "org:acme-legacy", predicted, collected)
	for scope := range predicted {
		if scope != "org:acme-legacy" {
			t.Errorf("prediction for an owned org: %s %v", scope, predicted[scope])
		}
	}
	var legacy *DoctorOrg
	for i := range rep.Orgs {
		if rep.Orgs[i].Login == "acme-legacy" {
			legacy = &rep.Orgs[i]
		}
		if o := rep.Orgs[i]; o.Login != "acme-legacy" && o.Status == "ok" && o.Role != RoleOwner {
			t.Errorf("org %s role %q, want owner", o.Login, o.Role)
		}
	}
	if legacy == nil || legacy.Role != RoleNone || legacy.Repos == nil || *legacy.Repos != 28 ||
		legacy.ReposSource != ReposVisible || !legacy.ReposLowerBound {
		t.Fatalf("acme-legacy: %+v", legacy)
	}
	fix := "org owner on acme-legacy (SSO enforced: join through the identity provider first)"
	if c := findCheck(rep, "owner acme-legacy"); c == nil || c.Status != StatusWarn || c.Fix != fix ||
		!strings.Contains(c.Detail, "at least 28 visible to this token") {
		t.Fatalf("owner check: %+v", c)
	}
	for _, want := range []string{"fix: " + fix, "(enterprise GraphQL and visible-to-token counts)",
		"org acme-legacy: ip_allow_list, app_installations, repositories, outside_collaborators, can_push:collaborators, secret_scanning, can_push:teams (token is not an org owner)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "nothing predicted") {
		t.Errorf("output says nothing predicted:\n%s", out)
	}
}

// Per-org mode (no enterprise access): roles come from the memberships API,
// and the prediction still matches collect, default permission included.
func TestDoctorPredictsCollectCoveragePerOrg(t *testing.T) {
	f := newFakeGitHub(t)
	f.enterpriseForbidden = true
	f.pageSize = 100
	rep, out, predicted, collected := predictedVsCollected(t, f)
	if rep.Mode != ModePerOrg {
		t.Fatalf("mode %q", rep.Mode)
	}
	assertSameCoverage(t, "org:acme-legacy", predicted, collected)
	if len(predicted) != 1 {
		t.Errorf("predictions for owned orgs: %v", predicted)
	}
	if c := findCheck(rep, "owner acme-legacy"); c == nil || c.Fix != "org owner on acme-legacy" {
		t.Fatalf("owner check: %+v\n%s", c, out)
	}
}

// A REST repository count read by a token that does not own the org is
// flagged as a lower bound.
func TestDoctorNotOwnedRESTCountIsLowerBound(t *testing.T) {
	f := ownerFake()
	f.notOwned = map[string]bool{"acme-actions": true}
	rep, out := runDoctor(t, f)
	var o DoctorOrg
	for _, x := range rep.Orgs {
		if x.Login == "acme-actions" {
			o = x
		}
	}
	if o.Role != RoleNone || !o.ReposLowerBound || o.ReposSource != ReposVisible || o.Repos == nil || *o.Repos != 2 {
		t.Fatalf("acme-actions: %+v", o)
	}
	if rep.Estimate == nil || rep.Estimate.ReposLowerBound != 1 {
		t.Fatalf("estimate: %+v", rep.Estimate)
	}
	for _, want := range []string{"(at least 2 visible to this token; the real total needs org owner)",
		"the repo count and the request estimate are lower bounds: 1 org not owned"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, warns := rep.Counts(); warns != 1 {
		t.Errorf("want 1 warning (owner acme-actions), got %d:\n%s", warns, out)
	}
}

// The enterprise GraphQL totalCount counts only what the token can see: for
// an org the token is not a member of it can be 0 although the org has public
// repositories and hidden private ones. Doctor reports public_repos as a lower
// bound and never says the org has 0; an owned org keeps its exact count.
func TestDoctorNotMemberGraphQLZeroIsLowerBound(t *testing.T) {
	f := ownerFake()
	f.notOwned = map[string]bool{"acme-actions": true}
	f.repos["acme-actions"] = 40 // 2 public, 38 private the token cannot see
	f.gqlRepos = map[string]int{"acme": 12, "acme-actions": 0}
	rep, out := runDoctor(t, f)
	orgs := map[string]DoctorOrg{}
	for _, o := range rep.Orgs {
		orgs[o.Login] = o
	}
	if o := orgs["acme-actions"]; o.Repos == nil || *o.Repos != 2 || !o.ReposLowerBound || o.ReposSource != ReposVisible {
		t.Fatalf("acme-actions: %+v", o)
	}
	if o := orgs["acme"]; o.Repos == nil || *o.Repos != 12 || o.ReposLowerBound || o.ReposSource != ReposGraphQL {
		t.Fatalf("acme (owned): %+v", o)
	}
	if c := findCheck(rep, "owner acme-actions"); c == nil || !strings.Contains(c.Detail, "at least 2 visible to this token") {
		t.Fatalf("owner check: %+v", c)
	}
	if strings.Contains(out, "has 0") {
		t.Errorf("output claims an empty org:\n%s", out)
	}
	js, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"login":"acme-actions","status":"ok","repos":2,"repos_source":"visible_to_token","repos_lower_bound":true,"role":"none"}`; !strings.Contains(string(js), want) {
		t.Errorf("JSON lacks %s:\n%s", want, js)
	}
}

// A non-member org with no repository visible to the token reports the
// repo count as unknown, not as 0, and still flags it as a lower bound.
func TestDoctorNotMemberNothingVisibleIsUnknown(t *testing.T) {
	f := ownerFake()
	f.notOwned = map[string]bool{"acme-actions": true}
	f.repos["acme-actions"] = 0
	f.gqlRepos = map[string]int{"acme-actions": 0}
	rep, out := runDoctor(t, f)
	c := findCheck(rep, "owner acme-actions")
	if c == nil || !strings.Contains(c.Detail, "repo count unknown: none visible to this token") || strings.Contains(out, "has 0") {
		t.Fatalf("owner check: %+v\n%s", c, out)
	}
	for _, o := range rep.Orgs {
		if o.Login == "acme-actions" && (!o.ReposLowerBound || o.ReposSource != ReposVisible) {
			t.Fatalf("acme-actions: %+v", o)
		}
	}
}
