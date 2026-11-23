package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// ghesFront serves the fake GitHub the way GitHub Enterprise Server does:
// REST under /api/v3, GraphQL at /api/graphql and the version at
// /api/v3/meta. It records the Host header and path of every request.
type ghesFront struct {
	f       *fakeGitHub
	srv     *httptest.Server
	version string // installed_version; "" makes /meta fail with 500
	mu      sync.Mutex
	hosts   []string
	paths   []string
}

func newGHESFront(t *testing.T, version string) *ghesFront {
	t.Helper()
	g := &ghesFront{f: newFakeGitHub(t), version: version}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *ghesFront) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.hosts = append(g.hosts, r.Host)
	g.paths = append(g.paths, r.Method+" "+r.URL.Path)
	g.mu.Unlock()
	switch {
	case r.URL.Path == "/api/v3/meta":
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
			return
		}
		if g.version == "" {
			writeJSON(w, 500, map[string]string{"message": "Server Error"})
			return
		}
		writeJSON(w, 200, map[string]any{"installed_version": g.version, "verifiable_password_authentication": true})
		return
	case r.URL.Path == "/api/graphql":
		r.URL.Path = "/graphql"
	case strings.HasPrefix(r.URL.Path, "/api/v3/"):
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/v3")
	default:
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
		return
	}
	// The fake writes Link headers on its own URL; rewrite them onto ours.
	rec := httptest.NewRecorder()
	g.f.serve(rec, r)
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if k == "Link" {
				v = strings.ReplaceAll(v, g.f.srv.URL, g.srv.URL+"/api/v3")
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (g *ghesFront) collect(t *testing.T) *graph.Graph {
	t.Helper()
	c, err := NewClient(ClientOptions{BaseURL: g.srv.URL + "/api/v3", GraphQLURL: g.srv.URL + "/api/graphql",
		Token: testToken, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	gr, err := Collect(context.Background(), Config{Enterprise: "acme", Client: c})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return gr
}

func (g *ghesFront) sawPath(sub string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range g.paths {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func TestGHESEndpointsAndHost(t *testing.T) {
	g := newGHESFront(t, "3.14.2")
	gr := g.collect(t)
	host := strings.TrimPrefix(g.srv.URL, "http://")

	g.mu.Lock()
	for i, h := range g.hosts {
		if h != host {
			t.Errorf("request %s went to host %q, want %q", g.paths[i], h, host)
		}
	}
	var rest, gql int
	for _, p := range g.paths {
		switch {
		case p == "POST /api/graphql":
			gql++
		case strings.HasPrefix(p, "GET /api/v3/"):
			rest++
		default:
			t.Errorf("request outside /api/v3 and /api/graphql: %s", p)
		}
	}
	g.mu.Unlock()
	if rest == 0 || gql == 0 {
		t.Fatalf("REST %d, GraphQL %d requests; want both", rest, gql)
	}

	ix := newIndex(gr)
	ent := ix.node(t, "enterprise:acme")
	if ent.Attrs[graph.AttrHost] != host || ent.Attrs[graph.AttrGHESVersion] != "3.14.2" {
		t.Errorf("enterprise attrs = %v", ent.Attrs)
	}
	if graph.Host(gr) != host {
		t.Errorf("graph.Host = %q", graph.Host(gr))
	}
	// 3.14 has every gated API but consumed licenses.
	if !g.sawPath("/actions/permissions/access") || !g.sawPath("/rules/branches/") {
		t.Error("actions access and branch rules should be read on GHES 3.14")
	}
	if g.sawPath("/consumed-licenses") {
		t.Error("consumed licenses are not available on GHES and should not be requested")
	}
	if c, ok := hasCoverage(gr, "enterprise:acme", graph.AttrMembers); !ok || !strings.Contains(c.Reason, "not available on GHES 3.14.2") {
		t.Errorf("members coverage = %+v, %v", c, ok)
	}
	if !g.sawPath("/orgs/acme-app/members") {
		t.Error("members should come from the org members API")
	}
	// An action owner that is not an org on the instance comes from github.com.
	found := false
	for _, n := range gr.Nodes {
		if n.Kind == graph.KindActionRef && n.Attrs[attrInEnterprise] == "false" {
			found = true
			if n.Attrs[attrSource] != graph.GitHubDotCom {
				t.Errorf("%s: source = %q, want github.com", n.ID, n.Attrs[attrSource])
			}
		}
		if n.Kind == graph.KindActionRef && n.Attrs[attrInEnterprise] == "true" && n.Attrs[attrSource] != "" {
			t.Errorf("%s: enterprise action has source %q", n.ID, n.Attrs[attrSource])
		}
	}
	if !found {
		t.Fatal("fixture has no action outside the enterprise")
	}
}

func TestGHESOldVersionSkipsCollectors(t *testing.T) {
	g := newGHESFront(t, "3.3.0")
	gr := g.collect(t) // the run succeeds
	if g.sawPath("/actions/permissions/access") {
		t.Error("actions access requested on GHES 3.3")
	}
	if g.sawPath("/rules/branches/") || g.sawPath("/rulesets") {
		t.Error("rulesets requested on GHES 3.3")
	}
	ix := newIndex(gr)
	var gated int
	for _, n := range gr.Nodes {
		if n.Kind != graph.KindRepo || n.Attrs[graph.AttrActionsAccess] == "" || n.Attrs[graph.AttrVisibility] == "public" {
			continue
		}
		gated++
		ev := n.Evidence
		if e, ok := n.AttrEvidence[graph.AttrActionsAccess]; ok {
			ev = e
		}
		if n.Attrs[graph.AttrActionsAccess] != graph.AccessUnknown || ev != graph.NotVisible {
			t.Errorf("%s actions_access = %q (%q)", n.ID, n.Attrs[graph.AttrActionsAccess], ev)
		}
		c, ok := hasCoverage(gr, n.ID, graph.AttrActionsAccess)
		if !ok || !strings.HasPrefix(c.Reason, "not available on GHES 3.3.0") || c.NeedsFix != "upgrade to GHES >= 3.4 or run as site admin" {
			t.Errorf("%s coverage = %+v", n.ID, c)
		}
	}
	if gated == 0 {
		t.Fatal("no non-public action host repo in the fixture")
	}
	c, ok := hasCoverage(gr, "enterprise:acme", capRulesets)
	if !ok || !strings.Contains(c.Reason, "needs GHES 3.11") || c.NeedsFix != "upgrade to GHES >= 3.11 or run as site admin" {
		t.Errorf("rulesets coverage = %+v, %v", c, ok)
	}
	// Classic protection is still read, so branch refs keep a live answer.
	for _, n := range gr.Nodes {
		if n.Kind == graph.KindActionRef && n.Attrs[graph.AttrRefKind] == "branch" && n.Attrs[attrInEnterprise] == "true" &&
			n.Attrs[graph.AttrRefProtected] == "" {
			t.Errorf("%s has no ref_protected", n.ID)
		}
	}
	if ix.node(t, "enterprise:acme").Attrs[graph.AttrGHESVersion] != "3.3.0" {
		t.Error("ghes_version not recorded")
	}
}

func TestGHESBelowEnterpriseSettings(t *testing.T) {
	g := newGHESFront(t, "2.22.5")
	gr := g.collect(t)
	ix := newIndex(gr)
	org := ix.node(t, "org:acme-app")
	for _, spec := range settingSpecs {
		if org.Attrs[spec.attr] != "unknown" || org.AttrEvidence[spec.attr] != graph.NotVisible {
			t.Errorf("%s = %q (%q), want unknown not_visible", spec.attr, org.Attrs[spec.attr], org.AttrEvidence[spec.attr])
		}
		if c, ok := hasCoverage(gr, "enterprise:acme", spec.attr); !ok || !strings.Contains(c.Reason, "not available on GHES 2.22.5") {
			t.Errorf("%s coverage = %+v, %v", spec.attr, c, ok)
		}
	}
}

func TestGHESUnknownVersionRunsEverything(t *testing.T) {
	g := newGHESFront(t, "")
	gr := g.collect(t)
	ent := newIndex(gr).node(t, "enterprise:acme")
	if ent.Attrs[graph.AttrGHESVersion] != "unknown" || ent.AttrEvidence[graph.AttrGHESVersion] != graph.NotVisible {
		t.Errorf("ghes_version = %q (%q)", ent.Attrs[graph.AttrGHESVersion], ent.AttrEvidence[graph.AttrGHESVersion])
	}
	if _, ok := hasCoverage(gr, "enterprise:acme", graph.AttrGHESVersion); !ok {
		t.Error("missing ghes_version coverage")
	}
	if !g.sawPath("/actions/permissions/access") || !g.sawPath("/consumed-licenses") {
		t.Error("with an unknown version every collector should run")
	}
}

func TestGitHubDotComRecordsHostWithoutMeta(t *testing.T) {
	_, ix := collectAcme(t)
	ent := ix.node(t, "enterprise:acme")
	if ent.Attrs[graph.AttrHost] != graph.GitHubDotCom {
		t.Errorf("host = %q", ent.Attrs[graph.AttrHost])
	}
	if _, ok := ent.Attrs[graph.AttrGHESVersion]; ok {
		t.Error("ghes_version set on github.com")
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"":                                 "github.com",
		"https://api.github.com":           "github.com",
		"https://api.github.com/":          "github.com",
		"https://GHES.example/api/v3":      "ghes.example",
		"https://ghes.example/api/v3/":     "ghes.example",
		"http://127.0.0.1:8080/api/v3":     "127.0.0.1:8080",
		"https://proxy.example/github":     "github.com",
		"http://127.0.0.1:8080":            "github.com",
		"https://ghes.example:8443/api/v3": "ghes.example:8443",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
	if h := (Config{Host: "GHES.Example", BaseURL: "https://proxy.example"}).host(); h != "ghes.example" {
		t.Errorf("Config.Host override = %q", h)
	}
}

func TestVersionBelow(t *testing.T) {
	for _, tc := range []struct {
		have, min string
		want      bool
	}{
		{"3.3.0", "3.4", true},
		{"3.4.0", "3.4", false},
		{"3.10.1", "3.11", true},
		{"3.11", "3.11", false},
		{"3.14.2", "3.4", false},
		{"2.22.5", "3.0", true},
		{"4.0.0", "3.11", false},
		{"", "3.4", false},
		{"garbage", "3.4", false},
	} {
		if got := versionBelow(tc.have, tc.min); got != tc.want {
			t.Errorf("versionBelow(%q, %q) = %v, want %v", tc.have, tc.min, got, tc.want)
		}
	}
}

func TestGHESCapabilityTable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range ghesCapabilities {
		if seen[c.key] {
			t.Errorf("duplicate capability %s", c.key)
		}
		seen[c.key] = true
		if c.collector == "" {
			t.Errorf("%s: no collector", c.key)
		}
		if c.min != "" {
			if _, _, ok := parseVersion(c.min); !ok {
				t.Errorf("%s: bad min %q", c.key, c.min)
			}
		}
	}
	for _, k := range []string{capEnterpriseSettings, capConsumedLicenses, capActionsAccess, capRulesets} {
		if !seen[k] {
			t.Errorf("capability %s missing from the table", k)
		}
	}
}

// TestTokenStaysOnHost: the token reaches only the configured host, also
// across redirects to another host, while same-host redirects keep it.
func TestTokenStaysOnHost(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			mu.Lock()
			leaked = append(leaked, r.URL.Path)
			mu.Unlock()
		}
		writeJSON(w, 200, map[string]string{"ok": "other"})
	}))
	defer other.Close()
	var apiHosts []string
	var api *httptest.Server
	api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		apiHosts = append(apiHosts, r.Host)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v3/cross":
			http.Redirect(w, r, other.URL+"/landing", http.StatusFound)
		case "/api/v3/moved":
			http.Redirect(w, r, api.URL+"/api/v3/here", http.StatusMovedPermanently)
		case "/api/v3/here":
			if r.Header.Get("Authorization") != "Bearer "+testToken {
				writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
				return
			}
			writeJSON(w, 200, map[string]string{"ok": "here"})
		default:
			writeJSON(w, 404, map[string]string{"message": "Not Found"})
		}
	}))
	defer api.Close()
	c, err := NewClient(ClientOptions{BaseURL: api.URL + "/api/v3", Token: testToken, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := c.GetJSON(context.Background(), "/cross", &out); err != nil || out["ok"] != "other" {
		t.Fatalf("cross-host redirect: %v %v", out, err)
	}
	if err := c.GetJSON(context.Background(), "/moved", &out); err != nil || out["ok"] != "here" {
		t.Fatalf("same-host redirect: %v %v", out, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leaked) > 0 {
		t.Errorf("Authorization sent to another host on %v", leaked)
	}
	want := strings.TrimPrefix(api.URL, "http://")
	for _, h := range apiHosts {
		if h != want {
			t.Errorf("API request with Host %q, want %q", h, want)
		}
	}
}

// TestRedirectGuardSubdomain: net/http keeps Authorization on a redirect to
// a subdomain; the guard strips it.
func TestRedirectGuardSubdomain(t *testing.T) {
	base, err := url.Parse("https://ghes.example/api/v3")
	if err != nil {
		t.Fatal(err)
	}
	hc := withRedirectGuard(&http.Client{}, base, "https://ghes.example/api/graphql")
	req, _ := http.NewRequest(http.MethodGet, "https://evil.ghes.example/x", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	prev, _ := http.NewRequest(http.MethodGet, "https://ghes.example/api/v3/x", nil)
	if err := hc.CheckRedirect(req, []*http.Request{prev}); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("Authorization kept on a redirect to a subdomain")
	}
	down, _ := http.NewRequest(http.MethodGet, "http://ghes.example/api/v3/x", nil)
	down.Header.Set("Authorization", "Bearer "+testToken)
	if err := hc.CheckRedirect(down, []*http.Request{prev}); err != nil {
		t.Fatal(err)
	}
	if down.Header.Get("Authorization") != "" {
		t.Error("Authorization kept on an https to http downgrade")
	}
	same, _ := http.NewRequest(http.MethodGet, "https://ghes.example/api/graphql", nil)
	same.Header.Set("Authorization", "Bearer "+testToken)
	_ = hc.CheckRedirect(same, []*http.Request{prev})
	if same.Header.Get("Authorization") == "" {
		t.Error("Authorization stripped on a same-host redirect")
	}
	many := make([]*http.Request, maxRedirects)
	if err := hc.CheckRedirect(same, many); err == nil {
		t.Error("no redirect limit")
	}
}
