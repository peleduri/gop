package collect

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// This file holds GitHub App mode: gop signs an App JWT, lists the App's
// installations, and mints one read-only installation token per org. Each
// org's requests carry that org's token, so one run covers every org the App
// is installed on and cross-org paths still join.
//
// The App private key is parsed once and held in memory only. It is never
// logged, printed, written or put in an error. Installation tokens are
// treated the same way.

// DefaultAppPermissions are the permissions requested for every installation
// token. Requesting explicit read permissions down-scopes the token even when
// the App was granted more.
var DefaultAppPermissions = map[string]string{
	"metadata":                    "read",
	"contents":                    "read",
	"members":                     "read",
	"administration":              "read",
	"actions":                     "read",
	"organization_administration": "read",
}

const (
	// appJWTBackdate and appJWTLifetime follow GitHub's guidance: iat 60s in
	// the past for clock drift, exp at most 10 minutes ahead.
	appJWTBackdate = 60 * time.Second
	appJWTLifetime = 9 * time.Minute
	// appTokenRefresh re-mints an installation token when less than this remains.
	appTokenRefresh = 5 * time.Minute

	srcAppInstalls = "rest:GET /app/installations"
)

// appMode reports whether cfg selects GitHub App authentication.
func (cfg Config) appMode() bool { return cfg.AppID != 0 || len(cfg.AppPrivateKeyPEM) > 0 }

// validateAuth checks that exactly one authentication mode is configured.
func (cfg Config) validateAuth() error {
	if !cfg.appMode() {
		return nil
	}
	if cfg.Token != "" {
		return errors.New("collect: a token and GitHub App credentials are mutually exclusive; set one")
	}
	if cfg.AppID <= 0 {
		return errors.New("collect: GitHub App mode needs the App ID")
	}
	if len(cfg.AppPrivateKeyPEM) == 0 {
		return errors.New("collect: GitHub App mode needs the App private key")
	}
	for p, v := range cfg.AppPermissions {
		if v != "read" {
			return fmt.Errorf("collect: GitHub App permission %q must be \"read\": gop only requests read-only tokens", p)
		}
	}
	return nil
}

// parseAppKey parses a PEM RSA private key (PKCS#1 or PKCS#8). Errors never
// include key material.
func parseAppKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("collect: GitHub App private key is not PEM encoded")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("collect: GitHub App private key: invalid PKCS#1 RSA key")
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("collect: GitHub App private key: invalid PKCS#8 key")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("collect: GitHub App private key is not an RSA key")
		}
		return rk, nil
	}
	return nil, fmt.Errorf("collect: GitHub App private key: unsupported PEM block %q", block.Type)
}

// signAppJWT builds an RS256 JWT for the App: iat = now-60s, exp = now+9m, iss = appID.
func signAppJWT(key *rsa.PrivateKey, appID int64, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(struct {
		IAT int64 `json:"iat"`
		EXP int64 `json:"exp"`
		ISS int64 `json:"iss"`
	}{now.Add(-appJWTBackdate).Unix(), now.Add(appJWTLifetime).Unix(), appID})
	if err != nil {
		return "", err
	}
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("collect: signing GitHub App JWT failed")
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// appInstallation is one org installation of the App and its current token.
type appInstallation struct {
	id        int64
	login     string
	suspended bool
	// perms are the permissions the installation is granted, as listed by
	// GET /app/installations (nil when the listing omits them).
	perms map[string]string

	mu      sync.Mutex
	token   string
	expires time.Time
	client  *Client
}

// appAuth mints and caches installation tokens for one collection run.
type appAuth struct {
	id    int64
	key   *rsa.PrivateKey
	perms map[string]string
	base  *Client // transport, retry settings and clock
	jwt   *Client // JWT-authenticated, limited to /app/*

	installs map[string]*appInstallation // lower account login -> installation
	fallback *Client                     // for content reads of orgs without an installation
	// listed is set once installs holds GET /app/installations, so the
	// sequential pass after a parallel prefetch does not list them again.
	listed bool
	// memo, when set, gives every installation client a response memo
	// (parallel.go): org workers record responses and the sequential pass
	// replays them.
	memo bool
}

func newAppAuth(cfg Config, base *Client) (*appAuth, error) {
	key, err := parseAppKey(cfg.AppPrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	perms := cfg.AppPermissions
	if len(perms) == 0 {
		perms = DefaultAppPermissions
	}
	a := &appAuth{id: cfg.AppID, key: key, perms: perms, base: base, installs: map[string]*appInstallation{}}
	a.jwt = base.WithTokenSource(appJWTSource{a})
	a.jwt.onlyPrefix = base.base.Path + "/app/"
	return a, nil
}

// appJWTSource signs a fresh JWT for every request to /app/*.
type appJWTSource struct{ a *appAuth }

func (s appJWTSource) Token(context.Context) (string, error) {
	return signAppJWT(s.a.key, s.a.id, s.a.base.now())
}

// listInstallations reads GET /app/installations into a.installs.
func (a *appAuth) listInstallations(ctx context.Context) error {
	if a.listed {
		return nil
	}
	err := a.jwt.GetPages(ctx, "/app/installations?per_page=100", func(page []byte) error {
		var batch []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
			SuspendedAt *string           `json:"suspended_at"`
			Permissions map[string]string `json:"permissions"`
		}
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding app installations: %w", err)
		}
		for _, in := range batch {
			if in.ID == 0 || in.Account.Login == "" {
				continue
			}
			a.installs[strings.ToLower(in.Account.Login)] = &appInstallation{
				id: in.ID, login: in.Account.Login, suspended: in.SuspendedAt != nil && *in.SuspendedAt != "",
				perms: in.Permissions,
			}
		}
		return nil
	})
	a.listed = err == nil
	return err
}

// installation returns the usable (not suspended) installation for an account.
func (a *appAuth) installation(login string) (*appInstallation, bool) {
	in, ok := a.installs[strings.ToLower(login)]
	if !ok || in.suspended {
		return nil, false
	}
	return in, true
}

// logins returns the account logins of every usable installation, sorted.
func (a *appAuth) logins() []string {
	out := make([]string, 0, len(a.installs))
	for _, in := range a.installs {
		if !in.suspended {
			out = append(out, in.login)
		}
	}
	sort.Strings(out)
	return out
}

// client returns the client that authenticates as the account's installation.
func (a *appAuth) client(login string) (*Client, bool) {
	in, ok := a.installation(login)
	if !ok {
		return nil, false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.client == nil {
		in.client = a.base.WithTokenSource(installSource{a: a, in: in})
		// Each installation has its own hourly budget: track it, and pause
		// on its rate limits, apart from the other installations.
		in.client.rate = newInstallRateTracker()
		if a.memo {
			in.client.memo = newResponseMemo()
		}
	}
	return in.client, true
}

// installSource hands out an installation's token, minting it on first use
// and again whenever less than appTokenRefresh remains.
type installSource struct {
	a  *appAuth
	in *appInstallation
}

func (s installSource) Token(ctx context.Context) (string, error) {
	s.in.mu.Lock()
	defer s.in.mu.Unlock()
	if s.in.token != "" && s.in.expires.Sub(s.a.base.now()) >= appTokenRefresh {
		return s.in.token, nil
	}
	tok, exp, err := s.a.mint(ctx, s.in)
	if err != nil {
		return "", err
	}
	s.in.token, s.in.expires = tok, exp
	return tok, nil
}

// mint calls POST /app/installations/{id}/access_tokens, the only non-GET REST
// call gop makes, asking for read-only permissions. It refuses a token whose
// granted permissions include anything but read.
func (a *appAuth) mint(ctx context.Context, in *appInstallation) (string, time.Time, error) {
	var resp struct {
		Token       string            `json:"token"`
		ExpiresAt   time.Time         `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
	}
	path := "/app/installations/" + strconv.FormatInt(in.id, 10) + "/access_tokens"
	if err := a.jwt.postJSON(ctx, path, map[string]any{"permissions": a.perms}, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("minting installation token for %s: %w", in.login, err)
	}
	if resp.Token == "" {
		return "", time.Time{}, fmt.Errorf("minting installation token for %s: no token in the response", in.login)
	}
	for p, v := range resp.Permissions {
		if v != "read" {
			return "", time.Time{}, fmt.Errorf("minting installation token for %s: GitHub granted %s:%s; gop only accepts read-only tokens", in.login, p, v)
		}
	}
	a.base.logf("collect: minted read-only installation token for %s (expires %s)", in.login, resp.ExpiresAt.UTC().Format(time.RFC3339))
	return resp.Token, resp.ExpiresAt, nil
}

// noTokenSource is the token source of the collector's default client in App
// mode: every request must go through an org's installation client, so any
// request that reaches it fails instead of going out unauthenticated.
type noTokenSource struct{}

func (noTokenSource) Token(context.Context) (string, error) {
	return "", errors.New("collect: GitHub App mode: request has no org installation client")
}

// appPermissionFor names the GitHub App permission a REST path needs, or "".
func appPermissionFor(path string) string {
	path, _, _ = strings.Cut(path, "?")
	if i := strings.Index(path, "/repos/"); i >= 0 {
		segs := strings.Split(strings.Trim(path[i+len("/repos/"):], "/"), "/")
		if len(segs) < 3 {
			return "metadata"
		}
		switch segs[2] {
		case "contents":
			return "contents"
		case "actions":
			return "administration"
		case "branches":
			if segs[len(segs)-1] == "protection" {
				return "administration"
			}
			return "metadata"
		case "collaborators", "rules", "rulesets":
			return "metadata"
		}
		return ""
	}
	if i := strings.Index(path, "/orgs/"); i >= 0 {
		segs := strings.Split(strings.Trim(path[i+len("/orgs/"):], "/"), "/")
		if len(segs) < 2 {
			return ""
		}
		switch segs[1] {
		case "members", "teams", "outside_collaborators":
			return "members"
		case "actions":
			return "organization_administration"
		case "custom-repository-roles":
			return "organization_custom_roles"
		case "repos":
			return "metadata"
		}
	}
	return ""
}

// fixFor returns the coverage fix for err: in App mode a 403 on an endpoint
// names the App permission to grant; otherwise fix is returned unchanged.
func (k *collector) fixFor(err error, fix string) string {
	if k.app == nil || StatusOf(err) != 403 {
		return fix
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		return fix
	}
	if p := appPermissionFor(ae.Path); p != "" {
		return "grant the App " + p + ":read"
	}
	return fix
}

// cl returns the client for requests about an owner's resources: the owner's
// installation client in App mode, else the collector's client. Orgs without
// an installation fall back to a selected org's client, which can still read
// public content.
func (k *collector) cl(owner string) *Client {
	if k.app == nil {
		return k.c
	}
	if c, ok := k.app.client(owner); ok {
		return c
	}
	if k.app.fallback != nil {
		return k.app.fallback
	}
	return k.c
}

// collectOrgsApp replaces the enterprise org list in App mode. The App's
// installations seed the enterprise org set (so USES into any installed org
// resolve), and the orgs to collect are cfg.Orgs, else every installed org.
// A selected org without an installation is a not_visible org node with
// coverage naming the fix.
func (k *collector) collectOrgsApp(ctx context.Context) error {
	k.entHidden = true
	k.orgsSrc = srcAppInstalls
	k.cover("enterprise:"+k.enterprise, "enterprise", appEnterpriseReason, enterpriseFix)
	if err := k.app.listInstallations(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("collect: listing GitHub App installations: %w", err)
	}
	installed := k.app.logins()
	for _, l := range installed {
		k.entOrgs[strings.ToLower(l)] = l
	}

	logins := installed
	if len(k.cfg.Orgs) > 0 {
		logins = nil
		seen := map[string]bool{}
		for _, o := range k.cfg.Orgs {
			if !seen[strings.ToLower(o)] {
				seen[strings.ToLower(o)] = true
				logins = append(logins, o)
			}
		}
	}
	var selected []string
	for _, login := range logins {
		in, ok := k.app.installation(login)
		if !ok {
			k.coverNotInstalled(login)
			continue
		}
		selected = append(selected, in.login)
	}
	if len(selected) == 0 {
		return errors.New("collect: the GitHub App is not installed on any selected organization; install it with read-only permissions")
	}
	k.app.fallback, _ = k.app.client(selected[0])
	k.logf("collect: GitHub App mode: %d installations, collecting %d orgs", len(installed), len(selected))
	for _, login := range selected {
		if err := k.addRESTOrg(ctx, login, srcAppInstalls, "app_installation"); err != nil {
			return err
		}
	}
	return nil
}

// coverNotInstalled records a selected org the App cannot read.
func (k *collector) coverNotInstalled(login string) {
	n := k.node("org:"+login, graph.KindOrg, login)
	n.Evidence = graph.NotVisible
	setAttr(n, attrSource, srcConfigOrgs, graph.Live)
	k.entOrgs[strings.ToLower(login)] = login
	reason := "GitHub App not installed on " + login
	if in, ok := k.app.installs[strings.ToLower(login)]; ok && in.suspended {
		reason = "GitHub App installation on " + login + " is suspended"
	}
	k.cover(n.ID, "installation", reason, "install the App on "+login+" with read-only permissions")
}
