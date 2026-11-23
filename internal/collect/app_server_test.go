package collect

import (
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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The App key is generated once per test binary and never written to disk.
var (
	testAppKeyOnce sync.Once
	testAppKey     *rsa.PrivateKey
)

func appTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testAppKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testAppKey = k
	})
	return testAppKey
}

// appTestPEM returns the test key as PKCS#1 PEM.
func appTestPEM(t *testing.T) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appTestKey(t))})
}

const testAppID = 4242

// fakeApp is the GitHub App side of fakeGitHub.
type fakeApp struct {
	t        *testing.T
	pub      *rsa.PublicKey
	installs map[string]int64 // account login -> installation id
	now      func() time.Time // the server's clock, shared with the client under test
	lifetime time.Duration    // installation token lifetime (default 1h)
	// grant overrides the permissions returned by the mint (default: as requested).
	grant map[string]string
	// forbid answers these paths with 403, as for a permission the App lacks.
	forbid map[string]bool

	mu       sync.Mutex
	tokens   map[string]string // installation token -> account login
	mints    map[string]int    // account login -> tokens minted
	requests []string          // "METHOD /path" for every request
	perms    []map[string]string
}

func newFakeApp(t *testing.T, now func() time.Time, installs map[string]int64) *fakeApp {
	return &fakeApp{t: t, pub: &appTestKey(t).PublicKey, installs: installs, now: now, lifetime: time.Hour,
		forbid: map[string]bool{}, tokens: map[string]string{}, mints: map[string]int{}}
}

var mintRe = regexp.MustCompile(`^/app/installations/([0-9]+)/access_tokens$`)

// verifyJWT checks an RS256 App JWT against the public key and the clock.
func (a *fakeApp) verifyJWT(tok string) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var h struct{ Alg, Typ string }
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "RS256" {
		return fmt.Errorf("header %s", hb)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(a.pub, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	cb, err := enc.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var c struct {
		IAT, EXP, ISS int64
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		return err
	}
	now := a.now().Unix()
	if c.ISS != testAppID || c.IAT > now || c.EXP <= now || c.EXP-c.IAT > 600 {
		return fmt.Errorf("claims %s at %d", cb, now)
	}
	return nil
}

// ownerOf returns the org a REST path is about, or "".
func ownerOf(p string) string {
	for _, pre := range []string{"/orgs/", "/repos/"} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			owner, _, _ := strings.Cut(rest, "/")
			return owner
		}
	}
	return ""
}

// serve handles /app/* and checks installation tokens. It returns true when
// fakeGitHub should serve the request as an authenticated one.
func (a *fakeApp) serve(f *fakeGitHub, w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	a.mu.Lock()
	a.requests = append(a.requests, r.Method+" "+p)
	a.mu.Unlock()
	auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		a.t.Errorf("%s %s: no bearer token", r.Method, p)
		writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
		return false
	}
	if strings.HasPrefix(p, "/app/") {
		if err := a.verifyJWT(auth); err != nil {
			a.t.Errorf("%s %s: bad App JWT: %v", r.Method, p, err)
			writeJSON(w, 401, map[string]string{"message": "A JSON web token could not be decoded"})
			return false
		}
		a.serveApp(f, w, r)
		return false
	}
	a.mu.Lock()
	login, known := a.tokens[auth]
	a.mu.Unlock()
	if !known {
		a.t.Errorf("%s %s: not an installation token (JWT or unknown token sent outside /app/*)", r.Method, p)
		writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
		return false
	}
	// Per-org requests must carry that org's token. Orgs without an
	// installation (public content reads) and owner-less paths take any.
	if owner := ownerOf(p); owner != "" {
		if _, installed := a.installs[owner]; installed && !strings.EqualFold(owner, login) {
			a.t.Errorf("%s %s: carries the %s installation token", r.Method, p, login)
		}
	}
	if a.forbid[p] {
		writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
		return false
	}
	r.Header.Set("Authorization", "Bearer "+testToken)
	return true
}

func (a *fakeApp) serveApp(f *fakeGitHub, w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch m := mintRe.FindStringSubmatch(p); {
	case p == "/app/installations" && r.Method == http.MethodGet:
		logins := make([]string, 0, len(a.installs))
		for login := range a.installs {
			logins = append(logins, login)
		}
		sort.Strings(logins) // stable pages
		var items []json.RawMessage
		for _, login := range logins {
			b, _ := json.Marshal(map[string]any{"id": a.installs[login], "account": map[string]any{"login": login, "type": "Organization"}})
			items = append(items, b)
		}
		f.paged(w, r, items, listPage)
	case m != nil && r.Method == http.MethodPost:
		id, _ := strconv.ParseInt(m[1], 10, 64)
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		for login, iid := range a.installs {
			if iid != id {
				continue
			}
			a.mu.Lock()
			a.mints[login]++
			tok := fmt.Sprintf("ghs_synthetic_%s_%d", login, a.mints[login])
			a.tokens[tok] = login
			a.perms = append(a.perms, body.Permissions)
			a.mu.Unlock()
			grant := body.Permissions
			if a.grant != nil {
				grant = a.grant
			}
			writeJSON(w, 201, map[string]any{"token": tok, "expires_at": a.now().Add(a.lifetime).UTC().Format(time.RFC3339),
				"permissions": grant})
			return
		}
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
	default:
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
	}
}

func (a *fakeApp) mintCount(login string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mints[login]
}

func (a *fakeApp) allTokens() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.tokens))
	for tok := range a.tokens {
		out = append(out, tok)
	}
	return out
}

func (a *fakeApp) allRequests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...)
}
