package collect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "test-token-synthetic"

// fixture is the synthetic enterprise served by fakeGitHub.
type fixture struct {
	Enterprise string `json:"enterprise"`
	Orgs       []struct {
		Login       string            `json:"login"`
		Owner       bool              `json:"owner"`
		ArchivedAt  string            `json:"archived_at"`
		IPAllowList string            `json:"ip_allow_list"`
		IPEntries   int               `json:"ip_entries"`
		Settings    map[string]string `json:"settings"`
		Repos       []json.RawMessage `json:"repos"`
	} `json:"orgs"`
	Users []json.RawMessage `json:"users"`
}

// fakeGitHub implements just the endpoints the collector calls.
type fakeGitHub struct {
	t        *testing.T
	fx       fixture
	srv      *httptest.Server
	pageSize int

	mu       sync.Mutex
	failures map[string]int // path -> remaining 502s to inject
	hits     map[string]int // path?query -> request count
	refs     []string       // ?ref= values seen on contents requests
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "acme.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{t: t, pageSize: 3, failures: map[string]int{}, hits: map[string]int{}}
	if err := json.Unmarshal(raw, &f.fx); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{BaseURL: f.srv.URL, Token: testToken, MaxAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func (f *fakeGitHub) hitCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[key]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
		return
	}
	f.mu.Lock()
	key := r.URL.Path
	if r.URL.RawQuery != "" {
		key += "?" + r.URL.RawQuery
	}
	f.hits[key]++
	fail := f.failures[r.URL.Path] > 0
	if fail {
		f.failures[r.URL.Path]--
	}
	if ref := r.URL.Query().Get("ref"); ref != "" {
		f.refs = append(f.refs, ref)
	}
	f.mu.Unlock()
	if fail {
		writeJSON(w, 502, map[string]string{"message": "Server Error"})
		return
	}
	p := r.URL.Path
	switch {
	case p == "/graphql" && r.Method == http.MethodPost:
		f.graphql(w, r)
	case p == "/enterprises/"+f.fx.Enterprise+"/consumed-licenses":
		f.paged(w, r, f.fx.Users, func(page []json.RawMessage) any {
			return map[string]any{"total_seats_consumed": len(f.fx.Users), "users": page}
		})
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/repos"):
		f.repos(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/repos"))
	case strings.HasPrefix(p, "/repos/"):
		f.contents(w, r)
	default:
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
	}
}

// paged serves items in pages of f.pageSize with Link headers.
func (f *fakeGitHub) paged(w http.ResponseWriter, r *http.Request, items []json.RawMessage, wrap func([]json.RawMessage) any) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	start := (page - 1) * f.pageSize
	if start > len(items) {
		start = len(items)
	}
	end := start + f.pageSize
	if end > len(items) {
		end = len(items)
	}
	last := (len(items) + f.pageSize - 1) / f.pageSize
	if last < 1 {
		last = 1
	}
	link := func(n int) string {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(n))
		return fmt.Sprintf("<%s%s?%s>", f.srv.URL, r.URL.Path, q.Encode())
	}
	var links []string
	if page < last {
		links = append(links, link(page+1)+`; rel="next"`, link(last)+`; rel="last"`)
	}
	if page > 1 {
		links = append(links, link(1)+`; rel="first"`)
	}
	if len(links) > 0 {
		w.Header().Set("Link", strings.Join(links, ", "))
	}
	writeJSON(w, 200, wrap(items[start:end]))
}

func (f *fakeGitHub) repos(w http.ResponseWriter, r *http.Request, org string) {
	for _, o := range f.fx.Orgs {
		if o.Login != org {
			continue
		}
		var items []json.RawMessage
		for _, raw := range o.Repos {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			m["full_name"] = org + "/" + m["name"].(string)
			if _, ok := m["archived"]; !ok {
				m["archived"] = false
			}
			b, _ := json.Marshal(m)
			items = append(items, b)
		}
		f.paged(w, r, items, func(page []json.RawMessage) any {
			if page == nil {
				return []json.RawMessage{}
			}
			return page
		})
		return
	}
	writeJSON(w, 404, map[string]string{"message": "Not Found"})
}

func (f *fakeGitHub) knownRepo(owner, repo string) bool {
	for _, o := range f.fx.Orgs {
		if o.Login != owner {
			continue
		}
		for _, raw := range o.Repos {
			var m struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &m)
			if m.Name == repo {
				return true
			}
		}
	}
	return false
}

func fileEntry(path string, data []byte) map[string]any {
	enc := base64.StdEncoding.EncodeToString(data)
	var lines []string
	for len(enc) > 60 {
		lines = append(lines, enc[:60])
		enc = enc[60:]
	}
	lines = append(lines, enc)
	return map[string]any{
		"type": "file", "name": filepath.Base(path), "path": path,
		"encoding": "base64", "content": strings.Join(lines, "\n") + "\n",
	}
}

// contents serves /repos/{o}/{r}/contents/{path}. Workflow files come from
// testdata/workflows/{o}/{r}/, action metadata from testdata/actions/{o}/{r}/.
func (f *fakeGitHub) contents(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 4)
	notFound := func() { writeJSON(w, 404, map[string]string{"message": "Not Found"}) }
	if len(parts) != 4 || parts[2] != "contents" || !f.knownRepo(parts[0], parts[1]) {
		notFound()
		return
	}
	owner, repo, path := parts[0], parts[1], parts[3]
	wfDir := filepath.Join("testdata", "workflows", owner, repo)
	switch {
	case path == ".github/workflows":
		ents, err := os.ReadDir(wfDir)
		if err != nil {
			notFound()
			return
		}
		var out []map[string]any
		for _, e := range ents {
			out = append(out, map[string]any{"type": "file", "name": e.Name(), "path": ".github/workflows/" + e.Name()})
		}
		writeJSON(w, 200, out)
	case strings.HasPrefix(path, ".github/workflows/"):
		data, err := os.ReadFile(filepath.Join(wfDir, strings.TrimPrefix(path, ".github/workflows/")))
		if err != nil {
			notFound()
			return
		}
		writeJSON(w, 200, fileEntry(path, data))
	default:
		data, err := os.ReadFile(filepath.Join("testdata", "actions", owner, repo, filepath.FromSlash(path)))
		if err != nil {
			notFound()
			return
		}
		writeJSON(w, 200, fileEntry(path, data))
	}
}

var settingFieldRe = regexp.MustCompile(`(\w+SettingOrganizations)\(value: (\w+)`)

func cursorIndex(v any) int {
	s, _ := v.(string)
	n, _ := strconv.Atoi(s)
	return n
}

// gqlPage slices logins into a GraphQL connection page of f.pageSize.
func (f *fakeGitHub) gqlPage(nodes []map[string]any, after any) map[string]any {
	start := cursorIndex(after)
	if start > len(nodes) {
		start = len(nodes)
	}
	end := start + f.pageSize
	if end > len(nodes) {
		end = len(nodes)
	}
	page := nodes[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	return map[string]any{
		"nodes":    page,
		"pageInfo": map[string]any{"hasNextPage": end < len(nodes), "endCursor": strconv.Itoa(end)},
	}
}

func (f *fakeGitHub) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"message": "bad json"})
		return
	}
	q := req.Query
	switch {
	case strings.Contains(q, "ownerInfo"):
		m := settingFieldRe.FindStringSubmatch(q)
		if m == nil {
			writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"message": "unknown field"}}})
			return
		}
		var nodes []map[string]any
		for _, o := range f.fx.Orgs {
			if o.Settings[m[1]] == m[2] {
				nodes = append(nodes, map[string]any{"login": o.Login})
			}
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"enterprise": map[string]any{
			"ownerInfo": map[string]any{m[1]: f.gqlPage(nodes, req.Variables["after"])},
		}}})
	case strings.Contains(q, "organizations("):
		var nodes []map[string]any
		for _, o := range f.fx.Orgs {
			var archived any
			if o.ArchivedAt != "" {
				archived = o.ArchivedAt
			}
			nodes = append(nodes, map[string]any{"login": o.Login, "archivedAt": archived})
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"enterprise": map[string]any{
			"organizations": f.gqlPage(nodes, req.Variables["after"]),
		}}})
	case strings.Contains(q, "organization(login"):
		login, _ := req.Variables["login"].(string)
		for _, o := range f.fx.Orgs {
			if o.Login != login {
				continue
			}
			if !o.Owner {
				writeJSON(w, 200, map[string]any{
					"data": map[string]any{"organization": map[string]any{
						"ipAllowListEnabledSetting": nil, "ipAllowListEntries": nil,
					}},
					"errors": []map[string]any{
						{"type": "FORBIDDEN", "path": []string{"organization", "ipAllowListEnabledSetting"}, "message": "admin access required"},
						{"type": "FORBIDDEN", "path": []string{"organization", "ipAllowListEntries"}, "message": "admin access required"},
					},
				})
				return
			}
			writeJSON(w, 200, map[string]any{"data": map[string]any{"organization": map[string]any{
				"ipAllowListEnabledSetting": o.IPAllowList,
				"ipAllowListEntries":        map[string]any{"totalCount": o.IPEntries},
			}}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"organization": nil},
			"errors": []map[string]any{{"type": "NOT_FOUND", "message": "not found"}}})
	default:
		writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"message": "unsupported query"}}})
	}
}
