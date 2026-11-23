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
		// Outside collaborators (logins) and custom repository roles of the org.
		OutsideCollaborators []string          `json:"outside_collaborators"`
		CustomRoles          []json.RawMessage `json:"custom_roles"`
		Teams                []fixtureTeam     `json:"teams"`
	} `json:"orgs"`
	Users []json.RawMessage `json:"users"`
}

// fixtureTeam is one org team: its direct members, its parent and its repo grants.
type fixtureTeam struct {
	Slug             string   `json:"slug"`
	Parent           string   `json:"parent"`
	Privacy          string   `json:"privacy"`
	Members          []string `json:"members"`
	MembersForbidden bool     `json:"members_forbidden"`
	Repos            []struct {
		Name     string `json:"name"`
		RoleName string `json:"role_name"`
		Push     bool   `json:"push"`
	} `json:"repos"`
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
	// forbidCollab makes /repos/{o}/{r}/collaborators return 403 for "o/r",
	// on top of the fixture's collaborators_forbidden flag and non-owner orgs.
	forbidCollab map[string]bool
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "acme.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{t: t, pageSize: 3, failures: map[string]int{}, hits: map[string]int{}, forbidCollab: map[string]bool{}}
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
	case strings.HasPrefix(p, "/orgs/") && strings.Contains(p, "/teams"):
		f.teams(w, r, strings.TrimPrefix(p, "/orgs/"))
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/repos"):
		f.repos(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/repos"))
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/outside_collaborators"):
		f.outside(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/outside_collaborators"))
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/custom-repository-roles"):
		f.customRoles(w, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/custom-repository-roles"))
	case strings.HasPrefix(p, "/repos/") && strings.HasSuffix(p, "/collaborators"):
		f.collaborators(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/repos/"), "/collaborators"))
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
			delete(m, "collaborators")
			delete(m, "collaborators_forbidden")
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

func notFoundOrForbidden(w http.ResponseWriter, status int) {
	msg := "Not Found"
	if status == 403 {
		msg = "Must have push access to view repository collaborators."
	}
	writeJSON(w, status, map[string]string{"message": msg})
}

func listPage(page []json.RawMessage) any {
	if page == nil {
		return []json.RawMessage{}
	}
	return page
}

// collaborators serves /repos/{o}/{r}/collaborators from the repo's
// "collaborators" array. Non-owner orgs, repos flagged collaborators_forbidden
// and f.forbidCollab entries get 403.
func (f *fakeGitHub) collaborators(w http.ResponseWriter, r *http.Request, full string) {
	owner, name, _ := strings.Cut(full, "/")
	for _, o := range f.fx.Orgs {
		if o.Login != owner {
			continue
		}
		for _, raw := range o.Repos {
			var m struct {
				Name          string            `json:"name"`
				Collaborators []json.RawMessage `json:"collaborators"`
				Forbidden     bool              `json:"collaborators_forbidden"`
			}
			_ = json.Unmarshal(raw, &m)
			if m.Name != name {
				continue
			}
			f.mu.Lock()
			forbid := f.forbidCollab[full]
			f.mu.Unlock()
			if !o.Owner || m.Forbidden || forbid {
				notFoundOrForbidden(w, 403)
				return
			}
			f.paged(w, r, m.Collaborators, listPage)
			return
		}
	}
	notFoundOrForbidden(w, 404)
}

// teams serves /orgs/{o}/teams, /orgs/{o}/teams/{slug}/members and
// /orgs/{o}/teams/{slug}/repos. Non-owner orgs do not see secret teams. Like
// GitHub, a team's member list includes the members of its child teams.
func (f *fakeGitHub) teams(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")
	for _, o := range f.fx.Orgs {
		if o.Login != parts[0] {
			continue
		}
		visible := map[string]fixtureTeam{}
		for _, t := range o.Teams {
			if o.Owner || t.Privacy != "secret" {
				visible[t.Slug] = t
			}
		}
		switch {
		case len(parts) == 2 && parts[1] == "teams":
			var items []json.RawMessage
			for _, t := range o.Teams {
				if _, ok := visible[t.Slug]; !ok {
					continue
				}
				m := map[string]any{"slug": t.Slug, "name": t.Slug, "privacy": t.Privacy, "parent": nil}
				if t.Parent != "" {
					m["parent"] = map[string]any{"slug": t.Parent, "name": t.Parent}
				}
				b, _ := json.Marshal(m)
				items = append(items, b)
			}
			f.paged(w, r, items, listPage)
			return
		case len(parts) == 4 && parts[1] == "teams":
			t, ok := visible[parts[2]]
			if !ok {
				break
			}
			var items []json.RawMessage
			switch parts[3] {
			case "members":
				if t.MembersForbidden {
					writeJSON(w, 403, map[string]string{"message": "Must have admin rights to Team."})
					return
				}
				seen := map[string]bool{}
				var walk func(slug string)
				walk = func(slug string) {
					for _, l := range visible[slug].Members {
						if !seen[l] {
							seen[l] = true
							b, _ := json.Marshal(map[string]any{"login": l, "type": "User"})
							items = append(items, b)
						}
					}
					for _, c := range o.Teams {
						if c.Parent == slug {
							walk(c.Slug)
						}
					}
				}
				walk(t.Slug)
			case "repos":
				for _, rp := range t.Repos {
					b, _ := json.Marshal(map[string]any{
						"name": rp.Name, "full_name": o.Login + "/" + rp.Name, "role_name": rp.RoleName,
						"permissions": map[string]bool{"pull": true, "push": rp.Push, "maintain": rp.Push && rp.RoleName != "write", "admin": rp.RoleName == "admin"},
					})
					items = append(items, b)
				}
			default:
				notFoundOrForbidden(w, 404)
				return
			}
			f.paged(w, r, items, listPage)
			return
		}
	}
	notFoundOrForbidden(w, 404)
}

// outside serves /orgs/{o}/outside_collaborators (org owners only).
func (f *fakeGitHub) outside(w http.ResponseWriter, r *http.Request, org string) {
	for _, o := range f.fx.Orgs {
		if o.Login != org {
			continue
		}
		if !o.Owner {
			notFoundOrForbidden(w, 403)
			return
		}
		var items []json.RawMessage
		for _, l := range o.OutsideCollaborators {
			b, _ := json.Marshal(map[string]any{"login": l, "type": "User"})
			items = append(items, b)
		}
		f.paged(w, r, items, listPage)
		return
	}
	notFoundOrForbidden(w, 404)
}

// customRoles serves /orgs/{o}/custom-repository-roles (org owners only).
func (f *fakeGitHub) customRoles(w http.ResponseWriter, org string) {
	for _, o := range f.fx.Orgs {
		if o.Login != org {
			continue
		}
		if !o.Owner {
			notFoundOrForbidden(w, 403)
			return
		}
		roles := o.CustomRoles
		if roles == nil {
			roles = []json.RawMessage{}
		}
		writeJSON(w, 200, map[string]any{"total_count": len(roles), "custom_roles": roles})
		return
	}
	notFoundOrForbidden(w, 404)
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
