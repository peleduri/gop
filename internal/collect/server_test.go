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
	"sort"
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
		// OrgREST is the GET /orgs/{org} body (login is added by the server).
		OrgREST map[string]any `json:"org_rest"`
		// WorkflowPerms is the org's default GITHUB_TOKEN permission (read|write).
		WorkflowPerms string `json:"actions_workflow_permissions"`
	} `json:"orgs"`
	Users []json.RawMessage `json:"users"`
}

// fixtureTeam is one org team: its direct members, its parent and its repo grants.
type fixtureTeam struct {
	ID               int64    `json:"id"`
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

	// enterpriseForbidden answers every enterprise GraphQL query with
	// enterprise:null + FORBIDDEN and consumed-licenses with 403, like a token
	// without read:enterprise.
	enterpriseForbidden bool
	// installation makes the token an App installation token: /user/orgs is
	// refused and /installation/repositories lists every fixture repo.
	installation bool
	// noUserOrgs makes /user/orgs return an empty list.
	noUserOrgs bool
	// extraWorkflows adds workflow files on top of testdata/workflows, keyed
	// "owner/repo/file.yml", so one test can plant a reference without
	// changing the shared fixture.
	extraWorkflows map[string]string

	// Branch protection, loaded from each repo's branch_rules, branch_protection
	// and rulesets. Tests may change these before collecting.
	rules      map[string][]json.RawMessage // "o/r@branch" -> active rules
	protection map[string]json.RawMessage   // "o/r@branch" -> classic protection
	rulesets   map[string]json.RawMessage   // "o/r#id" -> ruleset (with bypass_actors)
	forbidRule map[string]bool              // "o/r" -> /rules/branches returns 403
	hideBypass bool                         // rulesets omit bypass_actors, as for non-admins
	// forbidWorkflowPerms makes both default workflow permissions endpoints
	// return 403 for every repo and org.
	forbidWorkflowPerms bool
	userIDs             map[int64]string // /user/{id} -> login
	// app, when set, makes the fake a GitHub App host (app_server_test.go):
	// /app/* takes the App JWT and every other path an installation token.
	app *fakeApp

	// Refs and tag immutability, loaded from each repo's refs and releases.
	tags, branches map[string]map[string]bool // "o/r" -> names
	releases       map[string]bool            // "o/r@tag" -> immutable
	forbidRulesets map[string]bool            // "o/r" -> the rulesets list returns 403
	forbidReleases map[string]bool            // "o/r" -> releases/tags/{tag} returns 403
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "acme.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{t: t, pageSize: 3, failures: map[string]int{}, hits: map[string]int{}, forbidCollab: map[string]bool{},
		extraWorkflows: map[string]string{}}
	if err := json.Unmarshal(raw, &f.fx); err != nil {
		t.Fatal(err)
	}
	f.loadProtection(t)
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
	if f.app != nil && !f.app.serve(f, w, r) {
		return
	}
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
	case p == "/enterprises/"+f.fx.Enterprise+"/consumed-licenses" && f.enterpriseForbidden:
		writeJSON(w, 403, map[string]string{"message": "Resource not accessible by personal access token"})
	case p == "/enterprises/"+f.fx.Enterprise+"/consumed-licenses":
		f.paged(w, r, f.fx.Users, func(page []json.RawMessage) any {
			return map[string]any{"total_seats_consumed": len(f.fx.Users), "users": page}
		})
	case strings.HasSuffix(p, "/actions/permissions/workflow"):
		f.workflowPerms(w, p)
	case strings.HasPrefix(p, "/orgs/") && strings.Contains(p, "/teams"):
		f.teams(w, r, strings.TrimPrefix(p, "/orgs/"))
	case p == "/user/orgs":
		f.userOrgs(w, r)
	case p == "/installation/repositories":
		f.installationRepos(w, r)
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/members"):
		f.orgMembers(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/members"))
	case strings.HasPrefix(p, "/orgs/") && !strings.Contains(strings.TrimPrefix(p, "/orgs/"), "/"):
		f.org(w, strings.TrimPrefix(p, "/orgs/"))
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/repos"):
		f.repos(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/repos"))
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/outside_collaborators"):
		f.outside(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/outside_collaborators"))
	case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/custom-repository-roles"):
		f.customRoles(w, strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/custom-repository-roles"))
	case strings.HasPrefix(p, "/repos/") && strings.HasSuffix(p, "/collaborators"):
		f.collaborators(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/repos/"), "/collaborators"))
	case strings.HasPrefix(p, "/repos/") && strings.HasSuffix(p, "/actions/permissions/access"):
		f.actionsAccess(w, strings.TrimSuffix(strings.TrimPrefix(p, "/repos/"), "/actions/permissions/access"))
	case strings.HasPrefix(p, "/repos/") && f.tagFacts(w, r):
	case strings.HasPrefix(p, "/repos/") && f.branchProtection(w, r):
	case strings.HasPrefix(p, "/user/"):
		f.user(w, strings.TrimPrefix(p, "/user/"))
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
			delete(m, "branch_rules")
			delete(m, "branch_protection")
			delete(m, "rulesets")
			delete(m, "actions_access")
			delete(m, "actions_access_forbidden")
			delete(m, "refs")
			delete(m, "releases")
			delete(m, "workflows_dir_object")
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
				m := map[string]any{"id": t.ID, "slug": t.Slug, "name": t.Slug, "privacy": t.Privacy, "parent": nil}
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
	_, ok := f.fixtureRepo(owner, repo)
	return ok
}

// fixtureRepoFlags are the per-repo fixture flags the contents endpoint reads.
type fixtureRepoFlags struct {
	Name string `json:"name"`
	// WorkflowsDirObject makes .github/workflows answer with a JSON object
	// (as for a file or a submodule) instead of a directory listing.
	WorkflowsDirObject bool `json:"workflows_dir_object"`
}

func (f *fakeGitHub) fixtureRepo(owner, repo string) (fixtureRepoFlags, bool) {
	for _, o := range f.fx.Orgs {
		if o.Login != owner {
			continue
		}
		for _, raw := range o.Repos {
			var m fixtureRepoFlags
			_ = json.Unmarshal(raw, &m)
			if m.Name == repo {
				return m, true
			}
		}
	}
	return fixtureRepoFlags{}, false
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
	f.mu.Lock()
	extra := map[string]string{}
	for k, v := range f.extraWorkflows {
		if name, ok := strings.CutPrefix(k, owner+"/"+repo+"/"); ok {
			extra[name] = v
		}
	}
	f.mu.Unlock()
	flags, _ := f.fixtureRepo(owner, repo)
	switch {
	case path == ".github/workflows" && flags.WorkflowsDirObject:
		writeJSON(w, 200, map[string]any{"type": "submodule", "name": "workflows", "path": path,
			"submodule_git_url": "https://example.invalid/acme/workflows.git"})
	case path == ".github/workflows":
		ents, err := os.ReadDir(wfDir)
		if err != nil && len(extra) == 0 {
			notFound()
			return
		}
		var out []map[string]any
		for _, e := range ents {
			out = append(out, map[string]any{"type": "file", "name": e.Name(), "path": ".github/workflows/" + e.Name()})
		}
		for name := range extra {
			out = append(out, map[string]any{"type": "file", "name": name, "path": ".github/workflows/" + name})
		}
		writeJSON(w, 200, out)
	case strings.HasPrefix(path, ".github/workflows/"):
		name := strings.TrimPrefix(path, ".github/workflows/")
		if body, ok := extra[name]; ok {
			writeJSON(w, 200, fileEntry(path, []byte(body)))
			return
		}
		data, err := os.ReadFile(filepath.Join(wfDir, name))
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
	if f.enterpriseForbidden && strings.Contains(q, "enterprise(slug") {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"enterprise": nil},
			"errors": []map[string]any{{"type": "FORBIDDEN", "path": []string{"enterprise"}, "message": "must be an enterprise owner"}}})
		return
	}
	switch {
	case strings.Contains(q, "ref(qualifiedName"):
		f.refLookups(w, q, req.Variables)
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

// userOrgs serves /user/orgs: every fixture org for a user token, 403 for an
// installation token.
func (f *fakeGitHub) userOrgs(w http.ResponseWriter, r *http.Request) {
	if f.installation {
		writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
		return
	}
	var items []json.RawMessage
	if !f.noUserOrgs {
		for _, o := range f.fx.Orgs {
			b, _ := json.Marshal(map[string]any{"login": o.Login})
			items = append(items, b)
		}
	}
	f.paged(w, r, items, listPage)
}

// installationRepos serves /installation/repositories for installation tokens.
func (f *fakeGitHub) installationRepos(w http.ResponseWriter, r *http.Request) {
	if !f.installation {
		writeJSON(w, 403, map[string]string{"message": "This endpoint requires an installation access token"})
		return
	}
	var items []json.RawMessage
	for _, o := range f.fx.Orgs {
		for _, raw := range o.Repos {
			var m struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &m)
			b, _ := json.Marshal(map[string]any{"name": m.Name, "full_name": o.Login + "/" + m.Name,
				"owner": map[string]any{"login": o.Login, "type": "Organization"}})
			items = append(items, b)
		}
	}
	f.paged(w, r, items, func(page []json.RawMessage) any {
		return map[string]any{"total_count": len(items), "repositories": listPage(page)}
	})
}

// org serves GET /orgs/{org} from the fixture's org_rest block.
func (f *fakeGitHub) org(w http.ResponseWriter, org string) {
	for _, o := range f.fx.Orgs {
		if o.Login != org {
			continue
		}
		body := map[string]any{"login": o.Login}
		for k, v := range o.OrgREST {
			body[k] = v
		}
		writeJSON(w, 200, body)
		return
	}
	notFoundOrForbidden(w, 404)
}

// orgMembers serves /orgs/{org}/members[?role=admin] from the fixture users'
// "org:Role" license roles.
func (f *fakeGitHub) orgMembers(w http.ResponseWriter, r *http.Request, org string) {
	known := false
	for _, o := range f.fx.Orgs {
		known = known || o.Login == org
	}
	if !known {
		notFoundOrForbidden(w, 404)
		return
	}
	admin := r.URL.Query().Get("role") == "admin"
	var items []json.RawMessage
	for _, raw := range f.fx.Users {
		var u struct {
			Login string   `json:"github_com_login"`
			Roles []string `json:"github_com_member_roles"`
		}
		_ = json.Unmarshal(raw, &u)
		for _, role := range u.Roles {
			scope, rl, _ := strings.Cut(role, ":")
			if scope == org && (!admin || rl == "Owner") {
				b, _ := json.Marshal(map[string]any{"login": u.Login, "type": "User"})
				items = append(items, b)
				break
			}
		}
	}
	f.paged(w, r, items, listPage)
}

// loadProtection indexes each repo's branch_rules, branch_protection and rulesets.
func (f *fakeGitHub) loadProtection(t *testing.T) {
	t.Helper()
	f.rules, f.protection, f.rulesets = map[string][]json.RawMessage{}, map[string]json.RawMessage{}, map[string]json.RawMessage{}
	f.forbidRule, f.userIDs = map[string]bool{}, map[int64]string{}
	f.tags, f.branches, f.releases = map[string]map[string]bool{}, map[string]map[string]bool{}, map[string]bool{}
	f.forbidRulesets, f.forbidReleases = map[string]bool{}, map[string]bool{}
	for _, o := range f.fx.Orgs {
		for _, raw := range o.Repos {
			var m struct {
				Name       string                       `json:"name"`
				Rules      map[string][]json.RawMessage `json:"branch_rules"`
				Protection map[string]json.RawMessage   `json:"branch_protection"`
				Rulesets   []json.RawMessage            `json:"rulesets"`
				Refs       struct {
					Tags     []string `json:"tags"`
					Branches []string `json:"branches"`
				} `json:"refs"`
				Releases []struct {
					Tag       string `json:"tag"`
					Immutable bool   `json:"immutable"`
				} `json:"releases"`
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			full := o.Login + "/" + m.Name
			f.tags[full], f.branches[full] = map[string]bool{}, map[string]bool{}
			for _, n := range m.Refs.Tags {
				f.tags[full][n] = true
			}
			for _, n := range m.Refs.Branches {
				f.branches[full][n] = true
			}
			for _, rl := range m.Releases {
				f.releases[full+"@"+rl.Tag] = rl.Immutable
			}
			for b, rs := range m.Rules {
				f.rules[full+"@"+b] = rs
			}
			for b, p := range m.Protection {
				f.protection[full+"@"+b] = p
			}
			for _, rs := range m.Rulesets {
				var id struct {
					ID int64 `json:"id"`
				}
				_ = json.Unmarshal(rs, &id)
				f.rulesets[full+"#"+strconv.FormatInt(id.ID, 10)] = rs
			}
		}
	}
}

func (f *fakeGitHub) orgOwner(login string) bool {
	for _, o := range f.fx.Orgs {
		if o.Login == login {
			return o.Owner
		}
	}
	return false
}

// branchProtection serves /repos/{o}/{r}/rules/branches/{b},
// /repos/{o}/{r}/branches/{b}[/protection] and /repos/{o}/{r}/rulesets/{id}.
// It reports false for any other /repos/ path. Classic protection details and
// ruleset bypass actors are visible only in orgs the token owns.
func (f *fakeGitHub) branchProtection(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 4)
	if len(parts) < 4 || !f.knownRepo(parts[0], parts[1]) {
		return false
	}
	full := parts[0] + "/" + parts[1]
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case parts[2] == "rules" && strings.HasPrefix(parts[3], "branches/"):
		if f.forbidRule[full] {
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
			return true
		}
		items := f.rules[full+"@"+strings.TrimPrefix(parts[3], "branches/")]
		if items == nil {
			items = []json.RawMessage{}
		}
		writeJSON(w, 200, items)
	case parts[2] == "branches":
		branch, details := strings.CutSuffix(parts[3], "/protection")
		prot, protected := f.protection[full+"@"+branch]
		if !details {
			writeJSON(w, 200, map[string]any{"name": branch, "protected": protected,
				"protection": map[string]any{"enabled": protected}})
			return true
		}
		switch {
		case !f.orgOwner(parts[0]):
			writeJSON(w, 403, map[string]string{"message": "Must have admin rights to Repository."})
		case !protected:
			writeJSON(w, 404, map[string]string{"message": "Branch not protected"})
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(prot)
		}
	case parts[2] == "rulesets":
		rs, ok := f.rulesets[full+"#"+parts[3]]
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "Not Found"})
			return true
		}
		var m map[string]any
		_ = json.Unmarshal(rs, &m)
		if f.hideBypass || !f.orgOwner(parts[0]) {
			delete(m, "bypass_actors")
		}
		writeJSON(w, 200, m)
	default:
		return false
	}
	return true
}

// user serves /user/{account_id} from f.userIDs.
func (f *fakeGitHub) user(w http.ResponseWriter, id string) {
	n, _ := strconv.ParseInt(id, 10, 64)
	f.mu.Lock()
	login, ok := f.userIDs[n]
	f.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
		return
	}
	writeJSON(w, 200, map[string]any{"login": login, "id": n, "type": "User"})
}

// refLookups answers the collector's aliased ref batch: r<i> is
// repository(owner: $o<i>, name: $n<i>) with t: refs/tags/... ($t<i>) and
// b: refs/heads/... ($h<i>). An unknown repo is null with a NOT_FOUND error
// for its alias only. Owner, repo and ref strings must arrive as variables:
// the query text naming a fixture org fails the test.
func (f *fakeGitHub) refLookups(w http.ResponseWriter, q string, vars map[string]any) {
	f.mu.Lock()
	f.hits["graphql:refs"]++
	f.mu.Unlock()
	for _, o := range f.fx.Orgs {
		if strings.Contains(q, o.Login) {
			f.t.Errorf("ref query interpolates %q into the query text:\n%s", o.Login, q)
		}
	}
	data := map[string]any{}
	var errs []map[string]any
	for i := 0; ; i++ {
		owner, ok := vars[fmt.Sprintf("o%d", i)].(string)
		if !ok {
			break
		}
		name, _ := vars[fmt.Sprintf("n%d", i)].(string)
		tq, _ := vars[fmt.Sprintf("t%d", i)].(string)
		hq, _ := vars[fmt.Sprintf("h%d", i)].(string)
		alias := fmt.Sprintf("r%d", i)
		if !strings.Contains(q, alias+": repository(owner: $o"+strconv.Itoa(i)+", name: $n"+strconv.Itoa(i)+")") {
			f.t.Errorf("alias %s not in query:\n%s", alias, q)
		}
		full := owner + "/" + name
		if !f.knownRepo(owner, name) {
			data[alias] = nil
			errs = append(errs, map[string]any{"type": "NOT_FOUND", "path": []string{alias},
				"message": "Could not resolve to a Repository with the name '" + full + "'."})
			continue
		}
		f.mu.Lock()
		hasTag := f.tags[full][strings.TrimPrefix(tq, "refs/tags/")]
		hasBranch := f.branches[full][strings.TrimPrefix(hq, "refs/heads/")]
		f.mu.Unlock()
		ref := func(ok bool) any {
			if !ok {
				return nil
			}
			return map[string]any{"target": map[string]any{"oid": "0123456789abcdef0123456789abcdef01234567"}}
		}
		data[alias] = map[string]any{"t": ref(hasTag), "b": ref(hasBranch)}
	}
	body := map[string]any{"data": data}
	if len(errs) > 0 {
		body["errors"] = errs
	}
	writeJSON(w, 200, body)
}

// tagFacts serves /repos/{o}/{r}/releases/tags/{tag} from the repo's releases
// and the /repos/{o}/{r}/rulesets list from its rulesets (target defaults to
// branch). It reports false for any other path.
func (f *fakeGitHub) tagFacts(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 3)
	if len(parts) < 3 || !f.knownRepo(parts[0], parts[1]) {
		return false
	}
	full := parts[0] + "/" + parts[1]
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasPrefix(parts[2], "releases/tags/"):
		if f.forbidReleases[full] {
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
			return true
		}
		tag := strings.TrimPrefix(parts[2], "releases/tags/")
		immutable, ok := f.releases[full+"@"+tag]
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "Not Found"})
			return true
		}
		writeJSON(w, 200, map[string]any{"tag_name": tag, "immutable": immutable, "draft": false})
	case parts[2] == "rulesets":
		if f.forbidRulesets[full] {
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
			return true
		}
		var ids []int64
		for key := range f.rulesets {
			if id, ok := strings.CutPrefix(key, full+"#"); ok {
				n, _ := strconv.ParseInt(id, 10, 64)
				ids = append(ids, n)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		var items []json.RawMessage
		for _, id := range ids {
			var m struct {
				Name        string `json:"name"`
				Target      string `json:"target"`
				Enforcement string `json:"enforcement"`
			}
			_ = json.Unmarshal(f.rulesets[full+"#"+strconv.FormatInt(id, 10)], &m)
			if m.Target == "" {
				m.Target = "branch"
			}
			b, _ := json.Marshal(map[string]any{"id": id, "name": m.Name, "target": m.Target,
				"enforcement": m.Enforcement, "source_type": "Repository", "source": full})
			items = append(items, b)
		}
		f.paged(w, r, items, listPage)
	default:
		return false
	}
	return true
}
