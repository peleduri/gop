package collect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// MaxNestedDepth bounds how deep transitive action and reusable-workflow
// references are expanded. Workflow-level references are depth 1.
const MaxNestedDepth = 3

// Config drives one collection run.
type Config struct {
	// Enterprise slug, e.g. "acme".
	Enterprise string
	// Token is a GitHub token. It is never logged or put in errors.
	Token string
	// Orgs, when non-empty, limits per-org collection to these logins.
	Orgs []string

	// Client options, used when Client is nil.
	BaseURL     string
	GraphQLURL  string
	MaxAttempts int
	Logf        func(format string, args ...any)

	// Client overrides the options above when set.
	Client *Client
}

// Source API labels recorded on edges and used in coverage.
const (
	srcOrgs        = "graphql:enterprise.organizations"
	srcDefaultPerm = "graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations"
	srcWorkflowDir = "rest:GET /repos/{owner}/{repo}/contents/.github/workflows"
	srcWorkflow    = "rest:GET /repos/{owner}/{repo}/contents/{path}"
	srcNested      = "rest:GET /repos/{owner}/{repo}/contents/{path}?ref={ref}"
)

// Attribute keys this package adds beyond the graph contract.
const (
	attrRepositories = "repositories"
	attrOwners       = "owners"
	attrNested       = "nested"
)

type orgState struct {
	login        string
	archived     bool
	node         *graph.Node
	ownerVisible bool
	repos        []*graph.Node
}

type queued struct {
	id    string
	use   ActionUse
	depth int
}

type collector struct {
	c          *Client
	cfg        Config
	now        time.Time
	nodes      map[string]*graph.Node
	edges      map[string]*graph.Edge
	coverage   []graph.Coverage
	covSeen    map[string]bool
	orgs       []*orgState
	byLower    map[string]*orgState // collected orgs
	entOrgs    map[string]string    // lower login -> login for every enterprise org
	repoIDs    map[string]string    // lower "owner/repo" -> node id
	queue      []queued
	expanded   map[string]bool
	enterprise string
}

// Collect reads the enterprise and returns the evidence graph.
func Collect(ctx context.Context, cfg Config) (*graph.Graph, error) {
	if cfg.Enterprise == "" {
		return nil, errors.New("collect: enterprise slug is required")
	}
	c := cfg.Client
	if c == nil {
		var err error
		c, err = NewClient(ClientOptions{
			BaseURL: cfg.BaseURL, GraphQLURL: cfg.GraphQLURL, Token: cfg.Token,
			MaxAttempts: cfg.MaxAttempts, Logf: cfg.Logf,
		})
		if err != nil {
			return nil, err
		}
	}
	k := &collector{
		c: c, cfg: cfg, now: time.Now().UTC(), enterprise: cfg.Enterprise,
		nodes: map[string]*graph.Node{}, edges: map[string]*graph.Edge{},
		covSeen: map[string]bool{}, byLower: map[string]*orgState{},
		entOrgs: map[string]string{}, repoIDs: map[string]string{}, expanded: map[string]bool{},
	}
	if err := k.run(ctx); err != nil {
		return nil, err
	}
	return k.graph(), nil
}

func (k *collector) run(ctx context.Context) error {
	ent := k.node("enterprise:"+k.enterprise, graph.KindEnterprise, k.enterprise)
	if err := k.collectOrgs(ctx); err != nil {
		return err
	}
	ent.Attrs["orgs"] = strconv.Itoa(len(k.entOrgs))
	if err := k.collectSettings(ctx); err != nil {
		return err
	}
	if err := k.collectMembers(ctx); err != nil {
		return err
	}
	for _, o := range k.orgs {
		if o.archived {
			continue
		}
		if err := k.collectOwnerView(ctx, o); err != nil {
			return err
		}
		if err := k.collectRepos(ctx, o); err != nil {
			return err
		}
		k.canPush(o)
	}
	for _, o := range k.orgs {
		for _, r := range o.repos {
			if r.Attrs[graph.AttrArchived] == "true" {
				continue // archived repositories cannot run workflows
			}
			if err := k.collectWorkflows(ctx, o, r); err != nil {
				return err
			}
		}
	}
	return k.expandNested(ctx)
}

// ---- graph helpers ----

func (k *collector) node(id string, kind graph.NodeKind, name string) *graph.Node {
	if n, ok := k.nodes[id]; ok {
		return n
	}
	n := &graph.Node{ID: id, Kind: kind, Name: name, Attrs: map[string]string{}, Evidence: graph.Live}
	k.nodes[id] = n
	return n
}

func setAttr(n *graph.Node, key, val string, ev graph.Evidence) {
	n.Attrs[key] = val
	if ev == n.Evidence || ev == "" {
		if n.AttrEvidence != nil {
			delete(n.AttrEvidence, key)
		}
		return
	}
	if n.AttrEvidence == nil {
		n.AttrEvidence = map[string]graph.Evidence{}
	}
	n.AttrEvidence[key] = ev
}

func (k *collector) edge(from, to string, kind graph.EdgeKind, ev graph.Evidence, src string, attrs map[string]string) {
	key := from + "\x00" + string(kind) + "\x00" + to
	if _, ok := k.edges[key]; ok {
		return
	}
	k.edges[key] = &graph.Edge{From: from, To: to, Kind: kind, Evidence: ev, SourceAPI: src, ObservedAt: k.now, Attrs: attrs}
}

func (k *collector) cover(scope, fact, reason, fix string) {
	key := scope + "\x00" + fact
	if k.covSeen[key] {
		return
	}
	k.covSeen[key] = true
	k.coverage = append(k.coverage, graph.Coverage{Scope: scope, Fact: fact, Reason: reason, NeedsFix: fix})
}

func (k *collector) graph() *graph.Graph {
	g := &graph.Graph{
		Schema: graph.SchemaVersion, CollectedAt: k.now, Enterprise: k.enterprise,
		Nodes: make([]graph.Node, 0, len(k.nodes)), Edges: make([]graph.Edge, 0, len(k.edges)),
		Coverage: k.coverage,
	}
	if g.Coverage == nil {
		g.Coverage = []graph.Coverage{}
	}
	for _, n := range k.nodes {
		if len(n.Attrs) == 0 {
			n.Attrs = nil
		}
		g.Nodes = append(g.Nodes, *n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	for _, e := range k.edges {
		g.Edges = append(g.Edges, *e)
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.To < b.To
	})
	return g
}

func (k *collector) logf(format string, args ...any) { k.c.logf(format, args...) }

// ---- enterprise owner view ----

type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

type orgConn struct {
	Nodes []struct {
		Login      string  `json:"login"`
		ArchivedAt *string `json:"archivedAt"`
	} `json:"nodes"`
	PageInfo pageInfo `json:"pageInfo"`
}

const orgsQuery = `query($slug: String!, $after: String) {
  enterprise(slug: $slug) {
    organizations(first: 100, after: $after) {
      nodes { login archivedAt }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

func (k *collector) collectOrgs(ctx context.Context) error {
	var after any
	type entry struct {
		login    string
		archived bool
	}
	var all []entry
	for {
		var data struct {
			Enterprise *struct {
				Organizations orgConn `json:"organizations"`
			} `json:"enterprise"`
		}
		gqlErrs, err := k.c.GraphQL(ctx, orgsQuery, map[string]any{"slug": k.enterprise, "after": after}, &data)
		if err != nil {
			return fmt.Errorf("collect: listing enterprise organizations: %w", err)
		}
		if data.Enterprise == nil {
			if len(gqlErrs) > 0 {
				return fmt.Errorf("collect: enterprise %q: %w", k.enterprise, gqlErrs)
			}
			return fmt.Errorf("collect: enterprise %q not found or not visible to the token", k.enterprise)
		}
		for _, n := range data.Enterprise.Organizations.Nodes {
			all = append(all, entry{n.Login, n.ArchivedAt != nil && *n.ArchivedAt != ""})
		}
		pi := data.Enterprise.Organizations.PageInfo
		if !pi.HasNextPage || pi.EndCursor == "" {
			break
		}
		after = pi.EndCursor
	}
	allow := map[string]bool{}
	for _, o := range k.cfg.Orgs {
		allow[strings.ToLower(o)] = true
	}
	for _, e := range all {
		k.entOrgs[strings.ToLower(e.login)] = e.login
		if len(allow) > 0 && !allow[strings.ToLower(e.login)] {
			continue
		}
		n := k.node("org:"+e.login, graph.KindOrg, e.login)
		setAttr(n, graph.AttrArchived, strconv.FormatBool(e.archived), graph.Live)
		o := &orgState{login: e.login, archived: e.archived, node: n}
		k.orgs = append(k.orgs, o)
		k.byLower[strings.ToLower(e.login)] = o
	}
	for _, want := range k.cfg.Orgs {
		if _, ok := k.entOrgs[strings.ToLower(want)]; !ok {
			k.cover("org:"+want, "org", "organization is not in enterprise "+k.enterprise+" (or not visible to the token)",
				"check the org login, or enterprise owner on "+k.enterprise)
		}
	}
	k.logf("collect: enterprise %s: %d orgs (%d selected)", k.enterprise, len(all), len(k.orgs))
	return nil
}

// settingSpec maps one ownerInfo per-org list family onto an org attribute.
type settingSpec struct {
	field      string
	attr       string
	values     [][2]string // enum value -> attr value; later entries win on overlap
	complement string      // attr value for orgs absent from every list ("" = unknown)
}

var settingSpecs = []settingSpec{
	{field: "samlIdentityProviderSettingOrganizations", attr: graph.AttrSSO,
		values: [][2]string{{"UNCONFIGURED", "none"}, {"CONFIGURED", "configured"}, {"ENFORCED", "enforced"}}},
	{field: "twoFactorRequiredSettingOrganizations", attr: graph.AttrTwoFactor,
		values: [][2]string{{"true", "required"}, {"false", "not_required"}}},
	{field: "defaultRepositoryPermissionSettingOrganizations", attr: graph.AttrDefaultPerm,
		values: [][2]string{{"NONE", "none"}, {"READ", "read"}, {"WRITE", "write"}, {"ADMIN", "admin"}}},
	{field: "membersCanCreateRepositoriesSettingOrganizations", attr: graph.AttrMembersCreate,
		values: [][2]string{{"ALL", "true"}}, complement: "false"},
	{field: "membersCanChangeRepositoryVisibilitySettingOrganizations", attr: graph.AttrChangeVisiblity,
		values: [][2]string{{"false", "false"}, {"true", "true"}}},
	{field: "membersCanDeleteRepositoriesSettingOrganizations", attr: graph.AttrDeleteRepos,
		values: [][2]string{{"false", "false"}, {"true", "true"}}},
	{field: "allowPrivateRepositoryForkingSettingOrganizations", attr: graph.AttrPrivateForks,
		values: [][2]string{{"false", "false"}, {"true", "true"}}},
}

func settingQuery(field, value string) string {
	return fmt.Sprintf(`query($slug: String!, $after: String) {
  enterprise(slug: $slug) {
    ownerInfo {
      %s(value: %s, first: 100, after: $after) {
        nodes { login }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}`, field, value)
}

// settingOrgs returns the logins in one ownerInfo list, following pagination.
func (k *collector) settingOrgs(ctx context.Context, field, value string) ([]string, error) {
	var out []string
	var after any
	q := settingQuery(field, value)
	for {
		var data struct {
			Enterprise *struct {
				OwnerInfo map[string]*struct {
					Nodes []struct {
						Login string `json:"login"`
					} `json:"nodes"`
					PageInfo pageInfo `json:"pageInfo"`
				} `json:"ownerInfo"`
			} `json:"enterprise"`
		}
		gqlErrs, err := k.c.GraphQL(ctx, q, map[string]any{"slug": k.enterprise, "after": after}, &data)
		if err != nil {
			return nil, err
		}
		if data.Enterprise == nil || data.Enterprise.OwnerInfo == nil || data.Enterprise.OwnerInfo[field] == nil {
			if len(gqlErrs) > 0 {
				return nil, gqlErrs
			}
			return nil, errors.New("ownerInfo not returned")
		}
		conn := data.Enterprise.OwnerInfo[field]
		for _, n := range conn.Nodes {
			out = append(out, n.Login)
		}
		if !conn.PageInfo.HasNextPage || conn.PageInfo.EndCursor == "" {
			return out, nil
		}
		after = conn.PageInfo.EndCursor
	}
}

func (k *collector) collectSettings(ctx context.Context) error {
	for _, spec := range settingSpecs {
		assigned := map[string]string{}
		var failure error
		for _, v := range spec.values {
			logins, err := k.settingOrgs(ctx, spec.field, v[0])
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				failure = err
				continue
			}
			for _, l := range logins {
				assigned[strings.ToLower(l)] = v[1]
			}
		}
		if failure != nil {
			k.cover("enterprise:"+k.enterprise, spec.attr,
				"could not read enterprise ownerInfo."+spec.field+": "+failure.Error(),
				"enterprise owner on "+k.enterprise)
		}
		for _, o := range k.orgs {
			val, ok := assigned[strings.ToLower(o.login)]
			switch {
			case ok:
				setAttr(o.node, spec.attr, val, graph.Live)
			case failure == nil && spec.complement != "":
				setAttr(o.node, spec.attr, spec.complement, graph.Live)
			default:
				setAttr(o.node, spec.attr, "unknown", graph.NotVisible)
				if failure == nil {
					k.cover(o.node.ID, spec.attr, "organization missing from every ownerInfo."+spec.field+" list",
						"enterprise owner on "+k.enterprise)
				}
			}
		}
	}
	return nil
}

// ---- members (enterprise consumed licenses) ----

func (k *collector) collectMembers(ctx context.Context) error {
	members := map[string]map[string]bool{}
	owners := map[string]map[string]bool{}
	path := "/enterprises/" + url.PathEscape(k.enterprise) + "/consumed-licenses?per_page=100"
	err := k.c.GetPages(ctx, path, func(page []byte) error {
		var body struct {
			Users []struct {
				Login string   `json:"github_com_login"`
				Roles []string `json:"github_com_member_roles"`
			} `json:"users"`
		}
		if err := json.Unmarshal(page, &body); err != nil {
			return fmt.Errorf("decoding consumed-licenses: %w", err)
		}
		for _, u := range body.Users {
			if u.Login == "" {
				continue
			}
			for _, role := range u.Roles {
				i := strings.LastIndex(role, ":")
				if i <= 0 {
					continue
				}
				scope, r := role[:i], role[i+1:]
				if strings.Contains(scope, "/") {
					continue // repository collaborator role, not org membership
				}
				org := strings.ToLower(scope)
				if members[org] == nil {
					members[org] = map[string]bool{}
				}
				members[org][u.Login] = true
				if strings.EqualFold(r, "Owner") {
					if owners[org] == nil {
						owners[org] = map[string]bool{}
					}
					owners[org][u.Login] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		k.cover("enterprise:"+k.enterprise, graph.AttrMembers, "could not read consumed licenses: "+err.Error(),
			"enterprise owner on "+k.enterprise)
	}
	for _, o := range k.orgs {
		mn := k.node("members:"+o.login, graph.KindOrgMembers, o.login+" members")
		if err != nil {
			setAttr(o.node, graph.AttrMembers, "unknown", graph.NotVisible)
			setAttr(mn, graph.AttrMembers, "unknown", graph.NotVisible)
			continue
		}
		m := strconv.Itoa(len(members[strings.ToLower(o.login)]))
		setAttr(o.node, graph.AttrMembers, m, graph.Live)
		setAttr(o.node, attrOwners, strconv.Itoa(len(owners[strings.ToLower(o.login)])), graph.Live)
		setAttr(mn, graph.AttrMembers, m, graph.Live)
	}
	return nil
}

// ---- org owner view ----

const ownerViewQuery = `query($login: String!) {
  organization(login: $login) {
    ipAllowListEnabledSetting
    ipAllowListEntries { totalCount }
  }
}`

func (k *collector) ownerFix(o *orgState) string {
	fix := "org owner on " + o.login
	if o.node.Attrs[graph.AttrSSO] == "enforced" {
		fix += " (SSO enforced: join through the identity provider first)"
	}
	return fix
}

func (k *collector) collectOwnerView(ctx context.Context, o *orgState) error {
	var data struct {
		Organization *struct {
			IPAllowListEnabledSetting *string `json:"ipAllowListEnabledSetting"`
			IPAllowListEntries        *struct {
				TotalCount int `json:"totalCount"`
			} `json:"ipAllowListEntries"`
		} `json:"organization"`
	}
	gqlErrs, err := k.c.GraphQL(ctx, ownerViewQuery, map[string]any{"login": o.login}, &data)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var reason string
	switch {
	case err != nil:
		reason = "could not read org settings: " + err.Error()
	case gqlErrs.HasType("FORBIDDEN"):
		reason = "token is not an org owner"
	case data.Organization == nil || data.Organization.IPAllowListEnabledSetting == nil:
		reason = "org settings not returned"
		if len(gqlErrs) > 0 {
			reason += ": " + gqlErrs.Error()
		}
	}
	if reason != "" {
		o.ownerVisible = false
		setAttr(o.node, graph.AttrIPAllowList, "unknown", graph.NotVisible)
		setAttr(o.node, graph.AttrIPAllowEntries, "unknown", graph.NotVisible)
		k.cover(o.node.ID, "ip_allow_list", reason, k.ownerFix(o))
		return nil
	}
	o.ownerVisible = true
	val := "off"
	if *data.Organization.IPAllowListEnabledSetting == "ENABLED" {
		val = "on"
	}
	setAttr(o.node, graph.AttrIPAllowList, val, graph.Live)
	if data.Organization.IPAllowListEntries != nil {
		setAttr(o.node, graph.AttrIPAllowEntries, strconv.Itoa(data.Organization.IPAllowListEntries.TotalCount), graph.Live)
	} else {
		setAttr(o.node, graph.AttrIPAllowEntries, "unknown", graph.NotVisible)
	}
	return nil
}

// ---- repositories ----

type apiRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Visibility    string `json:"visibility"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
}

func (k *collector) collectRepos(ctx context.Context, o *orgState) error {
	var repos []apiRepo
	err := k.c.GetPages(ctx, "/orgs/"+url.PathEscape(o.login)+"/repos?type=all&per_page=100", func(page []byte) error {
		var batch []apiRepo
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding repos: %w", err)
		}
		repos = append(repos, batch...)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		setAttr(o.node, attrRepositories, "unknown", graph.NotVisible)
		k.cover(o.node.ID, attrRepositories, "could not list repositories: "+err.Error(), k.ownerFix(o))
		return nil
	}
	for _, r := range repos {
		id := "repo:" + o.login + "/" + r.Name
		n := k.node(id, graph.KindRepo, o.login+"/"+r.Name)
		vis := r.Visibility
		if vis == "" {
			vis = "public"
			if r.Private {
				vis = "private"
			}
		}
		setAttr(n, graph.AttrVisibility, vis, graph.Live)
		setAttr(n, graph.AttrArchived, strconv.FormatBool(r.Archived), graph.Live)
		setAttr(n, "fork", strconv.FormatBool(r.Fork), graph.Live)
		setAttr(n, "org", o.login, graph.Live)
		if r.DefaultBranch != "" {
			setAttr(n, "default_branch", r.DefaultBranch, graph.Live)
		}
		k.repoIDs[strings.ToLower(o.login+"/"+r.Name)] = id
		o.repos = append(o.repos, n)
	}
	if o.ownerVisible {
		setAttr(o.node, attrRepositories, strconv.Itoa(len(repos)), graph.Live)
	} else {
		// The count is what the token could see, not the org total.
		setAttr(o.node, attrRepositories, strconv.Itoa(len(repos)), graph.NotVisible)
		setAttr(o.node, "repositories_partial", "true", graph.Live)
		k.cover(o.node.ID, attrRepositories,
			"token is not an org owner: only repositories visible to the token are listed", k.ownerFix(o))
	}
	k.logf("collect: org %s: %d repos", o.login, len(repos))
	return nil
}

// canPush adds members -> repo edges when the org default permission grants push.
func (k *collector) canPush(o *orgState) {
	perm := o.node.Attrs[graph.AttrDefaultPerm]
	if (perm != "write" && perm != "admin") || o.node.AttrEvidence[graph.AttrDefaultPerm] != "" {
		return
	}
	mid := "members:" + o.login
	for _, r := range o.repos {
		k.edge(mid, r.ID, graph.CanPush, graph.Live, srcDefaultPerm, map[string]string{
			graph.AttrVia:       graph.ViaDefaultPerm,
			"permission":        perm,
			graph.AttrTwoFactor: o.node.Attrs[graph.AttrTwoFactor],
			graph.AttrSSO:       o.node.Attrs[graph.AttrSSO],
		})
	}
}

// ---- workflows ----

type contentEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func contentsPath(owner, repo, path, ref string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	p := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/contents/" + strings.Join(segs, "/")
	if ref != "" {
		p += "?ref=" + url.QueryEscape(ref)
	}
	return p
}

func (k *collector) getFile(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	var f contentEntry
	if err := k.c.GetJSON(ctx, contentsPath(owner, repo, path, ref), &f); err != nil {
		return nil, err
	}
	if f.Type != "" && f.Type != "file" {
		return nil, fmt.Errorf("%s is a %s, not a file", path, f.Type)
	}
	if f.Encoding != "base64" {
		return nil, fmt.Errorf("%s: unsupported content encoding %q (file too large?)", path, f.Encoding)
	}
	data, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(f.Content))
	if err != nil {
		return nil, fmt.Errorf("%s: decoding base64: %w", path, err)
	}
	return data, nil
}

func (k *collector) collectWorkflows(ctx context.Context, o *orgState, repo *graph.Node) error {
	name := strings.TrimPrefix(repo.ID, "repo:"+o.login+"/")
	full := o.login + "/" + name
	var raw json.RawMessage
	err := k.c.GetJSON(ctx, contentsPath(o.login, name, ".github/workflows", ""), &raw)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if IsNotFound(err) {
			setAttr(repo, "workflows", "0", graph.Live)
			return nil
		}
		setAttr(repo, "workflows", "unknown", graph.NotVisible)
		k.cover(repo.ID, "workflows", "could not list workflows: "+err.Error(), "read access to contents on "+full)
		return nil
	}
	var entries []contentEntry
	if json.Unmarshal(raw, &entries) != nil {
		setAttr(repo, "workflows", "0", graph.Live)
		return nil
	}
	count := 0
	for _, e := range entries {
		if e.Type != "file" || !isYAMLName(e.Name) {
			continue
		}
		data, err := k.getFile(ctx, o.login, name, e.Path, "")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			k.cover(repo.ID, "workflow:"+e.Path, "could not read workflow: "+err.Error(), "read access to contents on "+full)
			continue
		}
		count++
		wid := "workflow:" + full + "/" + e.Path
		wn := k.node(wid, graph.KindWorkflow, full+"/"+e.Path)
		setAttr(wn, "repo", full, graph.Live)
		setAttr(wn, "path", e.Path, graph.Live)
		k.edge(wid, repo.ID, graph.DefinedIn, graph.Live, srcWorkflowDir, nil)
		facts, err := ParseWorkflow(data)
		if err != nil {
			setAttr(wn, "parse_error", truncate(err.Error(), 200), graph.Live)
			k.cover(wid, "workflow_parse", err.Error(), "fix the workflow YAML in "+full)
			continue
		}
		k.addWorkflowFacts(wid, full, facts)
	}
	setAttr(repo, "workflows", strconv.Itoa(count), graph.Live)
	return nil
}

func (k *collector) addWorkflowFacts(wid, full string, f *WorkflowFacts) {
	for _, u := range f.Uses {
		k.addUse(wid, u, srcWorkflow, 1)
	}
	if f.IDTokenWrite {
		id := "oidc:" + full
		k.node(id, graph.KindOIDC, full+" OIDC token")
		k.edge(wid, id, graph.ExecutesWith, graph.Live, srcWorkflow, map[string]string{
			"permission": "id-token: write", "scopes": strings.Join(f.IDTokenScopes, ","),
		})
	}
	if f.HasSecrets() {
		id := "secret:" + full
		k.node(id, graph.KindSecret, full+" secrets")
		attrs := map[string]string{}
		if len(f.Secrets) > 0 {
			attrs["secrets"] = strings.Join(f.Secrets, ",")
		}
		if f.InheritsSecrets {
			attrs["inherit"] = "true"
		}
		k.edge(wid, id, graph.ExecutesWith, graph.Live, srcWorkflow, attrs)
	}
	if f.SelfHosted {
		id := "runner:" + full
		k.node(id, graph.KindRunner, full+" self-hosted runners")
		k.edge(wid, id, graph.ExecutesWith, graph.Live, srcWorkflow, map[string]string{
			"labels": strings.Join(f.RunnerLabels, ","),
		})
	}
}

// addUse records from -USES-> action and, for enterprise-internal targets,
// action -RESOLVES_TO-> repo, and queues the action for nested expansion.
func (k *collector) addUse(from string, u ActionUse, src string, depth int) {
	aid := "action:" + u.Raw
	an := k.node(aid, graph.KindActionRef, u.Raw)
	setAttr(an, "owner", u.Owner, graph.Live)
	setAttr(an, "repo", u.Repo, graph.Live)
	if u.Path != "" {
		setAttr(an, "path", u.Path, graph.Live)
	}
	setAttr(an, "ref", u.Ref, graph.Live)
	setAttr(an, graph.AttrRefKind, u.RefKind, graph.Live)
	if u.IsReusableWorkflow() {
		setAttr(an, "reusable_workflow", "true", graph.Live)
	}
	attrs := map[string]string{graph.AttrRefKind: u.RefKind, "level": u.Level}
	if u.Job != "" {
		attrs["job"] = u.Job
	}
	k.edge(from, aid, graph.Uses, graph.Live, src, attrs)

	org, inside := k.entOrgs[strings.ToLower(u.Owner)]
	setAttr(an, "in_enterprise", strconv.FormatBool(inside), graph.Live)
	if !inside {
		return
	}
	full := org + "/" + u.Repo
	rid, ok := k.repoIDs[strings.ToLower(full)]
	if !ok {
		rid = "repo:" + full
		rn := k.node(rid, graph.KindRepo, full)
		setAttr(rn, "org", org, graph.Live)
		setAttr(rn, "collected", "false", graph.Live)
		k.repoIDs[strings.ToLower(full)] = rid
	}
	k.edge(aid, rid, graph.ResolvesTo, graph.Live, srcOrgs, nil)
	if !k.expanded[aid] {
		k.expanded[aid] = true
		cu := u
		cu.Owner = org
		k.queue = append(k.queue, queued{id: aid, use: cu, depth: depth})
	}
}

// expandNested follows composite actions and reusable workflows inside the
// enterprise, up to MaxNestedDepth, never visiting a node twice.
func (k *collector) expandNested(ctx context.Context) error {
	for len(k.queue) > 0 {
		q := k.queue[0]
		k.queue = k.queue[1:]
		an := k.nodes[q.id]
		if q.depth > MaxNestedDepth {
			setAttr(an, attrNested, "unknown", graph.NotVisible)
			setAttr(an, "nested_reason", fmt.Sprintf("depth limit %d reached", MaxNestedDepth), graph.Live)
			continue
		}
		u := q.use
		var data []byte
		var err error
		var path string
		if u.IsReusableWorkflow() {
			path = u.Path
			data, err = k.getFile(ctx, u.Owner, u.Repo, path, u.Ref)
		} else {
			for _, fname := range []string{"action.yml", "action.yaml"} {
				path = strings.Trim(u.Path+"/"+fname, "/")
				data, err = k.getFile(ctx, u.Owner, u.Repo, path, u.Ref)
				if !IsNotFound(err) {
					break
				}
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			setAttr(an, attrNested, "unknown", graph.NotVisible)
			reason := "could not read " + path + " at " + u.Ref + ": " + err.Error()
			if IsNotFound(err) {
				reason = path + " not found at " + u.Ref + " (missing, or repository not visible to the token)"
			}
			k.cover(q.id, "nested_uses", reason, "read access to contents on "+u.Owner+"/"+u.Repo)
			continue
		}
		var nested []ActionUse
		if u.IsReusableWorkflow() {
			facts, perr := ParseWorkflow(data)
			if perr != nil {
				setAttr(an, attrNested, "unknown", graph.NotVisible)
				k.cover(q.id, "nested_uses", perr.Error(), "fix "+path+" in "+u.Owner+"/"+u.Repo)
				continue
			}
			nested = facts.Uses
		} else {
			uses, using, perr := ParseCompositeAction(data)
			if perr != nil {
				setAttr(an, attrNested, "unknown", graph.NotVisible)
				k.cover(q.id, "nested_uses", perr.Error(), "fix "+path+" in "+u.Owner+"/"+u.Repo)
				continue
			}
			if using != "" {
				setAttr(an, "runs_using", using, graph.Live)
			}
			nested = uses
		}
		setAttr(an, attrNested, strconv.Itoa(len(nested)), graph.Live)
		for _, nu := range nested {
			k.addUse(q.id, nu, srcNested, q.depth+1)
		}
	}
	return nil
}

// WriteGraph writes g as indented JSON.
func WriteGraph(w io.Writer, g *graph.Graph) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}
