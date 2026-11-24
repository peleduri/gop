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

	// GitHub App mode (mutually exclusive with Token). gop signs an App JWT,
	// lists the App's installations and mints one read-only installation
	// token per org. Enterprise-level APIs are skipped.
	//
	// AppID is the App's numeric ID.
	AppID int64
	// AppPrivateKeyPEM is the App's PEM private key. It is held in memory
	// only and never logged, printed, written or put in an error.
	AppPrivateKeyPEM []byte
	// AppPermissions are requested for every installation token (default
	// DefaultAppPermissions). Every value must be "read".
	AppPermissions map[string]string

	// Host is the GitHub host, "github.com" or a GitHub Enterprise Server
	// host such as "github.acme.example". Empty derives it from BaseURL
	// (HostOf). On GHES gop reads the server version and skips the
	// collectors it does not support (ghes.go).
	Host string

	// Client options, used when Client is nil.
	BaseURL     string
	GraphQLURL  string
	MaxAttempts int
	Logf        func(format string, args ...any)
	// Verbose logs every per-repository not-visible error (for example a
	// repository whose collaborators the token cannot list) as it happens.
	// By default they are counted and logged as one summary line per org and
	// fact; the coverage entries are the same either way.
	Verbose bool

	// Client overrides the options above when set.
	Client *Client

	// BatchSize is how many repositories (or nested references) one batched
	// GraphQL query reads (default DefaultBatchSize). It halves on its own
	// when GitHub reports a query too expensive.
	BatchSize int
	// DisableGraphQLBatch reads every workflow and action file over REST,
	// one request per file (for GHES versions that lack the GraphQL fields,
	// and for debugging).
	DisableGraphQLBatch bool
	// Progress, when set, receives progress updates. When nil and Logf is
	// set, a line is logged at most every 5 seconds.
	Progress func(Progress)

	// CacheDir, when set, turns on the on-disk REST response cache
	// (cache.go): cached GETs are revalidated with If-None-Match or
	// If-Modified-Since, and a 304 serves the cached body. Empty (the
	// default) means no cache. The directory holds API responses, as
	// sensitive as graph.json; gop creates it 0700 and refuses one other
	// users can read.
	CacheDir string
	// Resume, with CacheDir, reuses without a request every entry the
	// interrupted previous run (same enterprise and orgs) fetched.
	Resume bool
	// MergeInto, with Orgs, re-collects only Orgs and merges the result into
	// this earlier graph of the same enterprise (Merge): cross-org references
	// from the re-collected orgs resolve to MergeInto's repo nodes instead of
	// stubs, and actions of the re-collected orgs that other orgs use are
	// read again. Collect then returns the merged graph. It is read, never
	// modified.
	MergeInto *graph.Graph
	// MergeForce lets MergeInto merge graphs collected with different
	// enterprise visibility (MergeOptions.Force).
	MergeForce bool

	// MaxRequests, when positive, stops the run after that many HTTP
	// requests (responses the cache serves without a request do not count)
	// and returns a partial graph with a *PartialError.
	MaxRequests int
	// Reserve, when positive, keeps that many requests of the rate limit
	// unspent for other jobs on the same token: before a request that would
	// leave fewer, the run waits for the reset, and stops partial when it
	// cannot (the reset time is unknown or more than an hour away).
	Reserve int
	// Priority lists orgs to collect first, in this order. The rest follow
	// by member count, largest first, then in listed order.
	Priority []string
}

// Source API labels recorded on edges and used in coverage.
const (
	srcOrgs        = "graphql:enterprise.organizations"
	srcDefaultPerm = "graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations"
	srcWorkflowDir = "rest:GET /repos/{owner}/{repo}/contents/.github/workflows"
	srcWorkflow    = "rest:GET /repos/{owner}/{repo}/contents/{path}"
	srcNested      = "rest:GET /repos/{owner}/{repo}/contents/{path}?ref={ref}"
	srcLicenses    = "rest:GET /enterprises/{enterprise}/consumed-licenses"
	srcCollabs     = "rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct"
	srcOutside     = "rest:GET /orgs/{org}/outside_collaborators"
	srcTeams       = "rest:GET /orgs/{org}/teams"
	srcTeamMembers = "rest:GET /orgs/{org}/teams/{team_slug}/members?role=all"
	srcTeamRepos   = "rest:GET /orgs/{org}/teams/{team_slug}/repos"
)

// Attribute keys this package adds beyond the graph contract.
const (
	attrRepositories = "repositories"
	attrOwners       = "owners"
	attrNested       = "nested"
	attrCollabs      = "collaborators"
	attrPermission   = "permission"
	attrBaseRole     = "base_role"
	attrRole         = "role"
	attrDynamicUses  = "dynamic_uses"
	attrCollected    = "collected"
)

type orgState struct {
	login        string
	archived     bool
	node         *graph.Node
	ownerVisible bool
	repos        []*graph.Node
	owners       []string        // logins with the Owner role (consumed licenses), sorted
	outside      map[string]bool // lower login -> true for outside collaborators
	customRoles  map[string]string
	rolesLoaded  bool
	rest         *apiOrg // GET /orgs/{org}, read only when the enterprise is not visible
	// collabErr is the first error listing a repository's collaborators.
	collabErr error
	// notVisible counts per-repository not-visible errors by fact until the
	// org's summary line is logged (notvisible.go).
	notVisible map[string]*notVisibleTally
	// workflowDefault caches the org's default workflow permissions (token.go).
	workflowDefault *orgWorkflowDefault
}

// repoGrant is a repository-scoped role from the consumed-licenses list, e.g.
// "acme-actions/deploy:Write". It proves a grant exists, not that it allows push.
type repoGrant struct {
	login string
	role  string
}

type queued struct {
	id    string
	use   ActionUse
	depth int
}

type collector struct {
	// codeowners is each repo's parsed CODEOWNERS (absent: none or unread),
	// policy the policy files found per repo (policyfiles.go).
	codeowners map[string]Codeowners
	policy     map[string][]string
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
	idByLower  map[string]string      // lower login -> identity node id
	repoGrants map[string][]repoGrant // lower "owner/repo" -> license grants
	// app is set in GitHub App mode (app.go).
	app *appAuth
	// entHidden is set when the token cannot read the enterprise; orgs then
	// come from cfg.Orgs or discovery (orgscope.go).
	entHidden     bool
	orgsSrc       string                 // source API of the org list
	unknownOwners map[string]string      // lower login -> login of action owners with in_enterprise=unknown
	oidcEdges     []*oidcEdge            // OIDC edges that call reusable workflows (oidcclaims.go)
	calledOIDC    map[string]*calledOIDC // action id -> reusable workflow that mints a token
	// batch is the batched GraphQL file reader state (batch.go).
	batch batchState
	// protOff disables batched branch protection reads after a query GitHub
	// does not support (hardening.go); rulesetBypass caches ruleset bypass
	// actors read over REST by ruleset ID.
	protOff       bool
	rulesetBypass map[int64]*apiRulesetBypass
	// collabOff disables batched collaborator reads after a query GitHub
	// does not support (collabbatch.go).
	collabOff bool
	// progressFn receives progress updates (progress.go); nil means none.
	progressFn func(Progress)
	// host is the GitHub host; ghes is set when it is a GitHub Enterprise
	// Server, and ghesVersion holds its version once read ("" = unknown).
	host        string
	ghes        bool
	ghesVersion string
	// locks holds each repo's parsed actions.lock, by repo node ID (actionslock.go).
	locks map[string]*actionsLock
	// botLines holds the line of each bot merge workflow's merging step, by
	// workflow node ID (botmerge.go).
	botLines map[string]int
	// botFacts holds each workflow's bot facts by node ID, and botScriptWFs
	// the workflows whose steps run repo scripts to follow (botscript.go).
	botFacts     map[string]*botFacts
	botScriptWFs []botScriptWF

	// actionsApproveOrg caches each org's "allow GitHub Actions to approve
	// pull requests" setting (botapprove.go).
	actionsApproveOrg map[string]*orgCanApprove
	// followWFs are the workflows whose trigger and agent facts wait for
	// the files one level down, and calledWFs the reusable workflows the
	// nested expansion read, by action node ID (indirect.go).
	followWFs []followWF
	calledWFs map[string][]byte
	// scanned holds the files read for scanning, by repo, path and ref (readScanned).
	scanned map[string]scannedFile

	// phase is the run step in progress and phaseOrg the index in orgs of
	// the org a per-org phase is on, for the coverage of a stopped run
	// (partial.go).
	phase    string
	phaseOrg int
}

// Collect reads the enterprise and returns the evidence graph.
func Collect(ctx context.Context, cfg Config) (*graph.Graph, error) {
	if cfg.Enterprise == "" {
		return nil, errors.New("collect: enterprise slug is required")
	}
	if err := cfg.validateAuth(); err != nil {
		return nil, err
	}
	if err := cfg.checkMergeInto(); err != nil {
		return nil, err
	}
	c := cfg.Client
	if c == nil {
		var err error
		c, err = newClient(ClientOptions{
			BaseURL: cfg.BaseURL, GraphQLURL: cfg.GraphQLURL, Token: cfg.Token,
			MaxAttempts: cfg.MaxAttempts, Logf: cfg.Logf,
		}, !cfg.appMode())
		if err != nil {
			return nil, err
		}
	}
	if cfg.MaxRequests < 0 || cfg.Reserve < 0 {
		return nil, errors.New("collect: MaxRequests and Reserve must not be negative")
	}
	// Running out of the request budget or the rate limit cancels ctx with
	// the cause, so every step stops as on an interrupt (budget.go).
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	budget := &requestBudget{max: cfg.MaxRequests, reserve: cfg.Reserve, stop: stop}
	c = c.withBudget(budget)
	var cache *responseCache
	if cfg.CacheDir != "" {
		var err error
		if cache, err = openCache(cfg.CacheDir); err != nil {
			return nil, err
		}
		c = c.withCache(cache)
	}
	var app *appAuth
	if cfg.appMode() {
		var err error
		if app, err = newAppAuth(cfg, c); err != nil {
			return nil, err
		}
		// Every App-mode request goes through an org's installation client.
		c = c.WithTokenSource(noTokenSource{})
	}
	k := &collector{
		c: c, cfg: cfg, now: time.Now().UTC(), enterprise: cfg.Enterprise,
		nodes: map[string]*graph.Node{}, edges: map[string]*graph.Edge{},
		covSeen: map[string]bool{}, byLower: map[string]*orgState{},
		entOrgs: map[string]string{}, repoIDs: map[string]string{}, expanded: map[string]bool{},
		idByLower: map[string]string{}, codeowners: map[string]Codeowners{}, policy: map[string][]string{}, repoGrants: map[string][]repoGrant{}, orgsSrc: srcOrgs, app: app,
		batch: newBatchState(cfg), progressFn: progressFunc(cfg),
		host: cfg.host(),
	}
	k.ghes = isGHES(k.host)
	if cache != nil {
		resumed, err := cache.beginRun(cfg.Enterprise, cfg.Orgs, cfg.Resume, k.now)
		if err != nil {
			return nil, err
		}
		if resumed {
			k.logf("collect: cache: resuming the interrupted run started %s", cache.resumeSince.UTC().Format(time.RFC3339))
		}
	}
	runErr := k.run(ctx)
	if runErr == nil && ctx.Err() != nil {
		// A step that records a failed request as coverage may have
		// finished after the stop.
		runErr = context.Cause(ctx)
	}
	if runErr != nil {
		reason := partialReason(ctx, runErr)
		if reason == "" {
			return nil, runErr
		}
		return k.stopped(cache, reason, runErr, budget.Sent())
	}
	g := k.graph()
	k.logCoverage(g)
	if cache != nil {
		st := cache.Stats()
		k.logf("collect: cache %d hits (304), %d fetched, %d resumed", st.Hits, st.Fetched, st.Resumed)
		if err := cache.endRun(); err != nil {
			k.logf("collect: cache: removing %s: %v", cacheRunFile, err)
		}
	}
	if cfg.MergeInto != nil {
		return MergeWith(cfg.MergeInto, g, cfg.Orgs, MergeOptions{Force: cfg.MergeForce})
	}
	return g, nil
}

// stopped returns the partial graph of a run stopped for reason, with a
// *PartialError. The cache keeps its run file, so --resume continues the run.
func (k *collector) stopped(cache *responseCache, reason string, cause error, sent int) (*graph.Graph, error) {
	phase := k.phase
	g := k.partialGraph(reason)
	k.logCoverage(g)
	k.logf("collect: stopped (%s) in the %s phase after %d requests: the graph is partial", reason, phase, sent)
	if cache != nil {
		st := cache.Stats()
		k.logf("collect: cache %d hits (304), %d fetched, %d resumed; --resume continues from here", st.Hits, st.Fetched, st.Resumed)
	}
	if k.cfg.MergeInto != nil {
		merged, err := MergeWith(k.cfg.MergeInto, g, k.cfg.Orgs, MergeOptions{Force: k.cfg.MergeForce})
		if err != nil {
			return nil, err
		}
		g = merged
	}
	return g, &PartialError{Reason: reason, Err: cause}
}

// logCoverage logs one line per org (and the enterprise) that has unknown
// facts: how much of the graph is not_visible and how many coverage entries
// explain it.
func (k *collector) logCoverage(g *graph.Graph) {
	for _, c := range graph.CoverageSummary(g) {
		if c.NotVisibleNodes+c.NotVisibleEdges+c.NotVisibleAttrs+c.Entries == 0 {
			continue
		}
		k.logf("collect: coverage %s: %d not_visible nodes, %d edges, %d attrs, %d entries",
			strings.TrimPrefix(c.Org, "org:"), c.NotVisibleNodes, c.NotVisibleEdges, c.NotVisibleAttrs, c.Entries)
	}
}

func (k *collector) run(ctx context.Context) error {
	ent := k.node("enterprise:"+k.enterprise, graph.KindEnterprise, k.enterprise)
	collectOrgs := k.collectOrgs
	if k.app != nil {
		collectOrgs = k.collectOrgsApp
	}
	k.enter(PhaseOrgs)
	if err := collectOrgs(ctx); err != nil {
		return err
	}
	k.orderOrgs(false)
	k.warnPriority()
	if err := k.detectGHES(ctx, ent); err != nil {
		return err
	}
	k.progress(PhaseOrgs, len(k.orgs), len(k.orgs))
	if k.entHidden {
		setAttr(ent, "orgs", "unknown", graph.NotVisible)
	} else {
		ent.Attrs["orgs"] = strconv.Itoa(len(k.entOrgs))
	}
	k.seedFromBase()
	k.enter(PhaseSettings)
	if err := k.collectSettings(ctx); err != nil {
		return err
	}
	k.progress(PhaseSettings, 1, 1)
	k.enter(PhaseMembers)
	if err := k.collectMembers(ctx); err != nil {
		return err
	}
	k.progress(PhaseMembers, 1, 1)
	k.orderOrgs(true)
	k.enter(PhaseRepos)
	for i, o := range k.orgs {
		k.phaseOrg = i
		if o.archived {
			k.cover(o.node.ID, attrRepositories, "organization is archived; not collected",
				"none: archived organizations cannot run workflows")
			k.progress(PhaseRepos, i+1, len(k.orgs))
			continue
		}
		if err := k.collectOwnerView(ctx, o); err != nil {
			return err
		}
		if err := k.collectRepos(ctx, o); err != nil {
			return err
		}
		k.canPush(o)
		if err := k.collectPushGrants(ctx, o); err != nil {
			return err
		}
		if err := k.collectTeams(ctx, o); err != nil {
			return err
		}
		// Owner edges come after collaborator edges: k.edge keeps the first edge
		// per (from, kind, to), so a direct grant to an owner keeps via=direct.
		k.ownerPush(o)
		k.flushNotVisible(o)
		k.progress(PhaseRepos, i+1, len(k.orgs))
	}
	k.enter(PhaseWorkflows)
	if err := k.collectAllWorkflows(ctx); err != nil {
		return err
	}
	k.seedBaseActions()
	k.enter(PhaseNested)
	if err := k.expandNested(ctx); err != nil {
		return err
	}
	k.applyActionsLocks()
	k.linkJobWorkflowRefs()
	k.coverUnknownOwners()
	k.pushToStubs()
	k.enter(phaseActionsAccess)
	if err := k.collectActionsAccess(ctx); err != nil {
		return err
	}
	k.enter(phaseRefs)
	if err := k.resolveRefs(ctx); err != nil {
		return err
	}
	k.enter(phaseTags)
	if err := k.collectTagImmutability(ctx); err != nil {
		return err
	}
	k.enter(PhaseProtection)
	if err := k.collectBranchProtection(ctx); err != nil {
		return err
	}
	k.enter(phaseIndirect)
	if err := k.followIndirect(ctx); err != nil {
		return err
	}
	k.enter(phaseBotScripts)
	if err := k.followBotScripts(ctx); err != nil {
		return err
	}
	k.enter(phaseActionsApprov)
	if err := k.collectActionsApprove(ctx); err != nil {
		return err
	}
	k.addBotMergePaths()
	k.enter(phasePolicyFiles)
	if err := k.collectPolicyFiles(ctx); err != nil {
		return err
	}
	k.enter(phaseRefProtection)
	return k.collectRefProtection(ctx)
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
	k.edges[key] = &graph.Edge{From: from, To: to, Kind: kind, Evidence: ev, SourceAPI: src, ObservedAt: k.observedAt(), Attrs: attrs}
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
	sortEdges(g.Edges)
	if len(k.orgs) > 0 {
		g.OrgCollectedAt = make(map[string]time.Time, len(k.orgs))
		for _, o := range k.orgs {
			g.OrgCollectedAt[o.login] = k.now
		}
	}
	return g
}

// sortEdges orders edges by (from, kind, to), then parallel edges (a grant
// next to a via=ref_bypass edge per branch) by via and ref.
func sortEdges(edges []graph.Edge) {
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Attrs[graph.AttrVia] != b.Attrs[graph.AttrVia] {
			return a.Attrs[graph.AttrVia] < b.Attrs[graph.AttrVia]
		}
		return a.Attrs[graph.AttrRef] < b.Attrs[graph.AttrRef]
	})
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
			if after != nil {
				return fmt.Errorf("collect: enterprise %q: organizations page not returned: %v", k.enterprise, gqlErrs)
			}
			// Org-scoped App tokens, non-owner PATs and tokens without
			// read:enterprise land here: collect per org instead of failing.
			return k.collectOrgsWithoutEnterprise(ctx, gqlErrs)
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
	return settingOrgs(ctx, k.c, k.enterprise, field, value)
}

// settingOrgs returns the logins in one ownerInfo list of enterprise, read
// with c and following pagination.
func settingOrgs(ctx context.Context, c *Client, enterprise, field, value string) ([]string, error) {
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
		gqlErrs, err := c.GraphQL(ctx, q, map[string]any{"slug": enterprise, "after": after}, &data)
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
	if k.entHidden {
		k.collectSettingsPerOrg()
		return nil
	}
	if reason, fix, skip := k.ghesGate(capEnterpriseSettings); skip {
		for _, spec := range settingSpecs {
			k.cover("enterprise:"+k.enterprise, spec.attr, reason, fix)
			for _, o := range k.orgs {
				setAttr(o.node, spec.attr, "unknown", graph.NotVisible)
			}
		}
		return nil
	}
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

// identity returns the identity node for a login, matching logins case-insensitively.
func (k *collector) identity(login string) *graph.Node {
	if id, ok := k.idByLower[strings.ToLower(login)]; ok {
		return k.nodes[id]
	}
	id := "identity:" + login
	k.idByLower[strings.ToLower(login)] = id
	return k.node(id, graph.KindIdentity, login)
}

// collectMembers reads the enterprise consumed licenses. Every licensed user
// becomes an identity node with a MEMBER_OF edge per collected org membership.
// Org owners are kept for ownerPush; repository-scoped roles are kept for
// collectPushGrants and never become edges on their own.
func (k *collector) collectMembers(ctx context.Context) error {
	members := map[string]map[string]bool{}
	owners := map[string]map[string]bool{}
	path := "/enterprises/" + url.PathEscape(k.enterprise) + "/consumed-licenses?per_page=100"
	var err error
	ghesReason, ghesFix, ghesSkip := k.ghesGate(capConsumedLicenses)
	switch {
	case k.app != nil:
		// Installation tokens cannot read the enterprise: members come from
		// each org's members API instead.
		err = errAppMode
	case ghesSkip:
		err = errors.New(ghesReason)
	default:
		err = k.collectLicenses(ctx, path, members, owners)
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		reason, fix := "could not read consumed licenses: "+err.Error(), "enterprise owner on "+k.enterprise
		switch {
		case k.app != nil:
			reason, fix = appEnterpriseReason+": consumed licenses are not read; members come from "+srcOrgMembers, enterpriseFix
		case ghesSkip:
			reason, fix = ghesReason+"; members come from "+srcOrgMembers, ghesFix
		}
		k.cover("enterprise:"+k.enterprise, graph.AttrMembers, reason, fix)
	}
	return k.finishMembers(ctx, err, members, owners, ghesSkip)
}

// collectLicenses reads the enterprise consumed licenses into members and owners.
func (k *collector) collectLicenses(ctx context.Context, path string, members, owners map[string]map[string]bool) error {
	return k.c.GetPages(ctx, path, func(page []byte) error {
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
			idn := k.identity(u.Login)
			for _, role := range u.Roles {
				i := strings.LastIndex(role, ":")
				if i <= 0 {
					continue
				}
				scope, r := role[:i], role[i+1:]
				if strings.Contains(scope, "/") {
					// Repository role: too coarse to prove push access by itself.
					key := strings.ToLower(scope)
					k.repoGrants[key] = append(k.repoGrants[key], repoGrant{login: u.Login, role: r})
					continue
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
				if o, ok := k.byLower[org]; ok {
					k.edge(idn.ID, o.node.ID, graph.MemberOf, graph.Live, srcLicenses,
						map[string]string{attrRole: strings.ToLower(r)})
				}
			}
		}
		return nil
	})
}

// finishMembers sets each collected org's member counts and owners, from the
// licenses or, when they could not be read, from the org members API.
//
// perOrg makes the org members API the fallback even when the enterprise is
// visible (a GHES version without consumed licenses).
func (k *collector) finishMembers(ctx context.Context, err error, members, owners map[string]map[string]bool, perOrg bool) error {
	for _, o := range k.orgs {
		mn := k.node("members:"+o.login, graph.KindOrgMembers, o.login+" members")
		if err != nil {
			if k.entHidden || perOrg {
				if ferr := k.collectOrgMembers(ctx, o, mn); ferr != nil {
					return ferr
				}
				continue
			}
			setAttr(o.node, graph.AttrMembers, "unknown", graph.NotVisible)
			setAttr(mn, graph.AttrMembers, "unknown", graph.NotVisible)
			continue
		}
		m := strconv.Itoa(len(members[strings.ToLower(o.login)]))
		setAttr(o.node, graph.AttrMembers, m, graph.Live)
		setAttr(o.node, attrOwners, strconv.Itoa(len(owners[strings.ToLower(o.login)])), graph.Live)
		setAttr(mn, graph.AttrMembers, m, graph.Live)
		for l := range owners[strings.ToLower(o.login)] {
			o.owners = append(o.owners, l)
		}
		sort.Strings(o.owners)
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
	return orgOwnerFix(o.login, o.node.Attrs[graph.AttrSSO] == "enforced")
}

// orgOwnerFix is the coverage fix for a fact only an owner of org can read.
// gop doctor prints the same line for the facts it predicts.
func orgOwnerFix(org string, ssoEnforced bool) string {
	fix := "org owner on " + org
	if ssoEnforced {
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
	gqlErrs, err := k.cl(o.login).GraphQL(ctx, ownerViewQuery, map[string]any{"login": o.login}, &data)
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
		// The ip_allow_list coverage entry covers the details too.
		setAttr(o.node, graph.AttrIPAllowListEntries, "unknown", graph.NotVisible)
		setAttr(o.node, graph.AttrIPAllowListApps, "unknown", graph.NotVisible)
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
	return k.collectIPAllowDetails(ctx, o)
}

// ipAllowDetailsQuery reads, for an org owner, whether the IP allow list also
// applies to installed GitHub Apps and which entries are active. Only
// isActive is read: entry values (IP ranges) never enter the graph. It is a
// separate query so a server without these fields keeps ip_allow_list.
const ipAllowDetailsQuery = `query($login: String!, $after: String) {
  organization(login: $login) {
    ipAllowListForInstalledAppsEnabledSetting
    ipAllowListEntries(first: 100, after: $after) {
      nodes { isActive }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

// collectIPAllowDetails sets ip_allow_list_apps and ip_allow_list_entries
// (the active entry count) for an org whose owner view is visible.
func (k *collector) collectIPAllowDetails(ctx context.Context, o *orgState) error {
	apps, active := "", 0
	var after any
	var reason string
	for reason == "" {
		var data struct {
			Organization *struct {
				Apps    *string `json:"ipAllowListForInstalledAppsEnabledSetting"`
				Entries *struct {
					Nodes []struct {
						IsActive bool `json:"isActive"`
					} `json:"nodes"`
					PageInfo pageInfo `json:"pageInfo"`
				} `json:"ipAllowListEntries"`
			} `json:"organization"`
		}
		gqlErrs, err := k.cl(o.login).GraphQL(ctx, ipAllowDetailsQuery, map[string]any{"login": o.login, "after": after}, &data)
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case err != nil:
			reason = "could not read IP allow list details: " + err.Error()
		case data.Organization == nil || data.Organization.Entries == nil:
			reason = "IP allow list details not returned"
			if len(gqlErrs) > 0 {
				reason += ": " + gqlErrs.Error()
			}
		}
		if reason != "" {
			break
		}
		if after == nil && data.Organization.Apps != nil {
			apps = "off"
			if *data.Organization.Apps == "ENABLED" {
				apps = "on"
			}
		}
		for _, n := range data.Organization.Entries.Nodes {
			if n.IsActive {
				active++
			}
		}
		pi := data.Organization.Entries.PageInfo
		if !pi.HasNextPage || pi.EndCursor == "" {
			break
		}
		after = pi.EndCursor
	}
	if reason != "" {
		setAttr(o.node, graph.AttrIPAllowListEntries, "unknown", graph.NotVisible)
		setAttr(o.node, graph.AttrIPAllowListApps, "unknown", graph.NotVisible)
		k.cover(o.node.ID, graph.AttrIPAllowListEntries, reason, k.ownerFix(o))
		return nil
	}
	setAttr(o.node, graph.AttrIPAllowListEntries, strconv.Itoa(active), graph.Live)
	if apps == "" {
		setAttr(o.node, graph.AttrIPAllowListApps, "unknown", graph.NotVisible)
		k.cover(o.node.ID, graph.AttrIPAllowListApps, "ipAllowListForInstalledAppsEnabledSetting not returned", k.ownerFix(o))
		return nil
	}
	setAttr(o.node, graph.AttrIPAllowListApps, apps, graph.Live)
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
	// SecurityAndAnalysis is null or absent unless the token is a repo
	// admin, org owner or security manager.
	SecurityAndAnalysis *apiSecurityAnalysis `json:"security_and_analysis"`
}

func (k *collector) collectRepos(ctx context.Context, o *orgState) error {
	var repos []apiRepo
	err := k.cl(o.login).GetPages(ctx, "/orgs/"+url.PathEscape(o.login)+"/repos?type=all&per_page=100", func(page []byte) error {
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
		k.cover(o.node.ID, attrRepositories, "could not list repositories: "+err.Error(), k.fixFor(err, k.ownerFix(o)))
		return nil
	}
	var secrets secretTally
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
		if !r.Archived {
			applySecretScanning(n, r.SecurityAndAnalysis, &secrets)
		}
		k.repoIDs[strings.ToLower(o.login+"/"+r.Name)] = id
		o.repos = append(o.repos, n)
	}
	k.coverSecretScanning(o, secrets)
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

// canPush adds members -> repo edges when the org default permission grants
// push. They are inferred (rule default_perm): derived from the org setting,
// not read from each repo's permission list.
func (k *collector) canPush(o *orgState) {
	perm := o.node.Attrs[graph.AttrDefaultPerm]
	if o.node.AttrEvidence[graph.AttrDefaultPerm] == graph.NotVisible {
		k.cover(o.node.ID, "can_push:default_perm",
			"default repository permission not visible: members' push access through it is unknown",
			"enterprise owner on "+k.enterprise+", or "+k.ownerFix(o))
	}
	if (perm != "write" && perm != "admin") || o.node.AttrEvidence[graph.AttrDefaultPerm] != "" {
		return
	}
	mid := "members:" + o.login
	src := srcDefaultPerm
	if k.entHidden {
		src = srcOrgREST
	}
	for _, r := range o.repos {
		k.edge(mid, r.ID, graph.CanPush, graph.Inferred, src, map[string]string{
			graph.AttrVia:       graph.ViaDefaultPerm,
			graph.AttrRule:      graph.RuleDefaultPerm,
			"permission":        perm,
			graph.AttrTwoFactor: o.node.Attrs[graph.AttrTwoFactor],
			graph.AttrSSO:       o.node.Attrs[graph.AttrSSO],
		})
	}
}

// ownerPush adds identity -> repo edges for every owner of the org: an org
// owner is admin on every repository in it. They are inferred (rule
// org_owner) from the owner list, not read from each repo.
func (k *collector) ownerPush(o *orgState) {
	for _, login := range o.owners {
		idn := k.identity(login)
		for _, r := range o.repos {
			k.edge(idn.ID, r.ID, graph.CanPush, graph.Inferred, srcLicenses, map[string]string{
				graph.AttrVia: graph.ViaOrgOwner, graph.AttrRule: graph.RuleOrgOwner, attrPermission: "admin",
			})
		}
	}
}

// collectPushGrants lists the org's outside collaborators, then the direct
// collaborators of every non-archived repository, and records push grants.
// Repositories whose collaborators the token cannot list get one org-level
// coverage entry and not_visible edges for the license grants on them.
func (k *collector) collectPushGrants(ctx context.Context, o *orgState) error {
	if err := k.collectOutside(ctx, o); err != nil {
		return err
	}
	pre, err := k.prefetchCollaborators(ctx, o)
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range o.repos {
		if r.Attrs[graph.AttrArchived] == "true" {
			continue
		}
		if collabs, ok := pre[r.ID]; ok {
			k.applyCollaborators(ctx, o, r, collabs)
			continue
		}
		ok, err := k.collectCollaborators(ctx, o, r)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		failed++
		setAttr(r, attrCollabs, "unknown", graph.NotVisible)
		full := strings.TrimPrefix(r.ID, "repo:")
		for _, g := range k.repoGrants[strings.ToLower(full)] {
			idn := k.identity(g.login)
			k.edge(idn.ID, r.ID, graph.CanPush, graph.NotVisible, srcLicenses, map[string]string{
				graph.AttrVia: k.via(o, g.login), attrPermission: "unknown", "license_role": g.role,
			})
		}
	}
	if failed > 0 {
		k.cover(o.node.ID, "can_push:collaborators",
			fmt.Sprintf("could not list collaborators on %d repos (needs push access)", failed),
			k.fixFor(o.collabErr, k.ownerFix(o)+", or push access on each repository"))
	}
	return nil
}

// via labels a direct grant: outside collaborators are users who are not org members.
func (k *collector) via(o *orgState, login string) string {
	if o.outside[strings.ToLower(login)] {
		return graph.ViaOutsideCollaborator
	}
	return graph.ViaDirect
}

// collectOutside reads the org's outside collaborators once. They hold no org
// membership (no MEMBER_OF edge) but still get identity nodes.
func (k *collector) collectOutside(ctx context.Context, o *orgState) error {
	o.outside = map[string]bool{}
	var logins []string
	err := k.cl(o.login).GetPages(ctx, "/orgs/"+url.PathEscape(o.login)+"/outside_collaborators?per_page=100", func(page []byte) error {
		var batch []struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding outside collaborators: %w", err)
		}
		for _, u := range batch {
			if u.Login != "" {
				logins = append(logins, u.Login)
			}
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		k.cover(o.node.ID, "outside_collaborators",
			"could not list outside collaborators: "+err.Error()+"; direct grants are labelled via=direct",
			k.fixFor(err, k.ownerFix(o)))
		return nil
	}
	for _, l := range logins {
		o.outside[strings.ToLower(l)] = true
		k.identity(l)
	}
	return nil
}

type apiPermissions struct {
	Push     bool `json:"push"`
	Maintain bool `json:"maintain"`
	Admin    bool `json:"admin"`
}

// canPush reports whether repository permissions include push.
func (p apiPermissions) canPush() bool { return p.Push || p.Maintain || p.Admin }

// pushRole is the role recorded on a CAN_PUSH edge: the API's role_name (which
// names custom repository roles), or the highest built-in role the permissions imply.
func pushRole(roleName string, p apiPermissions) string {
	if roleName != "" {
		return roleName
	}
	switch {
	case p.Admin:
		return "admin"
	case p.Maintain:
		return "maintain"
	}
	return "write"
}

type apiCollaborator struct {
	Login       string         `json:"login"`
	RoleName    string         `json:"role_name"`
	Permissions apiPermissions `json:"permissions"`
}

// builtinRoles are the repository roles GitHub defines; any other role_name is
// a custom repository role.
var builtinRoles = map[string]bool{"read": true, "pull": true, "triage": true, "write": true, "push": true, "maintain": true, "admin": true}

// collectCollaborators lists a repository's direct collaborators and adds a
// CAN_PUSH edge for each one whose permissions include push. It reports false
// when the list could not be read (403/404 or another API error).
func (k *collector) collectCollaborators(ctx context.Context, o *orgState, repo *graph.Node) (bool, error) {
	name := strings.TrimPrefix(repo.ID, "repo:"+o.login+"/")
	var collabs []apiCollaborator
	path := "/repos/" + url.PathEscape(o.login) + "/" + url.PathEscape(name) + "/collaborators?affiliation=direct&per_page=100"
	err := k.cl(o.login).GetPages(ctx, path, func(page []byte) error {
		var batch []apiCollaborator
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding collaborators: %w", err)
		}
		collabs = append(collabs, batch...)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		k.repoNotVisible(o, "collaborators", repo.ID, err)
		if o.collabErr == nil {
			o.collabErr = err
		}
		return false, nil
	}
	k.applyCollaborators(ctx, o, repo, collabs)
	return true, nil
}

// applyCollaborators adds a CAN_PUSH edge for each collaborator whose
// permissions include push. The REST and batched GraphQL reads both end here.
func (k *collector) applyCollaborators(ctx context.Context, o *orgState, repo *graph.Node, collabs []apiCollaborator) {
	for _, c := range collabs {
		p := c.Permissions
		if c.Login == "" || !p.canPush() {
			continue
		}
		role := pushRole(c.RoleName, p)
		attrs := map[string]string{graph.AttrVia: k.via(o, c.Login), attrPermission: role}
		if !builtinRoles[strings.ToLower(role)] {
			if base := k.baseRole(ctx, o, role); base != "" {
				attrs[attrBaseRole] = base
			}
		}
		idn := k.identity(c.Login)
		k.edge(idn.ID, repo.ID, graph.CanPush, graph.Live, srcCollabs, attrs)
	}
}

// baseRole returns the base role of a custom repository role, reading the org's
// custom roles once. Failure is coverage only: permissions.push already decides reach.
func (k *collector) baseRole(ctx context.Context, o *orgState, role string) string {
	if !o.rolesLoaded {
		o.rolesLoaded = true
		o.customRoles = map[string]string{}
		var body struct {
			CustomRoles []struct {
				Name     string `json:"name"`
				BaseRole string `json:"base_role"`
			} `json:"custom_roles"`
		}
		if err := k.cl(o.login).GetJSON(ctx, "/orgs/"+url.PathEscape(o.login)+"/custom-repository-roles", &body); err != nil {
			if ctx.Err() == nil {
				k.cover(o.node.ID, "custom_repository_roles", "could not read custom repository roles: "+err.Error(),
					k.fixFor(err, k.ownerFix(o)))
			}
		} else {
			for _, r := range body.CustomRoles {
				o.customRoles[strings.ToLower(r.Name)] = r.BaseRole
			}
		}
	}
	return o.customRoles[strings.ToLower(role)]
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
	if err := k.cl(owner).GetJSON(ctx, contentsPath(owner, repo, path, ref), &f); err != nil {
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
	err := k.cl(o.login).GetJSON(ctx, contentsPath(o.login, name, ".github/workflows", ""), &raw)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if IsNotFound(err) {
			setAttr(repo, "workflows", "0", graph.Live)
			return nil
		}
		setAttr(repo, "workflows", "unknown", graph.NotVisible)
		k.cover(repo.ID, "workflows", "could not list workflows: "+err.Error(), k.fixFor(err, "read access to contents on "+full))
		return nil
	}
	var entries []contentEntry
	if json.Unmarshal(raw, &entries) != nil {
		// A file, a submodule or another shape: the workflows are unknown, not absent.
		setAttr(repo, "workflows", "unknown", graph.NotVisible)
		k.cover(repo.ID, "workflows", "unexpected contents response for .github/workflows",
			"check .github/workflows in "+full+" is a directory")
		return nil
	}
	for _, e := range entries {
		if e.Name != actionsLockName {
			continue
		}
		if e.Type != "file" {
			k.noteActionsLock(repo, nil, errLockNotFile)
			break
		}
		data, err := k.getFile(ctx, o.login, name, e.Path, "")
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		k.noteActionsLock(repo, data, err)
		break
	}
	count := 0
	var pending []tokenDefault
	for _, e := range entries {
		if e.Type != "file" || !isYAMLName(e.Name) {
			continue
		}
		data, err := k.getFile(ctx, o.login, name, e.Path, "")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			k.cover(repo.ID, "workflow:"+e.Path, "could not read workflow: "+err.Error(), k.fixFor(err, "read access to contents on "+full))
			continue
		}
		count++
		pending = k.processWorkflowFile(o, repo, e.Path, data, pending)
	}
	setAttr(repo, "workflows", strconv.Itoa(count), graph.Live)
	return k.resolveTokenDefaults(ctx, o, repo, pending)
}

// processWorkflowFile adds the facts of one default-branch workflow file of
// repo. The REST and the batched GraphQL path share it, so both build the
// same graph from the same bytes.
func (k *collector) processWorkflowFile(o *orgState, repo *graph.Node, path string, data []byte, pending []tokenDefault) []tokenDefault {
	full := strings.TrimPrefix(repo.ID, "repo:")
	wid := "workflow:" + full + "/" + path
	wn := k.node(wid, graph.KindWorkflow, full+"/"+path)
	setAttr(wn, "repo", full, graph.Live)
	setAttr(wn, "path", path, graph.Live)
	k.edge(wid, repo.ID, graph.DefinedIn, graph.Live, srcWorkflowDir, nil)
	facts, err := ParseWorkflow(data)
	if err != nil {
		setAttr(wn, "parse_error", truncate(err.Error(), 200), graph.Live)
		k.cover(wid, "workflow_parse", err.Error(), "fix the workflow YAML in "+full)
		return pending
	}
	facts.SetFile(path, repo.Attrs["default_branch"])
	k.addWorkflowFacts(wid, full, facts)
	pending = k.addTokenFacts(wid, wn, repo, facts, pending)
	if !k.trackFollow(o, repo, wid, wn, path, data, facts) {
		k.addTriggerFacts(o, repo, wid, wn, facts)
		addAgentFacts(wn, facts)
	}
	bf := parseBotFacts(data, facts.Triggers, nil)
	k.addBotFacts(wn, bf)
	k.trackBotScripts(o, repo, wn, data, facts.Triggers, bf)
	return pending
}

func (k *collector) addWorkflowFacts(wid, full string, f *WorkflowFacts) {
	for _, u := range f.Uses {
		k.addUse(wid, u, srcWorkflow, 1)
	}
	if f.IDTokenWrite {
		id := "oidc:" + full
		k.node(id, graph.KindOIDC, full+" OIDC token")
		attrs := oidcAttrs(full, f)
		locate(attrs, f.File, f.FileRef, f.IDTokenLine(), 0)
		k.edge(wid, id, graph.ExecutesWith, graph.Live, srcWorkflow, attrs)
		k.trackOIDCEdge(f, attrs)
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
		k.node(id, graph.KindRunner, full+" self-hosted runners").Name = full + " self-hosted runners"
		attrs := map[string]string{"labels": strings.Join(f.RunnerLabels, ",")}
		locate(attrs, f.File, f.FileRef, f.RunsOnLine, 0)
		k.edge(wid, id, graph.ExecutesWith, graph.Live, srcWorkflow, attrs)
	}
	if f.UnknownRunners {
		k.addUnknownRunner(wid, full, f)
	}
	if n := len(f.DynamicUses); n > 0 {
		setAttr(k.nodes[wid], attrDynamicUses, strconv.Itoa(n), graph.Live)
		k.cover(wid, attrDynamicUses, "uses: is an expression; the action cannot be resolved statically",
			"none: replace the expression with literal owner/repo@sha references to make them visible")
	}
}

// addUnknownRunner records jobs whose runs-on is neither GitHub-hosted nor
// self-hosted (a custom label, a runner group or an expression): the runner
// may be self-hosted, so the edge is not_visible, not absent. A workflow that
// also runs on self-hosted runners keeps its live edge (one edge per pair).
func (k *collector) addUnknownRunner(wid, full string, f *WorkflowFacts) {
	id := "runner:" + full
	k.node(id, graph.KindRunner, full+" runners")
	attrs := map[string]string{"labels": strings.Join(f.UnknownRunnerLabels, ","), "classification": RunnerUnknown}
	locate(attrs, f.File, f.FileRef, f.UnknownRunsOnLine, 0)
	k.edge(wid, id, graph.ExecutesWith, graph.NotVisible, srcWorkflow, attrs)
	k.cover(wid, "runner_labels",
		"runs-on "+strings.Join(f.UnknownRunnerLabels, ",")+" is not a GitHub-hosted label: the runner may be self-hosted",
		"org owner (runner groups and self-hosted runners are not read yet)")
}

// addUse records from -USES-> action and, for enterprise-internal targets,
// action -RESOLVES_TO-> repo, and queues the action for nested expansion.
func (k *collector) addUse(from string, u ActionUse, src string, depth int) {
	an := k.actionNode(u)
	attrs := map[string]string{graph.AttrRefKind: u.RefKind, "level": u.Level}
	if u.Job != "" {
		attrs["job"] = u.Job
	}
	locate(attrs, u.File, u.FileRef, u.Line, u.Column)
	k.edge(from, an.ID, graph.Uses, graph.Live, src, attrs)
	k.resolveAction(an, u, depth)
}

// actionNode declares the action_ref node of a reference.
func (k *collector) actionNode(u ActionUse) *graph.Node {
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
	return an
}

// resolveAction records whether the action's owner is an enterprise org and,
// when it is, action -RESOLVES_TO-> host repo (a stub when the repo was not
// collected), and queues the action for nested expansion at depth.
func (k *collector) resolveAction(an *graph.Node, u ActionUse, depth int) {
	aid := an.ID
	org, inside := k.entOrgs[strings.ToLower(u.Owner)]
	if !inside && k.entHidden {
		// Unknown, not outside: the owner may be an enterprise org the token can't see.
		k.markUnknownOwner(an, u.Owner)
		return
	}
	setAttr(an, attrInEnterprise, strconv.FormatBool(inside), graph.Live)
	if !inside {
		if k.ghes {
			// Not an org on the instance: the runner fetches it from
			// github.com (GitHub Connect or a local mirror).
			setAttr(an, attrSource, graph.GitHubDotCom, graph.Live)
		}
		return
	}
	full := org + "/" + u.Repo
	rid, ok := k.repoIDs[strings.ToLower(full)]
	if !ok {
		rid = "repo:" + full
		// Nothing about the repo itself was read: its node is not_visible,
		// while the org and collected=false are known.
		rn := k.node(rid, graph.KindRepo, full)
		rn.Evidence = graph.NotVisible
		setAttr(rn, "org", org, graph.Live)
		setAttr(rn, attrCollected, "false", graph.Live)
		k.repoIDs[strings.ToLower(full)] = rid
	}
	k.edge(aid, rid, graph.ResolvesTo, graph.Live, "derived:workflow.uses+"+k.orgsSrc, nil)
	if !k.expanded[aid] {
		k.expanded[aid] = true
		cu := u
		cu.Owner = org
		k.queue = append(k.queue, queued{id: aid, use: cu, depth: depth})
	}
}

// pushToStubs records who may push to stub repos: repositories that host an
// enterprise action but were not collected (their org is outside --orgs or
// archived, or the token does not list them). Without it reach through them
// would be quietly zero. When the host org was collected with a visible
// default_perm of write or admin, the normal default-permission edge is
// added; otherwise members:<org> -CAN_PUSH-> repo is not_visible, so the path
// shows as possible.
func (k *collector) pushToStubs() {
	var ids []string
	for id, n := range k.nodes {
		if n.Kind == graph.KindRepo && n.Attrs[attrCollected] == "false" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, rid := range ids {
		rn := k.nodes[rid]
		org := rn.Attrs["org"]
		o := k.byLower[strings.ToLower(org)]
		reason, fix := "host repository outside the collected orgs (--orgs)", "add "+org+" to --orgs"
		switch {
		case o != nil && o.archived:
			reason, fix = "host repository in an archived organization; not collected", "none: archived organizations are not collected"
		case o != nil:
			reason, fix = "host repository not listed for the token", "read access to "+strings.TrimPrefix(rid, "repo:")
		}
		k.cover(rid, "can_push", reason, fix)
		mid := "members:" + org
		k.node(mid, graph.KindOrgMembers, org+" members")
		if o != nil && !o.archived && o.node.AttrEvidence[graph.AttrDefaultPerm] == "" {
			if perm := o.node.Attrs[graph.AttrDefaultPerm]; perm == "write" || perm == "admin" {
				src := srcDefaultPerm
				if k.entHidden {
					src = srcOrgREST
				}
				k.edge(mid, rid, graph.CanPush, graph.Inferred, src, map[string]string{
					graph.AttrVia: graph.ViaDefaultPerm, graph.AttrRule: graph.RuleDefaultPerm, "permission": perm,
					graph.AttrTwoFactor: o.node.Attrs[graph.AttrTwoFactor], graph.AttrSSO: o.node.Attrs[graph.AttrSSO],
				})
				continue
			}
		}
		k.edge(mid, rid, graph.CanPush, graph.NotVisible, k.orgsSrc, map[string]string{graph.AttrVia: graph.ViaUnknown})
	}
}

// expandNested follows composite actions and reusable workflows inside the
// enterprise, up to MaxNestedDepth, never visiting a node twice. The queue is
// processed in waves by depth (it is breadth first, so a wave is the queue as
// it stands); each wave's files are prefetched in batched GraphQL queries,
// then every entry is processed in queue order, exactly as the REST path.
func (k *collector) expandNested(ctx context.Context) error {
	done := 0
	for len(k.queue) > 0 {
		wave := k.queue
		k.queue = nil
		pre, err := k.prefetchNested(ctx, wave)
		if err != nil {
			return err
		}
		for i, q := range wave {
			if err := k.expandOne(ctx, q, pre[i]); err != nil {
				return err
			}
			done++
			k.progress(PhaseNested, done, done+len(wave)-i-1+len(k.queue))
		}
	}
	return nil
}

// nestedFile is one prefetched nested file: data read from path, or err
// (a synthesized 404 when the file is missing).
type nestedFile struct {
	path string
	data []byte
	err  error
}

// expandOne expands one queued reference. pre, when set, is the file the
// batched GraphQL path already read; otherwise it is read over REST.
func (k *collector) expandOne(ctx context.Context, q queued, pre *nestedFile) error {
	an := k.nodes[q.id]
	if q.depth > MaxNestedDepth {
		setAttr(an, attrNested, "unknown", graph.NotVisible)
		setAttr(an, "nested_reason", fmt.Sprintf("depth limit %d reached", MaxNestedDepth), graph.Live)
		k.cover(q.id, "nested_uses", fmt.Sprintf("nested references deeper than %d levels are not followed", MaxNestedDepth),
			"none: pin the action to a commit SHA, or review its nested references by hand")
		return nil
	}
	u := q.use
	var data []byte
	var err error
	var path string
	switch {
	case pre != nil:
		path, data, err = pre.path, pre.data, pre.err
	case u.IsReusableWorkflow():
		path = u.Path
		data, err = k.getFile(ctx, u.Owner, u.Repo, path, u.Ref)
	default:
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
		k.cover(q.id, "nested_uses", reason, k.fixFor(err, "read access to contents on "+u.Owner+"/"+u.Repo))
		return nil
	}
	var nested []ActionUse
	if u.IsReusableWorkflow() {
		facts, perr := ParseWorkflow(data)
		if perr != nil {
			setAttr(an, attrNested, "unknown", graph.NotVisible)
			k.cover(q.id, "nested_uses", perr.Error(), "fix "+path+" in "+u.Owner+"/"+u.Repo)
			return nil
		}
		facts.SetFile(path, u.Ref)
		k.noteCalledOIDC(q.id, u, facts)
		if len(data) <= followMaxBytes {
			if k.calledWFs == nil {
				k.calledWFs = map[string][]byte{}
			}
			k.calledWFs[q.id] = data
		}
		nested = facts.Uses
	} else {
		uses, using, perr := ParseCompositeAction(data)
		if perr != nil {
			setAttr(an, attrNested, "unknown", graph.NotVisible)
			k.cover(q.id, "nested_uses", perr.Error(), "fix "+path+" in "+u.Owner+"/"+u.Repo)
			return nil
		}
		if using != "" {
			setAttr(an, "runs_using", using, graph.Live)
		}
		setFile(uses, path, u.Ref)
		nested = uses
	}
	setAttr(an, attrNested, strconv.Itoa(len(nested)), graph.Live)
	for _, nu := range nested {
		k.addUse(q.id, nu, srcNested, q.depth+1)
	}
	return nil
}

// WriteGraph writes g as indented JSON.
func WriteGraph(w io.Writer, g *graph.Graph) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}
