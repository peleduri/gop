// Package demo generates a synthetic enterprise graph so gop can be tried
// without a token. The output is deterministic for a given seed and size, uses
// only synthetic names (enterprise acme, orgs acme-*, users alice, bob,
// carol, dave, erin, user-NNN), and marks itself as demo data: the enterprise
// node carries demo=true and every edge's source_api (and every node's
// source_api attr) is "demo:<generator rule>", so nobody mistakes it for
// collected data.
//
// Every size plants the same core story on top of seeded filler:
//
//  1. members:acme-actions (default permission write, 2FA not required) can
//     push to acme-actions/deploy, and action:acme-actions/deploy@main runs in
//     most acme-app workflows, some with id-token: write and secrets.
//  2. acme-secure/vault pins acme-actions/deploy to a commit SHA: not reachable.
//  3. The nested-action trap: acme-secure/signer and acme-app/payments pin
//     acme-actions/release to a commit SHA, but release is a composite action
//     that calls acme-actions/setup@main, a branch acme-actions members can
//     push to. Pinning alone does not block that path.
//  4. acme-legacy's repositories are not visible to the token: one possible
//     (unconfirmed) path, with matching coverage entries.
//  5. acme-app/worker runs on a self-hosted runner pool.
//  6. acme-app/docs runs acme-oss/checkout-ish@v2, an action outside the
//     enterprise whose v2 tag an advisory lists as compromised: it reaches
//     the repo's secrets and ranks first.
//  7. acme-app/docs is public and runs claude-code-action on issue_comment
//     with allowed_non_write_users: "*" and a token that can push: anyone
//     on the internet can start the agent (agent_exposed), which ranks
//     right after the advisory.
//  8. A few accounts own most orgs: carol and dave own every visible org
//     of the small size, erin every one but acme-secure, and each of those
//     orgs also has two local owners. carol, dave and erin share one risk row grouped by cause
//     (standing org ownership), and the reduce_owners fix removes their
//     ownership while each org keeps its local owners.
//  9. acme-app/web is public and has an AI approve + self-merge chain: an AI
//     reviewer (ai-review.yml) approves pull requests with an App token and
//     ai-merge.yml lets the pull request's author merge through
//     tools/merge.py with the same App, which bypasses the rules on main.
//     Anyone who can open a pull request gets code onto main without human
//     review (CAN_MERGE_VIA_BOT), and it runs with web's OIDC trust.
//  10. Branch protection notes on a top path: acme-actions/deploy needs one
//     approval to reach main, acme-actions/setup is not protected, so a
//     push reaches its default branch directly.
package demo

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Options select the generated graph. Orgs and ReposPerOrg override the Size
// preset when positive. Orgs is at least 4 (the planted orgs).
type Options struct {
	Seed        int64
	Orgs        int
	ReposPerOrg int
	Size        string // small (default) | medium | large
}

// Size presets.
const (
	SizeSmall  = "small"  // 7 orgs, about 65 repos
	SizeMedium = "medium" // 20 orgs, about 1,000 repos
	SizeLarge  = "large"  // 60 orgs, about 10,000 repos
)

// Preset returns the org and repos-per-org counts for a size name.
func Preset(size string) (orgs, reposPerOrg int, ok bool) {
	switch size {
	case "", SizeSmall:
		return 7, 10, true
	case SizeMedium:
		return 20, 50, true
	case SizeLarge:
		return 60, 167, true
	}
	return 0, 0, false
}

// CollectedAt is the fixed timestamp on every demo graph and edge.
var CollectedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Planted node IDs, exported for tests and docs.
const (
	Enterprise      = "acme"
	DeployMain      = "action:acme-actions/deploy@main"
	DeployTag       = "action:acme-actions/deploy@v1"
	DeploySHA       = "action:acme-actions/deploy@3f2c9a8e1b7d4c6f0a5e9d8c7b6a5f4e3d2c1b0a"
	ReleaseSHA      = "action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5"
	SetupMain       = "action:acme-actions/setup@main"
	ActionsMembers  = "members:acme-actions"
	LegacyMembers   = "members:acme-legacy"
	legacyHiddenRep = "repo:acme-legacy/old-api"
)

// The planted action with a known advisory (story 6) and its synthetic
// advisory ID.
const (
	CheckoutIsh  = "action:acme-oss/checkout-ish@v2"
	DemoAdvisory = "GHSA-acme-demo-0001"
)

// Generator rules, used as "demo:<rule>" in source_api.
const (
	ruleEnterprise = "enterprise"
	ruleOrg        = "org-settings"
	ruleRepo       = "repo"
	ruleDefault    = "default-perm"
	ruleCollab     = "collaborator"
	ruleMember     = "membership"
	ruleWorkflow   = "workflow"
	ruleUses       = "uses"
	ruleResolves   = "action-host"
	ruleSecret     = "secrets"
	ruleOIDC       = "id-token-write"
	ruleCrossOrg   = "planted-cross-org"
	rulePinned     = "planted-sha-pin"
	ruleNested     = "planted-nested-action"
	ruleHidden     = "planted-not-visible"
	ruleRunner     = "planted-self-hosted-runner"
	ruleAdvisory   = "planted-advisory"
	ruleAgent      = "planted-ai-agent"
	ruleOwner      = "planted-org-owner"
	ruleBotMerge   = "planted-bot-self-merge"
	ruleProtection = "planted-branch-protection"
)

// The planted AI agent workflow (story 7).
const AgentWorkflow = "workflow:acme-app/docs/.github/workflows/claude.yml"

// The planted AI approve + self-merge chain (story 9).
const (
	BotMergeRepo   = "repo:acme-app/web"
	ReviewWorkflow = "workflow:acme-app/web/.github/workflows/ai-review.yml"
	MergeWorkflow  = "workflow:acme-app/web/.github/workflows/ai-merge.yml"
	MergeScript    = "tools/merge.py"
)

// The accounts that own most orgs (story 8). erin owns every visible org
// but acme-secure.
var MultiOrgOwners = []string{"identity:carol", "identity:dave", "identity:erin"}

type gen struct {
	nodes map[string]graph.Node
	edges map[string]graph.Edge
	rng   *rand.Rand
}

func src(rule string) string { return "demo:" + rule }

func (g *gen) node(id string, kind graph.NodeKind, name string, ev graph.Evidence, rule string, attrs map[string]string) {
	a := map[string]string{"source_api": src(rule)}
	for k, v := range attrs {
		a[k] = v
	}
	g.nodes[id] = graph.Node{ID: id, Kind: kind, Name: name, Attrs: a, Evidence: ev}
}

func (g *gen) edge(from string, kind graph.EdgeKind, to string, ev graph.Evidence, rule string, attrs map[string]string) {
	e := graph.Edge{From: from, To: to, Kind: kind, Evidence: ev, SourceAPI: src(rule), ObservedAt: CollectedAt}
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	g.edges[from+"\x00"+string(kind)+"\x00"+to+"\x00"+e.SourceAPI] = e
}

func refKind(action string) string {
	switch action {
	case DeployMain, SetupMain:
		return "branch"
	case DeployTag, CheckoutIsh:
		return "tag"
	}
	return "sha"
}

func (g *gen) org(name string, ev graph.Evidence, attrs map[string]string) {
	g.node("org:"+name, graph.KindOrg, name, ev, ruleOrg, attrs)
	g.node("members:"+name, graph.KindOrgMembers, "members of "+name, graph.Live, ruleOrg, nil)
}

func (g *gen) repo(org, name string, ev graph.Evidence, rule string) string {
	id := "repo:" + org + "/" + name
	g.node(id, graph.KindRepo, org+"/"+name, ev, rule, map[string]string{graph.AttrVisibility: "private"})
	return id
}

// workflow declares a workflow in org/repo and returns its ID.
func (g *gen) workflow(org, repo, file string, ev graph.Evidence, rule string) string {
	id := "workflow:" + org + "/" + repo + "/.github/workflows/" + file
	g.node(id, graph.KindWorkflow, org+"/"+repo+"/.github/workflows/"+file, ev, rule, nil)
	g.edge(id, graph.DefinedIn, "repo:"+org+"/"+repo, ev, rule, nil)
	return id
}

func (g *gen) uses(from, action, rule string) {
	g.edge(from, graph.Uses, action, graph.Live, rule, map[string]string{graph.AttrRefKind: refKind(action)})
}

// terminal declares a secret, oidc or runner node and the workflow's EXECUTES_WITH edge to it.
func (g *gen) terminal(wf, id string, kind graph.NodeKind, ev graph.Evidence, rule string) {
	g.node(id, kind, afterColon(id), ev, rule, nil)
	g.edge(wf, graph.ExecutesWith, id, ev, rule, nil)
}

func afterColon(id string) string {
	_, rest, ok := strings.Cut(id, ":")
	if !ok {
		return id
	}
	return rest
}

// Generate builds the demo graph. Same Options give a byte-identical graph
// once serialized: nodes are sorted by ID and edges by (from, kind, to, source).
func Generate(opts Options) *graph.Graph {
	orgs, rpo, ok := Preset(opts.Size)
	if !ok {
		orgs, rpo, _ = Preset(SizeSmall)
	}
	if opts.Orgs > 0 {
		orgs = opts.Orgs
	}
	if opts.ReposPerOrg > 0 {
		rpo = opts.ReposPerOrg
	}
	orgs = max(orgs, 4)
	seed := uint64(opts.Seed)
	g := &gen{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{},
		rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}

	g.node("enterprise:"+Enterprise, graph.KindEnterprise, Enterprise, graph.Live, ruleEnterprise,
		map[string]string{graph.AttrDemo: "true"})
	planted := g.plant()
	repos := map[string][]string{} // org -> filler-eligible repo IDs (visible)
	for _, id := range planted {
		o := afterColon(graph.OrgOf(id))
		repos[o] = append(repos[o], id)
	}

	orgNames := []string{"acme-actions", "acme-app", "acme-secure", "acme-legacy"}
	for i := 5; i <= orgs; i++ {
		orgNames = append(orgNames, fmt.Sprintf("acme-org-%02d", i-4))
	}
	defaultPerm := map[string]string{"acme-actions": "write", "acme-app": "read", "acme-secure": "read", "acme-legacy": "write"}
	for i, o := range orgNames[4:] {
		// Every fifth filler org (acme-org-05, -10, ...) has default permission
		// write, so medium and large have more than one write org while small
		// keeps the planted acme-actions story in front.
		perm := []string{"read", "read", "none"}[g.rng.IntN(3)]
		if (i+1)%5 == 0 {
			perm = "write"
		}
		tf := "required"
		if g.rng.IntN(5) == 0 {
			tf = "not_required"
		}
		sso := "enforced"
		if g.rng.IntN(10) < 3 {
			sso = "configured"
		}
		g.org(o, graph.Live, map[string]string{graph.AttrDefaultPerm: perm, graph.AttrTwoFactor: tf, graph.AttrSSO: sso,
			graph.AttrIPAllowList: "off", graph.AttrMembers: fmt.Sprint(10 + g.rng.IntN(200))})
		defaultPerm[o] = perm
	}

	// Filler repos. acme-secure is a small locked-down org: its two planted
	// repos only.
	for _, o := range orgNames {
		if o == "acme-secure" {
			continue
		}
		for n := len(repos[o]); n < rpo; n++ {
			name := fmt.Sprintf("svc-%03d", n+1)
			if o == "acme-legacy" {
				// The token cannot list acme-legacy's repositories: hidden, possible reach only.
				id := g.repo(o, name, graph.NotVisible, ruleHidden)
				g.edge("members:"+o, graph.CanPush, id, graph.NotVisible, ruleHidden,
					map[string]string{graph.AttrVia: graph.ViaDefaultPerm, "permission": "write"})
				continue
			}
			id := g.repo(o, name, graph.Live, ruleRepo)
			repos[o] = append(repos[o], id)
			g.filler(o, name)
		}
	}

	// Default-permission push for every visible repo of a write org.
	for _, o := range orgNames {
		if defaultPerm[o] != "write" || o == "acme-legacy" {
			continue
		}
		for _, r := range repos[o] {
			g.edge("members:"+o, graph.CanPush, r, graph.Inferred, ruleDefault,
				map[string]string{graph.AttrVia: graph.ViaDefaultPerm, graph.AttrRule: graph.RuleDefaultPerm, "permission": "write"})
		}
	}

	// Filler users: a membership each, and half get a direct write grant. They
	// stay out of acme-actions so the planted story (members:acme-actions,
	// bob) leads the report.
	visible := make([]string, 0, len(orgNames))
	for _, o := range orgNames {
		if o != "acme-legacy" && o != "acme-actions" {
			visible = append(visible, o)
		}
	}
	for u := 1; u <= orgs*4; u++ {
		id := fmt.Sprintf("identity:user-%03d", u)
		g.node(id, graph.KindIdentity, id[len("identity:"):], graph.Live, ruleMember, nil)
		o := visible[g.rng.IntN(len(visible))]
		g.edge(id, graph.MemberOf, "org:"+o, graph.Live, ruleMember, nil)
		if g.rng.IntN(2) == 0 {
			ro := visible[g.rng.IntN(len(visible))]
			r := repos[ro][g.rng.IntN(len(repos[ro]))]
			g.edge(id, graph.CanPush, r, graph.Live, ruleCollab, map[string]string{graph.AttrVia: "direct", "permission": "write"})
		}
	}
	g.owners(orgNames, repos)
	return g.graph()
}

// ownedOrgs is how many of the first org names story 8 covers: every org of
// the small size. Larger sizes keep the same owners, so the story (and the
// report size) does not grow with the filler.
const ownedOrgs = 7

// owners plants story 8: carol and dave own every visible org of the first
// ownedOrgs, erin every one but acme-secure, and each of those orgs has two
// local owners (filler users, one org each) so reduce_owners can cut the
// three and still leave each org MinOwnersPerOrg owners. acme-legacy has
// none: the token cannot list its repositories, so the graph shows no owners
// there.
func (g *gen) owners(orgNames []string, repos map[string][]string) {
	for _, id := range MultiOrgOwners {
		g.node(id, graph.KindIdentity, afterColon(id), graph.Live, ruleOwner, nil)
	}
	// An owner is also a member of each org it owns.
	own := func(who, org string) {
		g.edge(who, graph.MemberOf, "org:"+org, graph.Live, ruleOwner, nil)
		for _, r := range repos[org] {
			g.edge(who, graph.CanPush, r, graph.Inferred, ruleOwner, map[string]string{
				graph.AttrVia: graph.ViaOrgOwner, graph.AttrRule: graph.RuleOrgOwner, "permission": "admin"})
		}
	}
	k := 0
	for _, o := range orgNames[:min(len(orgNames), ownedOrgs)] {
		if o == "acme-legacy" {
			continue
		}
		for _, id := range MultiOrgOwners {
			if id == "identity:erin" && o == "acme-secure" {
				continue
			}
			own(id, o)
		}
		for range graph.MinOwnersPerOrg {
			k++
			own(fmt.Sprintf("identity:user-%03d", k), o)
		}
	}
}

// filler adds a seeded workflow to a filler repo.
func (g *gen) filler(org, repo string) {
	if g.rng.IntN(4) == 0 {
		return // no workflow
	}
	wf := g.workflow(org, repo, "ci.yml", graph.Live, ruleWorkflow)
	switch r := g.rng.IntN(20); {
	case r < 5:
		g.uses(wf, DeployMain, ruleUses)
	case r < 7:
		g.uses(wf, DeployTag, ruleUses)
	case r < 10:
		g.uses(wf, DeploySHA, ruleUses)
	case r < 11:
		g.uses(wf, ReleaseSHA, ruleUses)
	}
	if g.rng.IntN(7) == 0 {
		g.terminal(wf, "secret:"+org+"/"+repo, graph.KindSecret, graph.Live, ruleSecret)
	}
	if g.rng.IntN(12) == 0 {
		g.terminal(wf, "oidc:"+org+"/"+repo, graph.KindOIDC, graph.Live, ruleOIDC)
	}
}

// plant adds the fixed core story and returns the visible repo IDs it created.
// Names and shapes follow testdata/acme/graph.json.
func (g *gen) plant() []string {
	var repos []string
	r := func(org, name, rule string) string {
		id := g.repo(org, name, graph.Live, rule)
		repos = append(repos, id)
		return id
	}

	g.org("acme-actions", graph.Live, map[string]string{graph.AttrDefaultPerm: "write", graph.AttrTwoFactor: "not_required",
		graph.AttrSSO: "configured", graph.AttrIPAllowList: "off", graph.AttrMembers: "40"})
	g.org("acme-app", graph.Live, map[string]string{graph.AttrDefaultPerm: "read", graph.AttrTwoFactor: "required",
		graph.AttrSSO: "enforced", graph.AttrIPAllowList: "off", graph.AttrMembers: "120"})
	g.org("acme-secure", graph.Live, map[string]string{graph.AttrDefaultPerm: "read", graph.AttrTwoFactor: "required",
		graph.AttrSSO: "enforced", graph.AttrIPAllowList: "on", graph.AttrMembers: "8"})
	g.org("acme-legacy", graph.Live, map[string]string{graph.AttrDefaultPerm: "write", graph.AttrTwoFactor: "not_required",
		graph.AttrSSO: "none", graph.AttrIPAllowList: "unknown"})
	legacy := g.nodes["org:acme-legacy"]
	legacy.AttrEvidence = map[string]graph.Evidence{graph.AttrIPAllowList: graph.NotVisible}
	g.nodes["org:acme-legacy"] = legacy

	// (1) Shared actions in acme-actions.
	deploy := r("acme-actions", "deploy", ruleCrossOrg)
	setup := r("acme-actions", "setup", ruleNested)
	release := r("acme-actions", "release", ruleNested)
	for _, a := range []struct{ id, host, rule string }{
		{DeployMain, deploy, ruleCrossOrg}, {DeployTag, deploy, ruleCrossOrg}, {DeploySHA, deploy, rulePinned},
		{SetupMain, setup, ruleNested}, {ReleaseSHA, release, ruleNested},
	} {
		g.node(a.id, graph.KindActionRef, afterColon(a.id), graph.Live, a.rule, map[string]string{graph.AttrRefKind: refKind(a.id)})
		g.edge(a.id, graph.ResolvesTo, a.host, graph.Live, ruleResolves, nil)
	}
	g.uses(g.workflow("acme-actions", "deploy", "release.yml", graph.Live, ruleCrossOrg), SetupMain, ruleCrossOrg)
	g.node("identity:bob", graph.KindIdentity, "bob", graph.Live, ruleMember, nil)
	g.edge("identity:bob", graph.CanPush, deploy, graph.Live, ruleCollab, map[string]string{graph.AttrVia: "direct", "permission": "maintain"})
	g.edge("identity:bob", graph.MemberOf, "org:acme-actions", graph.Live, ruleMember, nil)

	// (3) The nested-action trap: release is pinned to a SHA by its consumers,
	// but the pinned composite action itself calls setup@main.
	g.uses(ReleaseSHA, SetupMain, ruleNested)

	// acme-app consumers of deploy@main.
	for _, name := range []string{"admin", "api", "billing", "docs", "gateway", "mobile", "search", "web", "worker"} {
		r("acme-app", name, ruleCrossOrg)
		wf := g.workflow("acme-app", name, "ci.yml", graph.Live, ruleCrossOrg)
		g.uses(wf, DeployMain, ruleCrossOrg)
		switch name {
		case "billing":
			g.terminal(wf, "secret:acme-app/billing", graph.KindSecret, graph.Live, ruleCrossOrg)
		case "web":
			g.terminal(wf, "oidc:acme-app/web", graph.KindOIDC, graph.Live, ruleCrossOrg)
		case "worker":
			// (5) Self-hosted runner pool.
			g.terminal(wf, "runner:acme-app/worker", graph.KindRunner, graph.Live, ruleRunner)
		}
	}
	r("acme-app", "auth", ruleCrossOrg)
	g.uses(g.workflow("acme-app", "auth", "ci.yml", graph.Live, ruleCrossOrg), DeployTag, ruleCrossOrg)
	r("acme-app", "infra", rulePinned)
	g.uses(g.workflow("acme-app", "infra", "ci.yml", graph.Live, rulePinned), DeploySHA, rulePinned)
	r("acme-app", "sandbox", ruleRepo)
	g.workflow("acme-app", "sandbox", "ci.yml", graph.Live, ruleRepo)
	r("acme-app", "payments", ruleNested)
	pay := g.workflow("acme-app", "payments", "release.yml", graph.Live, ruleNested)
	g.uses(pay, ReleaseSHA, ruleNested)
	g.terminal(pay, "oidc:acme-app/payments", graph.KindOIDC, graph.Live, ruleNested)
	g.terminal(pay, "secret:acme-app/payments", graph.KindSecret, graph.Live, ruleNested)
	g.node("identity:alice", graph.KindIdentity, "alice", graph.Live, ruleMember, nil)
	g.edge("identity:alice", graph.CanPush, "repo:acme-app/infra", graph.Live, ruleCollab, map[string]string{graph.AttrVia: "direct", "permission": "write"})
	g.edge("identity:alice", graph.MemberOf, "org:acme-app", graph.Live, ruleMember, nil)

	// (2) A SHA-pinned consumer that is NOT reachable.
	r("acme-secure", "vault", rulePinned)
	vault := g.workflow("acme-secure", "vault", "release.yml", graph.Live, rulePinned)
	g.uses(vault, DeploySHA, rulePinned)
	g.terminal(vault, "oidc:acme-secure/vault", graph.KindOIDC, graph.Live, rulePinned)
	// (3) ...and one that is, through the nested action.
	r("acme-secure", "signer", ruleNested)
	signer := g.workflow("acme-secure", "signer", "release.yml", graph.Live, ruleNested)
	g.uses(signer, ReleaseSHA, ruleNested)
	g.terminal(signer, "oidc:acme-secure/signer", graph.KindOIDC, graph.Live, ruleNested)

	// (6) An outside action whose tag was compromised (synthetic advisory).
	g.node(CheckoutIsh, graph.KindActionRef, afterColon(CheckoutIsh), graph.Live, ruleAdvisory, map[string]string{
		graph.AttrRefKind: "tag", "in_enterprise": "false", graph.AttrAdvisories: DemoAdvisory,
		graph.AttrAdvisorySeverity: "critical", graph.AttrAdvisoryFixed: "2.4.1"})
	preview := g.workflow("acme-app", "docs", "preview.yml", graph.Live, ruleAdvisory)
	g.uses(preview, CheckoutIsh, ruleAdvisory)
	g.terminal(preview, "secret:acme-app/docs", graph.KindSecret, graph.Live, ruleAdvisory)

	// (7) A public repo's AI agent that anyone can start by commenting.
	docs := g.nodes["repo:acme-app/docs"]
	docs.Attrs[graph.AttrVisibility] = "public"
	agent := g.workflow("acme-app", "docs", "claude.yml", graph.Live, ruleAgent)
	wn := g.nodes[agent]
	for k, v := range map[string]string{
		graph.AttrAgent: "claude-code-action", graph.AttrAgentSource: "uses", graph.AttrAgentConfidence: graph.AgentAction,
		graph.AttrAgentJobs: "claude", graph.AttrAgentGate: graph.GateAnyone, graph.AttrAgentExposure: graph.ExposureOutsiders,
		graph.AttrAgentPerms: "contents:write,pull-requests:write", graph.AttrAgentSecrets: "1", graph.AttrAgentRunner: "hosted",
		graph.AttrAgentTools: "dangerously_skip_permissions", graph.AttrAgentRefKind: "tag", "risky_triggers": "issue_comment",
	} {
		wn.Attrs[k] = v
	}
	g.nodes[agent] = wn
	g.node("external:anyone", graph.KindExternal, "anyone on the internet", graph.Live, ruleAgent, nil)
	g.edge("external:anyone", graph.CanTrigger, agent, graph.Live, ruleAgent, map[string]string{
		"trigger": "issue_comment", "exec": "agent", "job": "claude", "detail": "claude-code-action",
		graph.AttrFile: ".github/workflows/claude.yml", graph.AttrLine: "16"})
	g.edge(agent, graph.ExecutesWith, "secret:acme-app/docs", graph.Live, ruleAgent, nil)
	g.edge(agent, graph.CanPush, "repo:acme-app/docs", graph.Live, ruleAgent, map[string]string{graph.AttrVia: graph.ViaTokenWrite, graph.AttrJobs: "claude"})

	g.botMerge()
	// (10) Branch protection on the shared actions' repos: deploy needs an
	// approval, setup is not protected, release is protected.
	g.protect(deploy, map[string]string{graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "1",
		graph.AttrBranchSources: "ruleset:7", graph.AttrBranchValueSources: "required_reviews=ruleset:7"})
	g.protect(setup, map[string]string{graph.AttrBranchProtected: "false", graph.AttrBranchSources: "none",
		graph.AttrSecretPushProtection: "off"})
	g.protect(release, map[string]string{graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "2",
		graph.AttrBranchSources: "classic", graph.AttrBranchValueSources: "required_reviews=classic"})

	// (4) One hop the token cannot see.
	g.repo("acme-legacy", "old-api", graph.NotVisible, ruleHidden)
	g.edge(LegacyMembers, graph.CanPush, legacyHiddenRep, graph.NotVisible, ruleHidden,
		map[string]string{graph.AttrVia: graph.ViaDefaultPerm, "permission": "write"})
	old := g.workflow("acme-legacy", "old-api", "ci.yml", graph.Audit, ruleHidden)
	g.terminal(old, "secret:acme-legacy/old-api", graph.KindSecret, graph.Audit, ruleHidden)
	return repos
}

// protect sets a repo's default-branch, CODEOWNERS and secret scanning facts
// (story 10). Branch values not given default to off, as the collector
// writes them for a branch it could read; secret scanning and push
// protection default to on.
func (g *gen) protect(repo string, attrs map[string]string) {
	n := g.nodes[repo]
	a := map[string]string{"default_branch": "main", graph.AttrBranchCodeOwnerReview: "false",
		graph.AttrBranchDismissStale: "false", graph.AttrBranchLastPush: "false", graph.AttrBranchStatusChecks: "0",
		graph.AttrBranchSignedCommits: "false", graph.AttrBranchForcePush: "false", graph.AttrBranchPushRestricted: "false",
		graph.AttrBranchBypassActors: "0", graph.AttrBranchAdminBypass: "false", graph.AttrBranchAppBypass: "false",
		graph.AttrBranchReviews: "0", graph.AttrCodeowners: "none", graph.AttrCodeownersWorkflows: "false",
		graph.AttrSecretScanning: "on", graph.AttrSecretPushProtection: "on", graph.AttrSecretValidity: "off"}
	if attrs[graph.AttrBranchProtected] == "false" {
		for _, k := range []string{graph.AttrBranchCodeOwnerReview, graph.AttrBranchDismissStale, graph.AttrBranchLastPush,
			graph.AttrBranchStatusChecks, graph.AttrBranchSignedCommits, graph.AttrBranchForcePush,
			graph.AttrBranchPushRestricted, graph.AttrBranchBypassActors, graph.AttrBranchAdminBypass,
			graph.AttrBranchAppBypass, graph.AttrBranchReviews} {
			delete(a, k)
		}
	}
	for k, v := range attrs {
		a[k] = v
	}
	for k, v := range a {
		n.Attrs[k] = v
	}
	g.nodes[repo] = n
}

// botMerge plants story 9 on acme-app/web, shaped like what the collector
// writes for testdata/botmerge-script: an AI reviewer that approves with an
// App token and a merge workflow the pull request's author can start, which
// merges in tools/merge.py with the same App; the App bypasses the rules on
// main. web is public, so anyone who can open a pull request lands code on
// main without human review.
func (g *gen) botMerge() {
	const (
		reviewFile = ".github/workflows/ai-review.yml"
		mergeFile  = ".github/workflows/ai-merge.yml"
		secret     = "secret:acme-app/web"
		mergeApp   = "77" // the App the merge mints its token for, a bypass actor on main
	)
	g.protect(BotMergeRepo, map[string]string{graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "1",
		graph.AttrBranchBypassActors: "1", graph.AttrBranchAppBypass: "true", graph.AttrBranchSources: "ruleset:46",
		graph.AttrBranchValueSources: "required_reviews=ruleset:46,app_bypass=ruleset:46", graph.AttrSecretPushProtection: "off",
		graph.AttrBranchBypassApps: mergeApp + ":acme-merge-bot"})
	web := g.nodes[BotMergeRepo]
	for k, v := range map[string]string{
		graph.AttrVisibility: "public", graph.AttrReviewBypass: graph.ReviewBypassBotSelfMerge,
		graph.AttrReviewBypassReason: graph.ReviewBypassApp, graph.AttrReviewBypassApprove: reviewFile,
		graph.AttrReviewBypassMerge: mergeFile, graph.AttrBotMergeSource: graph.BotScriptPrefix + MergeScript,
		graph.AttrBotMergeStale: graph.StaleSuspected, graph.AttrBotMergeStaleConf: graph.StaleHeuristic,
		graph.AttrReviewBypassStale:  graph.StaleSuspected,
		graph.AttrAgentHoldsMergeKey: "true", graph.AttrAgentMergeKeyWorkflows: reviewFile,
		graph.AttrBotMergeApps: mergeApp, graph.AttrReviewBypassAppMatch: graph.AppMatched,
	} {
		web.Attrs[k] = v
	}
	web.AttrEvidence = map[string]graph.Evidence{graph.AttrBotMergeStale: graph.NotVisible, graph.AttrReviewBypassStale: graph.NotVisible}
	g.nodes[BotMergeRepo] = web

	review := g.workflow("acme-app", "web", "ai-review.yml", graph.Live, ruleBotMerge)
	rn := g.nodes[review]
	for k, v := range map[string]string{
		graph.AttrAgent: "claude-cli", graph.AttrAgentSource: "run", graph.AttrAgentConfidence: graph.AgentCLI,
		graph.AttrAgentJobs: "review", graph.AttrAgentGate: graph.GateNone, graph.AttrAgentExposure: graph.ExposureOutsiders,
		graph.AttrAgentSecrets: "2", graph.AttrAgentRunner: "hosted", graph.AttrAgentTools: "allowed_tools",
		graph.AttrBotApproves: "true", graph.AttrBotApproveToken: graph.BotTokenApp, graph.AttrBotApproveJobs: "review",
		graph.AttrBotApproveStart: graph.StarterPROpeners, "risky_triggers": "pull_request_target",
	} {
		rn.Attrs[k] = v
	}
	g.nodes[review] = rn
	merge := g.workflow("acme-app", "web", "ai-merge.yml", graph.Live, ruleBotMerge)
	mn := g.nodes[merge]
	for k, v := range map[string]string{
		graph.AttrBotMerges: "true", graph.AttrBotMergeToken: graph.BotTokenApp, graph.AttrBotMergeJobs: "merge",
		graph.AttrBotMergeStart: graph.StarterPROpeners, graph.AttrBotMergeGate: graph.BotGateAuthor,
		graph.AttrBotMergeTriggers: "issue_comment", graph.AttrBotMergeSource: graph.BotScriptPrefix + MergeScript,
		graph.AttrBotMergeApps:  mergeApp,
		graph.AttrBotMergeStale: graph.StaleSuspected, graph.AttrBotMergeStaleConf: graph.StaleHeuristic,
		"risky_triggers": "issue_comment",
	} {
		mn.Attrs[k] = v
	}
	mn.AttrEvidence = map[string]graph.Evidence{graph.AttrBotMergeStale: graph.NotVisible}
	g.nodes[merge] = mn

	g.node(secret, graph.KindSecret, afterColon(secret), graph.Live, ruleBotMerge, nil)
	g.edge(review, graph.ExecutesWith, secret, graph.Live, ruleBotMerge, map[string]string{"secrets": "ANTHROPIC_API_KEY,APP_PRIVATE_KEY"})
	g.edge(merge, graph.ExecutesWith, secret, graph.Live, ruleBotMerge, map[string]string{"secrets": "APP_PRIVATE_KEY"})
	g.node("external:anyone", graph.KindExternal, "anyone on the internet", graph.Live, ruleAgent, nil)
	g.edge("external:anyone", graph.CanTrigger, review, graph.Live, ruleBotMerge, map[string]string{
		"trigger": "pull_request_target", "exec": "agent", "job": "review", "detail": "claude-cli",
		graph.AttrFile: reviewFile, graph.AttrLine: "27"})
	g.edge("external:anyone", graph.CanMergeViaBot, BotMergeRepo, graph.Live, ruleBotMerge, map[string]string{
		graph.AttrMergeWorkflow: merge, graph.AttrApproveWorkflows: review, graph.AttrReviewBypassReason: graph.ReviewBypassApp,
		"trigger": "issue_comment", graph.AttrFile: mergeFile, graph.AttrLine: "24"})
}

func (g *gen) graph() *graph.Graph {
	out := &graph.Graph{
		Schema: graph.SchemaVersion, CollectedAt: CollectedAt, Enterprise: Enterprise,
		Nodes: make([]graph.Node, 0, len(g.nodes)), Edges: make([]graph.Edge, 0, len(g.edges)),
		Coverage: []graph.Coverage{
			{Scope: "org:acme-legacy", Fact: "repositories", Reason: "token is not an org owner",
				NeedsFix: "org owner on acme-legacy (SAML enforced: join through the IdP first)"},
			{Scope: "org:acme-legacy", Fact: "ip_allow_list", Reason: "token is not an org owner",
				NeedsFix: "org owner on acme-legacy"},
			// Story 9: the stale-approval suspicion is a heuristic, never confirmed.
			{Scope: MergeWorkflow, Fact: graph.FactStaleApprovals,
				Reason:   "suspected, heuristic: " + MergeScript + " seems to count approvals not tied to the head commit; gop matched text and never ran it",
				NeedsFix: "confirm by hand: read " + MergeScript + " and check it counts only APPROVED reviews whose commit_id is the pull request's head SHA"},
			{Scope: BotMergeRepo, Fact: graph.FactStaleApprovals,
				Reason:   "suspected, heuristic: the merge in " + MergeScript + " may count older approvals and ai-review.yml does not re-run on push",
				NeedsFix: "confirm by hand: read " + MergeScript + " and the pull_request types of ai-review.yml"},
		},
	}
	for _, n := range g.nodes {
		out.Nodes = append(out.Nodes, n)
	}
	for _, e := range g.edges {
		out.Edges = append(out.Edges, e)
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	sort.Slice(out.Edges, func(i, j int) bool {
		a, b := out.Edges[i], out.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.SourceAPI < b.SourceAPI
	})
	return out
}
