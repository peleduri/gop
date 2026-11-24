// Package graph holds gop's evidence graph: typed nodes and edges where every
// fact records how it was observed. This file is the shared contract between
// collectors, the analysis engine, the MCP server and the report.
package graph

import (
	"strings"
	"time"
)

// SchemaVersion is bumped on any breaking change to the serialized Graph.
// v2 added the inferred evidence level; Load still reads SchemaV1 documents.
const SchemaVersion = "gop.graph/v2"

// SchemaV1 is the previous version. Load accepts it and upgrades it in memory:
// a v1 document is a valid v2 document, except that it may not use inferred.
const SchemaV1 = "gop.graph/v1"

// Evidence says how a fact was observed. gop never turns "couldn't see" into "off".
type Evidence string

const (
	// Live: read from the current state through the API.
	Live Evidence = "live"
	// Inferred: derived from other observed facts by a documented rule (the
	// edge's Attrs[AttrRule] names it), e.g. members' push access from the
	// org's default repository permission. Counts toward confirmed reach.
	// Ranked between live and audit. Requires gop.graph/v2.
	Inferred Evidence = "inferred"
	// Audit: read from the audit log (bounded retention, may be stale). An
	// audit edge older than the graph's maximum audit age (see Options.MaxAuditAge)
	// is stale: it counts as not visible, so it can give possible reach only.
	Audit Evidence = "audit"
	// NotVisible: the token can't read this fact. The hop is unknown, not absent.
	NotVisible Evidence = "not_visible"
	// Supplied: read from a file the user supplied (a cloud OIDC trust policy);
	// gop did not observe it live. It counts as confirmed (the user asserts the
	// file reflects what is deployed), but every path through it is flagged
	// (Path.Supplied) and summaries name the file. Ranked between audit and
	// not_visible.
	Supplied Evidence = "supplied"
)

// SourceSupplied prefixes the source_api of facts read from a user-supplied
// file: "supplied:<path as given>".
const SourceSupplied = "supplied:"

// NodeKind is the type of a node.
type NodeKind string

const (
	KindEnterprise  NodeKind = "enterprise"
	KindOrg         NodeKind = "org"
	KindOrgMembers  NodeKind = "org_members" // the set of members of one org, as a single principal
	KindIdentity    NodeKind = "identity"    // a user, team or app; ID "identity:<login>" or "team:<org>/<slug>"
	KindRepo        NodeKind = "repo"
	KindWorkflow    NodeKind = "workflow"
	KindActionRef   NodeKind = "action_ref" // owner/repo[/path]@ref as consumed by workflows
	KindSecret      NodeKind = "secret"     // secrets scope reachable by a workflow
	KindOIDC        NodeKind = "oidc"       // id-token: write
	KindRunner      NodeKind = "runner"     // self-hosted runner pool
	KindCloudTarget NodeKind = "cloud_target"
	// KindExternal is a principal outside the enterprise; "external:anyone"
	// is anyone on the internet (who can fork a public repo or comment on it).
	KindExternal NodeKind = "external"
)

// EdgeKind is the type of an edge.
type EdgeKind string

const (
	// CanPush: principal (org_members, identity) can push to repo. Also
	// workflow -> repo with via=token_write: the workflow's GITHUB_TOKEN has
	// contents: write on its own repo. A workflow is never a principal.
	CanPush EdgeKind = "CAN_PUSH"
	// Uses: workflow -> action_ref, or action_ref -> action_ref for nested composite
	// actions and reusable workflows. Attrs["ref_kind"] is sha|tag|branch.
	Uses EdgeKind = "USES"
	// ResolvesTo: action_ref -> repo that hosts the action.
	ResolvesTo EdgeKind = "RESOLVES_TO"
	// DefinedIn: workflow -> repo it lives in. Code pushed to the repo changes the workflow.
	DefinedIn EdgeKind = "DEFINED_IN"
	// ExecutesWith: workflow -> secret | oidc | runner. Terminal impact.
	ExecutesWith EdgeKind = "EXECUTES_WITH"
	// MemberOf: identity -> org, identity -> team, or child team -> parent team.
	MemberOf EdgeKind = "MEMBER_OF"
	// CanTrigger: principal (org_members, identity, external) -> workflow. The
	// principal can cause a risky trigger (pull_request_target, workflow_run,
	// issue_comment, ...) of a workflow that then runs attacker-controlled code
	// (attrs trigger, exec=checkout|injection, job), so the principal controls
	// the workflow without push access.
	CanTrigger EdgeKind = "CAN_TRIGGER"
	// CanAssume: workflow -> cloud_target. A token the workflow can mint (its
	// EXECUTES_WITH edge to oidc) matches a supplied cloud trust policy. Added
	// by gop enrich --oidc-trust, never by collection. Terminal impact.
	// Evidence is supplied for a match, not_visible (with attrs.reason) when
	// gop cannot decide the match.
	CanAssume EdgeKind = "CAN_ASSUME"
)

// Node is a vertex. ID is stable and human-readable, e.g. "org:acme-actions",
// "repo:acme-app/web", "action:acme-actions/deploy@main".
type Node struct {
	ID    string            `json:"id"`
	Kind  NodeKind          `json:"kind"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs,omitempty"`
	// Evidence for the node's attributes as a whole. Per-attribute evidence
	// goes in AttrEvidence when it differs.
	Evidence     Evidence            `json:"evidence"`
	AttrEvidence map[string]Evidence `json:"attr_evidence,omitempty"`
}

// Edge is a directed fact. Every edge carries its evidence and API source.
type Edge struct {
	From       string            `json:"from"`
	To         string            `json:"to"`
	Kind       EdgeKind          `json:"kind"`
	Evidence   Evidence          `json:"evidence"`
	SourceAPI  string            `json:"source_api"` // e.g. "graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations"
	ObservedAt time.Time         `json:"observed_at"`
	Attrs      map[string]string `json:"attrs,omitempty"`
}

// Coverage records what the collector could not see and the access that would fix it.
type Coverage struct {
	Scope    string `json:"scope"`     // e.g. "org:acme-legacy"
	Fact     string `json:"fact"`      // e.g. "ip_allow_list", "repositories"
	Reason   string `json:"reason"`    // e.g. "token is not an org owner"
	NeedsFix string `json:"needs_fix"` // e.g. "org owner on acme-legacy (SAML enforced: join through the IdP first)"
}

// Graph is the serialized snapshot (graph.json).
type Graph struct {
	Schema      string     `json:"schema"`
	CollectedAt time.Time  `json:"collected_at"`
	Enterprise  string     `json:"enterprise"`
	Nodes       []Node     `json:"nodes"`
	Edges       []Edge     `json:"edges"`
	Coverage    []Coverage `json:"coverage"`
	// AuditRetentionDays is the audit log retention the audit facts were read
	// under. When set, audit edges older than half of it are stale by default.
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
	// OrgCollectedAt records when each org's facts were last read, keyed by
	// org login. A collection sets it to CollectedAt for every org it
	// collected; a merge of a partial re-collection into an older graph
	// (collect.Merge) keeps the older times of the orgs it did not re-collect.
	// Optional: graphs written before it existed omit it.
	OrgCollectedAt map[string]time.Time `json:"org_collected_at,omitempty"`
}

// Org attribute keys (Node.Attrs on KindOrg). Values are strings for a flat JSON shape.
const (
	AttrSSO             = "sso"               // enforced | configured | none
	AttrTwoFactor       = "two_factor"        // required | not_required
	AttrDefaultPerm     = "default_perm"      // none | read | write | admin
	AttrMembersCreate   = "members_create"    // true | false
	AttrChangeVisiblity = "change_visibility" // true | false
	AttrDeleteRepos     = "delete_repos"      // true | false
	AttrPrivateForks    = "private_forks"     // true | false
	AttrIPAllowList     = "ip_allow_list"     // on | off | unknown
	AttrIPAllowEntries  = "ip_allow_entries"  // integer as string
	AttrMembers         = "members"           // integer as string
	AttrArchived        = "archived"          // true | false
	AttrRefKind         = "ref_kind"          // sha | tag | branch (on Uses edges and action_ref nodes)
	AttrVisibility      = "visibility"        // public | private | internal (repos)
	// AttrDemo on the enterprise node marks a synthetic graph from gop demo.
	AttrDemo = "demo" // true
)

// IP allow list details on KindOrg, read by an org owner only. Counts and
// on/off values only: entry values (IP ranges) are never collected.
const (
	AttrIPAllowListEntries = "ip_allow_list_entries" // active entries, integer as string, or unknown
	AttrIPAllowListApps    = "ip_allow_list_apps"    // on | off | unknown: applies to installed GitHub Apps
)

// Source position attribute keys on USES and EXECUTES_WITH edges that come
// from a workflow file or composite action. All optional; values are strings.
const (
	AttrFile    = "file"     // repo-relative path of the file, e.g. .github/workflows/release.yml
	AttrFileRef = "file_ref" // commit or branch the file was read at, when known
	AttrLine    = "line"     // 1-based line, integer as string
	AttrCol     = "col"      // 1-based column of the value start, integer as string
)

// OIDC claim inputs on workflow -EXECUTES_WITH-> oidc edges. Keys are named
// after the GitHub Actions token claims (and the components of sub) that
// cloud trust policies match on, so a matcher can compare them directly with
// the patterns internal/oidc parses. All optional; values are strings.
const (
	AttrJobs            = "jobs"             // comma list of the job ids that can mint a token
	AttrEnvironments    = "environments"     // comma list of those jobs' environment names; EnvDynamic for an expression
	AttrJobWorkflowRef  = "job_workflow_ref" // comma list of called reusable workflows that mint it: owner/repo/path@refs/heads/x
	AttrRepository      = "repository"       // owner/repo the workflow runs in
	AttrRepositoryOwner = "repository_owner" // owner of that repo
	// EnvDynamic in AttrEnvironments stands for an environment set by an
	// expression such as ${{ inputs.env }}: any value is possible.
	EnvDynamic = "*dynamic*"
)

// CAN_ASSUME edge and cloud_target node attribute keys (gop enrich --oidc-trust).
// AttrFile ("file") on a CAN_ASSUME edge is the supplied trust file.
const (
	AttrMatchedSub = "matched_sub" // CAN_ASSUME: the trust's sub pattern(s) that matched, comma list; absent when the trust has no sub condition
	AttrClaims     = "claims"      // CAN_ASSUME: comma list of the claims the trust checks (sub, repository, environment, ...)
	AttrPointer    = "pointer"     // CAN_ASSUME: JSON pointer of the trust inside the file
	AttrProvider   = "provider"    // CAN_ASSUME, cloud_target: aws | gcp | azure
	AttrOIDC       = "oidc"        // CAN_ASSUME: the oidc node whose token is matched
	AttrReason     = "reason"      // CAN_ASSUME with evidence not_visible: why gop cannot decide the match
	AttrTrust      = "trust"       // CAN_ASSUME: the trust's own target when it names more than the node (an Azure federated credential)
	AttrAccount    = "account"     // cloud_target: AWS account, GCP project, Azure subscription when known
	AttrRole       = "role"        // cloud_target: role name, service account or identity
	AttrWarnings   = "warnings"    // cloud_target: comma list, e.g. no_sub_condition, no_aud_condition, wildcard_owner
)

// CAN_ASSUME edge and cloud_target node attribute keys from gop enrich
// --cartography (a Cartography export, see docs/cartography.md).
const (
	AttrSource      = "source"       // CAN_ASSUME, cloud_target: cartography when the trust came from a Cartography export; absent for trust files; action_ref: github.com on GHES for an owner that is not an org on the instance
	AttrObservedUse = "observed_use" // CAN_ASSUME: true when CloudTrail (through Cartography) saw a workflow of this repo assume the role
	AttrTimesUsed   = "times_used"   // CAN_ASSUME with observed_use: AssumeRoleWithWebIdentity count in Cartography's CloudTrail window, integer as string
	AttrLastUsed    = "last_used"    // CAN_ASSUME with observed_use: time of the last such call, as the export gives it
	// SourceCartography is the value of AttrSource for a Cartography export.
	SourceCartography = "cartography"
)

// Workflow node attribute keys from gop enrich --poutine (a poutine JSON
// report, see docs/poutine.md). They cite poutine's findings as a separate
// source: gop did not prove them, and they never change any evidence.
const (
	AttrPoutineRules    = "poutine_rules"    // workflow: sorted comma list of the poutine rule IDs with a finding in this workflow file
	AttrPoutineSeverity = "poutine_severity" // workflow: the highest poutine rule level among those findings: error | warning | note
	AttrPoutineJobs     = "poutine_jobs"     // workflow: sorted comma list of the job ids the findings name, when poutine names one
	AttrPoutineFile     = "poutine_file"     // workflow: the poutine report the findings were read from
	// FactPoutine is the Coverage.Fact of a poutine finding that matches no
	// workflow node: it is listed, never dropped silently.
	FactPoutine = "poutine_finding"
)

// poutineInjection are the poutine rule IDs whose finding means attacker
// input becomes code in the workflow: an expression injected into a script
// (injection) or untrusted fork code run by a build tool
// (untrusted_checkout_exec).
var poutineInjection = map[string]bool{"injection": true, "untrusted_checkout_exec": true}

// IsPoutineInjectionRule reports whether a poutine rule ID is injection-class.
func IsPoutineInjectionRule(id string) bool { return poutineInjection[id] }

// PoutineInjectable reports whether a workflow node carries an
// injection-class poutine finding (AttrPoutineRules).
func PoutineInjectable(n Node) bool {
	if n.Kind != KindWorkflow {
		return false
	}
	for _, r := range strings.Split(n.Attrs[AttrPoutineRules], ",") {
		if poutineInjection[r] {
			return true
		}
	}
	return false
}

// IsDemo reports whether g is synthetic demo data: the enterprise node
// ("enterprise:<slug>") carries demo=true.
func IsDemo(g *Graph) bool {
	if g == nil {
		return false
	}
	id := "enterprise:" + g.Enterprise
	for _, n := range g.Nodes {
		if n.ID == id {
			return n.Attrs[AttrDemo] == "true"
		}
	}
	return false
}

// CAN_PUSH provenance. Collectors set Attrs[AttrVia] so fixes know which edges they remove.
const (
	AttrVia                = "via"
	ViaDefaultPerm         = "default_perm"         // granted by the org's default repository permission
	ViaOrgOwner            = "org_owner"            // the identity is an owner of the repo's org (admin on every repo)
	ViaDirect              = "direct"               // a direct collaborator grant on the repo
	ViaOutsideCollaborator = "outside_collaborator" // a direct grant to a user who is not an org member
	ViaTeam                = "team"                 // a team repository grant; members and child teams reach it through MEMBER_OF
	ViaRefBypass           = "ref_bypass"           // may land code alone on a protected branch (Attrs[AttrRef]): a ruleset bypass actor, a classic bypass allowance or push restriction, or a repo admin when admins are not enforced
	ViaTokenWrite          = "token_write"          // workflow -> its own repo: the workflow's GITHUB_TOKEN has contents: write (Attrs["jobs"] lists the jobs)
	ViaUnknown             = "unknown"              // not_visible edge: members of a host org may push to a repo gop did not collect (outside --orgs, archived or not listed for the token)
)

// AttrRule on an inferred edge names the rule that derived it. Rule IDs are
// the CAN_PUSH via values they come from.
const (
	AttrRule        = "rule"
	RuleDefaultPerm = ViaDefaultPerm // members:X -CAN_PUSH-> every repo of X, from the org's default permission write or admin
	RuleOrgOwner    = ViaOrgOwner    // identity -CAN_PUSH-> every repo of an org it owns
)

// Branch protection of mutable action refs (on action_ref nodes with
// ref_kind=branch, and on via=ref_bypass CAN_PUSH edges).
const (
	AttrRefProtected  = "ref_protected"  // true | false | unknown (not_visible): pushing to the host repo alone cannot change the branch
	AttrRefProtection = "ref_protection" // comma list: reviews, dismiss_stale, last_push_approval, status_checks, push_restricted, admins_enforced
	AttrBypass        = "bypass"         // comma list of principal IDs that can land code alone, "none", or "unknown" (not_visible)
	AttrRef           = "ref"            // branch or tag name on via=ref_bypass edges; the ref on action_ref nodes
)

// How an action ref's kind was decided, and whether a tag can move (on
// enterprise-internal action_ref nodes).
const (
	AttrRefKindSource  = "ref_kind_source"      // api (looked up) | name (the name heuristic, a fallback)
	AttrRefAmbiguous   = "ref_ambiguous"        // true: the name is both a tag and a branch; ref_kind=branch, the more mutable reading
	AttrRefImmutable   = "ref_immutable"        // true | false | unknown (not_visible), ref_kind=tag only: pushing alone cannot move the tag
	AttrRefImmutableBy = "ref_immutable_reason" // immutable_release | tag_ruleset, when ref_immutable=true
)

// Values of ref_kind_source and ref_immutable_reason.
const (
	RefKindSourceAPI    = "api"
	RefKindSourceName   = "name"
	RefImmutableRelease = "immutable_release"
	RefImmutableRuleset = "tag_ruleset"
)

// Actions access of repos that host enterprise-internal actions, and the
// consumer side of USES edges into them. The engine gates the reverse USES hop
// on these (see actionsAccessAllows).
const (
	AttrActionsAccess = "actions_access" // repo: none | user | organization | enterprise | public | unknown (not_visible)
	AttrConsumerOrg   = "consumer_org"   // USES edge into an enterprise-hosted action: org login of the using workflow or action
)

// GitHub Actions dependency lockfiles (.github/workflows/actions.lock, written
// by gh actions-lock; see docs/actions-lock.md). The lockfile pins each
// workflow's actions, nested ones included, to commits, so a workflow that
// says @v4 runs the locked commit.
const (
	AttrActionsLock = "actions_lock" // repo: true (a lockfile was read) | unknown (not_visible or unreadable); USES edge from a workflow: locked | stale
	AttrLockedSHA   = "locked_sha"   // USES edge with actions_lock=locked: the commit the lockfile pins the action to
	AttrLockEntry   = "lock_entry"   // USES edge with actions_lock=stale: comma list of the lockfile's pin keys (owner/repo@ref) for the same action repo; absent when there is none
	AttrLockMissing = "lock_missing" // USES edge with actions_lock=stale: comma list of the nested refs (owner/repo@ref) the lockfile does not pin for this workflow
	// USES edge with actions_lock=locked whose locked_sha an advisory lists
	// as affected (set by the advisory check, see docs/advisories.md). They
	// describe the locked commit only, never the ref: the action node's
	// advisories attrs stay the ref-level match.
	AttrLockAdvisories       = "lock_advisories"        // comma list of the advisory IDs
	AttrLockAdvisorySeverity = "lock_advisory_severity" // highest severity: critical | high | medium | low | unknown
	AttrLockAdvisoryFixed    = "lock_advisory_fixed"    // first fixed version to move to before rerunning gh actions-lock; absent when one has no fix
)

// Values of actions_lock on USES edges.
const (
	// LockLocked: the lockfile lists this uses: for the workflow, with a
	// commit, and pins every nested ref gop saw under it. The engine drops the
	// edge's control hop: changing the action cannot change what the
	// workflow runs. A locked commit an advisory lists as affected
	// (lock_advisories) is ranked as a known advisory of its own.
	LockLocked = "locked"
	// LockStale: the repo has a lockfile, but it does not pin this uses: as
	// written (another ref, the workflow is missing, or a nested ref is
	// missing). It counts as unpinned.
	LockStale = "stale"
)

// Known-compromise and vulnerability advisories on action_ref nodes, from OSV
// GitHub Actions advisories (gop collect or gop enrich with advisory data, see
// docs/advisories.md). Set only when the node's ref is affected; a ref gop
// cannot place gets a coverage entry (fact advisories) instead, never a
// "safe" reading.
const (
	AttrAdvisories       = "advisories"        // comma list of advisory IDs, e.g. GHSA-xxxx-xxxx-xxxx
	AttrAdvisorySeverity = "advisory_severity" // highest severity: critical | high | medium | low | unknown
	AttrAdvisoryFixed    = "advisory_fixed"    // first fixed version that leaves every listed advisory; absent when one has no fix
)

// CoverageAdvisories is the coverage fact for advisory matching: skipped (no
// data) on the enterprise scope, or one entry per action ref gop could not
// place.
const CoverageAdvisories = "advisories"

// Default-branch hardening of a repo (repo nodes, see docs/schema.md "Repo
// hardening"). Context only: the engine never reads them, so evidence
// levels, counts, scores and rank order do not depend on them. Every value
// gop could not read is "unknown" (with attr evidence not_visible and a
// coverage entry), never "false" or "off".
const (
	// Effective default-branch protection, merged from classic branch
	// protection and the active repo, org and enterprise rulesets that target
	// the default branch. Merge rule: a requirement holds when any source
	// sets it (the highest review count, the union of status checks); a
	// bypass holds only when every protecting source allows it.
	AttrBranchProtected       = "branch_protected"         // true | false | unknown
	AttrBranchReviews         = "branch_required_reviews"  // integer as string | unknown
	AttrBranchCodeOwnerReview = "branch_code_owner_review" // true | false | unknown
	AttrBranchDismissStale    = "branch_dismiss_stale"     // true | false | unknown
	AttrBranchLastPush        = "branch_last_push_approval"
	AttrBranchStatusChecks    = "branch_status_checks"    // integer as string (distinct required checks) | unknown
	AttrBranchSignedCommits   = "branch_signed_commits"   // true | false | unknown
	AttrBranchForcePush       = "branch_allow_force_push" // true | false | unknown
	AttrBranchPushRestricted  = "branch_push_restricted"  // true | false | unknown
	AttrBranchBypassActors    = "branch_bypass_actors"    // integer as string | unknown
	AttrBranchAdminBypass     = "branch_admin_bypass"     // true | false | unknown: repo or org admins get past every protecting source
	AttrBranchAppBypass       = "branch_app_bypass"       // true | false | unknown: an app gets past every protecting source
	// AttrBranchSources lists the protecting sources: classic and
	// ruleset:<id>, comma separated, or none.
	AttrBranchSources = "branch_protection_sources"
	// AttrBranchValueSources records which source set each effective value:
	// comma list of key=source[+source], e.g.
	// required_reviews=ruleset:7,allow_force_push=classic+ruleset:7.
	AttrBranchValueSources = "branch_value_sources"

	// CODEOWNERS on the default branch.
	AttrCodeowners          = "codeowners"           // .github/CODEOWNERS | CODEOWNERS | docs/CODEOWNERS | none | unknown
	AttrCodeownersValid     = "codeowners_valid"     // true | false (a line gop or GitHub cannot parse)
	AttrCodeownersWorkflows = "codeowners_workflows" // true | false | unknown: the rule matching .github/workflows/ names an owner

	// Secret scanning, from the repo's security_and_analysis.
	AttrSecretScanning       = "secret_scanning"                 // on | off | unknown
	AttrSecretPushProtection = "secret_scanning_push_protection" // on | off | unknown
	AttrSecretValidity       = "secret_scanning_validity_checks" // on | off | unknown
)

// Coverage facts of repo hardening.
const (
	FactBranchProtection = "branch_protection"
	FactCodeowners       = "codeowners"
	FactSecretScanning   = "secret_scanning"
)

// AI coding agents in GitHub Actions (workflow nodes, see
// docs/agents-in-ci.md). The collector sets them when a workflow runs a known
// agent action, invokes a known agent CLI in a run: step, or (weak) only has
// an agent-like name. Values describe the workflow's agent jobs taken
// together: the weakest gate, the widest exposure, the union of the rest.
const (
	AttrAgent           = "agent"            // sorted comma list of agent kinds, e.g. claude-code-action,codex-cli
	AttrAgentSource     = "agent_source"     // sorted comma list of how each was found: uses | run | setup | name
	AttrAgentConfidence = "agent_confidence" // action | cli | name_only (strongest signal); name_only never makes a path agentic
	AttrAgentJobs       = "agent_jobs"       // sorted comma list of the agent job ids
	AttrAgentGate       = "agent_gate"       // write_access | listed_users | anyone | none | unknown: who the agent itself lets start it
	AttrAgentExposure   = "agent_exposure"   // outsiders | listed_users | fork_readonly | maintainers: who can start an agent job with the base repo's token and secrets
	AttrAgentPrompt     = "agent_prompt_injection"
	AttrAgentPerms      = "agent_permissions" // sorted comma list of the agent jobs' write scopes, e.g. contents:write,id-token:write; default when a job takes the repo default
	AttrAgentSecrets    = "agent_secrets"     // integer as string: secrets the agent jobs reference (GITHUB_TOKEN excluded)
	AttrAgentRunner     = "agent_runner"      // hosted | self_hosted | unknown
	AttrAgentTools      = "agent_tools"       // sorted comma list of tool and sandbox settings, from AgentToolFlags
	AttrAgentRefKind    = "agent_ref_kind"    // sha | tag | branch: the least pinned ref of the agent actions (absent for CLIs)
)

// Values of agent_confidence.
const (
	AgentAction   = "action"    // a step uses: a known agent action (or the Copilot setup workflow)
	AgentCLI      = "cli"       // a run: step invokes a known agent CLI non-interactively
	AgentNameOnly = "name_only" // only the workflow, job or file name looks like an agent: weak
)

// Values of agent_gate: who the agent action lets start a run, read from
// its inputs (claude-code-action and codex-action check that the actor has
// write access unless allowed_non_write_users / allow-users widen it).
const (
	GateWriteAccess = "write_access" // only actors with write access
	GateListed      = "listed_users" // write access plus named users
	GateAnyone      = "anyone"       // the check is turned off ('*')
	GateNone        = "none"         // the agent has no actor check (a CLI, a base action)
	GateUnknown     = "unknown"      // gop does not know the action's check: counted as possible, never as closed
)

// Values of agent_exposure.
const (
	ExposureOutsiders  = "outsiders"     // people without push access can start an agent job on a trigger that holds the base repo's token and secrets
	ExposureListed     = "listed_users"  // named users without write access can
	ExposureForkRO     = "fork_readonly" // anyone can start it from a fork's pull_request, which runs with a read-only token and no secrets
	ExposureMaintainer = "maintainers"   // only people with write (push) access can start it
)

// AgentToolFlags is the vocabulary of agent_tools: settings that widen or
// scope what the agent may do. allowed_tools means a tool list was given;
// every other value removes the agent's own approval or sandbox.
var AgentToolFlags = []string{
	"allowed_tools",
	"bypass_permissions",
	"dangerously_bypass_approvals_and_sandbox",
	"dangerously_skip_permissions",
	"full_auto",
	"safety_strategy_unsafe",
	"sandbox_danger_full_access",
	"yes_always",
	"yolo",
}
