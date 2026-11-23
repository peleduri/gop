// Package graph holds gop's evidence graph: typed nodes and edges where every
// fact records how it was observed. This file is the shared contract between
// collectors, the analysis engine, the MCP server and the report.
package graph

import "time"

// SchemaVersion is bumped on any breaking change to the serialized Graph.
const SchemaVersion = "gop.graph/v1"

// Evidence says how a fact was observed. gop never turns "couldn't see" into "off".
type Evidence string

const (
	// Live: read from the current state through the API.
	Live Evidence = "live"
	// Audit: inferred from the audit log (bounded retention, may be stale).
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
