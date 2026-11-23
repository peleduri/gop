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
)

// NodeKind is the type of a node.
type NodeKind string

const (
	KindEnterprise  NodeKind = "enterprise"
	KindOrg         NodeKind = "org"
	KindOrgMembers  NodeKind = "org_members" // the set of members of one org, as a single principal
	KindIdentity    NodeKind = "identity"    // a user, team or app; ID "identity:<login>"
	KindRepo        NodeKind = "repo"
	KindWorkflow    NodeKind = "workflow"
	KindActionRef   NodeKind = "action_ref" // owner/repo[/path]@ref as consumed by workflows
	KindSecret      NodeKind = "secret"     // secrets scope reachable by a workflow
	KindOIDC        NodeKind = "oidc"       // id-token: write
	KindRunner      NodeKind = "runner"     // self-hosted runner pool
	KindCloudTarget NodeKind = "cloud_target"
)

// EdgeKind is the type of an edge.
type EdgeKind string

const (
	// CanPush: principal (org_members, identity) can push to repo.
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
	// MemberOf: identity -> org.
	MemberOf EdgeKind = "MEMBER_OF"
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
)

// Source position attribute keys on USES and EXECUTES_WITH edges that come
// from a workflow file or composite action. All optional; values are strings.
const (
	AttrFile    = "file"     // repo-relative path of the file, e.g. .github/workflows/release.yml
	AttrFileRef = "file_ref" // commit or branch the file was read at, when known
	AttrLine    = "line"     // 1-based line, integer as string
	AttrCol     = "col"      // 1-based column of the value start, integer as string
)

// CAN_PUSH provenance. Collectors set Attrs[AttrVia] so fixes know which edges they remove.
const (
	AttrVia                = "via"
	ViaDefaultPerm         = "default_perm"         // granted by the org's default repository permission
	ViaOrgOwner            = "org_owner"            // the identity is an owner of the repo's org (admin on every repo)
	ViaDirect              = "direct"               // a direct collaborator grant on the repo
	ViaOutsideCollaborator = "outside_collaborator" // a direct grant to a user who is not an org member
)
