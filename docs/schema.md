# Graph schema: gop.graph/v1

`gop collect` writes a single JSON document (graph.json). The Go source of truth is [`internal/graph/types.go`](../internal/graph/types.go); this page describes the serialized form. Breaking changes bump `schema` (see [Versioning](#versioning)).

The machine-checkable contract is the JSON Schema (draft 2020-12) [`schema/gop.graph.v1.schema.json`](../schema/gop.graph.v1.schema.json), `$id` `https://github.com/peleduri/gop/schema/gop.graph.v1.schema.json`. Check a file with:

```
gop validate --graph graph.json [--format text|json]
```

`gop validate` checks that `schema` is a version gop knows, that the document conforms to that version's JSON Schema, and that every edge endpoint is a declared node. A `not_visible` node, attribute or edge with no `coverage` entry for itself or its org is a warning, not an error. Every problem names its JSON pointer, e.g. `/edges/3/evidence`. Exit codes: 0 valid (warnings allowed), 1 invalid, 2 usage error. The other commands load graph.json without running these checks.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `gop.graph/v1` for this version. |
| `collected_at` | RFC 3339 time | When collection finished. |
| `enterprise` | string | Enterprise slug, e.g. `acme`. |
| `nodes` | Node[] | Vertices. |
| `edges` | Edge[] | Directed facts. |
| `coverage` | Coverage[] | What the token could not see, and how to fix it. |

## Evidence

Every node and edge has `evidence`:

| Value | Meaning |
|---|---|
| `live` | Read from current state through the API. |
| `audit` | Inferred from the audit log (bounded retention, may be stale). |
| `not_visible` | The token can't read this fact. The hop is unknown, not absent. |

## Node

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable, human-readable: `org:acme-actions`, `repo:acme-app/web`, `action:acme-actions/deploy@main`. The prefix follows the kind (see below). |
| `kind` | NodeKind | See below. |
| `name` | string | Display name. |
| `attrs` | map[string]string | Optional. Flat string attributes. |
| `evidence` | Evidence | Evidence for the node's attributes as a whole. |
| `attr_evidence` | map[string]Evidence | Optional. Per-attribute evidence where it differs from `evidence`. |

### Node kinds

| Kind | ID | Meaning |
|---|---|---|
| `enterprise` | `enterprise:acme` | The enterprise. |
| `org` | `org:acme-actions` | An organization. |
| `org_members` | `members:acme-actions` | The set of members of one org, as a single principal. |
| `identity` | `identity:alice`, `team:acme-actions/platform` | A user (`identity:<login>`), team (`team:<org>/<slug>`) or app. |
| `repo` | `repo:acme-app/web` | A repository (exactly `owner/name`). |
| `workflow` | `workflow:acme-app/web/.github/workflows/ci.yml` | A workflow file. |
| `action_ref` | `action:acme-actions/deploy@main` | `owner/repo[/path]@ref` as consumed by workflows. |
| `secret` | `secret:acme-app/billing` | A secrets scope reachable by a workflow. |
| `oidc` | `oidc:acme-app/web` | `id-token: write` (cloud OIDC). |
| `runner` | `runner:acme-app/worker` | A self-hosted runner pool. |
| `cloud_target` | `cloud:...` | A cloud account or role trusted through OIDC. |

### Attributes

Values are strings to keep the JSON flat. Other keys may appear; consumers must ignore keys they don't know.

| Key | On | Values |
|---|---|---|
| `sso` | org | `enforced`, `configured`, `none` |
| `two_factor` | org | `required`, `not_required` |
| `default_perm` | org | `none`, `read`, `write`, `admin` |
| `members_create` | org | `true`, `false` |
| `change_visibility` | org | `true`, `false` |
| `delete_repos` | org | `true`, `false` |
| `private_forks` | org | `true`, `false` |
| `ip_allow_list` | org | `on`, `off`, `unknown` |
| `ip_allow_entries` | org | integer as string |
| `members` | org | integer as string |
| `archived` | org, repo | `true`, `false` |
| `visibility` | repo | `public`, `private`, `internal` |
| `collaborators` | repo | `unknown` (`not_visible`) when the token could not list the repo's direct collaborators |
| `members` | team | Everyone who holds the team's grants (`GET /orgs/{org}/teams/{slug}/members?role=all`, which includes child teams' members), integer as string; `unknown` (`not_visible`) when the list was refused |
| `org`, `slug`, `privacy` | team | The team's org, slug, and `closed` or `secret` |
| `teams_partial` | org | `true` when the token is not an org owner (secret teams are not listed) or the teams could not be listed |
| `ref_kind` | action_ref node, `USES` edge | `sha`, `tag`, `branch` |
| `file` | `USES`, `EXECUTES_WITH` edge | Repo-relative path of the workflow or action file the edge was read from, e.g. `.github/workflows/release.yml`. |
| `file_ref` | `USES`, `EXECUTES_WITH` edge | Commit or branch the file was read at, when known (the repo's default branch for top-level workflows, the parent `uses:` ref for nested files). |
| `line` | `USES`, `EXECUTES_WITH` edge | 1-based line, integer as string: the `uses:` value on `USES`, the `id-token: write` (or `write-all`) key on the OIDC edge, the `runs-on:` key on the runner edge. |
| `col` | `USES` edge | 1-based column where the `uses:` value starts (the opening quote, if quoted), integer as string. |

## Edge

| Field | Type | Meaning |
|---|---|---|
| `from` | string | Source node id. |
| `to` | string | Target node id. |
| `kind` | EdgeKind | See below. |
| `evidence` | Evidence | How the fact was observed. |
| `source_api` | string | API that supplied it, e.g. `graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations`. |
| `observed_at` | RFC 3339 time | When it was observed. |
| `attrs` | map[string]string | Optional. |

### Edge kinds

| Kind | From → To | Meaning |
|---|---|---|
| `CAN_PUSH` | org_members, identity → repo | The principal can push to the repo. |
| `USES` | workflow → action_ref | The workflow consumes the Action. `attrs.ref_kind` is `sha`, `tag` or `branch`. |
| `RESOLVES_TO` | action_ref → repo | The repo that hosts the Action. |
| `DEFINED_IN` | workflow → repo | The repo the workflow lives in. Code pushed there changes the workflow. |
| `EXECUTES_WITH` | workflow → secret, oidc, runner | Terminal impact: what the workflow runs with. |
| `MEMBER_OF` | identity → org, identity → team, team → team | Org membership, from the enterprise consumed licenses (`attrs.role` is `owner` or `member`; outside collaborators have none). Direct team membership (`GET /orgs/{org}/teams/{slug}/members?role=all`). A child team's nesting under its parent (`GET /orgs/{org}/teams`, `parent.slug`): members of the child reach what the parent reaches. |

### CAN_PUSH provenance

Every `CAN_PUSH` edge carries `attrs.via`, so fixes know which edges they remove, and `attrs.permission`:

| `via` | From | Source | `permission` |
|---|---|---|---|
| `default_perm` | org_members | The org's default repository permission (`write` or `admin`). | the default permission |
| `org_owner` | identity | An `Owner` role in the consumed licenses: owners are admin on every repo of the org. | `admin` |
| `direct` | identity | A direct collaborator grant with push (`GET /repos/{owner}/{repo}/collaborators?affiliation=direct`, `permissions.push`, `maintain` or `admin`). | `role_name`, e.g. `write`, `maintain`, or a custom role such as `deployer` (then `attrs.base_role` holds its base role when the token can read the org's custom roles) |
| `outside_collaborator` | identity | Same as `direct`, for a user listed by `GET /orgs/{org}/outside_collaborators` (not an org member). | as for `direct` |
| `team` | team | A team repository grant with push (`GET /orgs/{org}/teams/{slug}/repos`, `permissions.push`, `maintain` or `admin`). | `role_name`, including custom roles |

When an identity is both an owner and a direct collaborator on a repo, the `direct` edge is kept. When the collaborators list for a repo cannot be read (403/404), gop emits no live edge; instead each repository-scoped role in the consumed licenses for that repo (e.g. `acme-actions/deploy:Write`) becomes a `CAN_PUSH` edge with evidence `not_visible`, `permission=unknown` and `attrs.license_role`, which is possible reach, never confirmed. One coverage entry per org (`fact: can_push:collaborators`) counts the affected repos. `LowerDefaultPerm` removes only `via=default_perm` edges.

### Teams

Team IDs are `team:<org>/<slug>` (kind `identity`). The team members endpoint also returns the members of child teams, so to keep one fact per edge gop records only direct members: a team's list minus the lists of its direct children. A user who is both a direct member of a parent and a member of its child is then recorded on the child only, which reaches the same repositories. Members are fetched only for teams with a push grant and teams below one. When a team's member list returns 403/404, its `CAN_PUSH` edges stay `live` (the grant was observed), the team gets `members=unknown` and the org gets one `team_members:<slug>` coverage entry; no member edges are invented. When the token is not an org owner, secret teams and their grants are not listed: the org gets `teams_partial=true` and a `can_push:teams` coverage entry.

### Principals and scoring

`who_can_reach`, `reach` and `blast_radius` accept every principal: each `org_members` node and each `identity` node. Totals (`top_paths`, `what_if`, `suggest_fixes`) sum over the scoring principals only: every `org_members` node, plus identities with at least one `CAN_PUSH` edge or a `MEMBER_OF` edge to something that is not an org (a team). Teams qualify the same way: through their own grants or their nesting under a parent team. An identity whose only edges are org memberships reaches exactly what `members:X` reaches, so counting it again would multiply the `(principal, repo)` pair totals by the number of licensed users.

A reach path reads, for example: `members:acme-actions -CAN_PUSH-> repo:acme-actions/deploy <-RESOLVES_TO- action:acme-actions/deploy@main <-USES- workflow:acme-app/web/.github/workflows/release.yml -EXECUTES_WITH-> oidc:...`.

## Coverage

| Field | Type | Meaning |
|---|---|---|
| `scope` | string | e.g. `org:acme-legacy`. |
| `fact` | string | e.g. `ip_allow_list`, `repositories`. |
| `reason` | string | e.g. `token is not an org owner`. |
| `needs_fix` | string | The access that would make it visible, e.g. `org owner on acme-legacy (SAML enforced: join through the IdP first)`. |

## Example

```json
{
  "schema": "gop.graph/v1",
  "collected_at": "2026-01-01T00:00:00Z",
  "enterprise": "acme",
  "nodes": [
    {"id": "org:acme-actions", "kind": "org", "name": "acme-actions",
     "attrs": {"default_perm": "write", "two_factor": "required", "sso": "enforced"},
     "evidence": "live"},
    {"id": "action:acme-actions/deploy@main", "kind": "action_ref", "name": "acme-actions/deploy@main",
     "attrs": {"ref_kind": "branch"}, "evidence": "live"}
  ],
  "edges": [
    {"from": "workflow:acme-app/web/.github/workflows/release.yml", "to": "action:acme-actions/deploy@main",
     "kind": "USES", "evidence": "live", "source_api": "rest:repos.contents",
     "observed_at": "2026-01-01T00:00:00Z", "attrs": {"ref_kind": "branch"}}
  ],
  "coverage": [
    {"scope": "org:acme-legacy", "fact": "ip_allow_list", "reason": "token is not an org owner",
     "needs_fix": "org owner on acme-legacy"}
  ]
}
```

## Versioning

`schema` names the contract a file follows. Consumers should check it before reading anything else.

Non-breaking within `gop.graph/v1` (no version change):

- new optional fields on the top level, nodes, edges or coverage entries;
- new attribute keys in `attrs` or `attr_evidence`;
- new `coverage` facts and new `source_api` strings.

Breaking, bumps `schema` to `gop.graph/v2`:

- removing or renaming a field;
- making an optional field required, or changing a field's type;
- adding, removing or changing the meaning of an `evidence`, node `kind` or edge `kind` value;
- changing ID conventions (prefixes or the shape after them).

The JSON Schema allows unknown fields and attribute keys for this reason. Consumers must ignore attributes and fields they don't know rather than reject the file. A new major version ships as a new schema file (`schema/gop.graph.v2.schema.json`); `gop validate` keeps validating every version it lists as known.

## Changelog

| Version | gop release | Change |
|---|---|---|
| `gop.graph/v1` | v0.1.0 | First version. |
| `gop.graph/v1` | unreleased | Additive: JSON Schema published in `schema/gop.graph.v1.schema.json`; `file`, `file_ref`, `line`, `col` on `USES` and `EXECUTES_WITH` edges; `identity` nodes for licensed users; `CAN_PUSH` `via` values `org_owner`, `direct`, `outside_collaborator`, `team`; `identity` nodes with `team:<org>/<slug>` IDs (the engine already read this prefix as `identity`) and `MEMBER_OF` edges to teams. |
