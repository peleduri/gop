# Graph schema: gop.graph/v1

`gop collect` writes a single JSON document (graph.json). The Go source of truth is [`internal/graph/types.go`](../internal/graph/types.go); this page describes the serialized form. Breaking changes bump `schema`.

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
| `id` | string | Stable, human-readable: `org:acme-actions`, `repo:acme-app/web`, `action:acme-actions/deploy@main`. |
| `kind` | NodeKind | See below. |
| `name` | string | Display name. |
| `attrs` | map[string]string | Optional. Flat string attributes. |
| `evidence` | Evidence | Evidence for the node's attributes as a whole. |
| `attr_evidence` | map[string]Evidence | Optional. Per-attribute evidence where it differs from `evidence`. |

### Node kinds

| Kind | Meaning |
|---|---|
| `enterprise` | The enterprise. |
| `org` | An organization. |
| `org_members` | The set of members of one org, as a single principal. |
| `identity` | A user, team or app. |
| `repo` | A repository. |
| `workflow` | A workflow file. |
| `action_ref` | `owner/repo[/path]@ref` as consumed by workflows. |
| `secret` | A secrets scope reachable by a workflow. |
| `oidc` | `id-token: write` (cloud OIDC). |
| `runner` | A self-hosted runner pool. |
| `cloud_target` | A cloud account or role trusted through OIDC. |

### Attributes

Values are strings to keep the JSON flat.

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
| `MEMBER_OF` | identity → org | Org membership. |

A reach path reads, for example: `org_members:acme-actions -CAN_PUSH-> repo:acme-actions/deploy <-RESOLVES_TO- action:acme-actions/deploy@main <-USES- workflow:acme-app/web/.github/workflows/release.yml -EXECUTES_WITH-> oidc:...`.

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
