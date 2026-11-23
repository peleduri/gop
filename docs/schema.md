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
| `archived` | org, repo | `true`, `false` (`unknown`, `not_visible` for an org the token can't read) |
| `orgs` | enterprise | Number of enterprise orgs, integer as string; `unknown` (`not_visible`) when the token cannot read the enterprise |
| `in_enterprise_source` | org | Only when the token cannot read the enterprise: where the org came from: `config` (`--orgs`, counted as an enterprise org), `user_orgs` (`GET /user/orgs`) or `installation` (owners in `GET /installation/repositories`). `source` holds the API label. |
| `in_enterprise` | action_ref | `true` when the owner is an enterprise org (then a `RESOLVES_TO` edge points at the hosting repo), `false` when it is not. `unknown` (`not_visible`) when the token cannot read the enterprise and the owner is not a collected org: the owner may be an enterprise org gop can't see, so the reference is not resolved and one aggregated coverage entry (`scope: enterprise:<slug>`, `fact: in_enterprise`) names up to 20 such owners. It never reads as outside the enterprise. |
| `visibility` | repo | `public`, `private`, `internal` |
| `collaborators` | repo | `unknown` (`not_visible`) when the token could not list the repo's direct collaborators |
| `members` | team | Everyone who holds the team's grants (`GET /orgs/{org}/teams/{slug}/members?role=all`, which includes child teams' members), integer as string; `unknown` (`not_visible`) when the list was refused |
| `org`, `slug`, `privacy` | team | The team's org, slug, and `closed` or `secret` |
| `teams_partial` | org | `true` when the token is not an org owner (secret teams are not listed) or the teams could not be listed |
| `ref_kind` | action_ref node, `USES` edge | `sha`, `tag`, `branch` |
| `ref_protected` | action_ref node (enterprise-internal, `ref_kind=branch`) | `true` when branch protection stops a pusher from changing the branch alone, `false`, or `unknown` (`not_visible`, with a `ref_protection` coverage entry). See [Branch protection](#branch-protection). |
| `ref_protection` | action_ref node | Comma list of the branch's rules, in this order: `reviews` (a pull request needs at least one approval), `dismiss_stale`, `last_push_approval`, `status_checks`, `push_restricted` (an `update` rule or classic push restrictions), `admins_enforced`. Absent when there are none. |
| `bypass` | action_ref node with `ref_protected=true` | Comma list of the principal IDs that can still land code alone (each also has a `via=ref_bypass` edge), `none`, or `unknown` (`not_visible`, with a `bypass` coverage entry) when the bypass actors are visible to repository admins only. |
| `actions_access` | repo hosting a referenced enterprise action | The Actions access setting (`GET /repos/{owner}/{repo}/actions/permissions/access`): `none`, `user`, `organization` or `enterprise`; `public` for a public repo (no request); `unknown` (`not_visible`, with an `actions_access` coverage entry) when the setting can't be read (it needs repo admin) or has a value gop does not know. See [Actions access](#actions-access). |
| `consumer_org` | `USES` edge into an action that resolves to an enterprise repo | Org login of the using workflow's repo, or of the using composite action's host repo. Informational: the engine reads the repos from `DEFINED_IN` and `RESOLVES_TO`. |
| `file` | `USES`, `EXECUTES_WITH` edge | Repo-relative path of the workflow or action file the edge was read from, e.g. `.github/workflows/release.yml`. |
| `file_ref` | `USES`, `EXECUTES_WITH` edge | Commit or branch the file was read at, when known (the repo's default branch for top-level workflows, the parent `uses:` ref for nested files). |
| `line` | `USES`, `EXECUTES_WITH` edge | 1-based line, integer as string: the `uses:` value on `USES`, the `id-token: write` (or `write-all`) key on the OIDC edge, the `runs-on:` key on the runner edge. |
| `token_write` | workflow | `true` when the workflow's `GITHUB_TOKEN` has `contents: write` on its own repo (then a `via=token_write` `CAN_PUSH` edge points at the repo), `false`, or `unknown` (`not_visible`, with a `default_workflow_permissions` coverage entry) when a job takes the default and the default is not visible. See [Workflow tokens](#workflow-tokens). |
| `token_scopes` | workflow | Comma list of the token's other write scopes (`actions`, `id-token`, `packages`, `pull-requests`, ...), or `write-all`. Display only: the engine does not read it. |
| `col` | `USES` edge | 1-based column where the `uses:` value starts (the opening quote, if quoted), integer as string. |
| `demo` | enterprise | `true` on a synthetic graph from `gop demo`; MCP summaries and the report title then start with `[demo data]` |
| `source_api` | any node (demo graphs only) | `demo:<generator rule>`, matching the edges' `source_api` |

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
| `CAN_PUSH` | org_members, identity → repo; workflow → its own repo | The principal can push to the repo. From a workflow (`via=token_write`): the workflow's `GITHUB_TOKEN` can push to its repo, so whoever controls the workflow controls the repo. A workflow is never a principal. |
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
| `ref_bypass` | identity (user or team) | May land code alone on the protected branch `attrs.ref` (see [Branch protection](#branch-protection)). `attrs.rule_source` is `ruleset:<id>` or `branch_protection`; ruleset edges also carry `attrs.bypass_mode`. | `bypass` |
| `token_write` | workflow | The workflow's `GITHUB_TOKEN` has `contents: write` on the repo it lives in (see [Workflow tokens](#workflow-tokens)). `attrs.jobs` lists the job ids. | `contents: write` |

When an identity is both an owner and a direct collaborator on a repo, the `direct` edge is kept. When the collaborators list for a repo cannot be read (403/404), gop emits no live edge; instead each repository-scoped role in the consumed licenses for that repo (e.g. `acme-actions/deploy:Write`) becomes a `CAN_PUSH` edge with evidence `not_visible`, `permission=unknown` and `attrs.license_role`, which is possible reach, never confirmed. One coverage entry per org (`fact: can_push:collaborators`) counts the affected repos. `LowerDefaultPerm` removes only `via=default_perm` edges.

### Teams

Team IDs are `team:<org>/<slug>` (kind `identity`). The team members endpoint also returns the members of child teams, so to keep one fact per edge gop records only direct members: a team's list minus the lists of its direct children. A user who is both a direct member of a parent and a member of its child is then recorded on the child only, which reaches the same repositories. Members are fetched only for teams with a push grant and teams below one. When a team's member list returns 403/404, its `CAN_PUSH` edges stay `live` (the grant was observed), the team gets `members=unknown` and the org gets one `team_members:<slug>` coverage entry; no member edges are invented. When the token is not an org owner, secret teams and their grants are not listed: the org gets `teams_partial=true` and a `can_push:teams` coverage entry.

### Branch protection

For every enterprise-internal action ref on a branch, `gop collect` reads, once per (repo, branch), `GET /repos/{owner}/{repo}/rules/branches/{branch}` (every active rule from repo and org rulesets, readable with read access), `GET /repos/{owner}/{repo}/branches/{branch}` and, when the branch has classic protection, `GET /repos/{owner}/{repo}/branches/{branch}/protection` (admin only). For each ruleset that protects the branch it reads `GET /repos/{owner}/{repo}/rulesets/{id}?includes_parents=true` for `bypass_actors` (returned to admins only).

`ref_protected=true` when a pull request needs at least one approval and a stale approval can't be reused (`dismiss_stale_reviews_on_push` or classic `dismiss_stale_reviews`, or `require_last_push_approval`), or when an `update` rule or classic `restrictions` limit who may push. Required status checks alone don't count: the pusher controls the code under test and can make the checks pass. Reviews without stale-approval dismissal don't count either: get a harmless change approved, then push more commits. `ref_protected=unknown` when the rules can't be read, or when the branch has classic protection whose details are not visible and no ruleset protects it.

The principals that can still land code alone become `CAN_PUSH` edges to the repo with `via=ref_bypass` and `ref=<branch>`, next to (not replacing) their other grants: ruleset bypass actors (`Team` becomes `team:<org>/<slug>`, `User` becomes `identity:<login>`, `OrganizationAdmin` becomes each org owner, and the built-in `RepositoryRole` maintain, write or admin becomes the principals with exactly that role on the repo), classic `bypass_pull_request_allowances` users and teams when reviews protect the branch (otherwise classic `restrictions` users and teams), and repository admins when classic protection does not enforce admins. Apps, deploy keys, custom repository roles and role holders that are not fully visible get a `ref_bypass` coverage entry. When several rules protect one branch their lists are united: an over-approximation, since a real bypasser must bypass all of them.

The engine uses these facts on the `RESOLVES_TO` hop only. With `ref_protected=true` there is no `repo -> action` hop; each matching `ref_bypass` edge becomes a `principal -> action` hop instead (and with `bypass=unknown` the `repo -> action` hop stays, `not_visible`). With `ref_protected=unknown` the `repo -> action` hop is `not_visible`, so the path is possible, not confirmed. `false` or no attribute changes nothing. `DEFINED_IN` is not gated: a push to any unprotected branch runs that branch's copy of an `on: push` workflow with the repo's secrets. Tags are not looked at.

### Workflow tokens

A workflow's `GITHUB_TOKEN` gets `contents: write` from the file or from the default. gop resolves each job the way GitHub does: a job-level `permissions` key replaces the workflow-level one; a mapping that omits `contents` means `contents: none`; `write-all` is write, `read-all` is read, `{}` is none. A job with no `permissions` at either level takes the default. The workflow is `true` when any job resolves to write, else it takes the default when any job does, else `false`.

When some workflow in a repo takes the default, `gop collect` reads `GET /repos/{owner}/{repo}/actions/permissions/workflow` (`default_workflow_permissions`, admin only). When that is refused it reads `GET /orgs/{org}/actions/permissions/workflow` once per org. The repo can only be more restrictive than its org, so an org value of `read` proves `read`; `write` leaves the repo unknown.

For `token_write=true` the workflow gets `workflow -CAN_PUSH-> repo` with `via=token_write`, evidence `live`, and source `rest:GET /repos/{owner}/{repo}/contents/{path}` when the file decided, or the settings API that did. For `unknown` the same edge is `not_visible` and the repo gets a `default_workflow_permissions` coverage entry (`needs_fix: admin on <repo> (or org owner)`). The engine needs nothing more: `CAN_PUSH` is a full control hop, so the repo is expanded (its workflows and the actions it hosts), not just counted as CI reach. A `GITHUB_TOKEN` push is subject to branch protection like any push, so `ref_protected` still gates the `repo -> action` hop.

Known limitations: a `GITHUB_TOKEN` cannot change files under `.github/workflows/` (that needs the `workflows` permission, which it never has). gop still expands the repo to its workflows (`DEFINED_IN` reversed), because workflows almost always run repo code: scripts, local actions, build files. Such paths show `via=token_write` on the `CAN_PUSH` hop (`explain` prints edge attrs). Who can trigger the workflow (`pull_request` from forks always gets a read token) is not modeled yet, and other write scopes (`actions`, `packages`) are recorded in `token_scopes` only.

### Actions access

A private or internal repo's Actions "Access" setting decides which other repositories may use the actions and reusable workflows it hosts. `gop collect` reads it once for every repo that is the target of a `RESOLVES_TO` edge and records `actions_access` on the repo. The engine checks it on the reverse `USES` hop (action controls consumer), comparing the host repo (the action's `RESOLVES_TO` target) with the consumer's repo (a workflow's `DEFINED_IN` target, or a composite action's host):

| `actions_access` | Hop kept for |
|---|---|
| no attr, `public`, `enterprise` | every consumer |
| `organization`, `user` | consumers in the host's org (owner) |
| `none` | the host repo itself |
| `unknown` | consumers in the host's org; other consumers keep the hop as `not_visible`, so the path is possible, not confirmed |

A hop the setting forbids is dropped. Graphs without `actions_access` behave as before. The consumer side (the consumer org's allowed-actions policy) is not read yet.

### Principals and scoring

`who_can_reach`, `reach` and `blast_radius` accept every principal: each `org_members` node and each `identity` node. Workflows are not principals, even with a `via=token_write` `CAN_PUSH` edge. Totals (`top_paths`, `what_if`, `suggest_fixes`) sum over the scoring principals only: every `org_members` node, plus identities with at least one `CAN_PUSH` edge or a `MEMBER_OF` edge to something that is not an org (a team). Teams qualify the same way: through their own grants or their nesting under a parent team. An identity whose only edges are org memberships reaches exactly what `members:X` reaches, so counting it again would multiply the `(principal, repo)` pair totals by the number of licensed users.

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
| `gop.graph/v1` | unreleased | Additive: `ref_protected`, `ref_protection` and `bypass` on action_ref nodes (typed in the JSON Schema as `NodeAttrs`); `CAN_PUSH` `via=ref_bypass` with `ref`, `rule_source` and `bypass_mode`, possibly parallel to another `CAN_PUSH` edge between the same nodes; coverage facts `ref_protection`, `bypass` and `ref_bypass`. |
| `gop.graph/v1` | unreleased | Additive: `CAN_PUSH` from a workflow to its own repo with `via=token_write`, `permission=contents: write` and `jobs`; `token_write` and `token_scopes` on workflow nodes; coverage fact `default_workflow_permissions`. Coverage scoped to a repo also covers the workflows in it (`gop validate`). |
| `gop.graph/v1` | unreleased | Additive: `actions_access` on repo nodes (typed in the JSON Schema as `NodeAttrs`), `consumer_org` on `USES` edges (`EdgeAttrs`), coverage fact `actions_access`. |
