# Graph schema: gop.graph/v2

`gop collect` writes a single JSON document (graph.json). The Go source of truth is [`internal/graph/types.go`](../internal/graph/types.go); this page describes the serialized form. Breaking changes bump `schema` (see [Versioning](#versioning)).

The machine-checkable contract is the JSON Schema (draft 2020-12) [`schema/gop.graph.v2.schema.json`](../schema/gop.graph.v2.schema.json), `$id` `https://github.com/peleduri/gop/schema/gop.graph.v2.schema.json`. Documents written before v2 follow [`schema/gop.graph.v1.schema.json`](../schema/gop.graph.v1.schema.json); gop still reads and validates them (see [Changes](#changes)). Check a file with:

```
gop validate --graph graph.json [--format text|json]
```

`gop validate` checks that `schema` is a version gop knows, that the document conforms to that version's JSON Schema, that every edge endpoint is a declared node, and that every `supplied` edge names its file (`attrs.file`, `source_api` `supplied:<file>`). A `not_visible` node, attribute or edge with no `coverage` entry for itself or its org is a warning, not an error (an undecided `CAN_ASSUME` edge carries `attrs.reason` instead and is exempt). Every problem names its JSON pointer, e.g. `/edges/3/evidence`. Exit codes: 0 valid (warnings allowed), 1 invalid, 2 usage error. The other commands load graph.json without running these checks.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `gop.graph/v2` for this version (gop also reads `gop.graph/v1`). |
| `collected_at` | RFC 3339 time | When collection finished. |
| `enterprise` | string | Enterprise slug, e.g. `acme`. |
| `nodes` | Node[] | Vertices. |
| `edges` | Edge[] | Directed facts. |
| `coverage` | Coverage[] | What the token could not see, and how to fix it. |
| `audit_retention_days` | integer | Optional. The audit log retention the `audit` facts were read under. When set, an `audit` edge older than half of it is stale (see [Evidence](#evidence)). |
| `org_collected_at` | object, org login → RFC 3339 time | Optional. When each org's facts were last read. A collection sets every org it collected to `collected_at`. A graph that merges a re-collection of some orgs into an older graph (`collect.Merge`, `collect.Config.MergeInto`) keeps the older time for the other orgs, and `collected_at` is the re-collection's. Absent in graphs written before it existed. |

## Evidence

Every node and edge has `evidence`:

| Value | Meaning |
|---|---|
| `live` | Read from current state through the API. |
| `inferred` | Derived from other observed facts by a documented rule, named in the edge's `attrs.rule`. Counts as confirmed reach. Rules: `default_perm` (members of an org push to every repo of it, from the org's default repository permission `write` or `admin`; not read from each repo's permission list) and `org_owner` (an org owner is admin on every repo of the org, from the owner list). New in v2. |
| `audit` | Read from the audit log (bounded retention, may be stale). An `audit` edge whose `observed_at` is older than the maximum audit age before `collected_at` is **stale**: the engine treats the hop as `not_visible` (possible reach only, never a fix suggestion) and marks it (`Hop.stale`, `Path.stale`; text output `[audit, stale]`). The maximum age is half of `audit_retention_days` when set, else 90 days; `graph.Options.MaxAuditAge` overrides it. An edge without `observed_at` is never stale. |
| `supplied` | Read from a file the user supplied (a cloud OIDC trust policy given to `gop enrich --oidc-trust`); gop did not observe it live. Counts as confirmed reach (the user asserts the file reflects what is deployed), but a path through it has `supplied: true` and every summary of it says "cloud hop from supplied trust file <file>, not read from the cloud". A supplied edge has `source_api` `supplied:<file>` and `attrs.file`. Ranked between `audit` and `not_visible`: a path's evidence is its weakest hop, `live` > `inferred` > `audit` > `supplied` > `not_visible`. |
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
| `runner` | `runner:acme-app/worker` | The runners a repo's jobs run on. A `live` `EXECUTES_WITH` edge means a `self-hosted` label; a `not_visible` edge with `attrs.classification=unknown` means a custom label, a `group:` or an expression that may be self-hosted (with a `runner_labels` coverage entry on the workflow). GitHub-hosted labels (`ubuntu-*`, `windows-*`, `macos-*`) get no edge. |
| `cloud_target` | `cloud:aws:arn:aws:iam::111111111111:role/deploy`, `cloud:gcp:serviceAccount:deploy@acme-prod.iam.gserviceaccount.com`, `cloud:azure:app:<client id>` | A cloud identity a workflow's OIDC token can assume, from a supplied trust file (`gop enrich`): `cloud:<provider>:<id>` where id is the AWS role ARN; for GCP `serviceAccount:<email>` when an IAM binding lets the pool impersonate a service account, else the workload identity provider name; for Azure the application (`app:<client id>`) or managed identity (`identity:<resource id>`). Evidence `supplied`. |
| `external` | `external:anyone` | A principal outside the enterprise. `external:anyone` is anyone on the internet: they can fork a public repo, open pull requests and comment on it. See [Triggers](#triggers). |

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
| `ip_allow_entries` | org | integer as string: every IP allow list entry, active or not |
| `ip_allow_list_entries` | org | Active IP allow list entries (`ipAllowListEntries`, counting `isActive` only), integer as string; `unknown` (`not_visible`) when the token is not an org owner. Entry values (IP ranges) are never collected. |
| `ip_allow_list_apps` | org | `on`, `off`: whether the IP allow list also applies to installed GitHub Apps (`ipAllowListForInstalledAppsEnabledSetting`); `unknown` (`not_visible`) when the token is not an org owner. The `ip_allow_list` coverage entry of an org covers `ip_allow_entries`, `ip_allow_list_entries` and `ip_allow_list_apps` too. |
| `members` | org | integer as string |
| `archived` | org, repo | `true`, `false` (`unknown`, `not_visible` for an org the token can't read) |
| `orgs` | enterprise | Number of enterprise orgs, integer as string; `unknown` (`not_visible`) when the token cannot read the enterprise |
| `host` | enterprise | The GitHub host the graph was collected from: `github.com`, or a GitHub Enterprise Server host such as `github.acme.example`. `gop diff` refuses graphs from different hosts without `--force`; a graph without it (older or synthetic) compares with any host. `gop enrich` only matches OIDC trusts for that host's token issuer (see [docs/ghes.md](ghes.md)). |
| `ghes_version` | enterprise | GitHub Enterprise Server only: the server version from `GET /meta` (`installed_version`), e.g. `3.14.2`; `unknown` (`not_visible`, with a `ghes_version` coverage entry) when it can't be read. Collectors the version does not support are skipped with coverage `reason: "not available on GHES <version> ..."`. |
| `in_enterprise_source` | org | Only when the token cannot read the enterprise: where the org came from: `config` (`--orgs`, counted as an enterprise org), `user_orgs` (`GET /user/orgs`) or `installation` (owners in `GET /installation/repositories`). `source` holds the API label. |
| `in_enterprise` | action_ref | `true` when the owner is an enterprise org (then a `RESOLVES_TO` edge points at the hosting repo), `false` when it is not. `unknown` (`not_visible`) when the token cannot read the enterprise and the owner is not a collected org: the owner may be an enterprise org gop can't see, so the reference is not resolved and one aggregated coverage entry (`scope: enterprise:<slug>`, `fact: in_enterprise`) names up to 20 such owners. It never reads as outside the enterprise. On GitHub Enterprise Server an action whose owner is not an org on the instance has `in_enterprise=false` and `source=github.com`: the runner fetches it from github.com (GitHub Connect or a local mirror). |
| `visibility` | repo | `public`, `private`, `internal` |
| `collaborators` | repo | `unknown` (`not_visible`) when the token could not list the repo's direct collaborators |
| `members` | team | Everyone who holds the team's grants (`GET /orgs/{org}/teams/{slug}/members?role=all`, which includes child teams' members), integer as string; `unknown` (`not_visible`) when the list was refused |
| `org`, `slug`, `privacy` | team | The team's org, slug, and `closed` or `secret` |
| `teams_partial` | org | `true` when the token is not an org owner (secret teams are not listed) or the teams could not be listed |
| `ref_kind` | action_ref node, `USES` edge | `sha`, `tag`, `branch`. For enterprise-internal refs it comes from the API (see [Ref kind and tag immutability](#ref-kind-and-tag-immutability)); otherwise it is a guess from the name: 40 hex is `sha`, `v<digit>` or semver-like is `tag`, anything else is `branch`. |
| `ref_kind_source` | action_ref node (enterprise-internal, not `sha`) | `api` when the ref was looked up, `name` when `ref_kind` is the name guess because the ref could not be looked up (a `ref_kind` coverage entry says why) or is an abbreviated commit SHA. |
| `ref_ambiguous` | action_ref node | `true` when the name is both a tag and a branch of the host repo. `ref_kind` is then `branch`, and the engine treats the ref as mutable whatever its protection says. |
| `ref_immutable` | action_ref node with `ref_kind=tag` from the API | `true` when pushing alone cannot move the tag, `false`, or `unknown` (`not_visible`, with a `ref_immutable` coverage entry). |
| `ref_immutable_reason` | action_ref node with `ref_immutable=true` | `immutable_release` or `tag_ruleset`. |
| `ref_protected` | action_ref node (enterprise-internal, `ref_kind=branch`) | `true` when branch protection stops a pusher from changing the branch alone, `false`, or `unknown` (`not_visible`, with a `ref_protection` coverage entry). See [Branch protection](#branch-protection). |
| `ref_protection` | action_ref node | Comma list of the branch's rules, in this order: `reviews` (a pull request needs at least one approval), `dismiss_stale`, `last_push_approval`, `status_checks`, `push_restricted` (an `update` rule or classic push restrictions), `admins_enforced`. Absent when there are none. |
| `bypass` | action_ref node with `ref_protected=true` or `ref_immutable=true` | Comma list of the principal IDs that can still land code alone (each also has a `via=ref_bypass` edge), `none`, or `unknown` (`not_visible`, with a `bypass` coverage entry) when the bypass actors are visible to repository admins only. |
| `advisories` | action_ref node | Comma list of the OSV GitHub Actions advisory IDs that affect the ref (for example a hijacked tag), from `gop collect` or `gop enrich` with advisory data. Set only for affected refs; a ref gop cannot place gets a coverage entry (`fact: advisories`) instead, and a skipped check gets one on the enterprise. See [advisories.md](advisories.md). |
| `advisory_severity` | action_ref node with `advisories` | The highest advisory severity: `critical`, `high`, `medium`, `low` or `unknown`. |
| `advisory_fixed` | action_ref node with `advisories` | The first fixed version that leaves every listed advisory; absent when one has no fix. |
| `actions_access` | repo hosting a referenced enterprise action | The Actions access setting (`GET /repos/{owner}/{repo}/actions/permissions/access`): `none`, `user`, `organization` or `enterprise`; `public` for a public repo (no request); `unknown` (`not_visible`, with an `actions_access` coverage entry) when the setting can't be read (it needs repo admin) or has a value gop does not know. See [Actions access](#actions-access). |
| `actions_lock` | repo | `true` when gop read the repo's `.github/workflows/actions.lock` (`gh actions-lock`); `unknown` when one is listed but could not be read or parsed (with an `actions_lock` coverage entry; its refs then count as not locked). Absent: no lockfile. See [Actions lockfile](#actions-lockfile). |
| `actions_lock` | `USES` edge from a workflow in a repo with a lockfile | `locked` when the lockfile pins this `uses:` for the workflow and every nested ref gop collected under it; `stale` otherwise (counted as unpinned, with an `actions_lock:<owner/repo@ref>` coverage entry on the workflow). Remote reusable workflows are never marked: `gh actions-lock` does not lock them. |
| `locked_sha` | `USES` edge with `actions_lock=locked` | The commit the lockfile pins (40 or 64 hex). |
| `lock_entry` | `USES` edge with `actions_lock=stale` | Comma list of the lockfile's pin keys (`owner/repo@ref`) for the same action repo, when there are any (the lock was made for another ref). |
| `lock_missing` | `USES` edge with `actions_lock=stale` | Comma list of nested refs (`owner/repo@ref`) under the action that the lockfile does not pin for this workflow. |
| `lock_advisories` | `USES` edge with `actions_lock=locked` | Comma list of the advisory IDs that list `locked_sha` as affected (the advisory check, see [advisories](advisories.md)). It describes the locked commit only: the action node's `advisories` attrs stay the match on the ref, and other uses of the same ref are not flagged. |
| `lock_advisory_severity` | `USES` edge with `lock_advisories` | The highest severity among them: `critical`, `high`, `medium`, `low` or `unknown`. |
| `lock_advisory_fixed` | `USES` edge with `lock_advisories` | The first fixed version that leaves every one of them; absent when one has no fix. |
| `branch_protected` | repo (non-archived) | Whether classic branch protection or an active ruleset applies to the default branch: `true`, `false`, or `unknown` (`not_visible`, with a `branch_protection` coverage entry) when the rules could not be read. `unknown` is never read as unprotected. See [Repo hardening](#repo-hardening). |
| `branch_required_reviews`, `branch_status_checks`, `branch_bypass_actors` | repo | Approving reviews required (the highest over all sources), distinct required status checks, and bypass actors over all protecting sources (ruleset bypass actors plus classic pull request bypass allowances); integers as strings, or `unknown`. |
| `branch_code_owner_review`, `branch_dismiss_stale`, `branch_last_push_approval`, `branch_signed_commits`, `branch_push_restricted` | repo | `true` when any protecting source sets the requirement, `false`, or `unknown` when a source that could set it is not visible (classic details are admin only). |
| `branch_allow_force_push` | repo | `true` when no source blocks force pushes (classic `allow_force_pushes`, a `non_fast_forward` rule), `false`, or `unknown`. |
| `branch_admin_bypass`, `branch_app_bypass` | repo with `branch_protected=true` | `true` when repo or org admins (an app) get past every protecting source: classic protection without `enforce_admins` (an app in `bypass_pull_request_allowances`), a ruleset with an `OrganizationAdmin`, `EnterpriseOwner` or admin `RepositoryRole` bypass actor (an `Integration`); `false`; or `unknown` when a bypass list is admin only. |
| `branch_bypass_apps` | repo with `branch_app_bypass=true` | The GitHub Apps that get past every protecting source, as a sorted comma list of `<app id>` or `<app id>:<slug>` (ruleset `Integration` actor IDs, classic `bypass_pull_request_allowances` apps). Absent when a list is incomplete or no single App gets past every source. |
| `branch_protection_sources` | repo | The protecting sources, comma list of `classic` and `ruleset:<id>` (classic first), or `none`. |
| `branch_value_sources` | repo | Which source set each effective value: comma list of `key=source[+source]`, e.g. `required_reviews=ruleset:7,allow_force_push=classic+ruleset:7`. |
| `codeowners` | repo (non-archived) | The CODEOWNERS file GitHub uses on the default branch (the first of `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS`), `none`, or `unknown` (`not_visible`, with a `codeowners` coverage entry). No owner names are stored. |
| `codeowners_valid` | repo with a CODEOWNERS file | `false` when a line has syntax GitHub skips (a `!` negation, a `[ ]` range, an owner that is not `@user`, `@org/team` or an email). |
| `codeowners_workflows` | repo | `true` when the last rule matching `.github/workflows/*.yml` and `*.yaml` names an owner, so a workflow change needs a code owner's review where the branch requires it; `false`; or `unknown`. |
| `secret_scanning`, `secret_scanning_push_protection`, `secret_scanning_validity_checks` | repo (non-archived) | `on`, `off`, or `unknown` (`not_visible`), from the repository listing's `security_and_analysis`, which GitHub returns to repo admins, org owners and security managers only (one `secret_scanning` coverage entry per org counts the repos without it). |
| `consumer_org` | `USES` edge into an action that resolves to an enterprise repo | Org login of the using workflow's repo, or of the using composite action's host repo. Informational: the engine reads the repos from `DEFINED_IN` and `RESOLVES_TO`. |
| `file` | `USES`, `EXECUTES_WITH` edge | Repo-relative path of the workflow or action file the edge was read from, e.g. `.github/workflows/release.yml`. |
| `file_ref` | `USES`, `EXECUTES_WITH` edge | Commit or branch the file was read at, when known (the repo's default branch for top-level workflows, the parent `uses:` ref for nested files). |
| `line` | `USES`, `EXECUTES_WITH` edge | 1-based line, integer as string: the `uses:` value on `USES`, the `id-token: write` (or `write-all`) key on the OIDC edge, the `runs-on:` key on the runner edge. |
| `jobs` | `EXECUTES_WITH` edge to `oidc` | Comma list of the job ids that can mint an OIDC token: each job's permissions resolve to `id-token: write`, where job-level `permissions:` replace the workflow-level value (so a job that sets its own permissions without `id-token: write` is not listed, and a workflow none of whose jobs resolves to it has no OIDC edge). |
| `environments` | `EXECUTES_WITH` edge to `oidc` | Comma list of the distinct `environment:` names of those jobs (string form or the `name` of the mapping form), sorted, plus the environments of id-token jobs in enterprise reusable workflows they call. `*dynamic*` stands for an expression such as `${{ inputs.env }}`: any environment is possible. Absent when no such job has an environment; jobs without one get a `ref`-based `sub`. |
| `job_workflow_ref` | `EXECUTES_WITH` edge to `oidc` | Comma list of the enterprise reusable workflows, called by an id-token job (directly or through other reusable workflows), whose jobs mint the token, in the claim's form `owner/repo/.github/workflows/x.yml@refs/heads/main` (`refs/tags/v1` for a tag, the bare SHA for a SHA; branch versus tag follows the `ref_kind` naming heuristic). Absent when no called reusable workflow mints a token or the called workflow was not read. |
| `repository`, `repository_owner` | `EXECUTES_WITH` edge to `oidc` | The `repository` (`acme-app/web`) and `repository_owner` (`acme-app`) claims of the token: the repo the workflow runs in, also for tokens minted in a called reusable workflow. With `environments` and `job_workflow_ref` these are the inputs a cloud trust's `sub` (`repo:<repository>:environment:<env>`) and other claim conditions match against. The engine does not read them. |
| `token_write` | workflow | `true` when the workflow's `GITHUB_TOKEN` has `contents: write` on its own repo (then a `via=token_write` `CAN_PUSH` edge points at the repo), `false`, or `unknown` (`not_visible`, with a `default_workflow_permissions` coverage entry) when a job takes the default and the default is not visible. See [Workflow tokens](#workflow-tokens). |
| `risky_triggers` | workflow | Comma list of the workflow's triggers that run in the base repo's context on events people without push access can cause: `pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review`, `pull_request_review_comment`, `discussion`, `discussion_comment`, `issues`. Set whether or not gop found attacker-controlled execution. See [Triggers](#triggers). |
| `untrusted_checkout` | workflow | `exec` or `read_only`: the workflow checks out the pull request's head under a risky trigger, and a later step runs code from it (`exec`, with a `CAN_TRIGGER` edge `exec=checkout`) or gop sees none that does (`read_only`: untrusted input, not execution). See [Triggers](#triggers). |
| `bot_approves`, `bot_approve_token`, `bot_approve_jobs`, `bot_approve_starter`, `bot_merges`, `bot_merge_token`, `bot_merge_jobs`, `bot_merge_starter`, `bot_merge_gate`, `bot_merge_admin`, `bot_merge_triggers` | workflow | Jobs that submit an approving review or merge a pull request, the token source of those steps (`app`, `pat`, `github_token`, `unknown`), who can make them run (`pr_openers`, `org_members`, `pushers`, `maintainers`) and the merging job's actor check and triggers. See [agents-in-ci.md](agents-in-ci.md#ai-approve--self-merge). |
| `review_bypass`, `review_bypass_reason`, `review_bypass_approve`, `review_bypass_merge` | repo | `review_bypass=bot_self_merge` when a pull request's author can get code onto the default branch through a bot approve and a bot merge with no human review (`not_visible`, with a `review_bypass` coverage entry, when possible only); why (`app_bypass`, `admin_bypass`, `bot_approvals`, `unprotected`) and the workflow files. |
| `bot_merge_source`, `bot_approve_source`, `bot_merge_stale_approvals`, `bot_merge_stale_confidence` | workflow (and repo, for the merge of its review bypass) | `script:<path>` when the merge or approve call is in a repo script a step runs (read from the default branch, never executed); `bot_merge_stale_approvals=suspected` with confidence `heuristic` (attr evidence `not_visible`, with a `bot_merge_stale_approvals` coverage entry) when the merge script seems to count approvals not tied to the head commit. See [agents-in-ci.md](agents-in-ci.md#ai-approve--self-merge). |
| `review_bypass_stale_approval`, `agent_holds_merge_key`, `agent_merge_key_workflows` | repo | `suspected` (`not_visible`) when the merge counts older approvals and an approving workflow does not re-run on `synchronize`: the approval may not cover the merged code. `true` when an AI agent step holds the secret the bot merge uses, and the workflow files of those steps. |
| `bot_merge_apps`, `review_bypass_app_match` | workflow (and repo, for the merge of an `app_bypass` review bypass); repo | The Apps the merging steps' App tokens are for: the app id or slug the workflow names literally (`app-id: 123456` on an App token step, or `APP_ID` beside a private key in a script step's env), `unknown` for one it does not name (`vars.` or `secrets.`). `review_bypass_app_match` is `matched` (live) when one of them is in `branch_bypass_apps`; `unmatched` or `unknown` (`not_visible`) otherwise, and then the `app_bypass` review bypass is possible only. |
| `actions_can_approve_prs` | repo | The "Allow GitHub Actions to create and approve pull requests" setting (`can_approve_pull_request_reviews` of `GET /repos/{owner}/{repo}/actions/permissions/workflow`, else the org's: an org that does not allow it proves `false`), read only for a repo with a bot approval made with `GITHUB_TOKEN`. `true` confirms that approval, `false` rules it out, `unknown` (`not_visible`, with an `actions_can_approve_prs` coverage entry) leaves it possible. |
| `review_bypass_recounts_dismissed` | repo | `suspected` (`not_visible`, a heuristic) when the default branch rules dismiss stale reviews (`branch_dismiss_stale=true`) and the merge script counts `DISMISSED` reviews: the script re-counts approvals GitHub dismissed. |
| `approve_workflows`, `merge_workflow` | `CAN_MERGE_VIA_BOT` edge | The approving workflow node IDs (absent when no approval is needed) and the merging workflow node ID; also `review_bypass_reason`, `trigger`, `file`, `file_ref` and `line` (the merging step). |
| `trigger`, `exec`, `job`, `detail` | `CAN_TRIGGER` edge | The risky trigger, how the workflow runs attacker input (`checkout`, `injection`, or `agent`: an AI coding agent people without push access can start, `detail` naming its kind), the job id, and the matched value (e.g. `ref: ${{ github.event.pull_request.head.sha }}` or `github.event.comment.body`). Also `file`, `file_ref` and `line`: the line of the matched `with.ref`/`with.repository`, `run:` or `script:` key. |
| `author_association` | `CAN_TRIGGER` edge | Comma list of the `author_association` values the job's `if:` allows on a comment or review trigger, when gop could read such a gate. See [Triggers](#triggers). |
| `provider` | cloud_target, `CAN_ASSUME` edge | `aws`, `gcp`, `azure` |
| `account` | cloud_target | AWS account, GCP project or Azure subscription, when the trust file names it |
| `role` | cloud_target | Role name, GCP service account email, or Azure identity |
| `warnings` | cloud_target | Comma list of risk codes from the trusts behind it: `no_sub_condition` (no `sub` or other repository condition: any GitHub repository's token matches), `no_aud_condition`, `wildcard_owner`, `unparsed_condition`, `conditions_merged` (several ANDed conditions on one claim kept as any-of), `unknown_target` |
| `file`, `pointer` | `CAN_ASSUME` edge | The supplied trust file (as given, cleaned, with `/`) and the JSON pointer of the trust in it |
| `matched_sub` | `CAN_ASSUME` edge | Comma list of the trust's `sub` patterns that matched (or may match). Absent when the trust has no `sub` condition |
| `claims` | `CAN_ASSUME` edge | Comma list of the claims the trust checks, e.g. `sub` or `repository,repository_owner` |
| `oidc` | `CAN_ASSUME` edge | The `oidc` node whose token the trust matches |
| `trust` | `CAN_ASSUME` edge | The trust's own target when it names more than the `cloud_target` (an Azure federated credential `app:<id>/fic:<name>`, a GCP provider plus service account) |
| `reason` | `CAN_ASSUME` edge with evidence `not_visible` | Why gop cannot decide the match, e.g. the `sub` is branch-scoped and gop does not read triggers, the environment is an expression, or a condition was not understood |
| `source` | `CAN_ASSUME` edge, cloud_target, action_ref | `cartography` when the trust came from a Cartography export (`gop enrich --cartography`, see [docs/cartography.md](cartography.md)); then `file` is the export and `pointer` is `/<row>` or `/<row>/conditions/<block>`. Absent for trust files. On an action_ref: `github.com` on GitHub Enterprise Server when the owner is not an org on the instance (see `in_enterprise`) |
| `observed_use`, `times_used`, `last_used` | `CAN_ASSUME` edge | From a Cartography export: CloudTrail saw a workflow of this repo assume the role (`observed_use=true`), how many times in Cartography's lookback window and when last. Set on every `CAN_ASSUME` edge from that repo into that role, from any source. Evidence is unchanged; an observation that matches no edge is a warning, never an edge |
| `agent`, `agent_source`, `agent_confidence`, `agent_jobs`, `agent_gate`, `agent_exposure`, `agent_prompt_injection`, `agent_permissions`, `agent_secrets`, `agent_runner`, `agent_tools`, `agent_ref_kind` | workflow | AI coding agents in the workflow (see [docs/agents-in-ci.md](agents-in-ci.md)): the agent kinds, how they were found (`uses`, `run`, `setup`, `heuristic`, `name`), the strongest signal (`action`, `cli`, `heuristic`, `name_only`), the agent jobs, the weakest actor check, who can start an agent job with the repo's token and secrets (`outsiders`, `listed_users`, `fork_readonly`, `maintainers`), untrusted contexts in the prompt (and `pr_content` for a heuristic match), the token write scopes, the number of secrets, the runner class, tool and sandbox settings, and the least pinned agent action ref. A confirmed path into a workflow with `agent_exposure=outsiders` and write, secrets or OIDC through the principal's own `CAN_TRIGGER` edge ranks first after advisories and poutine (`agent_exposed` on the score). `name_only` is never ranked. |
| `poutine_rules`, `poutine_severity`, `poutine_jobs`, `poutine_file` | workflow | From a poutine JSON report (`gop enrich --poutine`, see [docs/poutine.md](poutine.md)): the sorted rule IDs of the findings in this workflow file, the highest rule level (`error`, `warning`, `note`), the job ids the findings name, and the report file. Cited from poutine, not proved by gop: evidence is unchanged. A confirmed reach into a workflow whose rules include `injection` or `untrusted_checkout_exec` ranks first in `top_risks` (`poutine_injectable` on the score). A finding that matches no workflow is a `poutine_finding` coverage entry |
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
| `CAN_TRIGGER` | org_members, identity, external → workflow | The principal can cause a risky trigger of the workflow, and the workflow then runs attacker-controlled code, so the principal controls the workflow without push access. See [Triggers](#triggers). |
| `CAN_MERGE_VIA_BOT` | org_members, external → repo | Anyone in the principal can open a pull request that the repo's workflows approve and merge with a bot token the default branch's rules let through, so the principal lands code on the default branch with no human review. A forward control hop like `CAN_PUSH`. Attrs `approve_workflows`, `merge_workflow`, `review_bypass_reason`, `trigger`, `file`, `line`. `not_visible` when a deciding fact (the bypass list, the required reviews) is unknown. See [agents-in-ci.md](agents-in-ci.md#ai-approve--self-merge). |
| `CAN_ASSUME` | workflow → cloud_target | A token the workflow can mint (its `EXECUTES_WITH` edge to `oidc`) satisfies a supplied cloud trust policy. Added by `gop enrich --oidc-trust` or `--cartography` (or `gop collect --oidc-trust`), never read from GitHub or the cloud. Terminal impact. Evidence `supplied` for a match, `not_visible` with `attrs.reason` when gop cannot decide it (possible reach). See [Paths out of GitHub](#paths-out-of-github). |
| `MEMBER_OF` | identity → org, identity → team, team → team | Org membership, from the enterprise consumed licenses (`attrs.role` is `owner` or `member`; outside collaborators have none). Direct team membership (`GET /orgs/{org}/teams/{slug}/members?role=all`). A child team's nesting under its parent (`GET /orgs/{org}/teams`, `parent.slug`): members of the child reach what the parent reaches. |

### CAN_PUSH provenance

Every `CAN_PUSH` edge carries `attrs.via`, so fixes know which edges they remove, and `attrs.permission`:

| `via` | From | Source | `permission` |
|---|---|---|---|
| `default_perm` | org_members | The org's default repository permission (`write` or `admin`). Evidence `inferred`, `attrs.rule=default_perm`. | the default permission |
| `org_owner` | identity | An `Owner` role in the consumed licenses: owners are admin on every repo of the org. Evidence `inferred`, `attrs.rule=org_owner`. | `admin` |
| `direct` | identity | A direct collaborator grant with push (`GET /repos/{owner}/{repo}/collaborators?affiliation=direct`, `permissions.push`, `maintain` or `admin`). | `role_name`, e.g. `write`, `maintain`, or a custom role such as `deployer` (then `attrs.base_role` holds its base role when the token can read the org's custom roles) |
| `outside_collaborator` | identity | Same as `direct`, for a user listed by `GET /orgs/{org}/outside_collaborators` (not an org member). | as for `direct` |
| `team` | team | A team repository grant with push (`GET /orgs/{org}/teams/{slug}/repos`, `permissions.push`, `maintain` or `admin`). | `role_name`, including custom roles |
| `ref_bypass` | identity (user or team) | May land code alone on the protected branch `attrs.ref` (see [Branch protection](#branch-protection)), or move the immutable tag `attrs.ref` (see [Ref kind and tag immutability](#ref-kind-and-tag-immutability)). `attrs.rule_source` is `ruleset:<id>` or `branch_protection`; ruleset edges also carry `attrs.bypass_mode`. | `bypass` |
| `token_write` | workflow | The workflow's `GITHUB_TOKEN` has `contents: write` on the repo it lives in (see [Workflow tokens](#workflow-tokens)). `attrs.jobs` lists the job ids. | `contents: write` |
| `unknown` | org_members | Evidence `not_visible`: the target is a stub repo (`collected=false`, node evidence `not_visible`) that hosts an enterprise action but was not collected (its org is outside `--orgs` or archived, or the token does not list it), so its members may be able to push. The repo gets a `can_push` coverage entry. When the host org was collected with a visible `default_perm` of `write` or `admin`, the normal `default_perm` edge is used instead. | absent |

When an identity is both an owner and a direct collaborator on a repo, the `direct` edge is kept. When the collaborators list for a repo cannot be read (403/404), gop emits no live edge; instead each repository-scoped role in the consumed licenses for that repo (e.g. `acme-actions/deploy:Write`) becomes a `CAN_PUSH` edge with evidence `not_visible`, `permission=unknown` and `attrs.license_role`, which is possible reach, never confirmed. One coverage entry per org (`fact: can_push:collaborators`) counts the affected repos. `LowerDefaultPerm` removes only `via=default_perm` edges.

### Teams

Team IDs are `team:<org>/<slug>` (kind `identity`). The team members endpoint also returns the members of child teams, so to keep one fact per edge gop records only direct members: a team's list minus the lists of its direct children. A user who is both a direct member of a parent and a member of its child is then recorded on the child only, which reaches the same repositories. Members are fetched only for teams with a push grant and teams below one. When a team's member list returns 403/404, its `CAN_PUSH` edges stay `live` (the grant was observed), the team gets `members=unknown` and the org gets one `team_members:<slug>` coverage entry; no member edges are invented. When the token is not an org owner, secret teams and their grants are not listed: the org gets `teams_partial=true` and a `can_push:teams` coverage entry.

### Branch protection

For every enterprise-internal action ref on a branch, `gop collect` reads, once per (repo, branch), `GET /repos/{owner}/{repo}/rules/branches/{branch}` (every active rule from repo and org rulesets, readable with read access), `GET /repos/{owner}/{repo}/branches/{branch}` and, when the branch has classic protection, `GET /repos/{owner}/{repo}/branches/{branch}/protection` (admin only). For each ruleset that protects the branch it reads `GET /repos/{owner}/{repo}/rulesets/{id}?includes_parents=true` for `bypass_actors` (returned to admins only).

`ref_protected=true` when a pull request needs at least one approval and a stale approval can't be reused (`dismiss_stale_reviews_on_push` or classic `dismiss_stale_reviews`, or `require_last_push_approval`), or when an `update` rule or classic `restrictions` limit who may push. Required status checks alone don't count: the pusher controls the code under test and can make the checks pass. Reviews without stale-approval dismissal don't count either: get a harmless change approved, then push more commits. `ref_protected=unknown` when the rules can't be read, or when the branch has classic protection whose details are not visible and no ruleset protects it.

The principals that can still land code alone become `CAN_PUSH` edges to the repo with `via=ref_bypass` and `ref=<branch>`, next to (not replacing) their other grants: ruleset bypass actors (`Team` becomes `team:<org>/<slug>`, `User` becomes `identity:<login>`, `OrganizationAdmin` becomes each org owner, and the built-in `RepositoryRole` maintain, write or admin becomes the principals with exactly that role on the repo), classic `bypass_pull_request_allowances` users and teams when reviews protect the branch (otherwise classic `restrictions` users and teams), and repository admins when classic protection does not enforce admins. Apps, deploy keys, custom repository roles and role holders that are not fully visible get a `ref_bypass` coverage entry. When several rules protect one branch their lists are united: an over-approximation, since a real bypasser must bypass all of them.

The engine uses these facts on the `RESOLVES_TO` hop only. With `ref_protected=true` there is no `repo -> action` hop; each matching `ref_bypass` edge becomes a `principal -> action` hop instead (and with `bypass=unknown` the `repo -> action` hop stays, `not_visible`). With `ref_protected=unknown` the `repo -> action` hop is `not_visible`, so the path is possible, not confirmed. `false` or no attribute changes nothing. `DEFINED_IN` is not gated: a push to any unprotected branch runs that branch's copy of an `on: push` workflow with the repo's secrets. Tags are gated the same way through `ref_immutable` (next section).

### Repo hardening

`gop collect` records the default-branch protection, CODEOWNERS and secret scanning of every collected, non-archived repo as repo attrs (above). They are **context only**: the engine never reads them, so evidence levels, confirmed and possible counts, scores and rank order are the same with and without them.

- **Protection** comes from one batched GraphQL query per 25 repos (the same grouping as the workflow reads): `repository { viewerPermission defaultBranchRef { refUpdateRule branchProtectionRule rules } }`. `rules` lists every active rule of repo, org and enterprise rulesets that applies to the default branch, with its ruleset's `source` and `bypassActors`; `branchProtectionRule` is classic protection with its admin-only details; `refUpdateRule` is classic protection as a non-admin sees it. A repo whose alias fails, or everything when batching is off or the query is not supported (an older GHES), is read over REST instead: `GET /repos/{o}/{r}/rules/branches/{branch}`, `GET /repos/{o}/{r}/branches/{branch}`, its `/protection` when the branch is protected, and `GET /repos/{o}/{r}/rulesets/{id}?includes_parents=true` once per ruleset ID for `bypass_actors`.
- **Merge rule.** Each source (classic protection, each ruleset) is read on its own, then merged: a requirement holds when any source sets it (the highest review count, the union of required checks, force push blocked by any source); a bypass (`branch_admin_bypass`, `branch_app_bypass`) holds only when every protecting source allows it. A source gop cannot read makes every value it could change `unknown`, except a requirement another source already sets. `branch_value_sources` names the source behind each value. A ruleset bypass list that comes back empty counts as "no bypass actors" only when the token can administer the ruleset's source (repo admin, org owner); otherwise it is `unknown`, since GitHub hides the list. Without admin, classic protection is read through `refUpdateRule` and attributed to `classic`; its admin-only details are `unknown`, with one `branch_protection` coverage entry per org.
- **CODEOWNERS** rides in the batched workflow read (three more object expressions per repo, no extra request); over REST it is up to three contents `GET`s, stopping at the first file.
- **Secret scanning** comes from the repository listing gop already reads, at no extra request.

**Path notes.** A forward `CAN_PUSH` hop into a repo with these attrs carries a `note` in `paths`, `who_can_reach`, the CLI text and the report: "push needs N approvals to reach `main`" (with " + CODEOWNERS on workflows" when code owner review is required and CODEOWNERS covers `.github/workflows/`), or "push reaches the default branch directly" when the branch is not protected, needs no approval and does not restrict pushes, allows force pushes, or lets admins bypass and the pusher holds admin. No note when a deciding value is `unknown`, and none on `via=ref_bypass` edges. Whether protection should cut reach (a push to a protected default branch only runs `pull_request` workflows) is left to a follow-up design.

**Advisory fixes.** `suggest_fixes` lists `hardening` suggestions apart from its fixes: `require_reviews` for a repo on a top risk path whose default branch is not protected or needs no approval, and `enable_push_protection` where push protection is `off`. `fix_plan` and `what_if` accept both (`{type, repo}`); they change no edge, so they never count as removing confirmed reach.

### Ref kind and tag immutability

`ref_kind` from the name alone is a guess: `acme-actions/deploy@release-2026` can be a tag and `acme-actions/setup@v2-dev` a branch. For every enterprise-internal action ref that is not a commit SHA, `gop collect` asks the GraphQL API, once per distinct (repo, ref) and 50 per query, for `refs/tags/<ref>` and `refs/heads/<ref>` (owner, repo and ref go in as query variables). Only the tag exists: `ref_kind=tag`. Only the branch: `ref_kind=branch`. Both: `ref_kind=branch` and `ref_ambiguous=true`. Each sets `ref_kind_source=api` and the same `ref_kind` on the incoming `USES` edges. When neither exists or the repo is not visible, the name guess stays, with `ref_kind_source=name` and a `ref_kind` coverage entry. An abbreviated SHA (7 to 39 hex) is not a valid action ref: it stays `branch`, `ref_kind_source=name`, and is not looked up.

For every `ref_kind=tag` from the API, once per (repo, tag), `gop collect` reads `GET /repos/{owner}/{repo}/releases/tags/{tag}`. A release with `immutable: true` makes `ref_immutable=true` (`ref_immutable_reason=immutable_release`): nobody can move the tag. A 404 (no release) says nothing either way. Otherwise it reads `GET /repos/{owner}/{repo}/rulesets?includes_parents=true` and, for each active ruleset with `target: tag`, `GET /repos/{owner}/{repo}/rulesets/{id}?includes_parents=true`. A ruleset applies when one of its `conditions.ref_name.include` patterns matches `refs/tags/<tag>` and no `exclude` pattern does (fnmatch style: `*` and `?` stop at `/`, `**` crosses it, `[...]` classes; `~ALL` matches every ref, `~DEFAULT_BRANCH` never a tag). When the applying rulesets hold both an `update` and a `deletion` rule, `ref_immutable=true` (`ref_immutable_reason=tag_ruleset`), and their bypass actors become `CAN_PUSH` edges with `via=ref_bypass` and `ref=<tag>`, mapped as for branch protection (or `bypass=unknown` when only admins can see them). `ref_immutable=false` when they don't (for example `deletion` alone: delete the tag and push it again). `ref_immutable=unknown` (`not_visible`) when the ruleset list or an applying tag ruleset can't be read, or the release can't be read and the rulesets don't make the tag immutable.

The engine reads `ref_immutable` for a node with `ref_kind=tag` exactly as it reads `ref_protected` for other refs: `true` drops the `repo -> action` hop and keeps the matching `ref_bypass` hops; `unknown` keeps the hop, `not_visible`, so paths through the tag are possible, never confirmed and never dropped. `ref_ambiguous=true` turns the gate off. `suggest_fixes` proposes no pin for a ref that is locked (`true`) with known bypass actors and no `ref_bypass` edge. The same decision drives `fix_plan`, `gop pin` and the report's "Pinned, still reachable" section: a locked ref with no matching bypass counts as pinned (it is never listed as a mutable nested ref, and an action locked that way can itself be a pinned exposure), a gate that is not visible (`unknown`, or `bypass=unknown`) is labelled "possibly mutable (immutability not visible)" ("protection" for a branch, "bypass actors" for unknown bypass), and an ambiguous or unlocked ref is mutable.

### Workflow tokens

A workflow's `GITHUB_TOKEN` gets `contents: write` from the file or from the default. gop resolves each job the way GitHub does: a job-level `permissions` key replaces the workflow-level one; a mapping that omits `contents` means `contents: none`; `write-all` is write, `read-all` is read, `{}` is none. A job with no `permissions` at either level takes the default. The workflow is `true` when any job resolves to write, else it takes the default when any job does, else `false`.

When some workflow in a repo takes the default, `gop collect` reads `GET /repos/{owner}/{repo}/actions/permissions/workflow` (`default_workflow_permissions`, admin only). When that is refused it reads `GET /orgs/{org}/actions/permissions/workflow` once per org. The repo can only be more restrictive than its org, so an org value of `read` proves `read`; `write` leaves the repo unknown.

For `token_write=true` the workflow gets `workflow -CAN_PUSH-> repo` with `via=token_write`, evidence `live`, and source `rest:GET /repos/{owner}/{repo}/contents/{path}` when the file decided, or the settings API that did. For `unknown` the same edge is `not_visible` and the repo gets a `default_workflow_permissions` coverage entry (`needs_fix: admin on <repo> (or org owner)`). The engine needs nothing more: `CAN_PUSH` is a full control hop, so the repo is expanded (its workflows and the actions it hosts), not just counted as CI reach. A `GITHUB_TOKEN` push is subject to branch protection like any push, so `ref_protected` still gates the `repo -> action` hop.

Known limitations: a `GITHUB_TOKEN` cannot change files under `.github/workflows/` (that needs the `workflows` permission, which it never has). gop still expands the repo to its workflows (`DEFINED_IN` reversed), because workflows almost always run repo code: scripts, local actions, build files. Such paths show `via=token_write` on the `CAN_PUSH` hop (`explain` prints edge attrs). The `restrict_token` fix removes a workflow's `via=token_write` edges (`permissions: contents: read`); the repo stays CI reach. Who can trigger the workflow is modeled separately (see [Triggers](#triggers)), and other write scopes (`actions`, `packages`) are recorded in `token_scopes` only.

### Triggers

Some triggers run a workflow in the base repo's context, with its secrets and a possibly write `GITHUB_TOKEN`, on events that people without push access can cause. `gop collect` reads `on:` in all three shapes (a string, a list, a map) and calls these triggers risky: `pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review`, `pull_request_review_comment`, `discussion`, `discussion_comment`, `issues`. The workflow gets `risky_triggers`.

A risky trigger alone does not run attacker code. For each job of such a workflow gop looks for these patterns, matching exact context names:

| `exec` | Pattern |
|---|---|
| `checkout` | A step `uses: actions/checkout@*` whose `with.ref` or `with.repository` contains `github.event.pull_request.head.`, `github.head_ref`, `refs/pull/`, `github.event.workflow_run.head_` or `github.event.issue.pull_request`, **and a later step that runs code from that checkout** (see below); or a `run:` containing `gh pr checkout` or `git fetch origin pull/`. |
| `agent` | An AI coding agent job that people without push access can start: a known agent action whose actor check lets them in, or an agent CLI in a `run:` step (see [agents-in-ci.md](agents-in-ci.md)). With an action whose check gop does not know, the edge is `not_visible`. A step with no known agent that holds a model API key and reads the pull request's content (`agent_confidence=heuristic`) also counts, with `not_visible` edges. |
| `injection` | A `run:` or `actions/github-script` `script` whose `${{ }}` expression uses `github.event.(issue\|pull_request\|comment\|review\|discussion).(title\|body\|head.ref\|head.label)`, `github.head_ref`, `github.event.workflow_run.head_branch` or `github.event.commits.*.message`. Passing the value through `env:` and reading `$VAR` in the script is not flagged. |

A checkout of the pull request's head is untrusted input; it is untrusted execution only when a later step of the job runs code from it. gop counts a later step as running it when the checkout is at the workspace root (the `actions/checkout` default) or at a path it cannot resolve and any step follows; when a `uses: ./<path>/...` local action loads from it; when a `run:` step works in it (`working-directory`, the job's `defaults.run.working-directory`, or `cd <path>`); or when a `run:` command is a file in it (`pr/build.sh`), an interpreter runs a script from it (`bash pr/x.sh`, `python pr/x.py`), or a build or install tool is pointed at it (`npm --prefix pr ci`, `make -C pr`, `pip install -e pr`, `go run ./pr/...`, `docker build pr`). A checkout into a subdirectory that only trusted code from the base branch reads makes no `CAN_TRIGGER` edge; the workflow gets `untrusted_checkout=read_only` (`exec` when some job runs the checkout). When such trusted code feeds the content to a model (a step that holds `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or a similar key and names the checkout, runs `gh pr diff` or `gh pr view`, or reads attacker contexts), gop records an `llm-script` agent with `agent_confidence=heuristic` and `agent_prompt_injection` including `pr_content` (see [agents-in-ci.md](agents-in-ci.md)).

When a job matches, the principals who can cause the trigger get `principal -CAN_TRIGGER-> workflow` (one edge per principal, evidence `live`, source `rest:GET /repos/{owner}/{repo}/contents/{path}`), by the repo's visibility:

| Visibility | Principals |
|---|---|
| `public` | `external:anyone`. |
| `internal` | `members:<org>` for every collected, non-archived org: every enterprise member can read an internal repo. |
| `private` | `members:<org>` of the repo's org when its `default_perm` is `read`, `write` or `admin`. With `none`, only collaborators and teams with read access can trigger it, which gop does not collect: no edge, and a `triggering_principals` coverage entry. |

A comment, review, issue or discussion trigger whose job `if:` checks the author's `author_association` (for example `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`) narrows this. gop reads the gate only when every top-level `||` branch of the condition either checks the association or applies to another event (`github.event_name == '<other>'`), and the condition has no `!` or `!=`. `MEMBER` (with or without `OWNER`, `COLLABORATOR`) gives `members:<org>` of the repo's org only; `OWNER` and `COLLABORATOR` alone give no edge and a `triggering_principals` coverage entry (gop does not collect read grants). `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, `FIRST_TIMER` and `NONE` do not narrow it: `CONTRIBUTOR` is anyone with a previously merged commit, outside contributors included. The edge records the allowed values in `author_association`.

`pull_request_target` and `workflow_run` need a pull request from a fork (for `workflow_run`, one that starts the upstream workflow). On an internal or private repo that needs the repo's org to allow forking private and internal repos (`private_forks`): `false` means no edge, `unknown` makes the edges `not_visible`. Comment, review, issue and discussion triggers need read access only. A visibility or setting gop can't read makes the edge `not_visible`, so the path is possible, never confirmed.

Plain `pull_request` gets no edge: from a fork, its `GITHUB_TOKEN` is read-only and secrets are withheld, so the fork's code runs with nothing worth taking.

The engine treats `CAN_TRIGGER` as a forward control hop, like `CAN_PUSH`: the workflow is controlled, so its `EXECUTES_WITH` terminals are reached, its repo counts as CI reach, and a `via=token_write` `CAN_PUSH` expands to the repo. Environment protection rules that withhold secrets until approval, `if:` conditions on jobs, and artifacts a `workflow_run` downloads are not modeled. The `harden_trigger` fix (`what_if`, `suggest_fixes`, `fix_plan`) removes every `CAN_TRIGGER` edge into one workflow. Its steps say which case each edge is: untrusted code runs (drop the head checkout or the step that runs it, or move attacker text into `env:`), or untrusted text reaches an AI step that acts with the job's token and secrets.

### Actions access

A private or internal repo's Actions "Access" setting decides which other repositories may use the actions and reusable workflows it hosts. `gop collect` reads it once for every repo that is the target of a `RESOLVES_TO` edge and records `actions_access` on the repo. The engine checks it on the reverse `USES` hop (action controls consumer), comparing the host repo (the action's `RESOLVES_TO` target) with the consumer's repo (a workflow's `DEFINED_IN` target, or a composite action's host):

| `actions_access` | Hop kept for |
|---|---|
| no attr, `public`, `enterprise` | every consumer |
| `organization`, `user` | consumers in the host's org (owner) |
| `none` | the host repo itself |
| `unknown` | consumers in the host's org; other consumers keep the hop as `not_visible`, so the path is possible, not confirmed |

A hop the setting forbids is dropped. Graphs without `actions_access` behave as before. The consumer side (the consumer org's allowed-actions policy) is not read yet.

### Actions lockfile

A repo that runs [`gh actions-lock`](https://github.com/github/gh-actions-lock) commits `.github/workflows/actions.lock`, which pins every action each workflow uses, nested ones included, to a commit. `gop collect` reads it from the workflow directory listing it already makes (the batched GraphQL read returns it with the workflow files; over REST it is one more contents `GET`, only when the listing has the file) and marks each workflow `USES` edge `actions_lock=locked` or `stale` (see [docs/actions-lock.md](actions-lock.md) for the format and matching rules). The engine drops the control hop of a `locked` edge: changing the action, or anything nested under it, does not change what that workflow runs. Other workflows that use the same action are unaffected. `stale` changes nothing. `suggest_fixes` does not propose pinning an action every use of which is locked, `fix_plan` and `gop pin` never edit a `uses:` line a lockfile governs (they list it, and say to rerun `gh actions-lock` for a stale one), and the report and the `gop://graph/summary` resource (`action_pins`) count "pinned in workflow" and "pinned by actions.lock" separately.

### Principals and scoring

`who_can_reach`, `reach` and `blast_radius` accept every principal: each `org_members`, `identity` and `external` node. Workflows are not principals, even with a `via=token_write` `CAN_PUSH` edge. Totals (`top_paths`, `what_if`, `suggest_fixes`) sum over the scoring principals only: every `org_members` and `external` node, plus identities with at least one `CAN_PUSH`, `CAN_TRIGGER` or `CAN_MERGE_VIA_BOT` edge or a `MEMBER_OF` edge to something that is not an org (a team). Teams qualify the same way: through their own grants or their nesting under a parent team. An identity whose only edges are org memberships reaches exactly what `members:X` reaches, so counting it again would multiply the `(principal, repo)` pair totals by the number of licensed users. The same holds for a member that does qualify: the totals count only the reach it holds without going through an `org_members` node (its own grants, teams and what they lead to); what it reaches through its org `MEMBER_OF` edge is counted once, on the `members:X` row. Its own score (`blast_radius`, `top_risks`, `what_if` per principal) still shows its full reach. So a team membership that grants nothing never changes the totals, and lowering an org's default permission removes the org's reach once, not once per member. `top_paths` (and `top_risks`) also lists each action_ref with `advisories` and confirmed reach as its own entry, and ranks every entry whose confirmed paths run through such an action first; those actions are not scoring principals (see [advisories.md](advisories.md#ranking)).

A reach path reads, for example: `members:acme-actions -CAN_PUSH-> repo:acme-actions/deploy <-RESOLVES_TO- action:acme-actions/deploy@main <-USES- workflow:acme-app/web/.github/workflows/release.yml -EXECUTES_WITH-> oidc:...`.

### Paths out of GitHub

`gop enrich --graph g.json --oidc-trust ./trust/ --out g2.json` reads AWS role or trust policy documents, GCP workload identity providers and service account IAM policies, and Azure federated credentials (internal/oidc), offline. For every `workflow -EXECUTES_WITH-> oidc` edge and every trust it matches the trust's conditions against the classes of id-token job the workflow can run, built from the edge's claim inputs:

- one per literal environment E: `sub` `repo:<repository>:environment:E`, `environment` E;
- one for an environment expression (`*dynamic*`): any environment;
- one for jobs without an environment: `sub` `repo:<repository>:ref:<unknown ref>` or `repo:<repository>:pull_request` (triggers are not read). `environments` is a set across jobs, so this class is known to exist only when the workflow has no environments, and is ruled out only for a workflow with a single id-token job that has a literal environment and calls no reusable workflow;
- `repository`, `repository_owner` exact; `job_workflow_ref` the workflow file at an unknown ref, or one of the called reusable workflows; any other claim (ref, actor, event, ids) unknown.

A trust matches (evidence `supplied`) when every condition holds for a class that surely runs, or for every class. It does not match (no edge) when no class can satisfy it. Anything else is undecided: evidence `not_visible` with `reason`. Conditions the parser kept looser than written (ANDed conditions as any-of, ignored negative conditions or Deny statements) make a match undecided, too. The token's `aud` is not checked: the workflow chooses it. A `sub` pattern that names the repository in a format other than the default ones (a custom sub template) is undecided, not dropped.

The hop starts at the workflow, not at the repo's shared `oidc` node, because each workflow's own environments and called workflows decide the match. Re-running with the same files replaces their `CAN_ASSUME` edges and unreferenced `cloud_target` nodes; `observed_at` is the graph's `collected_at`, so the same inputs give byte-identical output. Each `oidc` node none of whose workflows matched any supplied trust gets a coverage entry with `fact: cloud_trust` and `needs_fix: supply the trust policy for the cloud role this workflow assumes`. Scoring adds 13 per reached `cloud_target`.

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
  "schema": "gop.graph/v2",
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

Non-breaking within `gop.graph/v2` (no version change):

- new optional fields on the top level, nodes, edges or coverage entries;
- new attribute keys in `attrs` or `attr_evidence`;
- new `coverage` facts and new `source_api` strings.

Breaking, bumps `schema` to `gop.graph/v3`:

- removing or renaming a field;
- making an optional field required, or changing a field's type;
- adding, removing or changing the meaning of an `evidence`, node `kind` or edge `kind` value;
- changing ID conventions (prefixes or the shape after them).

The JSON Schema allows unknown fields and attribute keys for this reason. Consumers must ignore attributes and fields they don't know rather than reject the file. A new major version ships as a new schema file (`schema/gop.graph.v2.schema.json` for v2); `gop validate` keeps validating every version it lists as known.

## Changes

### gop.graph/v1 -> gop.graph/v2

v2 adds the evidence value `inferred`, the top-level field `audit_retention_days` and the edge attribute `rule`. Nothing was removed or renamed, so every v1 document is a valid v2 document.

- Readers must accept `inferred` and count it as confirmed reach, ranked between `live` and `audit`. A v1 reader rejects a v2 graph that contains `inferred` (gop releases before v2 check evidence values).
- v2 readers load v1: `graph.Load` accepts `gop.graph/v1`, upgrades it in memory (`schema` becomes `gop.graph/v2`, nothing else changes), and rejects a document that claims v1 but contains `inferred`. `gop validate` checks a v1 document against the v1 JSON Schema.
- Collectors now write `default_perm` and `org_owner` `CAN_PUSH` edges as `inferred` with `attrs.rule`; they were `live` in v1. Confirmed reach is unchanged.
- `audit` edges can be stale by age (see [Evidence](#evidence)). gop does not collect audit facts yet.
- Additive, in both v1 and v2: the optional top-level `org_collected_at` (per-org freshness). `collect.Merge` loads both graphs through `graph.Load`, so a v1 base merges with a v2 re-collection and the result is v2.

## Changelog

| Version | gop release | Change |
|---|---|---|
| `gop.graph/v1` | v0.1.0 | First version. |
| `gop.graph/v1` | unreleased | Additive: JSON Schema published in `schema/gop.graph.v1.schema.json`; `file`, `file_ref`, `line`, `col` on `USES` and `EXECUTES_WITH` edges; `identity` nodes for licensed users; `CAN_PUSH` `via` values `org_owner`, `direct`, `outside_collaborator`, `team`; `identity` nodes with `team:<org>/<slug>` IDs (the engine already read this prefix as `identity`) and `MEMBER_OF` edges to teams. |
| `gop.graph/v1` | unreleased | Additive: `ref_protected`, `ref_protection` and `bypass` on action_ref nodes (typed in the JSON Schema as `NodeAttrs`); `CAN_PUSH` `via=ref_bypass` with `ref`, `rule_source` and `bypass_mode`, possibly parallel to another `CAN_PUSH` edge between the same nodes; coverage facts `ref_protection`, `bypass` and `ref_bypass`. |
| `gop.graph/v1` | unreleased | Additive: `CAN_PUSH` from a workflow to its own repo with `via=token_write`, `permission=contents: write` and `jobs`; `token_write` and `token_scopes` on workflow nodes; coverage fact `default_workflow_permissions`. Coverage scoped to a repo also covers the workflows in it (`gop validate`). |
| `gop.graph/v1` | unreleased | Additive: optional top-level `org_collected_at` (per-org freshness, for graphs that merge a re-collection of some orgs into an older graph). |
| `gop.graph/v1` | unreleased | Additive: `ref_kind_source`, `ref_ambiguous`, `ref_immutable` and `ref_immutable_reason` on action_ref nodes (typed in the JSON Schema as `NodeAttrs`); `via=ref_bypass` edges whose `ref` is a tag; coverage facts `ref_kind` and `ref_immutable`. `ref_kind` of enterprise-internal refs now comes from the API. |
| `gop.graph/v1` | unreleased | Additive: `actions_access` on repo nodes (typed in the JSON Schema as `NodeAttrs`), `consumer_org` on `USES` edges (`EdgeAttrs`), coverage fact `actions_access`. |
| `gop.graph/v1` | unreleased | Additive: OIDC claim inputs `jobs`, `environments`, `job_workflow_ref`, `repository` and `repository_owner` on `EXECUTES_WITH` edges to `oidc` (typed in the JSON Schema as `EdgeAttrs`). The OIDC edge now exists only when at least one job resolves to `id-token: write` after job-level permissions replace workflow-level ones. |
| `gop.graph/v1` | unreleased | Additive: node kind `external` (`external:anyone`), edge kind `CAN_TRIGGER` with `trigger`, `exec`, `job` and `detail`, `risky_triggers` on workflow nodes, coverage fact `triggering_principals`. New kinds would normally bump the version (see above); they stay in v1 because `graph.Load` does not check kinds and the engine ignores edge kinds it does not know, so older gop releases load the file and only miss these paths (an older `gop validate` reports the new kinds). |
| `gop.graph/v1` | unreleased | Additive, still `gop.graph/v1` (before the first release that writes them): evidence value `supplied`; edge kind `CAN_ASSUME` (workflow → cloud_target) with `file`, `pointer`, `provider`, `oidc`, `matched_sub`, `claims`, `trust`, `reason`; `cloud_target` node attrs `provider`, `account`, `role`, `warnings`; coverage fact `cloud_trust`. Graphs without supplied trust files are unchanged. `graph.Load` checks evidence values, so a gop release older than this change rejects an enriched graph (run it on the graph from before `gop enrich`); the engine treats an edge kind it does not know as absent. |
| `gop.graph/v1` | unreleased | Additive: `file`, `file_ref` and `line` on `CAN_TRIGGER` edges. |
| `gop.graph/v2` | unreleased | Breaking: evidence value `inferred` (with edge attr `rule`), top-level `audit_retention_days`, stale `audit` facts. See [Changes](#changes). |
| `gop.graph/v2` | unreleased | Additive: `actions_lock` on repo nodes and workflow `USES` edges, `locked_sha`, `lock_entry` and `lock_missing` on `USES` edges (typed in the JSON Schema), coverage facts `actions_lock` and `actions_lock:<pin>`. |
| `gop.graph/v2` | unreleased | Additive: `advisories`, `advisory_severity` and `advisory_fixed` on action_ref nodes (typed in the JSON Schema as `NodeAttrs`); coverage fact `advisories`. |
| `gop.graph/v2` | unreleased | Additive: `lock_advisories`, `lock_advisory_severity` and `lock_advisory_fixed` on `USES` edges with `actions_lock=locked` (typed in the JSON Schema). |
| `gop.graph/v2` | unreleased | Additive: repo hardening attrs `branch_protected`, `branch_required_reviews`, `branch_code_owner_review`, `branch_dismiss_stale`, `branch_last_push_approval`, `branch_status_checks`, `branch_signed_commits`, `branch_allow_force_push`, `branch_push_restricted`, `branch_bypass_actors`, `branch_admin_bypass`, `branch_app_bypass`, `branch_protection_sources`, `branch_value_sources`, `codeowners`, `codeowners_valid`, `codeowners_workflows`, `secret_scanning`, `secret_scanning_push_protection`, `secret_scanning_validity_checks` (typed in the JSON Schema), coverage facts `branch_protection`, `codeowners`, `secret_scanning` and `secret_scanning_validity_checks`. |
| `gop.graph/v2` | unreleased | Additive: the `agent*` workflow attrs (typed in the JSON Schema) and `exec=agent` on `CAN_TRIGGER` edges. No bump: older releases load the file and ignore the attrs. |
| `gop.graph/v2` | unreleased | Additive: edge kind `CAN_MERGE_VIA_BOT`, the `bot_*` workflow attrs, the `review_bypass*` repo attrs, `approve_workflows` and `merge_workflow` on `CAN_MERGE_VIA_BOT` edges (typed in the JSON Schema), coverage fact `review_bypass`. No bump: `graph.Load` does not check kinds and the engine ignores edge kinds it does not know, so older releases load the file and only miss these paths. |
| `gop.graph/v2` | unreleased | Additive: `bot_merge_source`, `bot_approve_source`, `bot_merge_stale_approvals`, `bot_merge_stale_confidence`, `review_bypass_stale_approval`, `agent_holds_merge_key` and `agent_merge_key_workflows` (typed in the JSON Schema), coverage facts `bot_merge_stale_approvals` and `bot_script:<path>`. No bump: older releases load the file and ignore the attrs. |
| `gop.graph/v2` | unreleased | Additive: `branch_bypass_apps`, `bot_merge_apps`, `review_bypass_app_match`, `actions_can_approve_prs` and `review_bypass_recounts_dismissed` (typed in the JSON Schema), coverage fact `actions_can_approve_prs`. An `app_bypass` review bypass is confirmed only when the merging App matches a bypass App. No bump: older releases load the file and ignore the attrs. |
