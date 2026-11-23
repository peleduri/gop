# gop: GitHub Enterprise Org Posture

**Who can make code run where in your GitHub Enterprise.** gop maps an enterprise as an evidence graph and answers questions like: *members of acme-actions (default permission Write, 2FA not required) can push code that runs in 12 repos across 2 orgs, including a workflow with cloud OIDC. Which one change removes most of that?*

[![ci](https://github.com/peleduri/gop/actions/workflows/ci.yml/badge.svg)](https://github.com/peleduri/gop/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/peleduri/gop/badge)](https://scorecard.dev/viewer/?uri=github.com/peleduri/gop)
[![Go Report Card](https://goreportcard.com/badge/github.com/peleduri/gop)](https://goreportcard.com/report/github.com/peleduri/gop)
[![License](https://img.shields.io/github/license/peleduri/gop)](LICENSE)
[![Release](https://img.shields.io/github/v/release/peleduri/gop?include_prereleases&sort=semver)](https://github.com/peleduri/gop/releases)

gop is read-only. It joins org settings (default repository permission, 2FA, SSO), push access, workflows and the Actions they consume, including Actions nested inside composite Actions, and follows reach across org boundaries: members of one org push to a shared Action, and that Action runs inside another org's workflows with that org's secrets, OIDC trust and runners. You query the graph from an AI agent over MCP, from the CLI, or from a GitHub Action that builds an HTML report.

## 10-second demo

Real output from the synthetic enterprise in [`testdata/acme/graph.json`](testdata/acme/graph.json), trimmed where marked `...`:

```console
$ gop paths --graph testdata/acme/graph.json --from members:acme-actions
members:acme-actions has confirmed paths to 29 nodes; 0 more possible

Confirmed (every hop live or audit) (29):
  ...
  members:acme-actions -> oidc:acme-app/web  [confirmed]
      members:acme-actions =[CAN_PUSH, live]=> repo:acme-actions/deploy  source: rest:/orgs/{org}
      repo:acme-actions/deploy =[RESOLVES_TO (reversed), live]=> action:acme-actions/deploy@main  source: contents:.github/workflows
      action:acme-actions/deploy@main =[USES (reversed), live]=> workflow:acme-app/web/.github/workflows/ci.yml  source: contents:.github/workflows
      workflow:acme-app/web/.github/workflows/ci.yml =[EXECUTES_WITH, live]=> oidc:acme-app/web  source: contents:.github/workflows
  ...

$ gop report --graph testdata/acme/graph.json --out - --format md
> Members of acme-actions can push code that runs in 12 repos across 2 orgs (confirmed), including 1 cloud OIDC trust, 1 secret scope, 1 self-hosted runner pool.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 72% of confirmed reach.
...
| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 18 | 72% |
| 2 | Lower the default repository permission of acme-actions to read | 4 | 88% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 1 | 92% |
...

$ gop who --graph testdata/acme/graph.json --target secret:acme-legacy/old-api
0 principals can control secret:acme-legacy/old-api (confirmed); 1 more possible through a not visible hop

Possible (at least one hop not visible) (1):
  members:acme-legacy -> secret:acme-legacy/old-api  [possible: a hop is not visible]
      members:acme-legacy =[CAN_PUSH, not visible]=> repo:acme-legacy/old-api  source: rest:/orgs/{org}
      ...
```

The last answer is the point of the tool: the token could not read acme-legacy's repositories, so gop reports a *possible* path, not "no path".

To record this yourself with [vhs](https://github.com/charmbracelet/vhs): `vhs docs/demo.tape`.

## The nested-action trap

In the demo fixture, pinning `deploy@main` is the right first fix. Change one detail and it stops working. In the collector's end-to-end fixture ([`internal/collect/testdata`](internal/collect/testdata)), `acme-actions/deploy` is a composite Action whose first step is `uses: acme-actions/setup@main`:

1. Members of acme-actions (default permission Write) can push to `acme-actions/setup`.
2. `setup@main` runs inside every `deploy`, including in acme-secure, which pins `deploy` to a full commit SHA.
3. Pinning `acme-actions/deploy@main` to a SHA removes **0** of the acme-actions members' confirmed (principal, repo) pairs: whoever controls `setup` still controls every `deploy` consumer. (It does cut reach for bob and erin, whose direct grants cover `deploy` only, and for the `platform` team and its child team `platform-oncall`, whose grant covers `deploy` only.)
4. gop's fix planner picks pinning `deploy@main` first (23 of 64 confirmed pairs, 36%), because of those direct and team grants, then **lowering acme-actions' default permission to read** (12 more pairs), the only fix that cuts the members' reach. The rest comes from org owners and other direct and team grants, which neither fix touches.
5. Reproduce it: `go test ./internal/collect -run TestEndToEndAcme -v`.

gop counts a SHA pin as blocking a path only when the whole nested chain under it is immutable.

`gop demo` plants the same trap: `acme-secure/signer` pins `acme-actions/release` to a SHA, but `release` calls `acme-actions/setup@main`. `gop demo | gop report --graph - --out - --format md` lists it under "Pinned, still reachable", and `what_if` pinning `deploy@main` leaves that path in place.

## Why gop

Good tools already cover GitHub security. Most of them answer "is this repo or org configured well?" or "is this workflow file safe?". gop answers a different question: across every org in the enterprise, **who can make code run where, and through which hops?**

| | Checks | Scope | Output | Examples |
|---|---|---|---|---|
| Posture checklists | Org and repo settings against best practice | One repo or one org at a time | Pass/fail findings | [OpenSSF Scorecard](https://github.com/ossf/scorecard), [Legitify](https://github.com/Legit-Labs/legitify), ghqr, gitsec |
| Workflow linters | Dangerous patterns in workflow files: injection, `pull_request_target`, unpinned refs, broad permissions | Workflow files | Findings per file and line | [zizmor](https://github.com/zizmorcore/zizmor), [poutine](https://github.com/boostsecurityio/poutine), [actionlint](https://github.com/rhysd/actionlint) |
| Offensive tooling | What an attacker holding a token can exploit: runners, pwn requests, secrets | What one token can reach | Attack paths for red teams | [Gato-X](https://github.com/AdnaneKhan/gato-x) |
| **gop** | Who can push code that ends up running in which repo's CI, with which secrets, OIDC trusts and runners | The whole enterprise, across orgs and nested Actions | A graph with evidence on every hop, confirmed vs possible reach, and the fewest changes that remove the most reach | |

Use them together. A linter tells you a workflow is unsafe; Scorecard tells you a repo lacks branch protection; gop tells you that the members of another org can change what that workflow runs. gop does not lint workflow contents for injection, and it is not an exploitation tool.

## Try it without a token

`gop demo` writes a synthetic enterprise (`acme`, orgs `acme-*`, users `alice`, `bob`, `user-NNN`) with no token and no network. It plants the cross-org `acme-actions/deploy@main` path, a SHA-pinned consumer that is safe, a SHA-pinned composite action that is not (it calls `acme-actions/setup@main` inside), one hop the token cannot see in `acme-legacy`, and a self-hosted runner.

```sh
go install github.com/peleduri/gop/cmd/gop@latest
gop demo | gop report --graph - --out - --format md   # the headline, fixes, and "Pinning is not enough"
claude mcp add gop -- gop serve --demo                # then ask: who can make code run in acme-app/web?
```

`gop demo [--size small|medium|large] [--seed N] [--out graph.json]` writes the graph (stdout by default); `small` is about 60 repos, `medium` about 1,000, `large` about 10,000. The same size and seed give a byte-identical file. `gop serve --demo` and `gop report --demo` build the small graph in memory. Demo graphs say so: the enterprise node carries `demo=true`, every `source_api` starts with `demo:`, and every MCP summary and report title starts with `[demo data]`.

## Quick start

```sh
go install github.com/peleduri/gop/cmd/gop@latest                  # or Homebrew / a signed release, see Install
GITHUB_TOKEN=... gop collect --enterprise acme --out graph.json     # read-only, see "Token and permissions"
gop report --graph graph.json --out report.html                     # or ask your agent, below
```

No enterprise handy? Every read command works on the fixture: `--graph testdata/acme/graph.json`.

### Connect your agent (MCP over stdio)

Claude Code:

```sh
claude mcp add gop -- gop serve --graph /path/to/graph.json
```

Cursor, VS Code and other clients: [docs/mcp-clients.md](docs/mcp-clients.md). `gop mcp-config --client claude|cursor|vscode --graph graph.json` prints the config with the absolute path filled in. Use an absolute path, and keep the graph out of shared or synced folders.

Then ask: "Who can make code run in acme-app/web?", "What happens if we pin acme-actions/deploy@main to a SHA?", or "What couldn't the token see?"

### MCP tools

Every tool is annotated read-only, and every answer keeps confirmed and possible reach apart.

| Tool | Answers |
|---|---|
| `who_can_reach` | Which principals can make code run in a target repo, workflow, action, secret scope, OIDC trust or runner pool, with one shortest path each. |
| `blast_radius` | Everything one principal (an org's members, a user, a team, an app) can make code run in, with a score. |
| `paths` | The concrete hops from a principal, optionally to one target, each with its edge kind, evidence level and API source. |
| `top_risks` | Principals ranked by confirmed blast radius. |
| `what_if` | Reach before and after hypothetical fixes: `pin_ref` (pin an action to a SHA), `lower_default_perm` (set an org's default permission to read or none), `restrict_token` (set a workflow's `GITHUB_TOKEN` to `contents: read`) or `harden_trigger` (stop a workflow from running attacker-controlled code on its risky triggers). |
| `suggest_fixes` | A greedy plan: the fixes that remove the most confirmed (principal, repo) pairs, with the cumulative percentage. |
| `fix_plan` | Concrete change steps for one fix (`fix`, or `suggestion_rank` from `suggest_fixes`): every workflow line to edit with a one-line diff, or the org setting with its REST call as text. gop never runs the steps. |
| `explain` | Why an edge exists: evidence, `source_api`, `observed_at` and attributes. |
| `coverage` | What the token could not see, and the access that would make it visible. |
| `diff` | What changed since a baseline snapshot (`gop serve --graph new.json --baseline old.json`): new and removed paths, settings, edges, score deltas and coverage, filterable by principal and target kind. Same report as `gop diff --format json`; lost visibility is never reported as a fix. |

### MCP resources and prompts

Resources give an agent cheap context before its first tool call:

| Resource | Contents |
|---|---|
| `gop://graph/summary` | Enterprise, `collected_at`, age in hours, schema, node and edge counts by kind, evidence mix (live, audit, not_visible), orgs with `default_perm`, `two_factor` and `sso`, and the top 5 principals by confirmed score (JSON). |
| `gop://graph/coverage` | The `coverage` tool's answer (JSON). |
| `gop://graph/schema` | Node ID conventions and edge semantics: [docs/schema.md](docs/schema.md) (Markdown). |
| `gop://node/{+id}` | One node with its in and out edges, e.g. `gop://node/repo:acme-app/web` (JSON; the ID may be raw or percent-encoded). |

Prompts start a guided flow: `triage_enterprise` (optional `focus`: `oidc`, `secrets`, `runners` or `all`), `review_action` (`action`, e.g. `action:acme-actions/deploy@main`) and `explain_path` (`from`, `to`). Each keeps confirmed and possible apart and never reports a not-visible fact as off. When the snapshot is more than 7 days old, the summary and every prompt say "snapshot is N days old".

### CLI

```
gop collect --enterprise <slug> --out graph.json [--orgs a,b] [--app-id N --app-key-file PATH] [--oidc-trust <files>]
gop enrich  --graph graph.json [--oidc-trust <file|dir>[,...]] [--cartography export.json] --out graph2.json
gop doctor  --enterprise <slug> [--github-url URL] [--orgs a,b] [--format text|json] [--app-id N --app-key-file PATH]
gop demo    [--size small|medium|large] [--seed N] [--out graph.json]
gop serve   --graph graph.json | --demo  [--baseline old.json]
gop report  --graph graph.json | --demo  --out report.html [--format html|md] [--top N]
gop paths   --graph graph.json --from <principal> [--to <node>]
gop who     --graph graph.json --target <node>
gop validate --graph graph.json [--format text|json]
gop redact  --graph graph.json --out shareable.json [--salt-file key] [--keep-attr k1,k2] [--map-out mapping.json]
gop diff    OLD.json NEW.json [--format text|json|markdown] [--fail-on confirmed-increase|any-new-path]
gop fix-plan --graph graph.json --pin <action> | --lower-default-perm <org> [--to read|none] | --restrict-token <workflow> | --harden-trigger <workflow> [--format text|markdown|json]
gop sarif   --graph graph.json --out gop.sarif | --split-by-repo DIR [--top N] [--min-severity low|medium|high|critical] [--include-possible]
gop pin     --action <owner/repo@ref> [--graph graph.json [--repo owner/repo] [--offline]] [--github-url URL] [--format diff|text|json]
gop export  --format cypher graph.json [--out gop.cypher] [--github-url URL]
gop mcp-config --client claude|cursor|vscode --graph graph.json
gop version
```

`gop fix-plan` turns a fix into a checklist: for `--pin action:acme-actions/deploy@main`, every workflow and nested action that uses the ref, sorted by repo and file, with the line and a one-line diff when the graph has line attributes; for `--lower-default-perm org:acme-actions`, the setting with its UI path and REST call, and the repos where members lose push; for `--restrict-token workflow:acme-app/web/.github/workflows/ci.yml`, where to set `permissions: contents: read` (a top-level block when the jobs take the repo's default, the listed jobs when the file grants write); for `--harden-trigger workflow:acme-app/docs/.github/workflows/preview.yml`, the job and line of each head checkout or script injection, with the change to make. Markdown output pastes into a ticket. gop never runs the steps or calls write APIs.

`gop pin --action acme-actions/deploy@main` resolves the ref to its commit SHA with one read-only call (`GET /repos/{owner}/{repo}/commits/{ref}`), says whether the ref is a tag or a branch (tags can move too), and prints the replacement `uses:` value. With `--graph`, it also fetches each consuming workflow file (read-only) and prints a unified diff per file that applies with `git apply`; use `--repo acme-app/web` to get one repo's part, then `gop pin ... --repo acme-app/web | git apply` in that checkout. `--offline` skips the file reads and prints the one-line hunks `fix-plan` shows. It warns when the action itself uses mutable refs, since pinning the outer ref does not close those. The token comes from `GITHUB_TOKEN` (or `GH_TOKEN`); gop pin sends only GET requests and writes to stdout only. To keep pins current afterwards, use Dependabot or Renovate.

`gop sarif` writes one SARIF 2.1.0 result per fixable edge for code-scanning style triage: `GOP001` for each `uses:` line of a mutable action ref that principals outside the consuming org can change (with the file and line), `GOP002` for an org whose default permission gives members push. `--split-by-repo DIR` writes one file per repo. SARIF lists attack paths, so uploading it to code scanning shows them to everyone with alert access on the repo: gop never uploads it, and [docs/sarif.md](docs/sarif.md) explains the trade-off.
`gop redact` makes a graph safe to attach to a bug report. Every org, repo, user, team, action, workflow file, secret name, runner label, environment and cloud name becomes a stable synthetic name (`acme-org-03`, `acme-org-03/repo-012`, `user-007`, `.github/workflows/wf-004.yml`; SHAs become other 40-hex strings, tags `v1.N`, branches `branch-N`), member, IP allow list and observed role-use (`times_used`) counts are bucketed and timestamps, including `last_used`, shift by one offset. Structure, evidence and the attrs reach depends on are kept, so reach and scores are the same as on the real graph. Attr keys gop does not define are dropped unless `--keep-attr` names them. Names come from HMAC-SHA256 under the salt: `--salt-file` gives the same names on every run, and without it each run uses a random salt. Before writing, it checks that no original name of 3 or more characters appears in the output and fails, writing nothing, if one does. `--map-out` writes the real-to-synthetic mapping to a local file: keep it, never share it. Regenerate a report from the redacted graph instead of redacting report.html.

`gop diff` compares two snapshots and reports posture drift: new and removed paths, setting changes, score deltas and coverage gaps. Facts the newer token cannot see are reported as lost visibility, never as removed. See [docs/drift.md](docs/drift.md).

`gop export --format cypher graph.json > gop.cypher` writes an idempotent Neo4j script that loads gop's nodes, edges and computed reach next to [Cartography](https://github.com/cartography-cncf/cartography) data, linked to its GitHub repo, org and AWS role nodes. See [docs/cartography.md](docs/cartography.md#export-gop-to-neo4j).

`--graph -` reads the graph from stdin for `report`, `paths` and `who`. Node IDs look like `members:acme-actions`, `identity:bob`, `repo:acme-app/web`, `action:acme-actions/deploy@main`, `oidc:acme-app/web`. An unknown ID returns suggestions.

## No half truths

Every node and edge in the graph carries an evidence level:

| Evidence | Meaning |
|---|---|
| `live` | Read from current state through the GitHub API. |
| `audit` | Inferred from the enterprise audit log. Retention is bounded, so it may be stale or incomplete. The schema and engine support it; the collector does not read the audit log yet (planned). |
| `supplied` | Read from a file you supplied (a cloud OIDC trust policy, see [Paths out of GitHub](#paths-out-of-github)). gop did not observe it live. |
| `not_visible` | The token cannot read this fact. The hop is **unknown, not absent**. |

gop never turns "couldn't see" into "off". A path with any `not_visible` hop is **possible** reach and is never counted in headline numbers, scores or fix suggestions. A path where every hop is `live`, `audit` or `supplied` is **confirmed**; a path with a `supplied` hop is flagged and every summary of it names the file. The `coverage` list says what was missing and the access that would close the gap, for example "org owner on acme-legacy (SSO enforced: join through the identity provider first)".

How the engine reasons, briefly: push access controls a repo; a repo controls the workflows defined in it and every Action it hosts on a mutable ref (a branch, a tag, or a ref gop could not classify: it never assumes a pin it did not see); an Action controls every workflow and composite Action that uses it; a controlled workflow runs in its repo's CI with that workflow's secrets, OIDC token and runners. Running CI in a repo is counted as reach, not as push access to it. The rules are documented at the top of [`internal/graph/reach.go`](internal/graph/reach.go).

## Paths out of GitHub

An OIDC token is only half the story: what matters is the cloud role it turns into. Export your cloud trust configuration and give it to gop:

```sh
aws iam get-role --role-name deploy > trust/aws/deploy.json
gcloud iam workload-identity-pools providers describe github --workload-identity-pool=github \
  --location=global --project=acme-prod --format=json > trust/gcp/provider.json
az ad app federated-credential list --id <app-id> > trust/azure/web.json

gop enrich --graph graph.json --oidc-trust ./trust/ --out graph2.json
# or in one step: gop collect ... --oidc-trust ./trust/
```

`gop enrich` is offline: no token, no cloud API call. It matches each trust's `sub` and other claim conditions (AWS `StringEquals`/`StringLike`, GCP attribute conditions, Azure subjects and claims matching expressions) against what every workflow's token can carry, and adds `workflow -CAN_ASSUME-> cloud:<provider>:<role>`. Then:

```
$ gop who --graph graph2.json --target cloud:aws:arn:aws:iam::111111111111:role/deploy
2 principals can control cloud:aws:arn:aws:iam::111111111111:role/deploy (confirmed); 0 more possible
through a not visible hop (cloud hop from supplied trust file trust/aws/deploy.json, not read from the cloud)
  members:acme-actions -> cloud:aws:arn:aws:iam::111111111111:role/deploy  [confirmed]
      members:acme-actions =[CAN_PUSH, live]=> repo:acme-actions/deploy
      repo:acme-actions/deploy =[RESOLVES_TO (reversed), live]=> action:acme-actions/deploy@main
      action:acme-actions/deploy@main =[USES (reversed), live]=> workflow:acme-app/web/.github/workflows/release.yml
      workflow:acme-app/web/.github/workflows/release.yml =[CAN_ASSUME, supplied file]=> cloud:aws:arn:aws:iam::111111111111:role/deploy
```

Members of acme-actions can push code that assumes `role/deploy` in AWS account 111111111111, because `release.yml` runs in the `prod` environment that the role trusts (`repo:acme-app/web:environment:prod`) and uses an action they can push to.

Works with Cartography: if you run [Cartography](https://github.com/cartography-cncf/cartography), run the shipped query [`docs/cartography/oidc-trusts.cypher`](docs/cartography/oidc-trusts.cypher) and pass the export with `gop enrich --cartography export.json` instead of exporting trust files by hand (AWS only). Roles CloudTrail saw a repo assume are marked `observed_use` on the matching edge. See [docs/cartography.md](docs/cartography.md).

The evidence caveat: the cloud hop comes from your file, not from the cloud. gop counts it as confirmed because you assert the file is what is deployed, but it carries evidence `supplied`, `Path.Supplied` is set, and every summary, report and MCP answer says "cloud hop from supplied trust file <file>, not read from the cloud". A stale export gives stale answers.

When gop cannot decide a match, the edge is `not_visible` with a `reason` (possible reach), never dropped and never confirmed: a branch- or tag-scoped `sub` (gop does not read workflow triggers), an environment set by an expression, a condition it could not parse, a claim only known at run time, or a workflow that may have id-token jobs both with and without an environment. A trust with no `sub` condition matches every workflow that can mint a token, and its `cloud_target` carries the warning `no_sub_condition`. An `oidc` node that no supplied trust matches gets a `cloud_trust` coverage entry. gop assumes the default `sub` format; a `sub` pattern that names the repository in another format (a custom sub template) is possible, not dropped. The token's audience is not checked: the workflow chooses it. What the role can do once assumed is out of scope.

Scoring: each cloud role a principal reaches adds 13 to its blast radius score. The full formula (`internal/graph/score.go`) is `1×repos + 0.5×workflows + 2×orgs + 3×runners + 5×secrets + 8×oidc + 13×cloud roles`, multiplied by 1.5 for each weak control of the principal's org (2FA not required, SSO not enforced). Confirmed and possible reach are scored separately; only confirmed counts in the headline.

## What gop collects today

- Enterprise orgs, default repository permission, 2FA and SSO policy, and org settings: member repo creation, visibility changes, repo deletion, private forks, IP allow lists.
- Org membership counts and the repositories of each org.
- `CAN_PUSH` from an org's members to every repo in that org when the default repository permission is Write or Admin.
- `identity:` nodes for licensed users with `MEMBER_OF` their orgs, and `CAN_PUSH` from org owners (every repo in the org), direct collaborators and outside collaborators with push (including custom repository roles). When a repo's collaborators can't be listed, license-listed repo grants become `not_visible` (possible) edges.
- `team:` nodes with nested teams (`MEMBER_OF` the parent team), direct team members (`MEMBER_OF` the team), and `CAN_PUSH` from each team repository grant with push. Members of a child team reach the parent's repos through the nesting. A non-owner token can't see secret teams; that gap is recorded in coverage.
- Workflow files: the Actions and reusable workflows they use, `id-token: write`, secrets and self-hosted runners. Composite Actions and reusable workflows are expanded recursively at the referenced ref.
- The Actions access setting of each private or internal repo that hosts a referenced Action. A workflow in another org can only use the Action when the setting allows it; when the setting can't be read (it needs repo admin), cross-org paths through the Action are possible, not confirmed.

Not collected yet (planned): GitHub App grants, org-level custom roles, enterprise teams, audit log facts, branch protection and environment rules, and resumable collection.

GitHub Enterprise Server: `gop collect --github-url https://github.acme.example` (or `GOP_GITHUB_URL`) reads `/api/v3` and `/api/graphql` on that host and leaves the APIs its version lacks `not_visible`. See [docs/ghes.md](docs/ghes.md).

## Install

```sh
brew install peleduri/tap/gop                         # Homebrew (tap coming soon, see docs/install.md)
go install github.com/peleduri/gop/cmd/gop@latest     # from source
# or a signed archive from Releases: https://github.com/peleduri/gop/releases
```

Release archives are signed keyless with cosign and ship with SPDX SBOMs and SLSA build provenance. Checksum, signature and provenance steps, plus a "verify what you run" checklist, are in [docs/install.md](docs/install.md).

## Token and permissions

gop only reads, and it takes the token only from `GITHUB_TOKEN` (or `GH_TOKEN`), never as a flag; in GitHub App mode it takes the App ID and private key instead (below). Use a classic token from an **enterprise owner** with these scopes, or the equivalent read permissions on a GitHub App:

| Scope | Used for | If missing |
|---|---|---|
| `read:enterprise` | Enterprise ownerInfo: org list, enterprise-level default permissions, 2FA and SSO policy, membership | Enterprise settings are `not_visible`; orgs come from `--orgs`, or are discovered only where the token is a member (`GET /user/orgs`) or installed (`GET /installation/repositories`) |
| `read:org` | Org settings, repositories, IP allow lists | That org's settings and `CAN_PUSH` edges are `not_visible` |
| `repo` | Workflow and action file contents in private and internal repositories (`USES`, `EXECUTES_WITH` edges) | Workflows in those repos are `not_visible`, so cross-org paths through them are unknown |
| `read:audit_log` | Facts that only the audit log records (planned, not used yet) | No `audit` evidence |

Under SAML SSO enforcement the token must also be authorized for each org.

Before a long first collection, run `GITHUB_TOKEN=... gop doctor --enterprise acme`. In a handful of read-only requests it reports the token kind and mode (below), missing or broader-than-needed scopes, a classic token with no expiry, orgs where the token is not authorized for SSO, the remaining REST and GraphQL budget, an estimate of requests and minutes for `collect`, and what will come out `not_visible`, each with the fix. It never prints the token. Exit 0 all pass, 1 any fail, 3 warnings only. The token kind comes from GitHub's documented prefixes (`ghp_`, `github_pat_`, `ghs_`, ...); fine-grained and installation-token permissions are not exposed in headers, so doctor cannot check them. In App mode (`gop doctor --app-id N --app-key-file PATH`) doctor lists the App's installations, flags each `--orgs` entry without one, checks that every granted permission is `read` and that the App has each permission collect requests, mints one read-only token per org to probe it, and predicts what App mode leaves `not_visible`.

### Token modes

| Mode | What gop sees |
|---|---|
| (a) Enterprise-owner token, run locally | Full enterprise settings plus every org and repo the owner can see. **The intended mode.** |
| (b) GitHub App, one read-only installation token per org | gop signs an App JWT, lists the App's installations and mints an installation token per org (`POST /app/installations/{id}/access_tokens`, read permissions only: the one non-GET REST call gop makes, which changes no repository or org state). Each org's requests carry that org's token, so one run covers every installed org and cross-org paths still join. Enterprise APIs are not called: enterprise ownerInfo settings, SSO state, the enterprise org list and consumed licenses are `not_visible` (members come from each org's members API). Settings the org API returns (`GET /orgs/{org}`: default permission, 2FA, repo creation, private forks) stay `live`. A `uses:` owner outside the installed orgs gets `in_enterprise=unknown`. An `--orgs` entry without an installation is `not_visible` with coverage "install the App on X with read-only permissions"; a missing App permission gives coverage naming it. Run it with `gop collect --enterprise acme --out graph.json --app-id 123456 --app-key-file app.pem`, or set `GOP_APP_ID` and `GOP_APP_PRIVATE_KEY` (the PEM contents); App credentials and `GITHUB_TOKEN` are mutually exclusive. The key is read once, held in memory and never logged or written, and gop warns when the key file's mode is wider than `0600`; in CI it is itself a high-value credential. Grant the App read-only permissions: repository Metadata, Contents, Administration and Actions, and organization Members and Administration. Creating and installing the App is a manual step: see [docs/github-app-token.md](docs/github-app-token.md). Without App credentials, a single installation token passed as the token still works for its one org. |
| (c) A repository's `GITHUB_TOKEN` | One repository only. gop is not useful in this mode. |

### Rate limits

A token gets 5,000 REST requests per hour (GitHub Apps scale with installation size). Large enterprises take a while to collect. Collection is sequential today; it retries transient errors and waits out rate limits. Workflow and action files are read in batched GraphQL queries (25 repositories per query by default, halved automatically when GitHub reports a query too expensive), so they do not cost one REST request per file; a repository the batch cannot read falls back to REST. While it runs, `gop collect` prints a progress line to stderr at most every 5 seconds with the phase, the count done and the remaining REST and GraphQL budget. Resuming an interrupted collection is planned.

## Running in GitHub Actions: token risk

The Action (`uses: peleduri/gop/action@<sha>`) downloads a release, verifies its checksum (and cosign signature when cosign is installed), runs `gop collect` and `gop report`, and uploads both files as an artifact.

It runs on Linux, macOS and Windows runners (x64 and ARM64). Every step uses `shell: bash`: GitHub-hosted Windows runners have Git Bash; a self-hosted Windows runner needs Git for Windows (bash, `sha256sum`, `unzip`) and `gh` on `PATH`. Setting up the GitHub App (permissions, installation, where to keep the key, per-org tokens and the coverage you get) is in [docs/github-app-token.md](docs/github-app-token.md).

```yaml
permissions:
  contents: read
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: peleduri/gop/action@<full-commit-sha> # vX.Y.Z
        with:
          enterprise: acme
          app-id: ${{ vars.GOP_APP_ID }}
          app-private-key: ${{ secrets.GOP_APP_PRIVATE_KEY }}
          retention-days: 1
```

With `app-id` and `app-private-key` set, the Action runs gop in App mode (mode b): one read-only installation token per org the App is installed on, so a single run covers every installed org. The Action masks every line of the key and passes it only to `gop collect`. Without them it uses `token`, for example a token from a create-app-token step.

Read this before you set it up:

- **Prefer a read-only GitHub App** (App mode, or an installation token minted per run) over a PAT. An enterprise-owner PAT stored in Actions secrets creates exactly the high-value CI path gop reports: anyone who can change a workflow in that repository can use it.
- With App tokens, enterprise settings and any org the App is not installed in show as `not_visible` in the report (mode b above). The App private key in secrets is a high-value credential; keep it in a dedicated private repository with restricted workflow edit access.
- **Artifacts are readable by anyone with read access to the repository.** graph.json and report.html are an attack map. Run the Action only in a **private** repository, and keep `retention-days` at 1 (the default).
- For full coverage, run gop locally with an enterprise-owner token (mode a) instead.

### Fail the job when confirmed reach grows

A scheduled run nobody reads catches nothing. With `fail-on-reach-increase: "true"`, the Action compares this run's graph with the `gop-posture` artifact (or the name in `baseline-artifact`) of the newest previous successful run of the same workflow on the default branch, using `gop diff --fail-on confirmed-increase`. When confirmed (principal, repo) pairs grew, for example a new unpinned ref or a raised default permission, the job fails after the artifact upload, so the normal Actions failure notification reaches you and the artifact is kept.

```yaml
on:
  schedule:
    - cron: "17 3 * * *"
permissions:
  contents: read
  actions: read # list previous runs and download their artifact
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: peleduri/gop/action@<full-commit-sha> # vX.Y.Z
        with:
          enterprise: acme
          app-id: ${{ vars.GOP_APP_ID }}
          app-private-key: ${{ secrets.GOP_APP_PRIVATE_KEY }}
          fail-on-reach-increase: "true"
          retention-days: 2 # at least the schedule interval, or the baseline is gone
```

- The diff stays private: `diff.md` and `diff.json` (and `diff-stderr.txt`, when `gop diff` printed anything) go only into the artifact. The log and the step summary never name nodes; the summary gets one line, "confirmed reach increased; see artifact". No PR comments, issues or annotations.
- With no previous artifact (first run, or it expired) the gate logs "no baseline, skipping" and passes. If `gop diff` cannot compare the graphs (a different enterprise, a major schema change), the job fails after the upload, with the error in `diff-stderr.txt`.
- The gate needs `actions: read`. With the input off (the default) the Action makes no extra calls and needs no extra permissions.
- **Retention trade-off.** The baseline is the previous run's artifact, so it must outlive the schedule interval: with the default `retention-days: 1` and a weekly schedule, every run finds no baseline and the gate never fires. Set `retention-days` to at least the interval (2 for a nightly run, to absorb delays). Longer retention keeps the attack map readable for longer by anyone with read access to the repository, so keep the interval short rather than the retention long.
- A failed run is not successful, so the next run still compares against the last good baseline and stays red until the reach goes back down. To accept the new state, run the workflow once with the gate off (for example through a `workflow_dispatch` input).

## Security and privacy

- **Read-only.** gop makes no write calls to GitHub. The API client refuses every non-GET REST request and every GraphQL mutation before sending it; the only allowlisted exception is GitHub App mode minting a read-only installation token, which changes no repository or org state.
- **No telemetry.** gop sends nothing anywhere except read requests to the GitHub API.
- **Data stays local.** graph.json and the report are written to your disk with file mode 0600. Treat them as sensitive and never commit them.
- **MCP answers go to your agent.** When you connect `gop serve` to an agent, its answers flow to that agent and to whichever model provider it uses. gop itself sends nothing anywhere.

See [docs/threat-model.md](docs/threat-model.md) and [docs/schema.md](docs/schema.md). Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Architecture

![gop collect writes graph.json; the engine reads it and serves the MCP server, the CLI and the HTML report](docs/assets/architecture.svg)

`gop collect` writes one JSON document (`gop.graph/v1`, [schema](docs/schema.md), [JSON Schema](schema/gop.graph.v1.schema.json); check a file with `gop validate`). Everything else reads that file: the engine indexes it once and answers reach, scoring, what-if and fix-planning queries for the MCP server, the CLI and the report. The fix planner is a budgeted greedy over grouped fixes, not an exact min-cut, and it never suggests a fix whose edges are all `not_visible`.

Contributors: [docs/architecture.md](docs/architecture.md) has the package map, the data flow, the control-graph rules and the invariants to keep.

## Roadmap

Planned, roughly in order. Each item will get a [GitHub issue](https://github.com/peleduri/gop/issues); comment there if you need it.

- Team and GitHub App push grants
- Audit log collection (`audit` evidence)
- Branch protection, rulesets and environment protection as conditions on edges
- `what-if` and `fix` CLI subcommands (available over MCP today)
- Resumable and parallel collection
- Diff between two collections

## Contributing

Issues and PRs are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first: commits need a DCO sign-off, and all fixtures, examples and issues use synthetic names only (`acme`, `acme-actions`, `acme-app`). Never paste a real graph.json anywhere. Report security issues through [SECURITY.md](SECURITY.md). Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Status

Alpha. The graph schema (`gop.graph/v1`) and CLI flags may change before v1.0.

## License

[Apache-2.0](LICENSE)
