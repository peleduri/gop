# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Before v1.0 the graph schema and CLI
flags may change in minor releases.

## [Unreleased]

### Added

- `contrib/ossie/`: a reviewed [Apache Ossie](https://ossie.apache.org/) semantic
  model (`gop.ossie.yaml`, Ossie 0.3.0.dev0) of the `gop export --format sql`
  schema, for Ossie-aware tools such as NVIDIA Auto Ontology. It defines the
  terms (organization, repository, workflow, action, identity, principal,
  cloud role, secret, self-hosted runner, finding, run, reach) with synonyms,
  every edge label as a join, and measures: confirmed and possible reach (kept
  apart), unpinned reachable actions, orgs with write as the default
  permission, findings, and the run-over-run reach delta. `views.sql` adds one
  view per term over the export (load it after the export). A test validates
  the model against the Ossie JSON Schema, checks every referenced column
  exists in the export schema, and runs each measure's SQL on the demo export
  against the engine's numbers. The README covers loading into Auto Ontology
  and warns that it sends schema samples and questions to its model endpoint
  (NVIDIA's hosted API by default), so self-host models for real data.
- Opt-in REST response cache for `gop collect`: `--cache-dir DIR`
  (`Config.CacheDir`, off by default) stores `GET` responses that are `200`
  with an `ETag` or `Last-Modified` and revalidates them on the next run with
  `If-None-Match` or `If-Modified-Since`; a `304` serves the cached body and
  does not count against the primary rate limit. `--resume` (`Config.Resume`)
  makes an interrupted collection of the same enterprise and orgs reuse every
  response it already fetched without a request (`DIR/run.json` records the
  run start and is removed on success). Entries are keyed by method, absolute
  URL (host included), `Accept` type and a token fingerprint, so tokens and
  hosts never share entries; the token and request headers are never written.
  GraphQL, errors and the App token mint are never cached. Edges built from a
  resumed body keep that entry's `fetched_at` as `observed_at`. The progress
  line and a final `collect: cache N hits (304), M fetched, K resumed` line
  report the counts. The cache directory is created `0700` (an existing one
  other users can read is refused) with `0600` files written atomically; it
  holds API responses as sensitive as graph.json (see
  `docs/threat-model.md`).
- `gop export --format sql graph.json [graph2.json ...] --out gop.sql` writes
  graphs as a SQL script that `sqlite3` and `duckdb` both load, for questions
  that count and group, BI tools and text-to-SQL tools. Tables: `runs`,
  `nodes`, `node_attrs`, `edges`, `edge_attrs`, `findings` (top risks and fix
  candidates with the pairs each removes) and `reach` (gop's computed reach
  per scoring principal, confirmed or possible, with the shortest path), all
  keyed by `run_id`. Several graphs load as several runs, so trends work; the
  script deletes a run's rows before inserting them, so loading it again
  changes nothing and older runs stay. Evidence is plain text. Values with
  control characters are written JSON-encoded (`'...' ->> '$'`, SQLite 3.38+),
  so the script holds no raw control characters. gop writes text
  and links no SQLite driver: the binary grows by about 50 KB, where a pure-Go
  driver would add about 5 MB. `--out` writes mode 0600; the file lists attack
  paths. Schema and example queries: `docs/sql.md`.
- MCP tool `check_answerable` (`question_kind`, `subject`): before an agent
  gives an answer, says whether gop could see the facts that answer depends
  on. Deterministic, no model: for the part of the graph the named tool's
  answer depends on (the subject and everything upstream for `who_can_reach`,
  everything the subject reaches for `blast_radius` and `paths`, the whole
  enterprise for `top_risks`, `what_if` and `fix_plan`) it reads coverage
  entries, `not_visible` edges, attributes and nodes, and stale `audit` facts
  (older than the graph's maximum audit age, so `audit_retention_days` is
  honoured; `inferred` counts as visible), and returns `answerable` (`yes`, `partial` for a lower bound,
  or `no` when the subject or its org's repositories are not visible), the
  missing facts with scope, reason and fix, and a confidence note. It never
  says `yes` when a required fact is not visible. The required facts per
  question kind live in one table, listed in `docs/mcp-clients.md`. The
  server now sends instructions on initialize, and they and the
  `explain_path` prompt ask the agent to call `check_answerable` before giving
  a security conclusion.
- Graph tab in the HTML report: the filtered paths as a layered left-to-right
  inline SVG (principal → repo → action ref → workflow → impact), laid out in
  Go (longest-path layers, barycenter order) with no third-party library and
  no CDN, under the same CSP. Hops are solid for live, dashed for audit and
  dotted with `?` for not visible; reversed hops are drawn in control
  direction and say so. Hover or focus shows `source_api`, `observed_at` and
  attrs (`file:line` when known). Selecting a node (click, or Enter on the
  focused node) filters to the paths through it (`via=` in the address);
  "Simulate a pin" greys the paths a top-10 suggested pin removes, from
  `WhatIf` data embedded by Go. Above 300 nodes it asks to narrow the filter.
  Nodes are keyboard buttons, the tabs follow the ARIA tabs pattern, and a
  text list of the drawn paths is the SVG's text alternative. Unknown
  evidence classes keep their name instead of reading "not visible".
- Action input `fail-on-reach-increase` (default `"false"`) with
  `baseline-artifact` (default `gop-posture`): compares the run's graph with
  the artifact of the previous successful run of the same workflow on the
  default branch (`gop diff --fail-on confirmed-increase`) and fails the job
  after the artifact upload when confirmed reach grew. `diff.md` and
  `diff.json` go only into the artifact; the log and step summary never name
  nodes. No baseline logs "no baseline, skipping" and passes. Needs
  `actions: read`; off, the Action is unchanged. The gate is
  `action/diff-gate.sh`, tested against a built gop.
- `gop enrich --cartography <export>` imports AWS role trusts of GitHub Actions
  from a Cartography Neo4j database. Run the shipped read-only query
  `docs/cartography/oidc-trusts.cypher` (cypher-shell plain output, Neo4j
  Browser JSON, the HTTP API shape or a plain row array are accepted); gop maps
  each `TRUSTS_AWS_PRINCIPAL` condition block to the same trust model as
  `--oidc-trust` files, so `CAN_ASSUME` edges and cloud nodes come out as with
  the equivalent trust file (evidence `supplied`, plus `source=cartography`).
  CloudTrail role use (`ASSUMED_ROLE_WITH_WEB_IDENTITY`) sets
  `observed_use`, `times_used` and `last_used` on the matching edge; an
  observation with no matching trust is a warning, never an edge. Bad rows are
  warnings, never errors. gop has no Neo4j driver and needs no Neo4j
  credentials. GCP and Azure stay on trust files: Cartography does not store the
  GCP attribute mapping or Azure federated credentials (see
  `docs/cartography.md`).
- GitHub Enterprise Server support. `gop collect`, `gop doctor` and `gop pin`
  take `--github-url https://HOST` (or `GOP_GITHUB_URL`) and read
  `https://HOST/api/v3` and `https://HOST/api/graphql`; `--api-url` and
  `--graphql-url` override them for a proxy, and `http://` needs
  `--insecure-http`. Collect reads the server version from `GET /meta` and
  records `host` and `ghes_version` on the enterprise node (`host` is
  `github.com` on github.com). Collectors the version lacks (enterprise
  ownerInfo settings, consumed licenses, the Actions access setting,
  rulesets; minimums in `docs/ghes.md`, not yet verified per version) are
  skipped with coverage `not available on GHES <version>`, and the run
  succeeds. Actions whose owner is not an org on the instance get
  `source=github.com`. See `docs/ghes.md`.
- `gop export --format cypher graph.json > gop.cypher` writes an idempotent
  Neo4j Cypher script for Cartography users: gop nodes as `:GopNode` plus a
  kind label (`:GopRepo`, `:GopWorkflow`, `:GopCloudRole`, ...), gop edges with
  their kinds and `evidence`, `confirmed` and `gop_run`, and computed
  `GOP_REACHES` edges from each scored principal to the secrets, OIDC tokens,
  runners and cloud roles it controls, with the path. `SAME_AS` links join
  `:GopOrg`, `:GopRepo` and AWS `:GopCloudRole` nodes to Cartography's
  `GitHubOrganization`, `GitHubRepository` and `AWSRole` when those exist
  (`--github-url` for GitHub Enterprise Server). A re-export replaces the
  previous run of the same enterprise. Output is sorted and byte-identical
  for the same graph; every graph value is an escaped string literal and
  labels, relationship types and keys come from fixed lists. gop writes
  text only and has no Neo4j dependency. See `docs/cartography.md`.

- The Action runs on Windows runners (x64 and ARM64): the download step
  (now `action/install-gop.sh`) fetches the `.zip` release, verifies it with
  `sha256sum` from Git Bash, extracts `gop.exe` with `unzip` (or the Windows
  `tar.exe`) and adds its directory to `GITHUB_PATH` in Windows form. The
  reach gate runs `diff-gate.sh` through `bash`, and the baseline lookup
  strips any CR from `gh` output. Steps keep `shell: bash`; self-hosted
  Windows runners need Git for Windows and `gh`. A new `action-smoke` workflow
  (PRs touching `action/`) runs the download step, `gop version` and the gate
  against the latest release on Ubuntu, macOS and Windows, with no enterprise
  credential.
- `docs/github-app-token.md`: creating a read-only GitHub App for gop, what
  each permission unlocks and what goes `not_visible` without it, installing
  it per org, App mode vs minting a token with `actions/create-github-app-token`,
  where to keep the private key, and owner-token vs App coverage. Linked from
  the README's Action section.
- `gop report --previous old.json`: the report opens with a "What changed"
  banner built from `gop diff` (the same summary sentence, the dates, the top
  principal's score delta, and new confirmed, removed, new possible, setting
  and lost-visibility changes with exact counts), each item linking to its
  filtered view or org view. Without `--previous` there is no banner. The
  Action passes `--previous` when `fail-on-reach-increase` downloaded a
  baseline. See `docs/report.md`.
- Accessibility pass on the HTML report: `header`, `nav` and `main`
  landmarks with a skip link, one `h1` and ordered headings, captions and
  `th scope` on every table, a visible keyboard focus, evidence shown as text
  plus an icon (never color alone), WCAG AA contrast checked in light and
  dark themes, and an `aria-live` result count. Tested by parsing the
  rendered HTML (`golang.org/x/net/html`, a new test-only dependency).
- Engine benchmarks on a generated 10k-repo enterprise (`BenchmarkNewIndex`,
  `BenchmarkReach`, `BenchmarkWhoCanReach`, `BenchmarkTopPaths`,
  `BenchmarkSuggestFixes`), run once per CI build as a smoke test.
- Re-collect selected orgs into an existing graph without losing cross-org
  joins: `collect.Merge(base, fresh, orgs)` (and `MergeWith` with a `Force`
  option) replaces everything `base` holds for the re-collected orgs with
  `fresh`'s facts, keeps every other org's nodes and edges as they were
  (including USES edges from their workflows into the re-collected orgs'
  actions), replaces stub repos with real ones, rebuilds RESOLVES_TO, and
  checks the result (declared or inferable endpoints, no duplicate edges).
  `collect.Config.MergeInto` with `Orgs` runs the partial collection against
  the base graph, so cross-org references resolve to its repos and actions
  other orgs use are read again; the result equals a full collection. Merging
  refuses graphs of different enterprises, schemas or hosts, and graphs from
  different token modes unless forced. New optional top-level field
  `org_collected_at` (per-org freshness); a collection fills it for every org
  it collected. The schema version is unchanged. The CLI flag is planned.

### Changed

- `SuggestFixes` (`suggest_fixes`, `fix_plan` and the report's suggested
  fixes) is incremental: the control graph is built once and each candidate
  fix is scored as an overlay of removed edges, counting only confirmed
  repos, recomputing only the principals a fix can affect, and evaluating
  principals in parallel. On the 10k-repo benchmark a budget of 10 takes
  about 1 s on 4 cores (about 27 h before, extrapolated). `WhoCanReach`
  (`who_can_reach`, `gop who`) walks back from the target first and
  traverses forward only from principals that can reach it: about 10 ms
  instead of 4 s. Output is unchanged; property tests check both against the
  previous implementations on 200 generated graphs.

### Fixed

- `fix_plan`, `gop fix-plan --pin`, `gop pin` and the report's "Pinned, still
  reachable" section now use the same `ref_immutable`/`ref_protected` gate as
  reach. A nested tag that is an immutable release (or a protected branch)
  with no matching bypass is no longer reported as a mutable ref ("pin those
  too") or as a pinned exposure, and a locked outer ref counts as pinned. A
  nested ref whose gate is not visible stays listed, labelled "possibly
  mutable (immutability not visible)", and its exposure path is possible.
  `PinnedExposure` gains `via_note`, and `Via` is also set when the path
  enters the nested ref through a `ref_bypass` push.
- Opt-in SARIF output: `gop sarif --graph g.json --out gop.sarif [--top N]
  [--min-severity low|medium|high|critical] [--include-possible]` writes one
  SARIF 2.1.0 result per fixable edge. `GOP001 mutable-action-ref-reachable`
  is one result per `uses:` line of a branch or tag action ref whose host repo
  a principal outside the consuming org can change, located at the consuming
  repo's workflow file and line; `GOP002 default-permission-grants-push` is one
  result per org whose default permission is a `lower_default_perm` candidate,
  with a logical `org:<login>` location. Each result carries confirmed and
  possible principals, terminal counts, evidence, the fix and the share of
  reach it removes; severity follows terminal impact (critical for OIDC or a
  cloud role, high for secrets or self-hosted runners, medium for repo CI).
  Possible-only results are dropped unless `--include-possible`, then
  `level: note`. `partialFingerprints` are stable across runs.
  `--split-by-repo DIR` writes one file per repo. gop never uploads SARIF;
  [docs/sarif.md](docs/sarif.md) warns that code scanning shows the attack
  paths to everyone with alert access on the repo.
- Container image: each release publishes `ghcr.io/peleduri/gop:<version>`
  (and `:latest` for stable releases) for linux/amd64 and linux/arm64, built
  by goreleaser from `gcr.io/distroless/static-debian12:nonroot` pinned by
  digest. The image has no shell, runs as `65532:65532` with `ENTRYPOINT
  ["/gop"]`, and carries OCI labels. The release workflow signs it keyless by
  digest with cosign (same identity as `checksums.txt`), attaches a signed
  SPDX SBOM and pushes SLSA build provenance to the registry. CI checks the
  snapshot images on every PR. See docs/install.md#container.
- `docs/architecture.md`, a contributor guide: package map, a Mermaid data
  flow from the GitHub API to `graph.json` to the MCP tools and report, the
  control-graph rules (a verbatim copy of the comment in
  `internal/graph/reach.go`, kept identical by a test), the invariants every
  change must keep, and checklists for adding a collector, an MCP tool or a
  fix type. CONTRIBUTING links it and explains the labels and the golden
  update flow.
- `.github/labels.yml` describes the label set (type, area, priority, size,
  `good first issue`, `help wanted`, `agent-ready`), and
  `scripts/sync-labels.sh` prints or applies the matching `gh label`
  commands for the maintainer. No workflow writes labels.
- Release notes grouped by change type: `.github/release.yml` categories by label
  (Security, Features, Fixes, Docs, Dependencies), and goreleaser
  `changelog.use: github` groups by conventional commit prefix (`sec`,
  `feat`, `fix`, `docs`). `docs` commits now appear in the notes.
- CI checks PR titles against Conventional Commits (`pr-title` workflow, on
  `pull_request` with only `pull-requests: read`) and every repo-relative
  Markdown link and anchor (lychee, offline).

### Changed

- Graph schema `gop.graph/v2` (breaking): a new evidence level `inferred` for
  facts derived from other observed facts by a documented rule, named in the
  edge's `rule` attribute. Members' push access from an org's default
  permission (`rule=default_perm`) and org owners' admin access to every repo
  (`rule=org_owner`) are now `inferred` instead of `live`; confirmed reach is
  unchanged. gop still loads and validates `gop.graph/v1` graphs (upgraded in
  memory) and rejects a v1 document that uses `inferred`. JSON Schema:
  `schema/gop.graph.v2.schema.json`. Migration notes in `docs/schema.md`.
- `audit` facts now age out: an audit edge older than the maximum audit age
  (half of the new optional `audit_retention_days`, else 90 days; override
  with `graph.Options.MaxAuditAge`) counts as not visible, so it gives
  possible reach only, is never a fix candidate, and its path is marked
  `stale` (text output `[audit, stale]`). `explain` prints the `rule` of an
  inferred edge and `age_days` and `stale` of an audit edge.
- `--github-url` on `gop doctor` and `gop pin` now takes the instance URL
  (`https://HOST`); a REST root ending in `/api/v3` still works.
- `gop diff` refuses snapshots from different GitHub hosts (enterprise
  `host` attribute) without `--force`.
- `gop enrich` matches a cloud OIDC trust only when its issuer is the token
  issuer of the graph's host (`https://token.actions.githubusercontent.com`
  for github.com, `https://HOST/_services/token` for GHES). Graphs without
  `host` match any GitHub issuer, as before.

### Security

- The API client removes the `Authorization` header on any redirect that
  leaves the configured REST or GraphQL scheme and host. `net/http` alone
  keeps it for a subdomain, another port on the same host name, or an
  `https` to `http` downgrade.
- `gop redact --graph g.json --out shareable.json [--salt-file key]
  [--keep-attr k1,k2] [--map-out mapping.json]` pseudonymizes a graph for bug
  reports: orgs, repos, users, teams, actions, workflow files, secret names,
  runner labels, environments and cloud names become stable synthetic names
  (HMAC-SHA256 under the salt; SHAs stay 40-hex, tags become `v1.N`, branches
  `branch-N`, third-party owners `ext-NN`), member, IP allow list and
  Cartography `times_used` counts are bucketed, timestamps (including
  `last_used`) shift by one offset and coverage text is rewritten through the
  same map. Structure, evidence and reach are unchanged: reach
  counts and scores on the redacted graph equal the original's, and it passes
  `gop validate`. Attr keys gop does not define are dropped unless
  `--keep-attr` names them. A self-check fails the run, writing nothing, if an
  original name of 3+ characters is still in the output. The bug report
  template asks for `gop redact` output, never a raw graph.

## [0.3.0] - 2026-11-24

### Added

- Paths out of GitHub: `gop enrich --graph g.json --oidc-trust ./trust/ --out
  g2.json` (and `gop collect --oidc-trust`) reads exported AWS, GCP and Azure
  OIDC trust files offline and adds `workflow -CAN_ASSUME-> cloud:<provider>:<role>`
  where a workflow's token can assume the role, so `who_can_reach`,
  `blast_radius`, the report and `gop who`/`gop paths` show which principals
  reach which cloud roles. Matches come from the file, not the cloud: they
  carry the new evidence `supplied` (counted as confirmed, flagged on the path,
  and every summary names the file). Matches gop cannot decide (branch-scoped
  `sub` with unknown triggers, dynamic environments, unparsed conditions) are
  `not_visible` with a `reason`, so possible reach. Oidc nodes no supplied
  trust matches get a `cloud_trust` coverage entry. Each reached cloud role
  adds 13 to the blast radius score. Re-running with the same files gives a
  byte-identical graph.
- GitHub App mode in the CLI, the Action and `gop doctor`. `gop collect
  --app-id N --app-key-file PATH` (or `GOP_APP_ID` and `GOP_APP_PRIVATE_KEY`)
  mints a read-only installation token per org; it is a usage error (exit 2)
  together with `GITHUB_TOKEN`. The key is read once, never printed, and a key
  file wider than `0600` gets a warning. The Action takes `app-id` and
  `app-private-key` (masked line by line) and prefers them over `token`.
  `gop doctor --app-id/--app-key-file` lists installations, flags `--orgs`
  without one, checks that granted permissions are read-only and complete,
  and predicts what App mode leaves `not_visible`. CI runs actionlint on the
  workflows and the Action.
- Fix types `restrict_token` and `harden_trigger` in `what_if`, `suggest_fixes`
  and `fix_plan` (and `gop fix-plan --restrict-token` / `--harden-trigger`).
  `restrict_token` removes a workflow's `via=token_write` `CAN_PUSH` edges
  (`permissions: contents: read`); its plan says where to set it: a top-level
  block when the jobs take the repo's default, the listed jobs when the file
  grants write. `harden_trigger` removes every `CAN_TRIGGER` edge into a
  workflow; its plan has one step per untrusted execution with the job, line
  and change (drop the head checkout, or move attacker text into `env:`).
  `suggest_fixes` proposes each for workflows with a verified edge. Plan steps
  get an optional `change` field.
- Collector: `CAN_TRIGGER` edges carry `file`, `file_ref` and `line` (the
  checkout's `with.ref`/`with.repository`, or the `run:`/`script:` key).
- Coverage for every skipped fact. A `.github/workflows` that is not a
  directory listing gives `workflows=unknown` (`not_visible`) instead of `0`;
  a `uses:` expression (`${{ matrix.tool }}`) sets `dynamic_uses=<n>` on the
  workflow; a job whose `runs-on` is a custom label, a runner `group:` or an
  expression gets a `not_visible` `EXECUTES_WITH` edge to `runner:<org>/<repo>`
  (`classification=unknown`) instead of none; stub repos for actions outside
  the collected orgs are `not_visible` and get `members:<org> -CAN_PUSH->`
  (`not_visible`, `via=unknown`) or the org's default-permission edge, so
  reach through them is possible instead of zero. Each gets a coverage entry,
  as do archived orgs and orgs whose default permission is not visible.
  `graph.CoverageSummary` counts not_visible nodes, edges, attributes and
  coverage entries per org; the MCP `coverage` tool returns it as `orgs` and
  `gop collect` logs one line per org. `suggest_fixes` and `what_if` carry a
  caveat when a pinned action's nested references are not visible.
- HTML report filters and per-org views. The report embeds the paths, fixes,
  org settings and coverage as one JSON block and a small inline script adds a
  filter bar (evidence, terminal kind, org, principal, action ref kind) whose
  state lives in the URL hash (`#org=acme-app&ev=confirmed&kind=oidc`), plus a
  per-org view at `#/org/<org>` with settings and their evidence (unseen
  settings read "unknown", never "off"), inbound and outbound reach, fixes and
  coverage gaps. A CSP meta tag pins the one style and one script by hash, so
  the file cannot load anything remote. With JavaScript off the report reads as
  before. Embedded paths are capped at 500 per target org, with a note when cut.
- Collector and engine: risky triggers are reach. A workflow on
  `pull_request_target`, `workflow_run`, `issue_comment`, `issues`,
  `pull_request_review(_comment)` or `discussion(_comment)` that checks out
  the pull request's head or interpolates attacker text (`${{
  github.event.comment.body }}`, `github.head_ref`, ...) into a script gets
  `principal -CAN_TRIGGER-> workflow` from whoever can cause the event:
  `external:anyone` (new node kind `external`) for a public repo, every
  collected org's members for an internal one, the org's members for a
  private one when the default permission allows read. Fork triggers also
  need the org to allow private forks; an unreadable setting makes the edge
  `not_visible`. The engine treats `CAN_TRIGGER` as a control hop, so anyone
  on the internet can now reach a public repo's secrets through such a
  workflow. Workflows get `risky_triggers`; plain `pull_request` gets no edge
  (read-only token, no secrets from forks). See docs/schema.md, Triggers.
- `gop pin --action owner/repo@ref` resolves an action ref to its commit SHA
  with read-only GET requests (the commit, then whether the ref is a tag or a
  branch) and prints the pinned `uses:` value. With `--graph`, it reads each
  consuming workflow file and prints a unified diff per file that applies with
  `git apply` (`--repo` for one repo's part, `--offline` for the one-line
  hunks `fix-plan` shows), and warns about mutable refs nested in the action.
  It writes to stdout only, and its HTTP transport refuses any method but GET.
  `gop fix-plan` now points its resolve step at `gop pin`.
- MCP resources `gop://graph/summary` (enterprise, snapshot age, counts by
  node and edge kind, evidence mix, org settings, top 5 principals by
  confirmed score), `gop://graph/coverage`, `gop://graph/schema`
  (docs/schema.md) and the template `gop://node/{+id}` (a node with its in and
  out edges), plus the prompts `triage_enterprise`, `review_action` and
  `explain_path`. Prompt texts live in `internal/mcpserver/prompts/`. A
  snapshot older than 7 days is flagged in the summary and every prompt.
- MCP tool `fix_plan` and `gop fix-plan` turn a fix into concrete change
  steps: for `pin_ref`, one step per consuming workflow or nested action with
  file, line and a one-line diff (a placeholder SHA plus a step to resolve it),
  plus a caveat naming mutable refs the pinned action uses itself; for
  `lower_default_perm`, the setting's UI path and REST call (text only) and the
  repos where members lose push. Steps whose evidence is not visible are marked
  and listed last. Output as text, markdown checklist or JSON. gop never runs
  the steps or calls write APIs.
- `gop doctor --enterprise SLUG [--github-url URL] [--orgs a,b] [--format text|json]`:
  a read-only preflight for `collect`. It detects the token kind and mode
  (a/b/c), checks classic scopes (`X-OAuth-Scopes`), write scopes broader than
  gop needs and a classic token with no expiry, probes up to 100 orgs for
  SAML SSO authorization gaps (`X-GitHub-SSO`), reads `GET /rate_limit`,
  estimates requests and minutes for `collect`, and lists the predicted
  `not_visible` areas, each check with its fix. Exit 0 all pass, 1 any fail,
  3 warnings only. It never prints the token or a header value.
- Collector and engine: a workflow whose `GITHUB_TOKEN` has `contents: write`
  (explicitly, through `write-all`, or by the repo or org default workflow
  permission) controls its repo: `workflow -CAN_PUSH-> repo` with
  `via=token_write`. Whoever controls the workflow now reaches the repo's other
  workflows and the actions it hosts, not only its CI. Workflow nodes get
  `token_write` and `token_scopes`. The default is read from
  `GET /repos/{owner}/{repo}/actions/permissions/workflow`, falling back to the
  org setting (where `read` proves `read`); when neither is visible the edge is
  `not_visible` with a `default_workflow_permissions` coverage entry.
  Workflows are never principals.
- `internal/oidc` parses user-supplied cloud OIDC trust files offline into one
  model (provider, target identity, issuer, audiences, `sub` and other claim
  patterns): AWS IAM role trust policies (`aws iam get-role` / `list-roles`
  output or a bare policy document), GCP workload identity pool providers with
  optional service account IAM policies, and Azure federated identity
  credentials (including flexible `claimsMatchingExpression`). Directories are
  walked for `*.json`. Risky trusts carry warnings: no `sub` condition, wildcard
  owner, no audience check, and any condition that was not fully understood
  (kept as a `cel` pattern and treated as possible). No cloud API calls; the
  graph wiring follows separately.

- OIDC edges (`workflow -EXECUTES_WITH-> oidc`) carry the token claim inputs
  a cloud trust matches on: `jobs` (the jobs that can mint a token),
  `environments` (their `environment:` names, `*dynamic*` for an expression),
  `repository`, `repository_owner`, and `job_workflow_ref` when an id-token job
  calls an enterprise reusable workflow that mints the token. Additive; the
  engine does not read them yet.

### Changed

- OIDC detection follows job-level permissions: a job's own `permissions:`
  replace the workflow-level value, so a workflow with `permissions: write-all`
  whose jobs all set narrower permissions without `id-token: write` no longer
  gets an OIDC edge. The edge's `line` points at the key that grants the
  token (job-level when the job sets it).
- Cross-org `USES` now depends on the Actions access setting of the repo that
  hosts the action. The collector reads
  `GET /repos/{owner}/{repo}/actions/permissions/access` once per private or
  internal repo that hosts a referenced enterprise action, and records
  `actions_access` (`none`, `user`, `organization`, `enterprise`, `public` for
  public repos, or `unknown` (`not_visible`) with a coverage entry when the
  setting is refused). `USES` edges into enterprise actions carry
  `consumer_org`. The engine drops a `USES` hop the setting forbids (for
  example a workflow in `acme-app` using an action in an `acme-actions` repo
  set to `organization`), and makes a cross-org hop `not_visible` (possible,
  not confirmed) when the setting is unknown. Graphs without `actions_access`
  give the same results as before.

## [0.2.0] - 2026-11-23

### Added

- `gop mcp-config --client claude|cursor|vscode --graph PATH` prints the MCP
  client config (or the `claude mcp add` command) with the absolute graph path
  filled in. It only prints; it never writes files.
- Release config for a Homebrew cask in `peleduri/homebrew-tap` (tap coming
  soon). The upload is skipped unless `HOMEBREW_TAP_TOKEN` is set; one-time
  setup in `docs/maintainers.md`.
- `docs/install.md` (Homebrew, release archive, checksum, cosign and
  attestation verification, `go install`) and `docs/mcp-clients.md` (Claude
  Code, Cursor, VS Code and generic stdio snippets).
- Collector: per-org mode when the token cannot read the enterprise (org-scoped
  App installation tokens, non-owner PATs, no `read:enterprise`). Instead of
  failing, gop records an `enterprise` coverage entry, sets the enterprise
  `orgs=unknown`, and collects the `--orgs` list (counted as enterprise orgs)
  or the orgs discovered through `GET /user/orgs` or
  `GET /installation/repositories`. Org settings fall back to `GET /orgs/{org}`
  and members to `GET /orgs/{org}/members`; what neither returns stays
  `not_visible` with one coverage entry per setting at enterprise scope. Action
  owners outside the collected orgs get `in_enterprise=unknown` (`not_visible`)
  and one aggregated coverage entry, never `false`.
- `USES` and `EXECUTES_WITH` edges from workflow files and composite actions
  now carry their source position: `file`, `file_ref` (when known), `line` and,
  on `USES`, `col`. The `explain` summary shows `file:line`. Additive; graphs
  without these attributes still load.
- Collector: `identity:` nodes for every licensed user with `MEMBER_OF` edges,
  and `CAN_PUSH` from org owners (`via=org_owner`), direct collaborators
  (`via=direct`) and outside collaborators (`via=outside_collaborator`) with
  push, including custom repository roles. Repos whose collaborators can't be
  listed get one org-level coverage entry and `not_visible` edges for the
  repo grants listed in the consumed licenses.
- Collector: team grants. `team:<org>/<slug>` identity nodes, child team
  `MEMBER_OF` parent team, direct members `MEMBER_OF` their team, and
  `CAN_PUSH` from team repository grants with push (`via=team`, `permission`
  is the role name, custom roles included). A non-owner token gets a
  `can_push:teams` coverage entry and `teams_partial=true` on the org; a team
  whose member list is refused keeps its grants, gets `members=unknown` and a
  `team_members:<slug>` coverage entry.
- Engine: `Index.ScoringPrincipals()`. Totals in `top_paths`, `what_if` and
  `suggest_fixes` count org members plus identities with their own grants, so
  adding one identity per licensed user does not multiply pair totals.
- JSON Schema (draft 2020-12) for graph.json at
  `schema/gop.graph.v1.schema.json`, and `gop validate --graph graph.json
  [--format text|json]`: checks the schema version, JSON Schema conformance and
  that every edge endpoint is a node, and warns about `not_visible` facts with
  no coverage entry. Exit 0 valid, 1 invalid, 2 usage error.
- `docs/schema.md`: Versioning and Changelog sections.
- `gop diff OLD NEW`: posture drift between two snapshots (paths added,
  removed, upgraded, downgraded or lost to visibility; setting, edge, score and
  coverage changes) as text, Markdown or JSON, with `--only` and `--fail-on
  confirmed-increase|any-new-path` for CI. See `docs/drift.md`.
- `gop demo [--size small|medium|large] [--seed N] [--out graph.json]`:
  generates a deterministic synthetic enterprise graph with no token. It plants
  the cross-org `acme-actions/deploy@main` path, a safe SHA-pinned consumer, the
  nested-action trap (a SHA-pinned composite action that calls a branch ref in
  the same org), one not-visible hop with coverage, and a self-hosted runner.
- `gop serve --demo` and `gop report --demo`; `--graph -` reads the graph from
  stdin for `report`, `paths` and `who` (`gop demo | gop report --graph - --out -`).
- Demo graphs carry `demo=true` on the enterprise node; MCP tool summaries and
  the report title then start with `[demo data]`.
- Report section "Pinned, still reachable": SHA-pinned actions that a principal
  can still change through a nested mutable ref, with one path each.

- Collector and engine: branch protection gates mutable action refs. For
  each enterprise-internal action ref on a branch, gop reads the branch's
  active rules, its classic protection and the protecting rulesets' bypass
  actors, and sets `ref_protected` (`true`, `false`, `unknown`),
  `ref_protection` and `bypass` on the action node. Only pull request reviews
  that can't be reused after a push (stale-approval dismissal or last-push
  approval) and push restrictions count; status checks alone don't. Principals
  that can land code alone get `CAN_PUSH` edges with `via=ref_bypass` and
  `ref=<branch>`. A protected ref no longer lets every pusher to its host repo
  change it: only its bypass principals reach it, and an unreadable protection
  makes the path possible instead of confirmed. Additive; graphs without these
  attributes behave as before.

### Fixed

- The blast-radius multiplier ignores `MEMBER_OF` targets that are not orgs.
- `docs/schema.md`: the reach path example used `org_members:` IDs; the ID
  prefix is `members:`.
- `OrgOf` returns the org of a `team:<org>/<slug>` ID, so team principals get
  their org's blast-radius multiplier.

## [0.1.0] - 2026-11-23

First public version.

### Added

- `gop collect`: read-only collector for a GitHub Enterprise over REST and
  GraphQL. Reads the enterprise's orgs, default repository permission, 2FA and
  SSO policy, org settings (member repo creation, visibility changes, repo
  deletion, private forks, IP allow list), membership counts, repositories and
  workflow files. Derives `CAN_PUSH` from Write/Admin default permissions.
  Parses workflows for the Actions and reusable workflows they use,
  `id-token: write`, secrets and self-hosted runners, and expands composite
  Actions and reusable workflows recursively at the referenced ref (with a
  depth limit). `--orgs` limits collection. Token from `GITHUB_TOKEN` or
  `GH_TOKEN` only, scrubbed from errors. Retries transient errors and waits
  out rate limits.
- Evidence graph schema `gop.graph/v1` (graph.json): every node and edge
  carries `live`, `audit` or `not_visible` evidence and every edge a
  `source_api`; facts the token cannot read are recorded as `not_visible` with
  a `coverage` entry, never as "off".
- Reachability engine: shortest control paths from any principal, with
  confirmed reach (every hop live or audit) kept apart from possible reach (at
  least one not_visible hop). SHA pins block a path only when the whole nested
  Action chain is immutable.
- Blast radius score, top risks, what-if analysis (`pin_ref`,
  `lower_default_perm`) and a greedy fix planner ranked by confirmed
  (principal, repo) pairs removed. Fixes that touch only not_visible edges are
  never suggested.
- `gop serve`: MCP server over stdio with read-only tools `who_can_reach`,
  `blast_radius`, `paths`, `top_risks`, `what_if`, `suggest_fixes`, `explain`
  and `coverage`.
- `gop paths`, `gop who`: the same answers as text in the terminal.
- `gop report`: self-contained HTML or Markdown report with the headline, top
  risks, suggested fixes and top paths. Output files are written with mode
  0600.
- GitHub Action (`action/`) that downloads a release, verifies its checksum and
  (when cosign is present) its signature, runs collect and report, and uploads
  both files with a 1-day default retention.
- Release pipeline: goreleaser builds, keyless cosign signing, SPDX SBOMs, SLSA
  build provenance.
- Synthetic `acme` fixtures, threat model, schema docs.
