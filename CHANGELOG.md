# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Before v1.0 the graph schema and CLI
flags may change in minor releases.

## [Unreleased]

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
