# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Before v1.0 the graph schema and CLI
flags may change in minor releases.

## [Unreleased]

## [0.1.0] - unreleased

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
