# Contributing

Thanks for helping. gop is small and opinionated: read-only, no telemetry, and every fact carries an evidence level.

How the project is run is in [GOVERNANCE.md](GOVERNANCE.md); the maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md), and the direction is in [ROADMAP.md](ROADMAP.md). Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

Start with [docs/architecture.md](docs/architecture.md): the package map, how data flows from the GitHub API to `graph.json` to the MCP tools and report, the control-graph rules, the invariants every change must keep, and checklists for adding a collector, an MCP tool or a fix type.

## Finding something to work on

Issues carry labels for type, area, priority and size. The full set, with descriptions, is in [.github/labels.yml](.github/labels.yml).

- **`good first issue`**: small and well scoped, and you do not need to know the whole evidence model to do it. The issue says which files to touch. Comment that you are taking it and the maintainer will help if you get stuck.
- **`help wanted`**: the maintainer would welcome a PR, but it may need more context or design. Ask questions on the issue before you start.
- **`agent-ready`**: the spec is complete (what to build, acceptance criteria, test plan), so it can be implemented without more design, by a person or a coding agent.
- **Size** (`S`, `M`, `L`) is a rough effort estimate; **priority** (`p0`, `p1`, `p2`) is the order the maintainer plans to take them in. Area labels (`collector`, `engine`, `mcp`, `report`, `cli`, ...) name the package it touches.

## Dev setup

- Go version from `go.mod`
- Optional: `golangci-lint`, `govulncheck`, `goreleaser`, `actionlint`, `lychee`

```sh
git clone https://github.com/peleduri/gop && cd gop
go build ./cmd/gop
```

## Tests

```sh
go vet ./...
go test ./... -race -count=1
golangci-lint run
govulncheck ./...
./scripts/leak-check.sh
```

New functionality and bug fixes come with tests in the same pull request: a unit or golden test for new behaviour, and a test that fails without the fix for a bug. Collector changes are tested against the httptest fake GitHub, never the real API. A pull request that adds a feature without tests is not merged.

The agent-behaviour eval in `evals/` (Python, outside the Go module) has a deterministic part that needs no model: `pip install -r evals/requirements-dry.txt`, then `pytest evals` and `python -m evals.run --dry`. CI runs both. See [docs/evals.md](docs/evals.md) for the live run.

### Golden files

Golden files under `testdata/golden/` (in `cmd/gop`, `internal/collect`, `internal/mcpserver`, `internal/report` and `internal/fixplan`) pin the exact output of MCP tools, `gop who` / `gop paths`, `gop collect` against the fake GitHub, and the report. Output is deterministic, so a golden only changes when your code changes what gop prints. When it changes on purpose:

1. Run `go test ./... -update` (or `go test ./internal/mcpserver -update` for one package). This rewrites the goldens instead of comparing.
2. Read the diff (`git diff -- '*testdata/golden*'`). Every changed line should follow from your change; anything else is a bug or nondeterminism.
3. Run `go test ./... -race -count=1` without `-update` and commit the goldens in the same commit as the code.

Never edit a golden by hand, and never run `-update` to make an unexplained failure go away.

### Docs

`docs/architecture.md` holds a verbatim copy of the control-graph rules comment in `internal/graph/reach.go`; `go test ./docs` fails when they differ. CI also checks every repo-relative link and anchor in the Markdown files; run it locally with [lychee](https://lychee.cli.rs/): `lychee --offline --include-fragments './**/*.md'`.

CI runs the same checks. The leak check uses a private denylist that CI holds as a secret; it is skipped on PRs from forks, and the maintainer runs it before merge.

## Synthetic data only

This is a public repository. Fixtures, tests, examples, docs, issues and commit messages use only synthetic names: enterprise `acme`, orgs `acme-actions`, `acme-app` (and other `acme-*` names). Never commit a real graph.json, a real org, repo, user or company name, or a token, even redacted. Build fixtures by hand under `testdata/`.

## Design rules

- No write calls to GitHub.
- Every node and edge gets an evidence level (`live`, `inferred` with an `attrs.rule` for facts derived by a documented rule, `audit`, `not_visible`) and edges get a `source_api`. When the token cannot read something, record `not_visible` and a `coverage` entry; never default to "off".
- Breaking changes to the serialized graph bump `SchemaVersion` and update `docs/schema.md`.

## Sign-off (DCO)

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This adds `Signed-off-by: Your Name <you@example.com>` and certifies you have the right to submit the change under the project's license (Apache-2.0).

## Pull requests

Keep PRs focused, fill in the PR template checklist, and update docs when behavior changes.

PR titles follow [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<area>): <imperative summary>`, for example `feat(collect): read environment protection rules`. A CI check enforces it. Allowed types: `feat`, `fix`, `sec`, `docs`, `perf`, `refactor`, `test`, `ci`, `build`, `chore`, `revert`, `release`. PRs are squash-merged with the title as the commit message, and release notes are grouped by type (Security for `sec`, Features for `feat`, Fixes for `fix`, Docs for `docs`), so pick the type a user would look for. Report security issues through [SECURITY.md](SECURITY.md), not PRs.

## Contributor ladder

gop's roles, adapted from the [CNCF contributor ladder template](https://github.com/cncf/project-template/blob/main/CONTRIBUTOR_LADDER.md). Each role keeps the rights of the ones before it. You move up by doing the work of the next role, then asking (or being asked); nothing here depends on your employer.

### Participant

Anyone who uses gop, opens an issue (an "I ran gop" report, a false positive, a bug, a feature request), answers a question in Discussions, or comments on a pull request. No requirements beyond the [code of conduct](CODE_OF_CONDUCT.md).

### Contributor

Anyone with at least one merged pull request: code, tests, docs, fixtures or CI. Contributors are expected to follow this guide (sign-off, synthetic data only, design rules) and to respond to review on their pull requests. Contributors can be assigned issues and are credited in the release notes through their pull request titles.

### Reviewer

A contributor trusted to review pull requests in one or more areas (for example `collector`, `engine`, `report`, `mcp`, docs). Reviewers' approvals count toward merging, and they help triage issues in their area.

- Requirements: several non-trivial merged pull requests over at least two months, and reviews on other people's pull requests that show they know the evidence model and the design rules.
- How: nominate yourself or be nominated on an issue; a maintainer approves. Reviewers are listed by area in [.github/CODEOWNERS](.github/CODEOWNERS) once the project has any.

### Maintainer

Maintainers merge pull requests, cut releases, handle security and conduct reports, hold the project's accounts and set direction, as described in [GOVERNANCE.md](GOVERNANCE.md#maintainers).

- Requirements: active as a reviewer (or equivalent sustained contribution) for at least three months; a track record of quality code or docs across more than one area; reviews of at least 10 non-trivial pull requests; an understanding of the release, signing and security processes in [docs/maintainers.md](docs/maintainers.md) and [SECURITY.md](SECURITY.md); and willingness to take on the project's credentials responsibly.
- How: nomination and approval as described in [GOVERNANCE.md](GOVERNANCE.md#adding-a-maintainer). See also [Becoming a maintainer](MAINTAINERS.md#becoming-a-maintainer).

### Stepping down and inactivity

Anyone can step back from a role at any time; maintainers move to the emeritus list in [MAINTAINERS.md](MAINTAINERS.md). Reviewers and maintainers who are inactive for 12 months are asked whether they want to stay, and are moved back a step (or to emeritus) if they do not reply within 30 days. Removal for cause follows [GOVERNANCE.md](GOVERNANCE.md#removing-a-maintainer).
