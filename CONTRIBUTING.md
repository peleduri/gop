# Contributing

Thanks for helping. gop is small and opinionated: read-only, no telemetry, and every fact carries an evidence level.

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
