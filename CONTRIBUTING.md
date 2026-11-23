# Contributing

Thanks for helping. gop is small and opinionated: read-only, no telemetry, and every fact carries an evidence level.

## Dev setup

- Go version from `go.mod`
- Optional: `golangci-lint`, `govulncheck`, `goreleaser`, `actionlint`

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

Golden files under `testdata/golden/` pin the exact text of MCP tool output, `gop who` / `gop paths` and the report. If output changes on purpose, run `go test ./... -update` and commit the golden diff.

CI runs the same checks. The leak check uses a private denylist that CI holds as a secret; it is skipped on PRs from forks, and the maintainer runs it before merge.

## Synthetic data only

This is a public repository. Fixtures, tests, examples, docs, issues and commit messages use only synthetic names: enterprise `acme`, orgs `acme-actions`, `acme-app` (and other `acme-*` names). Never commit a real graph.json, a real org, repo, user or company name, or a token, even redacted. Build fixtures by hand under `testdata/`.

## Design rules

- No write calls to GitHub.
- Every node and edge gets an evidence level (`live`, `audit`, `not_visible`) and edges get a `source_api`. When the token cannot read something, record `not_visible` and a `coverage` entry; never default to "off".
- Breaking changes to the serialized graph bump `SchemaVersion` and update `docs/schema.md`.

## Sign-off (DCO)

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This adds `Signed-off-by: Your Name <you@example.com>` and certifies you have the right to submit the change under the project's license (Apache-2.0).

## Pull requests

Keep PRs focused, fill in the PR template checklist, and update docs when behavior changes. Report security issues through [SECURITY.md](SECURITY.md), not PRs.
