## What if

confirmed (principal, repo) pairs: 24 -> 24 (0% removed); possible pairs: 1 -> 1

> Hypothetical: gop changed nothing. gop fix-plan prints the steps of one fix.

### Fixes applied

- `restrict_token:workflow:acme-app/web/.github/workflows/ci.yml`: Set permissions: contents: read on the GITHUB_TOKEN of acme-app/web/.github/workflows/ci.yml

### Totals

| | Before | After |
|---|---:|---:|
| confirmed (principal, repo) pairs | 24 | 24 |
| possible (principal, repo) pairs | 1 | 1 |
| confirmed score | 174.5 | 172.2 |
| possible score | 19.1 | 19.1 |

### Paths that disappear (2)

| Principal | Target | Change | Path before |
|---|---|---|---|
| `identity:bob` | `workflow:acme-app/web/.github/workflows/nightly.yml` | confirmed -> gone | `identity:bob` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-app/web/.github/workflows/ci.yml` -> `repo:acme-app/web` -> `workflow:acme-app/web/.github/workflows/nightly.yml` |
| `members:acme-actions` | `workflow:acme-app/web/.github/workflows/nightly.yml` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-app/web/.github/workflows/ci.yml` -> `repo:acme-app/web` -> `workflow:acme-app/web/.github/workflows/nightly.yml` |

### Remaining top paths

| # | Principal | Score | Confirmed repos | Possible repos | Remaining path |
|---:|---|---:|---:|---:|---|
| 1 | `identity:bob` | 86.6 -> 85.5 | 12 -> 12 | 0 -> 0 | `identity:bob` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-app/web/.github/workflows/ci.yml` -> `oidc:acme-app/web` |
| 2 | `members:acme-actions` | 86.6 -> 85.5 | 12 -> 12 | 0 -> 0 | `members:acme-actions` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-app/web/.github/workflows/ci.yml` -> `oidc:acme-app/web` |
| 3 | `identity:alice` | 3.5 -> 3.5 | 1 -> 1 | 0 -> 0 | `identity:alice` -> `repo:acme-app/infra` |
| 4 | `members:acme-legacy` | 0.0 -> 0.0 | 0 -> 0 | 1 -> 1 | none confirmed |
