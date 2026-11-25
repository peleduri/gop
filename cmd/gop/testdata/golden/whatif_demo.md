## What if

[demo data] confirmed (principal, repo) pairs: 394 -> 360 (9% removed); possible pairs: 11 -> 11

> Hypothetical: gop changed nothing. gop fix-plan prints the steps of one fix.

### Fixes applied

- `default_perm:org:acme-actions-&gt;read`: Lower the default repository permission of acme-actions to read

### Totals

| | Before | After |
|---|---:|---:|
| confirmed (principal, repo) pairs | 394 | 360 |
| possible (principal, repo) pairs | 11 | 11 |
| confirmed score | 3437.4 | 3107.8 |
| possible score | 41.6 | 41.6 |

### Paths that disappear (99, showing 10)

| Principal | Target | Change | Path before |
|---|---|---|---|
| `identity:bob` | `oidc:acme-app/payments` | confirmed -> gone | `identity:bob` -> `members:acme-actions` -> `repo:acme-actions/setup` -> `action:acme-actions/setup@main` -> `action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5` -> `workflow:acme-app/payments/.github/workflows/release.yml` -> `oidc:acme-app/payments` |
| `identity:bob` | `oidc:acme-secure/signer` | confirmed -> gone | `identity:bob` -> `members:acme-actions` -> `repo:acme-actions/setup` -> `action:acme-actions/setup@main` -> `action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5` -> `workflow:acme-secure/signer/.github/workflows/release.yml` -> `oidc:acme-secure/signer` |
| `members:acme-actions` | `oidc:acme-app/payments` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/setup` -> `action:acme-actions/setup@main` -> `action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5` -> `workflow:acme-app/payments/.github/workflows/release.yml` -> `oidc:acme-app/payments` |
| `members:acme-actions` | `oidc:acme-app/web` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-app/web/.github/workflows/ci.yml` -> `oidc:acme-app/web` |
| `members:acme-actions` | `oidc:acme-org-01/svc-007` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-org-01/svc-007/.github/workflows/ci.yml` -> `oidc:acme-org-01/svc-007` |
| `members:acme-actions` | `oidc:acme-org-03/svc-007` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-org-03/svc-007/.github/workflows/ci.yml` -> `oidc:acme-org-03/svc-007` |
| `members:acme-actions` | `oidc:acme-org-03/svc-008` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/deploy` -> `action:acme-actions/deploy@main` -> `workflow:acme-org-03/svc-008/.github/workflows/ci.yml` -> `oidc:acme-org-03/svc-008` |
| `members:acme-actions` | `oidc:acme-secure/signer` | confirmed -> gone | `members:acme-actions` -> `repo:acme-actions/setup` -> `action:acme-actions/setup@main` -> `action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5` -> `workflow:acme-secure/signer/.github/workflows/release.yml` -> `oidc:acme-secure/signer` |
| `identity:bob` | `secret:acme-actions/svc-006` | confirmed -> gone | `identity:bob` -> `members:acme-actions` -> `repo:acme-actions/svc-006` -> `workflow:acme-actions/svc-006/.github/workflows/ci.yml` -> `secret:acme-actions/svc-006` |
| `identity:bob` | `secret:acme-actions/svc-009` | confirmed -> gone | `identity:bob` -> `members:acme-actions` -> `repo:acme-actions/svc-009` -> `workflow:acme-actions/svc-009/.github/workflows/ci.yml` -> `secret:acme-actions/svc-009` |

### Remaining top paths

| # | Principal | Score | Confirmed repos | Possible repos | Remaining path |
|---:|---|---:|---:|---:|---|
| 1 | `external:anyone` | 53.5 -> 53.5 | 3 -> 3 | 0 -> 0 | `external:anyone` -> `workflow:acme-app/api/.github/workflows/claude-fix.yml` -> `cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy` |
| 2 | `identity:carol` | 531.0 -> 531.0 | 55 -> 55 | 0 -> 0 | `identity:carol` -> `repo:acme-app/api` -> `workflow:acme-app/api/.github/workflows/claude-fix.yml` -> `cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy` |
| 3 | `identity:dave` | 531.0 -> 531.0 | 55 -> 55 | 0 -> 0 | `identity:dave` -> `repo:acme-app/api` -> `workflow:acme-app/api/.github/workflows/claude-fix.yml` -> `cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy` |
