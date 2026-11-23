# gop: who can make code run where

Enterprise **acme**, collected 2026-11-20T10:00:00Z

> Members of acme-actions can push code that runs in 12 repos across 2 orgs (confirmed), including 1 cloud OIDC trust, 1 secret scope, 1 self-hosted runner pool.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 72% of confirmed reach.

Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| identity:bob | 12 | 2 | 1 | 1 | 1 | 0 repos | 86.6 |
| members:acme-actions | 12 | 2 | 1 | 1 | 1 | 0 repos | 86.6 |
| identity:alice | 1 | 1 | 0 | 0 | 0 | 0 repos | 3.5 |
| members:acme-legacy | 0 | 0 | 0 | 0 | 0 | 1 repo + 1 impact | 0.0 |
| members:acme-app | 0 | 0 | 0 | 0 | 0 | 0 repos | 0.0 |
| members:acme-secure | 0 | 0 | 0 | 0 | 0 | 0 repos | 0.0 |

Score counts confirmed reach only.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 18 | 72% |
| 2 | Lower the default repository permission of acme-actions to read | 4 | 88% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 1 | 92% |

## Top paths

### identity:bob

- **confirmed** to oidc:acme-app/web
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to secret:acme-app/billing
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/billing/.github/workflows/ci.yml → secret:acme-app/billing, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to runner:acme-app/worker
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/worker/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/worker/.github/workflows/ci.yml → runner:acme-app/worker, EXECUTES\_WITH, **live**, contents:.github/workflows

### members:acme-actions

- **confirmed** to oidc:acme-app/web
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to secret:acme-app/billing
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/billing/.github/workflows/ci.yml → secret:acme-app/billing, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to runner:acme-app/worker
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/worker/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/worker/.github/workflows/ci.yml → runner:acme-app/worker, EXECUTES\_WITH, **live**, contents:.github/workflows

### identity:alice

- **confirmed** to repo:acme-app/infra
  1. identity:alice → repo:acme-app/infra, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators

### members:acme-legacy

- **possible: a hop is not visible** to secret:acme-legacy/old-api
  1. members:acme-legacy → repo:acme-legacy/old-api, CAN\_PUSH, **not visible**, rest:/orgs/{org}
  2. repo:acme-legacy/old-api → workflow:acme-legacy/old-api/.github/workflows/ci.yml, DEFINED\_IN (reversed), **audit**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-legacy/old-api/.github/workflows/ci.yml → secret:acme-legacy/old-api, EXECUTES\_WITH, **audit**, contents:.github/workflows

## Org settings

| Org | Default permission | 2FA | SSO | IP allow list | Members |
|---|---|---|---|---|---|
| acme-actions | write | not\_required | configured | _unknown_ | 40 |
| acme-app | read | required | enforced | _unknown_ | 120 |
| acme-legacy | write | not\_required | none | _not visible_ | _unknown_ |
| acme-secure | read | required | enforced | _unknown_ | 8 |

## Coverage

| Scope | Not visible | Why | Access that fixes it |
|---|---|---|---|
| org:acme-legacy | repositories | token is not an org owner | org owner on acme-legacy (SAML enforced: join through the IdP first) |
| org:acme-legacy | ip\_allow\_list | token is not an org owner | org owner on acme-legacy |

---

Generated by gop vTEST. This file maps attack paths in your organization. Treat it as sensitive.
