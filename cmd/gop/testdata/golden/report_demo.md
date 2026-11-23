# [demo data] gop: who can make code run where

Enterprise **acme**, collected 2026-01-01T00:00:00Z

> Members of acme-actions can push code that runs in 34 repos across 4 orgs (confirmed), including 4 cloud OIDC trusts, 6 secret scopes, 1 self-hosted runner pool.
>
> Lower the default repository permission of acme-actions to read to remove 59% of confirmed reach.
>
> Pinning is not enough: 1 action pinned to a commit SHA still runs a mutable ref that someone can push to.

Confirmed means every hop was read live or from the audit log. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| identity:bob | 34 | 4 | 4 | 6 | 1 | 0 repos | 273.4 |
| members:acme-actions | 34 | 4 | 4 | 6 | 1 | 0 repos | 273.4 |
| identity:user-020 | 1 | 1 | 0 | 1 | 0 | 0 repos | 8.5 |
| identity:user-005 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-006 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-012 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-013 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-018 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:alice | 1 | 1 | 0 | 0 | 0 | 0 repos | 3.5 |
| identity:user-001 | 1 | 1 | 0 | 0 | 0 | 0 repos | 3.5 |

Score counts confirmed reach only.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Lower the default repository permission of acme-actions to read | 47 | 59% |
| 2 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 16 | 79% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 4 | 84% |

## Pinned, still reachable

A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:

- **acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5** (used by 4 workflows) runs **acme-actions/setup@main**. members:acme-actions can change it (confirmed):
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **live**, demo:default-perm
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action

## Top paths

### identity:bob

- **confirmed** to oidc:acme-app/payments
  1. identity:bob → members:acme-actions, MEMBER\_OF, **live**, demo:membership
  2. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **live**, demo:default-perm
  3. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  4. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  5. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-app/payments/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  6. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action
- **confirmed** to oidc:acme-app/web
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, demo:collaborator
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, demo:planted-cross-org
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org
- **confirmed** to oidc:acme-secure/signer
  1. identity:bob → members:acme-actions, MEMBER\_OF, **live**, demo:membership
  2. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **live**, demo:default-perm
  3. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  4. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  5. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-secure/signer/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  6. workflow:acme-secure/signer/.github/workflows/release.yml → oidc:acme-secure/signer, EXECUTES\_WITH, **live**, demo:planted-nested-action

### members:acme-actions

- **confirmed** to oidc:acme-app/payments
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **live**, demo:default-perm
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  4. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-app/payments/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  5. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action
- **confirmed** to oidc:acme-app/web
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **live**, demo:default-perm
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, demo:planted-cross-org
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org
- **confirmed** to oidc:acme-secure/signer
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **live**, demo:default-perm
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  4. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-secure/signer/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  5. workflow:acme-secure/signer/.github/workflows/release.yml → oidc:acme-secure/signer, EXECUTES\_WITH, **live**, demo:planted-nested-action

### identity:user-020

- **confirmed** to secret:acme-org-01/svc-009
  1. identity:user-020 → repo:acme-org-01/svc-009, CAN\_PUSH, **live**, demo:collaborator
  2. repo:acme-org-01/svc-009 → workflow:acme-org-01/svc-009/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-01/svc-009/.github/workflows/ci.yml → secret:acme-org-01/svc-009, EXECUTES\_WITH, **live**, demo:secrets

### identity:user-005

- **confirmed** to repo:acme-app/sandbox
  1. identity:user-005 → repo:acme-app/sandbox, CAN\_PUSH, **live**, demo:collaborator

### identity:user-006

- **confirmed** to repo:acme-org-01/svc-003
  1. identity:user-006 → repo:acme-org-01/svc-003, CAN\_PUSH, **live**, demo:collaborator

### identity:user-012

- **confirmed** to repo:acme-secure/svc-005
  1. identity:user-012 → repo:acme-secure/svc-005, CAN\_PUSH, **live**, demo:collaborator

### identity:user-013

- **confirmed** to repo:acme-app/mobile
  1. identity:user-013 → repo:acme-app/mobile, CAN\_PUSH, **live**, demo:collaborator

### identity:user-018

- **confirmed** to repo:acme-org-01/svc-005
  1. identity:user-018 → repo:acme-org-01/svc-005, CAN\_PUSH, **live**, demo:collaborator

### identity:alice

- **confirmed** to repo:acme-app/infra
  1. identity:alice → repo:acme-app/infra, CAN\_PUSH, **live**, demo:collaborator

### identity:user-001

- **confirmed** to repo:acme-app/search
  1. identity:user-001 → repo:acme-app/search, CAN\_PUSH, **live**, demo:collaborator

## Org settings

| Org | Default permission | 2FA | SSO | IP allow list | Members |
|---|---|---|---|---|---|
| acme-actions | write | not\_required | configured | off | 40 |
| acme-app | read | required | enforced | off | 120 |
| acme-legacy | write | not\_required | none | _not visible_ | _unknown_ |
| acme-org-01 | read | not\_required | enforced | off | 40 |
| acme-secure | read | required | enforced | on | 8 |

## Coverage

| Scope | Not visible | Why | Access that fixes it |
|---|---|---|---|
| org:acme-legacy | repositories | token is not an org owner | org owner on acme-legacy (SAML enforced: join through the IdP first) |
| org:acme-legacy | ip\_allow\_list | token is not an org owner | org owner on acme-legacy |

---

Generated by gop dev. This file maps attack paths in your organization. Treat it as sensitive.
