# gop: who can make code run where

Enterprise **acme**, collected 2026-11-20T10:00:00Z

> Members of acme-actions can push code that runs in 12 repos across 2 orgs (confirmed), including 1 cloud OIDC trust, 1 secret scope, 1 self-hosted runner pool.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 75% of confirmed reach.

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
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 18 | 75% |
| 2 | Lower the default repository permission of acme-actions to read | 3 | 88% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 1 | 92% |

## Top paths

### identity:bob

- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to secret:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/billing/.github/workflows/ci.yml → secret:acme-app/billing, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to runner:acme-app/worker
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/worker/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/worker/.github/workflows/ci.yml → runner:acme-app/worker, EXECUTES\_WITH, **live**, contents:.github/workflows

### members:acme-actions

- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to secret:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/billing/.github/workflows/ci.yml → secret:acme-app/billing, EXECUTES\_WITH, **live**, contents:.github/workflows
- **confirmed** to runner:acme-app/worker
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/worker/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/worker/.github/workflows/ci.yml → runner:acme-app/worker, EXECUTES\_WITH, **live**, contents:.github/workflows

### identity:alice

- **confirmed** to repo:acme-app/infra
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:alice → repo:acme-app/infra, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators

### members:acme-legacy

- **possible: a hop is not visible** to secret:acme-legacy/old-api
  _Context, not part of the score: target org acme-legacy: SSO not enforced (none), IP allow list unknown_
  1. members:acme-legacy → repo:acme-legacy/old-api, CAN\_PUSH, **not visible**, rest:/orgs/{org}
  2. repo:acme-legacy/old-api → workflow:acme-legacy/old-api/.github/workflows/ci.yml, DEFINED\_IN (reversed), **audit**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-legacy/old-api/.github/workflows/ci.yml → secret:acme-legacy/old-api, EXECUTES\_WITH, **audit**, contents:.github/workflows

## Org settings

| Org | SSO | 2FA | IP allow list | Default permission | Members can create repos | Members can change visibility | Members can delete repos | Members can fork private repos | Members |
|---|---|---|---|---|---|---|---|---|---|
| acme-actions | configured | not\_required | [_unknown_](#why-unknown) | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 40 |
| acme-app | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 120 |
| acme-legacy | none | not\_required | [_unknown_](#why-unknown) | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-secure | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 8 |

### Why unknown

- **acme-actions**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-app**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-legacy**
  - IP allow list: not visible: token is not an org owner. Access that fixes it: org owner on acme-legacy
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-secure**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph

## Repo hardening

Context only: these facts never change evidence, counts or scores. Each cell is repos where it holds / repos with the fact; unknown (not visible to the token) is counted separately, never as off.

| Org | Repos | Protected default branch | Required reviews | CODEOWNERS covers workflows | Secret scanning | Push protection |
|---|---:|---|---|---|---|---|
| acme-actions | 2 | 1/2 | 1/2 | 1/2 | 2/2 | 1/2 |
| acme-app | 1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| acme-legacy | 1 | 0/1 (1 unknown) | 0/1 (1 unknown) | 0/1 (1 unknown) | 0/1 (1 unknown) | 0/1 (1 unknown) |

Repos on the top paths:

- **acme-actions/deploy**: default branch \`main\`: protected (ruleset:7), 1 approval, CODEOWNERS review, force push blocked; CODEOWNERS covers workflows; secret scanning on, push protection on
- **acme-actions/setup**: default branch \`main\`: not protected; no CODEOWNERS; secret scanning on, push protection off
- **acme-app/web**: default branch \`main\`: protected (classic), 2 approvals, force push blocked, admins can bypass; CODEOWNERS does not cover workflows; secret scanning on, push protection off

Hardening suggestions (advisory: not counted as removing confirmed reach):

- Require at least one approving review on the default branch of acme-actions/setup (default branch \`main\` is not protected)
- Enable secret scanning push protection on acme-actions/setup (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/web (secret scanning push protection is off)

## Coverage

| Scope | Not visible | Why | Access that fixes it |
|---|---|---|---|
| org:acme-legacy | repositories | token is not an org owner | org owner on acme-legacy (SAML enforced: join through the IdP first) |
| org:acme-legacy | ip\_allow\_list | token is not an org owner | org owner on acme-legacy |

---

Generated by gop vTEST. This file maps attack paths in your organization. Treat it as sensitive.
