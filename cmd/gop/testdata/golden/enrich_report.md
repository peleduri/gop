# gop: who can make code run where

Enterprise **acme**, collected 2026-11-20T10:00:00Z

> Members of acme-actions can push code that runs in 12 repos across 2 orgs (confirmed), including 1 cloud role, 1 cloud OIDC trust, 1 secret scope, 1 self-hosted runner pool. Cloud hops from supplied trust files testdata/acme/trust/aws/deploy.json, not read from the cloud.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 72% of confirmed reach.

Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry, or (a cloud hop) from a supplied file: a cloud trust policy you supplied, not read from the cloud. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | Cloud roles | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| identity:bob | 12 | 2 | 1 | 1 | 1 | 1 | 0 repos + 3 impact | 115.9 |
| members:acme-actions | 12 | 2 | 1 | 1 | 1 | 1 | 0 repos + 3 impact | 115.9 |
| identity:alice | 1 | 1 | 0 | 0 | 0 | 0 | 0 repos | 3.5 |

Score counts confirmed reach only.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 18 | 72% |
| 2 | Lower the default repository permission of acme-actions to read | 4 | 88% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 1 | 92% |

## Top paths

### identity:bob

- **confirmed** to cloud:aws:arn:aws:iam::111111111111:role/deploy
  _cloud hop from supplied trust file testdata/acme/trust/aws/deploy.json, not read from the cloud_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/release.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/release.yml → cloud:aws:arn:aws:iam::111111111111:role/deploy, CAN\_ASSUME, **supplied file**, supplied:testdata/acme/trust/aws/deploy.json
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
- **possible: a hop is not visible** to cloud:azure:app:11111111-1111-1111-1111-111111111111
  _cloud hop from supplied trust file testdata/acme/trust/azure/web-main.json, not read from the cloud_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → cloud:azure:app:11111111-1111-1111-1111-111111111111, CAN\_ASSUME, **not visible**, supplied:testdata/acme/trust/azure/web-main.json
     undecided: the ref in sub is not known: gop does not read workflow triggers, so a branch-, tag- or pull\_request-scoped sub may or may not match

### members:acme-actions

- **confirmed** to cloud:aws:arn:aws:iam::111111111111:role/deploy
  _cloud hop from supplied trust file testdata/acme/trust/aws/deploy.json, not read from the cloud_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/release.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/release.yml → cloud:aws:arn:aws:iam::111111111111:role/deploy, CAN\_ASSUME, **supplied file**, supplied:testdata/acme/trust/aws/deploy.json
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
- **possible: a hop is not visible** to cloud:azure:app:11111111-1111-1111-1111-111111111111
  _cloud hop from supplied trust file testdata/acme/trust/azure/web-main.json, not read from the cloud_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, rest:/orgs/{org}
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → cloud:azure:app:11111111-1111-1111-1111-111111111111, CAN\_ASSUME, **not visible**, supplied:testdata/acme/trust/azure/web-main.json
     undecided: the ref in sub is not known: gop does not read workflow triggers, so a branch-, tag- or pull\_request-scoped sub may or may not match

### identity:alice

- **confirmed** to repo:acme-app/infra
  1. identity:alice → repo:acme-app/infra, CAN\_PUSH, **live**, rest:/repos/{owner}/{repo}/collaborators

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
| oidc:acme-secure/vault | cloud\_trust | no supplied trust policy matches a token this repo's workflows can mint | supply the trust policy for the cloud role this workflow assumes |

---

Generated by gop vTEST. This file maps attack paths in your organization. Treat it as sensitive.
