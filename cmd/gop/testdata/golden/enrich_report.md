# Which AI agents and people can make code run where.

gop report: enterprise **acme**, collected 2026-11-20T10:00:00Z

**AI agents and bots:** No non-human actors (AI agents, bot merges, bot accounts) in this graph.

> Members of acme-actions can push code that runs in 12 repos across 2 orgs (confirmed), including 1 cloud role, 1 cloud OIDC trust, 1 secret scope, 1 self-hosted runner pool. Cloud hops from supplied trust files testdata/acme/trust/aws/deploy.json, not read from the cloud.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 75% of confirmed reach.

**AI agents in CI:** No workflow in this graph looks like an AI agent (gop looks for known agent actions and CLIs, and for agent-like names), so there is no agent funnel to draw.

**Also:** bots merge with no human: 0 confirmed, 0 possible; action refs with a known advisory: 0 affected, 0 unknown, 4 total; orgs gop could see: 2 fully, 2 partly.

Confirmed (✓) means every hop was read live (✓), inferred (≈) from other observed facts by a documented rule, or read from a recent audit log entry (↺), or (a cloud hop) from a supplied file (≡): a cloud trust policy you supplied, not read from the cloud. Possible (?) means at least one hop is not visible to the token: unknown, not absent.

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
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 18 | 75% |
| 2 | Lower the default repository permission of acme-actions to read | 3 | 88% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 1 | 92% |

## Top paths

### identity:bob

- **✓ confirmed** to cloud:aws:arn:aws:iam::111111111111:role/deploy
  _cloud hop from supplied trust file testdata/acme/trust/aws/deploy.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/release.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/release.yml → cloud:aws:arn:aws:iam::111111111111:role/deploy, CAN\_ASSUME, ≡ **supplied file**, supplied:testdata/acme/trust/aws/deploy.json
- **✓ confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/ci.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/billing/.github/workflows/ci.yml → secret:acme-app/billing, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **? possible: a hop is not visible** to cloud:azure:app:11111111-1111-1111-1111-111111111111
  _cloud hop from supplied trust file testdata/acme/trust/azure/web-main.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → cloud:azure:app:11111111-1111-1111-1111-111111111111, CAN\_ASSUME, ? **not visible**, supplied:testdata/acme/trust/azure/web-main.json
     undecided: the ref in sub is not known: gop does not read workflow triggers, so a branch-, tag- or pull\_request-scoped sub may or may not match

### members:acme-actions

- **✓ confirmed** to cloud:aws:arn:aws:iam::111111111111:role/deploy
  _cloud hop from supplied trust file testdata/acme/trust/aws/deploy.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/release.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/release.yml → cloud:aws:arn:aws:iam::111111111111:role/deploy, CAN\_ASSUME, ≡ **supplied file**, supplied:testdata/acme/trust/aws/deploy.json
- **✓ confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/ci.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/billing/.github/workflows/ci.yml → secret:acme-app/billing, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **? possible: a hop is not visible** to cloud:azure:app:11111111-1111-1111-1111-111111111111
  _cloud hop from supplied trust file testdata/acme/trust/azure/web-main.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}
     note: push needs 1 approval to reach \`main\` + CODEOWNERS on workflows
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), ✓ **live**, contents:.github/workflows
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), ✓ **live**, contents:.github/workflows
  4. workflow:acme-app/web/.github/workflows/ci.yml → cloud:azure:app:11111111-1111-1111-1111-111111111111, CAN\_ASSUME, ? **not visible**, supplied:testdata/acme/trust/azure/web-main.json
     undecided: the ref in sub is not known: gop does not read workflow triggers, so a branch-, tag- or pull\_request-scoped sub may or may not match

### identity:alice

- **✓ confirmed** to repo:acme-app/infra
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list unknown_
  1. identity:alice → repo:acme-app/infra, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators

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
| oidc:acme-secure/vault | cloud\_trust | no supplied trust policy matches a token this repo's workflows can mint | supply the trust policy for the cloud role this workflow assumes |

---

Generated by gop vTEST. This file maps attack paths in your organization. Treat it as sensitive.
