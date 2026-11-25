# Which AI agents and people can make code run where.

gop report: enterprise **acme**, collected 2026-11-20T10:00:00Z

**AI agents and bots:** No non-human actors (AI agents, bot merges, bot accounts) in this graph.

> 4 accounts that own 18 or more orgs can each push code that runs in 54 to 56 repos across 18 to 20 orgs (confirmed), including 3 secret scopes. The cause is standing org ownership: an org owner is admin on every repo of each org it owns.
>
> Remove standing org ownership from 13 accounts that own 5 or more orgs (keep at least 2 owners per org) to remove 62% of confirmed reach.

Confirmed (✓) means every hop was read live (✓), inferred (≈) from other observed facts by a documented rule, or read from a recent audit log entry (↺). Possible (?) means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| 4 owners of 18 to 20 orgs: identity:admin-a, identity:admin-b, identity:admin-c and 1 more | 54 to 56 | 18 to 20 | 0 | 3 | 0 | 0 repos | 139.0 |
| identity:bob | 51 | 17 | 0 | 3 | 0 | 0 repos | 125.5 |
| identity:lead-9 | 18 | 6 | 0 | 3 | 0 | 0 repos | 54.0 |
| identity:lead-3 | 20 | 8 | 0 | 0 | 0 | 0 repos | 46.0 |
| identity:lead-7 | 20 | 8 | 0 | 0 | 0 | 0 repos | 46.0 |
| identity:lead-2 | 21 | 7 | 0 | 0 | 0 | 0 repos | 45.5 |
| identity:lead-6 | 21 | 7 | 0 | 0 | 0 | 0 repos | 45.5 |
| identity:lead-5 | 18 | 6 | 0 | 1 | 0 | 0 repos | 44.0 |
| identity:lead-4 | 15 | 5 | 0 | 2 | 0 | 0 repos | 42.5 |
| identity:lead-1 | 18 | 6 | 0 | 0 | 0 | 0 repos | 39.0 |

Score counts confirmed reach only. A row grouped by cause shows the range of its members' confirmed repos and orgs; its other columns are its first member's. The JSON (`top_risks`) lists each member's own figures.

## Org ownership

88% of confirmed reach depends on standing org ownership: removing every org owner grant would remove 448 of 510 confirmed (principal, repo) pairs.

| Orgs owned | Accounts |
|---|---:|
| 1 org | 2 |
| 2–4 orgs | 10 |
| 5–9 orgs | 9 |
| 10+ orgs | 4 |

25 accounts own at least one org. An org owner is admin on every repo of the org, so an account that owns many orgs can push code that runs across all of them. gop counts owners from org owner grants on repos: an org with no repos shows no owners. The gop://graph/summary resource lists the accounts in each bucket.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Remove standing org ownership from 13 accounts that own 5 or more orgs (keep at least 2 owners per org) | 318 | 62% |
| 2 | Lower the default repository permission of acme-o22 to read | 3 | 63% |
| 3 | Lower the default repository permission of acme-o23 to read | 3 | 64% |

## Top paths

### identity:admin-a, one of 4 owners of 18 to 20 orgs

- **✓ confirmed** to secret:acme-o01/api
  _Context, not part of the score: target org acme-o01: SSO enforced, IP allow list unknown_
  1. identity:admin-a → repo:acme-o01/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o01/api → workflow:acme-o01/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o01/api/.github/workflows/ci.yml → secret:acme-o01/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o02/api
  _Context, not part of the score: target org acme-o02: SSO enforced, IP allow list unknown_
  1. identity:admin-a → repo:acme-o02/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o02/api → workflow:acme-o02/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o02/api/.github/workflows/ci.yml → secret:acme-o02/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o03/api
  _Context, not part of the score: target org acme-o03: SSO enforced, IP allow list unknown_
  1. identity:admin-a → repo:acme-o03/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o03/api → workflow:acme-o03/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o03/api/.github/workflows/ci.yml → secret:acme-o03/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows

### identity:bob

- **✓ confirmed** to secret:acme-o01/api
  _Context, not part of the score: target org acme-o01: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-o01/api, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-o01/api → workflow:acme-o01/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o01/api/.github/workflows/ci.yml → secret:acme-o01/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o02/api
  _Context, not part of the score: target org acme-o02: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-o02/api, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-o02/api → workflow:acme-o02/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o02/api/.github/workflows/ci.yml → secret:acme-o02/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o03/api
  _Context, not part of the score: target org acme-o03: SSO enforced, IP allow list unknown_
  1. identity:bob → repo:acme-o03/api, CAN\_PUSH, ✓ **live**, rest:/repos/{owner}/{repo}/collaborators
  2. repo:acme-o03/api → workflow:acme-o03/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o03/api/.github/workflows/ci.yml → secret:acme-o03/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows

### identity:lead-9

- **✓ confirmed** to secret:acme-o01/api
  _Context, not part of the score: target org acme-o01: SSO enforced, IP allow list unknown_
  1. identity:lead-9 → repo:acme-o01/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o01/api → workflow:acme-o01/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o01/api/.github/workflows/ci.yml → secret:acme-o01/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o02/api
  _Context, not part of the score: target org acme-o02: SSO enforced, IP allow list unknown_
  1. identity:lead-9 → repo:acme-o02/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o02/api → workflow:acme-o02/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o02/api/.github/workflows/ci.yml → secret:acme-o02/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o03/api
  _Context, not part of the score: target org acme-o03: SSO enforced, IP allow list unknown_
  1. identity:lead-9 → repo:acme-o03/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o03/api → workflow:acme-o03/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o03/api/.github/workflows/ci.yml → secret:acme-o03/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows

### identity:lead-3

- **✓ confirmed** to repo:acme-o16/api
  _Context, not part of the score: target org acme-o16: SSO enforced, IP allow list unknown_
  1. identity:lead-3 → repo:acme-o16/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin

### identity:lead-7

- **✓ confirmed** to repo:acme-o13/api
  _Context, not part of the score: target org acme-o13: SSO enforced, IP allow list unknown_
  1. identity:lead-7 → repo:acme-o13/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin

### identity:lead-2

- **✓ confirmed** to repo:acme-o11/api
  _Context, not part of the score: target org acme-o11: SSO enforced, IP allow list unknown_
  1. identity:lead-2 → repo:acme-o11/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin

### identity:lead-6

- **✓ confirmed** to repo:acme-o08/api
  _Context, not part of the score: target org acme-o08: SSO enforced, IP allow list unknown_
  1. identity:lead-6 → repo:acme-o08/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin

### identity:lead-5

- **✓ confirmed** to secret:acme-o03/api
  _Context, not part of the score: target org acme-o03: SSO enforced, IP allow list unknown_
  1. identity:lead-5 → repo:acme-o03/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o03/api → workflow:acme-o03/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o03/api/.github/workflows/ci.yml → secret:acme-o03/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows

### identity:lead-4

- **✓ confirmed** to secret:acme-o01/api
  _Context, not part of the score: target org acme-o01: SSO enforced, IP allow list unknown_
  1. identity:lead-4 → repo:acme-o01/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o01/api → workflow:acme-o01/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o01/api/.github/workflows/ci.yml → secret:acme-o01/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows
- **✓ confirmed** to secret:acme-o02/api
  _Context, not part of the score: target org acme-o02: SSO enforced, IP allow list unknown_
  1. identity:lead-4 → repo:acme-o02/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin
  2. repo:acme-o02/api → workflow:acme-o02/api/.github/workflows/ci.yml, DEFINED\_IN (reversed), ✓ **live**, rest:/repos/{owner}/{repo}/actions/workflows
  3. workflow:acme-o02/api/.github/workflows/ci.yml → secret:acme-o02/api, EXECUTES\_WITH, ✓ **live**, contents:.github/workflows

### identity:lead-1

- **✓ confirmed** to repo:acme-o06/api
  _Context, not part of the score: target org acme-o06: SSO enforced, IP allow list unknown_
  1. identity:lead-1 → repo:acme-o06/api, CAN\_PUSH, ≈ **inferred**, rest:/orgs/{org}/members?role=admin

## Org settings

| Org | SSO | 2FA | IP allow list | Default permission | Members can create repos | Members can change visibility | Members can delete repos | Members can fork private repos | Members |
|---|---|---|---|---|---|---|---|---|---|
| acme-o01 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o02 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o03 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o04 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o05 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o06 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o07 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o08 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o09 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o10 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o11 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o12 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o13 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o14 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o15 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o16 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o17 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o18 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o19 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o20 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o21 | enforced | required | [_unknown_](#why-unknown) | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o22 | enforced | required | [_unknown_](#why-unknown) | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-o23 | enforced | required | [_unknown_](#why-unknown) | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |

### Why unknown

- **acme-o01**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o02**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o03**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o04**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o05**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o06**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o07**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o08**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o09**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o10**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o11**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o12**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o13**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o14**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o15**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o16**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o17**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o18**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o19**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o20**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o21**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o22**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-o23**
  - IP allow list, Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph

## Coverage

Every fact gop looked for was visible to the token.

---

Generated by gop v0.0.0-test. This file maps attack paths in your organization. Treat it as sensitive.
