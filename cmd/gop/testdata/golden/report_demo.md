# [demo data] gop: who can make code run where

Enterprise **acme**, collected 2026-01-01T00:00:00Z

> acme-oss/checkout-ish@v2, a version with a known advisory (GHSA-acme-demo-0001; severity critical; fixed in 2.4.1), runs in 1 repo across 1 org (confirmed), including 1 secret scope.
>
> Lower the default repository permission of acme-actions to read to remove 50% of confirmed reach.
>
> Pinning is not enough: 1 action pinned to a commit SHA still runs a mutable ref that someone can push to.

Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| action:acme-oss/checkout-ish@v2 (known advisory: GHSA-acme-demo-0001; severity critical; fixed in 2.4.1) | 1 | 1 | 0 | 1 | 0 | 0 repos | 8.5 |
| external:anyone | 1 | 1 | 0 | 1 | 0 | 0 repos | 9.5 |
| identity:bob | 34 | 4 | 4 | 6 | 1 | 0 repos | 273.4 |
| members:acme-actions | 34 | 4 | 4 | 6 | 1 | 0 repos | 273.4 |
| identity:user-020 | 1 | 1 | 0 | 1 | 0 | 0 repos | 8.5 |
| identity:user-005 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-006 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-012 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-013 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:user-018 | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |

- external:anyone can start 1 exposed AI agent workflow without push access (see AI agents in CI).

Score counts confirmed reach only.

## AI agents in CI

1 workflow runs an AI coding agent; 1 can be started by people without push access, 1 of them while the agent holds write, secrets or OIDC. An agent reads the text of whoever starts it and acts with its job's token, secrets and tools, so a prompt injection uses all of them.

### acme-app/docs/.github/workflows/claude.yml (claude-code-action)

- Who can start it: outsiders: people without push access: anyone on the internet on issue\_comment
- What it holds: contents:write, pull-requests:write, secrets
- What it reaches: 1 secret scope, 1 repo
- Prompt injection: reads the triggering comment text
- Approvals off: dangerously\_skip\_permissions
  1. Restrict who can start it: remove allowed\_non\_write\_users / allow-users (or allowed\_bots) so the action's write-access check applies, or move it off issue\_comment, or require approval for outside contributors (an environment with required reviewers).
  2. Give the agent job a read-only token (permissions: contents: read; it now has contents:write, pull-requests:write) and make changes in a separate job that takes the agent's output.
  3. Pin the agent action to a full commit SHA: a tag can be moved to code that runs with this job's token and secrets.
  4. Drop dangerously\_skip\_permissions: keep the agent's own approval prompts and sandbox.
  5. Scope the allowed tools to what the job needs, for example --allowedTools "Bash(gh pr comment:\*)".

Agents are found by known actions and CLIs (docs/agents-in-ci.md). A name-only match is listed but never ranked. An action whose actor check gop does not know counts as possible, never as closed.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Lower the default repository permission of acme-actions to read | 34 | 50% |
| 2 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 16 | 74% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 4 | 79% |
| 4 | Stop acme-app/docs/.github/workflows/claude.yml from running attacker-controlled code on its risky triggers | 1 | 81% |

## Pinned, still reachable

A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:

- **acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5** (used by 4 workflows) runs **acme-actions/setup@main**. members:acme-actions can change it (confirmed):
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action

## Top paths

### action:acme-oss/checkout-ish@v2

- **confirmed** to secret:acme-app/docs
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. action:acme-oss/checkout-ish@v2 → workflow:acme-app/docs/.github/workflows/preview.yml, USES (reversed), **live**, demo:planted-advisory
  2. workflow:acme-app/docs/.github/workflows/preview.yml → secret:acme-app/docs, EXECUTES\_WITH, **live**, demo:planted-advisory

### external:anyone

- **confirmed** to secret:acme-app/docs
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. external:anyone → workflow:acme-app/docs/.github/workflows/claude.yml, CAN\_TRIGGER, **live**, demo:planted-ai-agent
  2. workflow:acme-app/docs/.github/workflows/claude.yml → secret:acme-app/docs, EXECUTES\_WITH, **live**, demo:planted-ai-agent

### identity:bob

- **confirmed** to oidc:acme-app/payments
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:bob → members:acme-actions, MEMBER\_OF, **live**, demo:membership
  2. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
  3. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  4. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  5. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-app/payments/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  6. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action
- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, demo:collaborator
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, demo:planted-cross-org
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org
- **confirmed** to oidc:acme-secure/signer
  1. identity:bob → members:acme-actions, MEMBER\_OF, **live**, demo:membership
  2. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
  3. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  4. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  5. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-secure/signer/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  6. workflow:acme-secure/signer/.github/workflows/release.yml → oidc:acme-secure/signer, EXECUTES\_WITH, **live**, demo:planted-nested-action

### members:acme-actions

- **confirmed** to oidc:acme-app/payments
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  4. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-app/payments/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  5. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action
- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, demo:default-perm
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, demo:planted-cross-org
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org
- **confirmed** to oidc:acme-secure/signer
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  4. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-secure/signer/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  5. workflow:acme-secure/signer/.github/workflows/release.yml → oidc:acme-secure/signer, EXECUTES\_WITH, **live**, demo:planted-nested-action

### identity:user-020

- **confirmed** to secret:acme-org-01/svc-009
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:user-020 → repo:acme-org-01/svc-009, CAN\_PUSH, **live**, demo:collaborator
  2. repo:acme-org-01/svc-009 → workflow:acme-org-01/svc-009/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-01/svc-009/.github/workflows/ci.yml → secret:acme-org-01/svc-009, EXECUTES\_WITH, **live**, demo:secrets

### identity:user-005

- **confirmed** to repo:acme-app/sandbox
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:user-005 → repo:acme-app/sandbox, CAN\_PUSH, **live**, demo:collaborator

### identity:user-006

- **confirmed** to repo:acme-org-01/svc-003
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:user-006 → repo:acme-org-01/svc-003, CAN\_PUSH, **live**, demo:collaborator

### identity:user-012

- **confirmed** to repo:acme-secure/svc-005
  1. identity:user-012 → repo:acme-secure/svc-005, CAN\_PUSH, **live**, demo:collaborator

### identity:user-013

- **confirmed** to repo:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:user-013 → repo:acme-app/mobile, CAN\_PUSH, **live**, demo:collaborator

### identity:user-018

- **confirmed** to repo:acme-org-01/svc-005
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:user-018 → repo:acme-org-01/svc-005, CAN\_PUSH, **live**, demo:collaborator

## Org settings

| Org | SSO | 2FA | IP allow list | Default permission | Members can create repos | Members can change visibility | Members can delete repos | Members can fork private repos | Members |
|---|---|---|---|---|---|---|---|---|---|
| acme-actions | configured | not\_required | off | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 40 |
| acme-app | enforced | required | off | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 120 |
| acme-legacy | none | not\_required | [_unknown_](#why-unknown) | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-org-01 | enforced | not\_required | off | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 40 |
| acme-secure | enforced | required | on | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 8 |

### Why unknown

- **acme-actions**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-app**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-legacy**
  - IP allow list: not visible: token is not an org owner. Access that fixes it: org owner on acme-legacy
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos, Members: not collected in this graph
- **acme-org-01**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-secure**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph

## Coverage

| Scope | Not visible | Why | Access that fixes it |
|---|---|---|---|
| org:acme-legacy | repositories | token is not an org owner | org owner on acme-legacy (SAML enforced: join through the IdP first) |
| org:acme-legacy | ip\_allow\_list | token is not an org owner | org owner on acme-legacy |

---

Generated by gop dev. This file maps attack paths in your organization. Treat it as sensitive.
