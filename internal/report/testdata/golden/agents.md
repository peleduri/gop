# gop: who can make code run where

Enterprise **acme**, collected 2026-11-20T12:00:00Z

**AI agents and bots:** 3 non-human actors; none can merge to a default branch without a human.

> identity:bob can push code that runs in 9 repos across 3 orgs (confirmed), including 1 cloud OIDC trust, 2 secret scopes, 1 self-hosted runner pool. 1 repo more possible through facts gop could not see.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 31% of confirmed reach.
>
> Pinning is not enough: 1 action pinned to a commit SHA still runs a mutable ref that someone can push to.

Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| identity:bob | 9 | 3 | 1 | 2 | 1 | 1 repo | 60.8 |
| members:acme-legacy | 3 | 2 | 0 | 1 | 0 | 1 repo | 19.5 |
| identity:carol | 3 | 2 | 0 | 1 | 0 | 0 repos | 13.0 |
| members:acme-app | 1 | 1 | 0 | 1 | 0 | 0 repos | 12.8 |
| external:anyone | 1 | 1 | 0 | 1 | 0 | 0 repos | 10.5 |
| members:acme-secure | 1 | 1 | 0 | 1 | 0 | 0 repos | 8.5 |
| identity:alice | 13 | 3 | 2 | 3 | 1 | 0 repos + 1 impact | 140.6 |
| members:acme-actions | 9 | 3 | 1 | 2 | 1 | 0 repos | 93.4 |
| 2 principals (team:acme-actions/platform): team:acme-actions/platform, team:acme-actions/platform-oncall | 7 | 2 | 1 | 1 | 1 | 0 repos | 68.6 |
| identity:erin | 7 | 2 | 1 | 1 | 1 | 0 repos | 30.5 |

- identity:bob can start 1 exposed AI agent workflow without push access (see AI agents in CI).
- members:acme-legacy can start 1 exposed AI agent workflow without push access (see AI agents in CI).
- identity:carol can start 1 exposed AI agent workflow without push access (see AI agents in CI).
- members:acme-app can start 1 exposed AI agent workflow without push access (see AI agents in CI).
- external:anyone can start 1 exposed AI agent workflow without push access (see AI agents in CI).
- members:acme-secure can start 1 exposed AI agent workflow without push access (see AI agents in CI).

Score counts confirmed reach only.

## AI agents in CI

4 workflows run an AI coding agent; 2 can be started by people without push access, 2 of them while the agent holds write, secrets or OIDC. An agent reads the text of whoever starts it and acts with its job's token, secrets and tools, so a prompt injection uses all of them.

### acme-actions/setup/.github/workflows/codex-review.yml (codex-cli)

- Who can start it: outsiders: people without push access: members:acme-actions, members:acme-app, members:acme-legacy and 1 more on pull\_request\_target
- What it holds: pull-requests:write, secrets
- What it reaches: 1 secret scope, 1 repo
- Prompt injection: github.event.pull\_request.title in the prompt; reads the triggering pull request text
- Approvals off: full\_auto
  1. Restrict who can start it: the agent has no actor check of its own, so move it off pull\_request\_target, check the actor's repository permission in a step before the agent runs, or require approval for outside contributors (an environment with required reviewers).
  2. Give the agent job a read-only token (permissions: contents: read; it now has pull-requests:write) and make changes in a separate job that takes the agent's output.
  3. Drop full\_auto: keep the agent's own approval prompts and sandbox.
  4. Scope the allowed tools to what the job needs, for example --allowedTools "Bash(gh pr comment:\*)".
  5. Stop interpolating github.event.pull\_request.title into the prompt or script: pass it through env or a file, and treat what the agent reads as untrusted.

### acme-app/docs/.github/workflows/claude.yml (claude-code-action)

- Who can start it: outsiders: people without push access: anyone on the internet on issue\_comment
- What it holds: contents:write, issues:write, pull-requests:write, secrets
- What it reaches: 1 secret scope, 1 repo
- Prompt injection: reads the triggering comment text
- Approvals off: dangerously\_skip\_permissions
  1. Restrict who can start it: remove allowed\_non\_write\_users / allow-users (or allowed\_bots) so the action's write-access check applies, or move it off issue\_comment, or require approval for outside contributors (an environment with required reviewers).
  2. Give the agent job a read-only token (permissions: contents: read; it now has contents:write, issues:write, pull-requests:write) and make changes in a separate job that takes the agent's output.
  3. Pin the agent action to a full commit SHA: a tag can be moved to code that runs with this job's token and secrets.
  4. Drop dangerously\_skip\_permissions: keep the agent's own approval prompts and sandbox.
  5. Scope the allowed tools to what the job needs, for example --allowedTools "Bash(gh pr comment:\*)".

### acme-app/docs/.github/workflows/gemini-review.yml (gemini-cli-action)

- Who can start it: anyone, from a fork's pull\_request (read-only token, no secrets) on pull\_request
- What it holds: secrets (not given to a fork's pull\_request run)
- What it reaches: 1 secret scope, 1 repo
  1. Pin the agent action to a full commit SHA: a tag can be moved to code that runs with this job's token and secrets.

### acme-app/docs/.github/workflows/ai-labeler.yml (name only)

- Who can start it: name only: not counted as an agent

Agents are found by known actions and CLIs (docs/agents-in-ci.md). A name-only match is listed but never ranked. An action whose actor check gop does not know counts as possible, never as closed.

## Org ownership

11% of confirmed reach depends on standing org ownership: removing every org owner grant would remove 7 of 62 confirmed (principal, repo) pairs.

| Orgs owned | Accounts |
|---|---:|
| 1 org | 1 |
| 2–4 orgs | 1 |
| 5–9 orgs | 0 |
| 10+ orgs | 0 |

2 accounts own at least one org. An org owner is admin on every repo of the org, so an account that owns many orgs can push code that runs across all of them. gop counts owners from org owner grants on repos: an org with no repos shows no owners. The gop://graph/summary resource lists the accounts in each bucket.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 19 | 31% |
| 2 | Lower the default repository permission of acme-actions to read | 8 | 44% |
| 3 | Harden acme-actions/setup/.github/workflows/codex-review.yml (untrusted code runs, and untrusted text reaches an AI step, on pull\_request\_target) | 4 | 50% |
| 4 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 4 | 56% |
| 5 | Lower the default repository permission of acme-legacy to read | 2 | 60% |

## Pinned, still reachable

A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:

- **acme-actions/deploy@0123456789abcdef0123456789abcdef01234567** (used by 3 workflows) runs **acme-actions/setup@main**. identity:alice can change it (confirmed):
  1. identity:alice → repo:acme-actions/setup, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses
     note: push reaches the default branch directly
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/setup@main → action:acme-actions/deploy@0123456789abcdef0123456789abcdef01234567, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}?ref={ref}

## Top paths

### identity:bob

- **confirmed** to oidc:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/deploy.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/billing/.github/workflows/deploy.yml → oidc:acme-app/billing, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. identity:bob → members:acme-app, MEMBER\_OF, **live**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. members:acme-app → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  3. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/mobile/.github/workflows/release.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/mobile/.github/workflows/release.yml → secret:acme-app/mobile, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **possible: a hop is not visible** to repo:acme-secure/vault-proxy
  1. identity:bob → members:acme-legacy, MEMBER\_OF, **live**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. members:acme-legacy → repo:acme-legacy/hidden-tool, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
  3. repo:acme-legacy/hidden-tool → action:acme-legacy/hidden-tool@v2, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  4. action:acme-legacy/hidden-tool@v2 → workflow:acme-secure/vault-proxy/.github/workflows/ci.yml, USES (reversed), **not visible**, rest:GET /repos/{owner}/{repo}/contents/{path}
  5. workflow:acme-secure/vault-proxy/.github/workflows/ci.yml → repo:acme-secure/vault-proxy, DEFINED\_IN, **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows

### members:acme-legacy

- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. members:acme-legacy → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  2. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **possible: a hop is not visible** to repo:acme-secure/vault-proxy
  1. members:acme-legacy → repo:acme-legacy/hidden-tool, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
  2. repo:acme-legacy/hidden-tool → action:acme-legacy/hidden-tool@v2, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-legacy/hidden-tool@v2 → workflow:acme-secure/vault-proxy/.github/workflows/ci.yml, USES (reversed), **not visible**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-secure/vault-proxy/.github/workflows/ci.yml → repo:acme-secure/vault-proxy, DEFINED\_IN, **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows

### identity:carol

- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. identity:carol → members:acme-secure, MEMBER\_OF, **live**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. members:acme-secure → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  3. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### members:acme-app

- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. members:acme-app → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  2. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### external:anyone

- **confirmed** to secret:acme-app/docs
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. external:anyone → workflow:acme-app/docs/.github/workflows/claude.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  2. workflow:acme-app/docs/.github/workflows/claude.yml → secret:acme-app/docs, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### members:acme-secure

- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. members:acme-secure → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  2. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### identity:alice

- **confirmed** to oidc:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:alice → repo:acme-app/billing, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. repo:acme-app/billing → workflow:acme-app/billing/.github/workflows/deploy.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  3. workflow:acme-app/billing/.github/workflows/deploy.yml → oidc:acme-app/billing, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to oidc:acme-app/search
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:alice → repo:acme-app/search, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. repo:acme-app/search → workflow:acme-app/search/.github/workflows/index.yaml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  3. workflow:acme-app/search/.github/workflows/index.yaml → oidc:acme-app/search, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. identity:alice → members:acme-actions, MEMBER\_OF, **live**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. members:acme-actions → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  3. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **possible: a hop is not visible** to runner:acme-app/search
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:alice → repo:acme-app/search, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. repo:acme-app/search → workflow:acme-app/search/.github/workflows/index.yaml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  3. workflow:acme-app/search/.github/workflows/index.yaml → runner:acme-app/search, EXECUTES\_WITH, **not visible**, rest:GET /repos/{owner}/{repo}/contents/{path}

### members:acme-actions

- **confirmed** to oidc:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/deploy.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/billing/.github/workflows/deploy.yml → oidc:acme-app/billing, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-actions/setup
  _Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_
  1. members:acme-actions → workflow:acme-actions/setup/.github/workflows/codex-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  2. workflow:acme-actions/setup/.github/workflows/codex-review.yml → secret:acme-actions/setup, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/mobile/.github/workflows/release.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/mobile/.github/workflows/release.yml → secret:acme-app/mobile, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### team:acme-actions/platform, one of 2 principals (team:acme-actions/platform)

- **confirmed** to oidc:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. team:acme-actions/platform → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /orgs/{org}/teams/{team\_slug}/repos
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/deploy.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/billing/.github/workflows/deploy.yml → oidc:acme-app/billing, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. team:acme-actions/platform → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /orgs/{org}/teams/{team\_slug}/repos
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/mobile/.github/workflows/release.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/mobile/.github/workflows/release.yml → secret:acme-app/mobile, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to runner:acme-app/infra
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. team:acme-actions/platform → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /orgs/{org}/teams/{team\_slug}/repos
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/infra/.github/workflows/apply.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/infra/.github/workflows/apply.yml → runner:acme-app/infra, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### identity:erin

- **confirmed** to oidc:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:erin → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/deploy.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/billing/.github/workflows/deploy.yml → oidc:acme-app/billing, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:erin → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/mobile/.github/workflows/release.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/mobile/.github/workflows/release.yml → secret:acme-app/mobile, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to runner:acme-app/infra
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:erin → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/infra/.github/workflows/apply.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/infra/.github/workflows/apply.yml → runner:acme-app/infra, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

## Org settings

| Org | SSO | 2FA | IP allow list | Default permission | Members can create repos | Members can change visibility | Members can delete repos | Members can fork private repos | Members |
|---|---|---|---|---|---|---|---|---|---|
| acme-actions | configured | not\_required | off (0 active entries, installed apps off) | write | true | false | false | true | 1 |
| acme-app | configured | required | off (0 active entries, installed apps off) | read | false | true | false | false | 3 |
| acme-archive | none | not\_required | [_unknown_](#why-unknown) | none | false | false | false | false | 0 |
| acme-legacy | enforced | not\_required | [_unknown_](#why-unknown) | write | true | true | true | true | 1 |
| acme-secure | enforced | required | on (4 active entries, installed apps on) | read | false | false | false | false | 1 |

### Why unknown

- **acme-archive**
  - IP allow list: not collected in this graph
- **acme-legacy**
  - IP allow list: not visible: token is not an org owner. Access that fixes it: org owner on acme-legacy (SSO enforced: join through the identity provider first)

## Repo hardening

Context only: these facts never change evidence, counts or scores. Each cell is repos where it holds / repos with the fact; unknown (not visible to the token) is counted separately, never as off.

| Org | Repos | Protected default branch | Required reviews | CODEOWNERS covers workflows | Secret scanning | Push protection |
|---|---:|---|---|---|---|---|
| acme-actions | 2 | 2/2 | 1/2 | 0/2 | 2/2 | 0/2 |
| acme-app | 9 | 0/0 | 0/0 | 0/9 | 9/9 | 0/9 |
| acme-legacy | 1 | 0/0 | 0/0 | 0/1 | 0/1 (1 unknown) | 0/1 (1 unknown) |
| acme-secure | 2 | 0/0 | 0/0 | 0/2 | 2/2 | 0/2 |

Repos on the top paths:

- **acme-actions/deploy**: default branch \`main\`: protected (ruleset:7), 1 approval, force push allowed; no CODEOWNERS; secret scanning on, push protection off
- **acme-app/infra**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/mobile**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/web**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/worker**: no CODEOWNERS; secret scanning on, push protection off
- **acme-legacy/old-site**: no CODEOWNERS; secret scanning unknown, push protection unknown
- **acme-secure/vault-proxy**: no CODEOWNERS; secret scanning on, push protection off
- **acme-secure/vendor-mirror**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/docs**: no CODEOWNERS; secret scanning on, push protection off
- **acme-actions/setup**: default branch \`main\`: protected (ruleset:8), no approvals required, force push allowed; no CODEOWNERS; secret scanning on, push protection off
- **acme-app/api**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/billing**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/notify**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/search**: no CODEOWNERS; secret scanning on, push protection off

Hardening suggestions (advisory: not counted as removing confirmed reach):

- Enable secret scanning push protection on acme-actions/deploy (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/infra (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/mobile (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/web (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/worker (secret scanning push protection is off)

## Coverage

| Scope | Not visible | Why | Access that fixes it |
|---|---|---|---|
| org:acme-app | team\_members:release | could not list members of team release: github api GET /orgs/acme-app/teams/release/members?role=all&amp;per\_page=100: HTTP 403: Must have admin rights to Team. | org owner on acme-app, or maintainer of team release |
| org:acme-legacy | ip\_allow\_list | token is not an org owner | org owner on acme-legacy (SSO enforced: join through the identity provider first) |
| org:acme-legacy | secret\_scanning | security\_and\_analysis not returned for 1 of 1 repositories (shown only to repo admins, org owners and security managers) | admin on those repositories, or org owner or security manager in acme-legacy |
| org:acme-legacy | repositories | token is not an org owner: only repositories visible to the token are listed | org owner on acme-legacy (SSO enforced: join through the identity provider first) |
| org:acme-legacy | outside\_collaborators | could not list outside collaborators: github api GET /orgs/acme-legacy/outside\_collaborators?per\_page=100: HTTP 403: Must have push access to view repository collaborators.; direct grants are labelled via=direct | org owner on acme-legacy (SSO enforced: join through the identity provider first) |
| org:acme-legacy | can\_push:collaborators | could not list collaborators on 1 repos (needs push access) | org owner on acme-legacy (SSO enforced: join through the identity provider first), or push access on each repository |
| org:acme-legacy | can\_push:teams | token is not an org owner: secret teams and their grants are not listed | org owner on acme-legacy (SSO enforced: join through the identity provider first) |
| org:acme-archive | repositories | organization is archived; not collected | none: archived organizations cannot run workflows |
| workflow:acme-app/search/.github/workflows/index.yaml | runner\_labels | runs-on gpu,linux is not a GitHub-hosted label: the runner may be self-hosted | org owner (runner groups and self-hosted runners are not read yet) |
| workflow:acme-app/search/.github/workflows/index.yaml | dynamic\_uses | uses: is an expression; the action cannot be resolved statically | none: replace the expression with literal owner/repo@sha references to make them visible |
| repo:acme-legacy/old-site | default\_workflow\_permissions | could not read the default workflow permissions: repo: github api GET /repos/acme-legacy/old-site/actions/permissions/workflow: HTTP 403: Must have admin rights to Repository.; org: github api GET /orgs/acme-legacy/actions/permissions/workflow: HTTP 403: Must have admin rights to Repository. | admin on acme-legacy/old-site (or org owner) |
| repo:acme-secure/vendor-mirror | workflows | unexpected contents response for .github/workflows | check .github/workflows in acme-secure/vendor-mirror is a directory |
| action:acme-legacy/hidden-tool@v2 | nested\_uses | action.yaml not found at v2 (missing, or repository not visible to the token) | read access to contents on acme-legacy/hidden-tool |
| repo:acme-legacy/hidden-tool | can\_push | host repository not listed for the token | read access to acme-legacy/hidden-tool |
| repo:acme-legacy/hidden-tool | actions\_access | could not read the Actions access setting of acme-legacy/hidden-tool: github api GET /repos/acme-legacy/hidden-tool/actions/permissions/access: HTTP 404: Not Found | admin on acme-legacy/hidden-tool (or org owner) |
| action:acme-legacy/hidden-tool@v2 | ref\_kind | repository acme-legacy/hidden-tool not found or not visible to the token (NOT\_FOUND: Could not resolve to a Repository with the name 'acme-legacy/hidden-tool'.); ref\_kind is a guess from the name | read access to acme-legacy/hidden-tool |

---

Generated by gop v0.0.0-test. This file maps attack paths in your organization. Treat it as sensitive.
