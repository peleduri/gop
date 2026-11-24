# gop: who can make code run where

Enterprise **acme**, collected 2026-11-24T12:00:00Z

> identity:alice can push code that runs in 13 repos across 3 orgs (confirmed), including 2 cloud OIDC trusts, 3 secret scopes, 1 self-hosted runner pool.
>
> Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it to remove 32% of confirmed reach.
>
> Pinning is not enough: 1 action pinned to a commit SHA still runs a mutable ref that someone can push to.

Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| identity:alice | 13 | 3 | 2 | 3 | 1 | 0 repos + 1 impact | 138.4 |
| members:acme-actions | 9 | 3 | 1 | 2 | 1 | 0 repos | 94.5 |
| 2 principals (team:acme-actions/platform): team:acme-actions/platform, team:acme-actions/platform-oncall | 7 | 2 | 1 | 2 | 1 | 0 repos | 82.1 |
| identity:bob | 9 | 3 | 1 | 2 | 1 | 1 repo | 61.5 |
| identity:erin | 7 | 2 | 1 | 2 | 1 | 0 repos | 36.5 |
| team:acme-app/release | 1 | 1 | 0 | 1 | 0 | 0 repos | 13.5 |
| external:anyone | 1 | 1 | 0 | 1 | 0 | 0 repos | 9.5 |
| members:acme-legacy | 2 | 1 | 0 | 0 | 0 | 1 repo | 6.8 |
| team:acme-legacy/legacy-vTESTs | 1 | 1 | 0 | 0 | 0 | 0 repos | 5.2 |
| identity:carol | 2 | 1 | 0 | 0 | 0 | 0 repos | 4.5 |

- external:anyone can get code onto the default branch of 1 repo without human review [bot_self_merge] (see AI approve + self-merge).

Score counts confirmed reach only.

## AI agents in CI

2 workflows run an AI coding agent; 1 can be started by people without push access, 1 of them while the agent holds write, secrets or OIDC. An agent reads the text of whoever starts it and acts with its job's token, secrets and tools, so a prompt injection uses all of them.

### acme-app/web/.github/workflows/ai-review.yml (claude-cli)

- Who can start it: outsiders: people without push access: anyone on the internet on issue\_comment, pull\_request\_target
- What it holds: secrets
- What it reaches: 1 secret scope, 1 repo
- Prompt injection: reads the triggering comment, pull request text
  1. Restrict who can start it: the agent has no actor check of its own, so move it off issue\_comment or pull\_request\_target, check the actor's repository permission in a step before the agent runs, or require approval for outside contributors (an environment with required reviewers).

### acme-app/web/.github/workflows/ai-merge.yml (name only)

- Who can start it: name only: not counted as an agent

Agents are found by known actions and CLIs (docs/agents-in-ci.md). A name-only match is listed but never ranked. An action whose actor check gop does not know counts as possible, never as closed.

## AI approve + self-merge

A bot approves a pull request its author can steer, and a workflow the author can start merges it with a bot token the default branch's rules let through: anyone who can open a pull request lands code with no human review. gop treats it like push access.

### acme-app/web

- a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)
- Who: external:anyone
- Why no human review: app\_bypass
- Merging App: 77, a bypass actor of the default branch rules
- Merge rules in a script: \`tools/merge.py\` (read from the default branch, not run)
- Stale approvals (suspected, heuristic): the script re-counts approvals GitHub dismissed: the rules dismiss stale reviews on push, and the merge counts DISMISSED reviews; confirm by hand
- The AI step holds the merge key: .github/workflows/ai-review.yml
  1. Require a human approval that bots cannot give: require CODEOWNERS review on \`main\` with human owners (or a team), so a bot approval never satisfies the rule.
  2. Remove the GitHub App \`77\` from the bypass actors of the rules on \`main\`: the merging workflow uses its token, so the merge skips every rule.
  3. Do not let PR authors trigger the merge: drop the author check from \`ai-merge.yml\`, or require a maintainer (author\_association OWNER, or a write-permission check) and an environment with required reviewers.
  4. Do not give the reviewer write or approve rights: let the AI reviewer comment (pull-requests: write without approving, or a read-only token) and keep approve and merge with people.
  5. Stop counting DISMISSED reviews in \`tools/merge.py\` (suspected, heuristic: confirm by hand): the rules already dismiss stale reviews on push, but the script re-counts approvals GitHub dismissed. Count only APPROVED reviews whose commit\_id is the head SHA.
  6. Re-run the AI review on every push: add synchronize to the pull\_request types of \`ai-review.yml\`, so an approval always covers the code that is merged.
  7. Keep the merge key out of the AI step: the agent in \`ai-review.yml\` holds the secret the merge uses, so a prompt injection can merge by itself. Give the merge its own App and key, outside the agent's env.

## Org ownership

12% of confirmed reach depends on standing org ownership: removing every org owner grant would remove 7 of 59 confirmed (principal, repo) pairs.

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
| 1 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 19 | 32% |
| 2 | Lower the default repository permission of acme-actions to read | 9 | 47% |
| 3 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 4 | 54% |
| 4 | Lower the default repository permission of acme-legacy to read | 2 | 58% |
| 5 | Pin acme-actions/setup@main to a commit SHA in every workflow that uses it | 1 | 59% |

## Pinned, still reachable

A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:

- **acme-actions/deploy@0123456789abcdef0123456789abcdef01234567** (used by 3 workflows) runs **acme-actions/setup@main**. identity:alice can change it (confirmed):
  1. identity:alice → repo:acme-actions/setup, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses
     note: push reaches the default branch directly
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/setup@main → action:acme-actions/deploy@0123456789abcdef0123456789abcdef01234567, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}?ref={ref}

## Top paths

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
- **confirmed** to secret:acme-app/docs
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:alice → repo:acme-app/docs, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. repo:acme-app/docs → workflow:acme-app/docs/.github/workflows/build.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  3. workflow:acme-app/docs/.github/workflows/build.yml → secret:acme-app/docs, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
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
- **confirmed** to secret:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/mobile/.github/workflows/release.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/mobile/.github/workflows/release.yml → secret:acme-app/mobile, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/web
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/web/.github/workflows/ci.yml → repo:acme-app/web, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/actions/permissions/workflow
     note: a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)
  5. repo:acme-app/web → workflow:acme-app/web/.github/workflows/ai-merge.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  6. workflow:acme-app/web/.github/workflows/ai-merge.yml → secret:acme-app/web, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

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
- **confirmed** to secret:acme-app/web
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. team:acme-actions/platform → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /orgs/{org}/teams/{team\_slug}/repos
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/web/.github/workflows/ci.yml → repo:acme-app/web, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/actions/permissions/workflow
     note: a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)
  5. repo:acme-app/web → workflow:acme-app/web/.github/workflows/ai-merge.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  6. workflow:acme-app/web/.github/workflows/ai-merge.yml → secret:acme-app/web, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### identity:bob

- **confirmed** to oidc:acme-app/billing
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/billing/.github/workflows/deploy.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/billing/.github/workflows/deploy.yml → oidc:acme-app/billing, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/mobile
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/mobile/.github/workflows/release.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/mobile/.github/workflows/release.yml → secret:acme-app/mobile, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **confirmed** to secret:acme-app/web
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:bob → repo:acme-app/web, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)
  2. repo:acme-app/web → workflow:acme-app/web/.github/workflows/ai-merge.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  3. workflow:acme-app/web/.github/workflows/ai-merge.yml → secret:acme-app/web, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
- **possible: a hop is not visible** to repo:acme-secure/vault-proxy
  1. identity:bob → members:acme-legacy, MEMBER\_OF, **live**, rest:GET /enterprises/{enterprise}/consumed-licenses
  2. members:acme-legacy → repo:acme-legacy/hidden-tool, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
  3. repo:acme-legacy/hidden-tool → action:acme-legacy/hidden-tool@v2, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  4. action:acme-legacy/hidden-tool@v2 → workflow:acme-secure/vault-proxy/.github/workflows/ci.yml, USES (reversed), **not visible**, rest:GET /repos/{owner}/{repo}/contents/{path}
  5. workflow:acme-secure/vault-proxy/.github/workflows/ci.yml → repo:acme-secure/vault-proxy, DEFINED\_IN, **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows

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
- **confirmed** to secret:acme-app/web
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. identity:erin → repo:acme-actions/deploy, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/collaborators?affiliation=direct
     note: push reaches the default branch directly
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-app/web/.github/workflows/ci.yml → repo:acme-app/web, CAN\_PUSH, **live**, rest:GET /repos/{owner}/{repo}/actions/permissions/workflow
     note: a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)
  5. repo:acme-app/web → workflow:acme-app/web/.github/workflows/ai-merge.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  6. workflow:acme-app/web/.github/workflows/ai-merge.yml → secret:acme-app/web, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### team:acme-app/release

- **confirmed** to secret:acme-app/docs
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. team:acme-app/release → repo:acme-app/docs, CAN\_PUSH, **live**, rest:GET /orgs/{org}/teams/{team\_slug}/repos
  2. repo:acme-app/docs → workflow:acme-app/docs/.github/workflows/build.yml, DEFINED\_IN (reversed), **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows
  3. workflow:acme-app/docs/.github/workflows/build.yml → secret:acme-app/docs, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### external:anyone

- **confirmed** to secret:acme-app/web
  _Context, not part of the score: target org acme-app: SSO not enforced (configured), IP allow list off_
  1. external:anyone → workflow:acme-app/web/.github/workflows/ai-review.yml, CAN\_TRIGGER, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}
  2. workflow:acme-app/web/.github/workflows/ai-review.yml → secret:acme-app/web, EXECUTES\_WITH, **live**, rest:GET /repos/{owner}/{repo}/contents/{path}

### members:acme-legacy

- **confirmed** to repo:acme-legacy/hidden-tool
  _Context, not part of the score: target org acme-legacy: SSO enforced, IP allow list unknown_
  1. members:acme-legacy → repo:acme-legacy/hidden-tool, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
- **possible: a hop is not visible** to repo:acme-secure/vault-proxy
  1. members:acme-legacy → repo:acme-legacy/hidden-tool, CAN\_PUSH, **inferred**, graphql:enterprise.ownerInfo.defaultRepositoryPermissionSettingOrganizations
  2. repo:acme-legacy/hidden-tool → action:acme-legacy/hidden-tool@v2, RESOLVES\_TO (reversed), **live**, derived:workflow.uses+graphql:enterprise.organizations
  3. action:acme-legacy/hidden-tool@v2 → workflow:acme-secure/vault-proxy/.github/workflows/ci.yml, USES (reversed), **not visible**, rest:GET /repos/{owner}/{repo}/contents/{path}
  4. workflow:acme-secure/vault-proxy/.github/workflows/ci.yml → repo:acme-secure/vault-proxy, DEFINED\_IN, **live**, rest:GET /repos/{owner}/{repo}/contents/.github/workflows

### team:acme-legacy/legacy-vTESTs

- **confirmed** to repo:acme-legacy/old-site
  _Context, not part of the score: target org acme-legacy: SSO enforced, IP allow list unknown_
  1. team:acme-legacy/legacy-vTESTs → repo:acme-legacy/old-site, CAN\_PUSH, **live**, rest:GET /orgs/{org}/teams/{team\_slug}/repos

### identity:carol

- **confirmed** to repo:acme-secure/vault-proxy
  1. identity:carol → repo:acme-secure/vault-proxy, CAN\_PUSH, **inferred**, rest:GET /enterprises/{enterprise}/consumed-licenses

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
| acme-app | 9 | 1/1 | 1/1 | 0/9 | 9/9 | 0/9 |
| acme-legacy | 1 | 0/0 | 0/0 | 0/1 | 0/1 (1 unknown) | 0/1 (1 unknown) |
| acme-secure | 2 | 0/0 | 0/0 | 0/2 | 2/2 | 0/2 |

Repos on the top paths:

- **acme-actions/deploy**: default branch \`main\`: protected (ruleset:7), 1 approval, force push allowed; no CODEOWNERS; secret scanning on, push protection off
- **acme-actions/setup**: default branch \`main\`: protected (ruleset:8), no approvals required, force push allowed; no CODEOWNERS; secret scanning on, push protection off
- **acme-app/api**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/billing**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/docs**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/infra**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/mobile**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/notify**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/search**: no CODEOWNERS; secret scanning on, push protection off
- **acme-app/web**: default branch \`main\`: protected (ruleset:46), 1 approval, force push blocked; no CODEOWNERS; secret scanning on, push protection off
- **acme-app/worker**: no CODEOWNERS; secret scanning on, push protection off
- **acme-legacy/old-site**: no CODEOWNERS; secret scanning unknown, push protection unknown

Hardening suggestions (advisory: not counted as removing confirmed reach):

- Enable secret scanning push protection on acme-actions/deploy (secret scanning push protection is off)
- Require at least one approving review on the default branch of acme-actions/setup (default branch \`main\` needs no approval)
- Enable secret scanning push protection on acme-actions/setup (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/api (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/billing (secret scanning push protection is off)

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
| workflow:acme-app/web/.github/workflows/ai-merge.yml | bot\_merge\_stale\_approvals | suspected, heuristic: tools/merge.py seems to count approvals not tied to the head commit (a dismissed review, or a review of an older commit it does not skip); gop matched text and never ran it | confirm by hand: read tools/merge.py and check it counts only APPROVED reviews whose commit\_id is the pull request's head SHA |

---

Generated by gop v0.0.0-test. This file maps attack paths in your organization. Treat it as sensitive.
