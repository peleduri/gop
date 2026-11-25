# [demo data] gop: who can make code run where

Enterprise **acme**, collected 2026-01-01T00:00:00Z

**AI agents and bots:** 8 non-human actors; 2 can merge to a default branch without a human (2 confirmed, 0 possible).

> acme-oss/checkout-ish@v2, a version with a known advisory (GHSA-acme-demo-0001; severity critical; fixed in 2.4.1), runs in 1 repo across 1 org (confirmed), including 1 secret scope.
>
> Remove standing org ownership from 3 accounts that own 5 or more orgs (keep at least 2 owners per org) to remove 42% of confirmed reach.
>
> Pinning is not enough: 1 action pinned to a commit SHA still runs a mutable ref that someone can push to.

Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry, or (a cloud hop) from a supplied file: a cloud trust policy you supplied, not read from the cloud. Possible means at least one hop is not visible to the token: unknown, not absent.

## Top risks

| Principal | Confirmed repos | Orgs | Cloud roles | OIDC | Secrets | Runners | Possible | Score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| action:acme-oss/checkout-ish@v2 (known advisory: GHSA-acme-demo-0001; severity critical; fixed in 2.4.1) | 1 | 1 | 0 | 0 | 1 | 0 | 0 repos | 8.5 |
| external:anyone | 3 | 1 | 1 | 2 | 3 | 0 | 0 repos | 53.5 |
| 3 owners of 5 to 6 orgs: identity:carol, identity:dave, identity:erin | 54 to 55 | 6 | 1 | 8 | 13 | 1 | 0 repos | 531.0 |
| 3 principals (identical reach): identity:bob, identity:user-001, identity:user-002 | 34 | 6 | 0 | 6 | 7 | 1 | 0 repos | 329.6 |
| members:acme-actions | 34 | 6 | 0 | 6 | 7 | 1 | 0 repos | 329.6 |
| 2 owners of 1 org: identity:user-004, identity:user-003 | 13 to 14 | 1 to 2 | 1 | 4 | 5 | 1 | 0 repos | 101.0 |
| 2 principals (org owners of acme-org-01): identity:user-007, identity:user-008 | 10 | 1 | 0 | 1 | 3 | 0 | 0 repos | 60.0 |
| identity:user-012 | 10 | 1 | 0 | 2 | 1 | 0 | 0 repos | 52.5 |
| identity:user-011 | 11 | 2 | 0 | 3 | 1 | 0 | 0 repos | 46.5 |
| identity:user-009 | 11 | 2 | 0 | 0 | 2 | 0 | 0 repos | 44.2 |

- external:anyone can start 1 exposed AI agent workflow without push access (see AI agents in CI).
- external:anyone can get code onto the default branch of 2 repos without human review [bot_self_merge] (see AI approve + self-merge).

Score counts confirmed reach only. A row grouped by cause shows the range of its members' confirmed repos and orgs; its other columns are its first member's. The JSON (`top_risks`) lists each member's own figures.

## AI agents in CI

4 workflows run an AI coding agent; 3 can be started by people without push access, 3 of them while the agent holds write, secrets or OIDC. An agent reads the text of whoever starts it and acts with its job's token, secrets and tools, so a prompt injection uses all of them.

### acme-app/api/.github/workflows/claude-fix.yml (claude-code-action)

- Who can start it: outsiders: people without push access: anyone on the internet on issue\_comment
- What it holds: contents:write, id-token:write, pull-requests:write, secrets
- What it reaches: 1 cloud role, 1 OIDC trust, 1 secret scope, 1 repo
- Prompt injection: reads the triggering comment text
- Approvals off: dangerously\_skip\_permissions
  1. Restrict who can start it: remove allowed\_non\_write\_users / allow-users (or allowed\_bots) so the action's write-access check applies, or move it off issue\_comment, or require approval for outside contributors (an environment with required reviewers).
  2. Give the agent job a read-only token (permissions: contents: read; it now has contents:write, id-token:write, pull-requests:write) and make changes in a separate job that takes the agent's output.
  3. Pin the agent action to a full commit SHA: a branch can be moved to code that runs with this job's token and secrets.
  4. Drop dangerously\_skip\_permissions: keep the agent's own approval prompts and sandbox.
  5. Scope the allowed tools to what the job needs, for example --allowedTools "Bash(gh pr comment:\*)".

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

### acme-app/web/.github/workflows/ai-review.yml (claude-cli)

- Who can start it: outsiders: people without push access: anyone on the internet on pull\_request\_target
- What it holds: secrets
- What it reaches: 1 secret scope, 1 repo
- Prompt injection: reads the triggering pull request text
  1. Restrict who can start it: the agent has no actor check of its own, so move it off pull\_request\_target, check the actor's repository permission in a step before the agent runs, or require approval for outside contributors (an environment with required reviewers).

### acme-secure/infra/.github/workflows/codex.yml (codex-cli)

- Who can start it: maintainers: write access only
- What it holds: read-only token, no secrets
- What it reaches: 1 repo
- Approvals off: full\_auto
  1. Drop full\_auto: keep the agent's own approval prompts and sandbox.
  2. Scope the allowed tools to what the job needs, for example --allowedTools "Bash(gh pr comment:\*)".

Agents are found by known actions and CLIs (docs/agents-in-ci.md). A name-only match is listed but never ranked. An action whose actor check gop does not know counts as possible, never as closed.

## Agent paths

4 agent paths; 3 in dangerous mode, 3 that people without push access can start.

1. Anyone on GitHub → claude-code-action (dangerous mode: dangerously\_skip\_permissions) in acme-app/api/.github/workflows/claude-fix.yml → Assume acme-prod-deploy. Evidence: live 7, inferred 1, supplied file 1.
2. Anyone on GitHub → claude-code-action (dangerous mode: dangerously\_skip\_permissions) in acme-app/docs/.github/workflows/claude.yml → Push to acme-app/docs. Evidence: live 6, inferred 1.
3. Anyone on GitHub → claude-cli in acme-app/web/.github/workflows/ai-review.yml → Merge to the default branch of acme-app/web. Evidence: live 6, inferred 1.
4. Maintainers with write access → codex-cli (dangerous mode: full\_auto) in acme-secure/infra/.github/workflows/codex.yml → Commands on the runner. Evidence: live 3, inferred 1.

The HTML report steps through each path and shows where a fix cuts it.

## AI approve + self-merge

A bot approves a pull request its author can steer, and a workflow the author can start merges it with a bot token the default branch's rules let through: anyone who can open a pull request lands code with no human review. gop treats it like push access.

### acme-app/api

- a PR author can get code onto \`main\` without human review: \`claude-fix.yml\` + \`auto-merge.yml\`
- Who: external:anyone
- Why no human review: app\_bypass
- Merging App: 91, a bypass actor of the default branch rules
- The AI step holds the merge key: .github/workflows/claude-fix.yml
- Policy files a pull request can edit without a code owner: AGENTS.md
  1. Require a human approval that bots cannot give: require CODEOWNERS review on \`main\` with human owners (or a team), so a bot approval never satisfies the rule.
  2. Remove the GitHub App \`91\` from the bypass actors of the rules on \`main\`: the merging workflow uses its token, so the merge skips every rule.
  3. Do not let PR authors trigger the merge: drop the author check from \`auto-merge.yml\`, or require a maintainer (author\_association OWNER, or a write-permission check) and an environment with required reviewers.
  4. Do not give the reviewer write or approve rights: let the AI reviewer comment (pull-requests: write without approving, or a read-only token) and keep approve and merge with people.
  5. Add CODEOWNERS lines with human owners for \`/AGENTS.md\`: these files steer the AI agents and reviewers, and a pull request can change them and still be merged by the bot.
  6. Keep the merge key out of the AI step: the agent in \`claude-fix.yml\` holds the secret the merge uses, so a prompt injection can merge by itself. Give the merge its own App and key, outside the agent's env.

### acme-app/web

- a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the approval may not cover the merged code (suspected, heuristic: the merge counts older approvals and the review does not re-run on push)
- Who: external:anyone
- Why no human review: app\_bypass
- Merging App: 77, a bypass actor of the default branch rules
- Merge rules in a script: \`tools/merge.py\` (read from the default branch, not run)
- Stale approvals (suspected, heuristic): the merge seems to count approvals not tied to the head commit; confirm by hand
- The AI step holds the merge key: .github/workflows/ai-review.yml
  1. Require a human approval that bots cannot give: require CODEOWNERS review on \`main\` with human owners (or a team), so a bot approval never satisfies the rule.
  2. Remove the GitHub App \`77\` from the bypass actors of the rules on \`main\`: the merging workflow uses its token, so the merge skips every rule.
  3. Do not let PR authors trigger the merge: drop the author check from \`ai-merge.yml\`, or require a maintainer (author\_association OWNER, or a write-permission check) and an environment with required reviewers.
  4. Do not give the reviewer write or approve rights: let the AI reviewer comment (pull-requests: write without approving, or a read-only token) and keep approve and merge with people.
  5. Count only approvals of the head commit in \`tools/merge.py\` (suspected, heuristic: confirm by hand): skip reviews whose commit\_id is not the head SHA and never count DISMISSED reviews.
  6. Re-run the AI review on every push: add synchronize to the pull\_request types of \`ai-review.yml\`, so an approval always covers the code that is merged.
  7. Keep the merge key out of the AI step: the agent in \`ai-review.yml\` holds the secret the merge uses, so a prompt injection can merge by itself. Give the merge its own App and key, outside the agent's env.

## Org ownership

81% of confirmed reach depends on standing org ownership: removing every org owner grant would remove 321 of 394 confirmed (principal, repo) pairs.

| Orgs owned | Accounts |
|---|---:|
| 1 org | 12 |
| 2–4 orgs | 0 |
| 5–9 orgs | 3 |
| 10+ orgs | 0 |

15 accounts own at least one org. An org owner is admin on every repo of the org, so an account that owns many orgs can push code that runs across all of them. gop counts owners from org owner grants on repos: an org with no repos shows no owners. The gop://graph/summary resource lists the accounts in each bucket.

## Suggested fixes

| # | Fix | Confirmed pairs removed | Cumulative removed |
|---:|---|---:|---:|
| 1 | Remove standing org ownership from 3 accounts that own 5 or more orgs (keep at least 2 owners per org) | 164 | 42% |
| 2 | Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it | 72 | 60% |
| 3 | Lower the default repository permission of acme-actions to read | 16 | 64% |
| 4 | Pin acme-actions/deploy@v1 to a commit SHA in every workflow that uses it | 10 | 66% |
| 5 | Pin acme-actions/setup@main to a commit SHA in every workflow that uses it | 6 | 68% |

## Pinned, still reachable

A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:

- **acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5** (used by 3 workflows) runs **acme-actions/setup@main**. identity:carol can change it (confirmed):
  1. identity:carol → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:planted-org-owner
     note: push reaches the default branch directly
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action

## Top paths

### action:acme-oss/checkout-ish@v2

- **confirmed** to secret:acme-app/docs
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. action:acme-oss/checkout-ish@v2 → workflow:acme-app/docs/.github/workflows/preview.yml, USES (reversed), **live**, demo:planted-advisory
  2. workflow:acme-app/docs/.github/workflows/preview.yml → secret:acme-app/docs, EXECUTES\_WITH, **live**, demo:planted-advisory

### external:anyone

- **confirmed** to cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy
  _cloud hop from supplied trust file demo/trust/aws/acme-prod-deploy.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. external:anyone → workflow:acme-app/api/.github/workflows/claude-fix.yml, CAN\_TRIGGER, **live**, demo:planted-agent-dangerous-mode
  2. workflow:acme-app/api/.github/workflows/claude-fix.yml → cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy, CAN\_ASSUME, **supplied file**, supplied:demo/trust/aws/acme-prod-deploy.json
- **confirmed** to oidc:acme-app/api
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. external:anyone → workflow:acme-app/api/.github/workflows/claude-fix.yml, CAN\_TRIGGER, **live**, demo:planted-agent-dangerous-mode
  2. workflow:acme-app/api/.github/workflows/claude-fix.yml → oidc:acme-app/api, EXECUTES\_WITH, **live**, demo:planted-agent-dangerous-mode
- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. external:anyone → repo:acme-app/web, CAN\_MERGE\_VIA\_BOT, **live**, demo:planted-bot-self-merge
     note: a PR author can get code onto \`main\` without human review: \`ai-review.yml\` + \`ai-merge.yml\` (merges in \`tools/merge.py\`); the approval may not cover the merged code (suspected, heuristic: the merge counts older approvals and the review does not re-run on push)
  2. repo:acme-app/web → workflow:acme-app/web/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:planted-cross-org
  3. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org

### identity:carol, one of 3 owners of 5 to 6 orgs

- **confirmed** to cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy
  _cloud hop from supplied trust file demo/trust/aws/acme-prod-deploy.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:carol → repo:acme-app/api, CAN\_PUSH, **inferred**, demo:planted-org-owner
     note: a PR author can get code onto \`main\` without human review: \`claude-fix.yml\` + \`auto-merge.yml\`
  2. repo:acme-app/api → workflow:acme-app/api/.github/workflows/claude-fix.yml, DEFINED\_IN (reversed), **live**, demo:planted-agent-dangerous-mode
  3. workflow:acme-app/api/.github/workflows/claude-fix.yml → cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy, CAN\_ASSUME, **supplied file**, supplied:demo/trust/aws/acme-prod-deploy.json
- **confirmed** to oidc:acme-app/api
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:carol → repo:acme-app/api, CAN\_PUSH, **inferred**, demo:planted-org-owner
     note: a PR author can get code onto \`main\` without human review: \`claude-fix.yml\` + \`auto-merge.yml\`
  2. repo:acme-app/api → workflow:acme-app/api/.github/workflows/claude-fix.yml, DEFINED\_IN (reversed), **live**, demo:planted-agent-dangerous-mode
  3. workflow:acme-app/api/.github/workflows/claude-fix.yml → oidc:acme-app/api, EXECUTES\_WITH, **live**, demo:planted-agent-dangerous-mode
- **confirmed** to oidc:acme-app/payments
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:carol → repo:acme-app/payments, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-app/payments → workflow:acme-app/payments/.github/workflows/release.yml, DEFINED\_IN (reversed), **live**, demo:planted-nested-action
  3. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action

### identity:bob, one of 3 principals (identical reach)

- **confirmed** to oidc:acme-app/payments
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:bob → members:acme-actions, MEMBER\_OF, **live**, demo:membership
  2. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
     note: push reaches the default branch directly
  3. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  4. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  5. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-app/payments/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  6. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action
- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, demo:collaborator
     note: push needs 1 approval to reach \`main\`
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, demo:planted-cross-org
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org
- **confirmed** to oidc:acme-org-01/svc-007
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:bob → repo:acme-actions/deploy, CAN\_PUSH, **live**, demo:collaborator
     note: push needs 1 approval to reach \`main\`
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-org-01/svc-007/.github/workflows/ci.yml, USES (reversed), **live**, demo:uses
  4. workflow:acme-org-01/svc-007/.github/workflows/ci.yml → oidc:acme-org-01/svc-007, EXECUTES\_WITH, **live**, demo:id-token-write

### members:acme-actions

- **confirmed** to oidc:acme-app/payments
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. members:acme-actions → repo:acme-actions/setup, CAN\_PUSH, **inferred**, demo:default-perm
     note: push reaches the default branch directly
  2. repo:acme-actions/setup → action:acme-actions/setup@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/setup@main → action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5, USES (reversed), **live**, demo:planted-nested-action
  4. action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5 → workflow:acme-app/payments/.github/workflows/release.yml, USES (reversed), **live**, demo:planted-nested-action
  5. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action
- **confirmed** to oidc:acme-app/web
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, demo:default-perm
     note: push needs 1 approval to reach \`main\`
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-app/web/.github/workflows/ci.yml, USES (reversed), **live**, demo:planted-cross-org
  4. workflow:acme-app/web/.github/workflows/ci.yml → oidc:acme-app/web, EXECUTES\_WITH, **live**, demo:planted-cross-org
- **confirmed** to oidc:acme-org-01/svc-007
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. members:acme-actions → repo:acme-actions/deploy, CAN\_PUSH, **inferred**, demo:default-perm
     note: push needs 1 approval to reach \`main\`
  2. repo:acme-actions/deploy → action:acme-actions/deploy@main, RESOLVES\_TO (reversed), **live**, demo:action-host
  3. action:acme-actions/deploy@main → workflow:acme-org-01/svc-007/.github/workflows/ci.yml, USES (reversed), **live**, demo:uses
  4. workflow:acme-org-01/svc-007/.github/workflows/ci.yml → oidc:acme-org-01/svc-007, EXECUTES\_WITH, **live**, demo:id-token-write

### identity:user-004, one of 2 owners of 1 org

- **confirmed** to cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy
  _cloud hop from supplied trust file demo/trust/aws/acme-prod-deploy.json, not read from the cloud_
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:user-004 → repo:acme-app/api, CAN\_PUSH, **inferred**, demo:planted-org-owner
     note: a PR author can get code onto \`main\` without human review: \`claude-fix.yml\` + \`auto-merge.yml\`
  2. repo:acme-app/api → workflow:acme-app/api/.github/workflows/claude-fix.yml, DEFINED\_IN (reversed), **live**, demo:planted-agent-dangerous-mode
  3. workflow:acme-app/api/.github/workflows/claude-fix.yml → cloud:aws:arn:aws:iam::111111111111:role/acme-prod-deploy, CAN\_ASSUME, **supplied file**, supplied:demo/trust/aws/acme-prod-deploy.json
- **confirmed** to oidc:acme-app/api
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:user-004 → repo:acme-app/api, CAN\_PUSH, **inferred**, demo:planted-org-owner
     note: a PR author can get code onto \`main\` without human review: \`claude-fix.yml\` + \`auto-merge.yml\`
  2. repo:acme-app/api → workflow:acme-app/api/.github/workflows/claude-fix.yml, DEFINED\_IN (reversed), **live**, demo:planted-agent-dangerous-mode
  3. workflow:acme-app/api/.github/workflows/claude-fix.yml → oidc:acme-app/api, EXECUTES\_WITH, **live**, demo:planted-agent-dangerous-mode
- **confirmed** to oidc:acme-app/payments
  _Context, not part of the score: target org acme-app: SSO enforced, IP allow list off_
  1. identity:user-004 → repo:acme-app/payments, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-app/payments → workflow:acme-app/payments/.github/workflows/release.yml, DEFINED\_IN (reversed), **live**, demo:planted-nested-action
  3. workflow:acme-app/payments/.github/workflows/release.yml → oidc:acme-app/payments, EXECUTES\_WITH, **live**, demo:planted-nested-action

### identity:user-007, one of 2 principals (org owners of acme-org-01)

- **confirmed** to oidc:acme-org-01/svc-007
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:user-007 → repo:acme-org-01/svc-007, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-01/svc-007 → workflow:acme-org-01/svc-007/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-01/svc-007/.github/workflows/ci.yml → oidc:acme-org-01/svc-007, EXECUTES\_WITH, **live**, demo:id-token-write
- **confirmed** to secret:acme-org-01/svc-001
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:user-007 → repo:acme-org-01/svc-001, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-01/svc-001 → workflow:acme-org-01/svc-001/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-01/svc-001/.github/workflows/ci.yml → secret:acme-org-01/svc-001, EXECUTES\_WITH, **live**, demo:secrets
- **confirmed** to secret:acme-org-01/svc-007
  _Context, not part of the score: target org acme-org-01: SSO enforced, IP allow list off_
  1. identity:user-007 → repo:acme-org-01/svc-007, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-01/svc-007 → workflow:acme-org-01/svc-007/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-01/svc-007/.github/workflows/ci.yml → secret:acme-org-01/svc-007, EXECUTES\_WITH, **live**, demo:secrets

### identity:user-012

- **confirmed** to oidc:acme-org-03/svc-007
  _Context, not part of the score: target org acme-org-03: SSO enforced, IP allow list off_
  1. identity:user-012 → repo:acme-org-03/svc-007, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-03/svc-007 → workflow:acme-org-03/svc-007/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-03/svc-007/.github/workflows/ci.yml → oidc:acme-org-03/svc-007, EXECUTES\_WITH, **live**, demo:id-token-write
- **confirmed** to oidc:acme-org-03/svc-008
  _Context, not part of the score: target org acme-org-03: SSO enforced, IP allow list off_
  1. identity:user-012 → repo:acme-org-03/svc-008, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-03/svc-008 → workflow:acme-org-03/svc-008/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-03/svc-008/.github/workflows/ci.yml → oidc:acme-org-03/svc-008, EXECUTES\_WITH, **live**, demo:id-token-write
- **confirmed** to secret:acme-org-03/svc-007
  _Context, not part of the score: target org acme-org-03: SSO enforced, IP allow list off_
  1. identity:user-012 → repo:acme-org-03/svc-007, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-03/svc-007 → workflow:acme-org-03/svc-007/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-03/svc-007/.github/workflows/ci.yml → secret:acme-org-03/svc-007, EXECUTES\_WITH, **live**, demo:secrets

### identity:user-011

- **confirmed** to oidc:acme-org-03/svc-007
  _Context, not part of the score: target org acme-org-03: SSO enforced, IP allow list off_
  1. identity:user-011 → repo:acme-org-03/svc-007, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-03/svc-007 → workflow:acme-org-03/svc-007/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-03/svc-007/.github/workflows/ci.yml → oidc:acme-org-03/svc-007, EXECUTES\_WITH, **live**, demo:id-token-write
- **confirmed** to oidc:acme-org-03/svc-008
  _Context, not part of the score: target org acme-org-03: SSO enforced, IP allow list off_
  1. identity:user-011 → repo:acme-org-03/svc-008, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-03/svc-008 → workflow:acme-org-03/svc-008/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-03/svc-008/.github/workflows/ci.yml → oidc:acme-org-03/svc-008, EXECUTES\_WITH, **live**, demo:id-token-write
- **confirmed** to oidc:acme-secure/vault
  1. identity:user-011 → repo:acme-secure/vault, CAN\_PUSH, **live**, demo:collaborator
  2. repo:acme-secure/vault → workflow:acme-secure/vault/.github/workflows/release.yml, DEFINED\_IN (reversed), **live**, demo:planted-sha-pin
  3. workflow:acme-secure/vault/.github/workflows/release.yml → oidc:acme-secure/vault, EXECUTES\_WITH, **live**, demo:planted-sha-pin

### identity:user-009

- **confirmed** to secret:acme-org-02/svc-001
  _Context, not part of the score: target org acme-org-02: SSO enforced, IP allow list off_
  1. identity:user-009 → repo:acme-org-02/svc-001, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-02/svc-001 → workflow:acme-org-02/svc-001/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-02/svc-001/.github/workflows/ci.yml → secret:acme-org-02/svc-001, EXECUTES\_WITH, **live**, demo:secrets
- **confirmed** to secret:acme-org-02/svc-009
  _Context, not part of the score: target org acme-org-02: SSO enforced, IP allow list off_
  1. identity:user-009 → repo:acme-org-02/svc-009, CAN\_PUSH, **inferred**, demo:planted-org-owner
  2. repo:acme-org-02/svc-009 → workflow:acme-org-02/svc-009/.github/workflows/ci.yml, DEFINED\_IN (reversed), **live**, demo:workflow
  3. workflow:acme-org-02/svc-009/.github/workflows/ci.yml → secret:acme-org-02/svc-009, EXECUTES\_WITH, **live**, demo:secrets

## Org settings

| Org | SSO | 2FA | IP allow list | Default permission | Members can create repos | Members can change visibility | Members can delete repos | Members can fork private repos | Members |
|---|---|---|---|---|---|---|---|---|---|
| acme-actions | configured | not\_required | off | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 40 |
| acme-app | enforced | required | off | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 120 |
| acme-legacy | none | not\_required | [_unknown_](#why-unknown) | write | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) |
| acme-org-01 | enforced | not\_required | off | read | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 40 |
| acme-org-02 | enforced | not\_required | off | none | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 141 |
| acme-org-03 | enforced | required | off | none | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | [_unknown_](#why-unknown) | 128 |
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
- **acme-org-02**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-org-03**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph
- **acme-secure**
  - Members can create repos, Members can change visibility, Members can delete repos, Members can fork private repos: not collected in this graph

## Repo hardening

Context only: these facts never change evidence, counts or scores. Each cell is repos where it holds / repos with the fact; unknown (not visible to the token) is counted separately, never as off.

| Org | Repos | Protected default branch | Required reviews | CODEOWNERS covers workflows | Secret scanning | Push protection |
|---|---:|---|---|---|---|---|
| acme-actions | 3 | 2/3 | 2/3 | 0/3 | 3/3 | 2/3 |
| acme-app | 2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 |
| acme-secure | 1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 |

Repos on the top paths:

- **acme-actions/deploy**: default branch \`main\`: protected (ruleset:7), 1 approval, force push blocked; no CODEOWNERS; secret scanning on, push protection on
- **acme-actions/release**: default branch \`main\`: protected (classic), 2 approvals, force push blocked; no CODEOWNERS; secret scanning on, push protection on
- **acme-actions/setup**: default branch \`main\`: not protected; no CODEOWNERS; secret scanning on, push protection off
- **acme-app/api**: default branch \`main\`: protected (ruleset:58), 1 approval, force push blocked; no CODEOWNERS; secret scanning on, push protection on
- **acme-app/web**: default branch \`main\`: protected (ruleset:46), 1 approval, force push blocked; no CODEOWNERS; secret scanning on, push protection off

Hardening suggestions (advisory: not counted as removing confirmed reach):

- Require at least one approving review on the default branch of acme-actions/setup (default branch \`main\` is not protected)
- Enable secret scanning push protection on acme-actions/setup (secret scanning push protection is off)
- Enable secret scanning push protection on acme-app/web (secret scanning push protection is off)

## Coverage

| Scope | Not visible | Why | Access that fixes it |
|---|---|---|---|
| org:acme-legacy | repositories | token is not an org owner | org owner on acme-legacy (SAML enforced: join through the IdP first) |
| org:acme-legacy | ip\_allow\_list | token is not an org owner | org owner on acme-legacy |
| workflow:acme-app/web/.github/workflows/ai-merge.yml | bot\_merge\_stale\_approvals | suspected, heuristic: tools/merge.py seems to count approvals not tied to the head commit; gop matched text and never ran it | confirm by hand: read tools/merge.py and check it counts only APPROVED reviews whose commit\_id is the pull request's head SHA |
| repo:acme-app/web | bot\_merge\_stale\_approvals | suspected, heuristic: the merge in tools/merge.py may count older approvals and ai-review.yml does not re-run on push | confirm by hand: read tools/merge.py and the pull\_request types of ai-review.yml |

---

Generated by gop dev. This file maps attack paths in your organization. Treat it as sensitive.
