# AI coding agents in GitHub Actions

AI coding agents now run inside GitHub Actions: `claude-code-action`, the
Codex action and CLI, the Copilot coding agent, AI pull request reviewers and
"AI fix" bots. An agent reads text that other people write (issue and pull
request titles and bodies, comments, diffs) and then acts with the job's
`GITHUB_TOKEN`, secrets, OIDC token and tools. When people without push
access can start the agent, a prompt injection in their text can use all of
those. gop finds agent workflows, says who can start them and what they
reach, and ranks the exposed ones first.

Why this matters: see the [Practical Guide to Securing AI Agents](https://github.com/peleduri/Practical-Guide-to-Securing-AI-Agents), [Part 15](https://github.com/peleduri/Practical-Guide-to-Securing-AI-Agents/blob/main/wiki/part-15-agents-in-ci.md) and Parts 6, 7
and 14. The short version: treat everything an agent reads as untrusted,
give it the least privilege its task needs, and keep the people who can start
it to the people you would let push.

## What gop detects

`gop collect` marks a workflow node with `agent=<kind>` (a comma list when it
runs several) and the attrs below. The table of known agents lives in one
file, [`internal/collect/agenttable.go`](../internal/collect/agenttable.go):
add a row there to detect a new action or CLI.

| Signal | `agent_source` | `agent_confidence` | Kinds |
|---|---|---|---|
| A step `uses:` a known agent action (any ref, any letter case; matched by `owner/repo[/path]`) | `uses` | `action` | `claude-code-action`, `claude-code-base-action`, `claude-code-security-review`, `codex-action`, `gemini-cli-action`, `pr-agent`, `opencode-action` |
| The Copilot coding agent setup job (`copilot-setup-steps`) | `setup` | `action` | `copilot-coding-agent` |
| A `run:` step invokes a known agent CLI non-interactively (a prompt flag or subcommand) | `run` | `cli` | `claude-cli` (`claude -p`), `codex-cli` (`codex exec`), `cursor-cli` (`cursor-agent -p`), `gemini-cli` (`gemini -p`), `aider` (`aider --message`), `opencode-cli` (`opencode run`), `llm-cli` (`llm "..."`), `ollama-cli` (`ollama run MODEL "..."`, `ollama run MODEL --ask "..." < file`, or `... \| ollama run MODEL`) |
| On a risky trigger, a job with no known agent has a step that holds a model API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OLLAMA_API_KEY`, `VLLM_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` and similar, as an env name or a secret name) and reads the pull request's content: a checkout of its head made by an earlier step (named in `run:`, `with:` or `env:`), `gh pr diff` or `gh pr view`, or attacker contexts | `heuristic` | `heuristic` | `llm-script` |
| Only the workflow name, the file name or a job id or name contains `ai-`, `claude`, `codex`, `copilot` or `llm` | `name` | `name_only` | `unknown` |

A heuristic match covers trusted code from the base branch that feeds the
pull request's files or text to a model, a custom script rather than a known
agent: it is untrusted text reaching an AI step that holds secrets, not
untrusted code running. Its `CAN_TRIGGER` edges are `not_visible`, so it gives
possible reach only and does not add to the `agent_exposed` rank factor.
Its `agent_prompt_injection` includes `pr_content`.

A name-only match is weak: it is listed in the report but never ranked, never
reported in SARIF and never makes a path agentic. A bare `claude --version`
or `npm install -g @openai/codex` is not an agent run, and neither is
`ollama pull`, `ollama serve` or an `ollama run MODEL` with no prompt
argument, `--ask` or redirected or piped stdin.

The action inputs and actor checks were read from each action's public README
and `action.yml`:

- `anthropics/claude-code-action` lets only actors with write access start
  it, unless `allowed_non_write_users` (a user list, or `*` for everyone) or
  `allowed_bots` widen it. Tool settings come from `claude_args` and
  `settings` (and the deprecated `allowed_tools`).
- `openai/codex-action` lets only actors with write access start it, plus the
  users in `allow-users`. Tool settings come from `codex-args`,
  `safety-strategy` and `sandbox`.
- `anthropics/claude-code-base-action` has no actor check of its own.
- A CLI in a `run:` step has no actor check.
- For the other actions gop does not know the check: it counts as `unknown`,
  so reach through them is possible, never confirmed and never "closed".

## Risk facts per agent workflow

| Attr | Meaning |
|---|---|
| `agent_jobs` | The agent job ids |
| `agent_gate` | The weakest actor check of the agent steps: `write_access`, `listed_users`, `anyone`, `none`, `unknown` |
| `agent_exposure` | Who can start an agent job with the base repo's token and secrets: `outsiders` (a risky trigger such as `pull_request_target`, `issue_comment`, `issues`, `discussion*` or `workflow_run`, and a gate that lets them in), `listed_users`, `fork_readonly` (only a fork's `pull_request`, which gets a read-only token and no secrets) or `maintainers` |
| `agent_prompt_injection` | Attacker-controlled contexts (`${{ github.event.issue.title }}`, ...) interpolated into the agent step's `with:`, `env:` or `run:`, found by the same patterns as gop's injection heuristic; `pr_content` when a heuristic match reads the pull request's files, diff or text, or a CLI step's script reads its diff or text (`gh pr diff`, `gh pr view`) |
| `agent_permissions` | The agent jobs' token write scopes: `contents:write`, `pull-requests:write`, `id-token:write`, `write-all`, ..., or `default` when a job takes the repo default |
| `agent_secrets` | How many secrets the agent jobs reference (`GITHUB_TOKEN` excluded) |
| `agent_runner` | `hosted`, `self_hosted` or `unknown` |
| `agent_tools` | `allowed_tools` when a tool list is given; `dangerously_skip_permissions`, `bypass_permissions`, `yolo`, `full_auto`, `dangerously_bypass_approvals_and_sandbox`, `safety_strategy_unsafe`, `sandbox_danger_full_access`, `yes_always` when the agent's own approval or sandbox is off |
| `agent_ref_kind` | The least pinned ref of the agent actions: `sha`, `tag` or `branch` |

When `agent_exposure` is `outsiders`, the collector adds
`principal -CAN_TRIGGER-> workflow` with `exec=agent` for the principals who
can cause the trigger without push access (anyone on the internet for a
public repo, the members of every org for an internal one, the org's members
for a private one), exactly as for the other risky-trigger patterns. With an
`unknown` gate, or a heuristic match, the edge is `not_visible`: possible
reach only. A job `if:` that checks the comment author's `author_association`
narrows who can trigger it (see [Triggers](schema.md#triggers)); note that
`CONTRIBUTOR` includes outside contributors.

Even when only maintainers can start an agent, it still reads the event's
text: a maintainer who asks the agent to look at an outsider's issue hands it
that outsider's words. The report says which text each agent reads.

## Ranking

`agent_exposed` on a score counts the confirmed-reached agent workflows that
the principal starts through its own `CAN_TRIGGER` edge (without push access)
while the agent holds write, secrets or OIDC. It is a rank factor applied
after known advisories and poutine findings and before the score: such a
principal ranks above every principal without one. It never changes the
score, the counts or any evidence, so the scores of principals that cannot
start an agent are unchanged. A principal that can already push to the
workflow's repo is not counted: it controls the workflow anyway.

## Where it shows

- **Report:** an "AI agents in CI" section lists every agent workflow, exposed
  ones first: who can start it, what it holds and reaches, the prompt
  injection exposure, which approvals are off, and the fixes. The risks table
  marks a principal that starts an exposed agent.
- **SARIF:** rule `GOP004 agent-workflow-exposed`, one result per agent
  workflow people without push access can start, at the agent step's line.
  `properties.agent` names the agent and `properties.agent_fixes` lists the
  fixes. See [sarif.md](sarif.md).
- **MCP:** `top_risks` and `blast_radius` summaries add "can start N AI agent
  workflow(s) ... without push access [agent_exposed]"; `explain` on an edge
  into an agent workflow adds an `agent` note.
- **fix-plan:** `harden_trigger` on an agent workflow suggests closing the
  agent to outsiders.

## Fixes

In the order the report lists them:

1. Restrict who can start it: keep the action's write-access check (remove
   `allowed_non_write_users`, `allow-users` and a `*` in `allowed_bots`), move
   the job off triggers outsiders can cause, or require approval for outside
   contributors (an environment with required reviewers).
2. Give the agent job a read-only token (`permissions: contents: read`) and
   make changes in a separate job that takes the agent's output.
3. Pin the agent action to a full commit SHA.
4. Drop `--dangerously-skip-permissions`, `--yolo`, `bypassPermissions`,
   `safety-strategy: unsafe` and similar flags.
5. Scope the allowed tools, for example
   `--allowedTools "Bash(gh pr comment:*)"`.
6. Stop interpolating `${{ github.event.* }}` into the prompt; pass the text
   through `env:` or a file and still treat it as untrusted.

## AI approve + self-merge

Branch protection that says "1 approval required" is wrong in practice when
the approval comes from a bot the pull request's author can steer and the
merge comes from a bot that the rules let through. A common shape:

1. An AI reviewer workflow reads the pull request and posts an **APPROVE**
   review with a GitHub App token.
2. A second workflow on `issue_comment` lets the pull request's author
   comment a keyword (for example `#ai-merge`) and merges with a token of a
   GitHub App that is a bypass actor of the default branch's rules.

Anyone who can open a pull request (and convince the reviewer) then lands
code on the default branch with no human review. gop models this as push.

**What gop detects.** `gop collect` marks a workflow node:

| Attr | Meaning |
|---|---|
| `bot_approves`, `bot_approve_jobs` | A job submits an approving review: `gh pr review --approve`, a `pulls/{n}/reviews` call with `APPROVE` (`gh api`, `curl`, `actions/github-script`), an approve action (`hmarr/auto-approve-action`, ...), or an agent action whose inputs let it run `gh pr review` |
| `bot_merges`, `bot_merge_jobs`, `bot_merge_admin` | A job merges: `gh pr merge` (`--admin` sets `bot_merge_admin`), a `pulls/{n}/merge` call, a GraphQL `mergePullRequest` or `enablePullRequestAutoMerge`, an automerge action (`peter-evans/enable-pull-request-automerge`, `pascalgn/automerge-action`, ...) |
| `bot_approve_token`, `bot_merge_token` | The token the step uses: `app` (the output of `actions/create-github-app-token` or a similar step, or an agent action's own app), `pat` (another secret), `github_token`, or `unknown` |
| `bot_approve_starter`, `bot_merge_starter` | Who can make the job run: `pr_openers` (`issue_comment`, `pull_request_target`, `workflow_run`: the base repo's context), `org_members` (an `author_association` check that admits `MEMBER`), `pushers` (`pull_request`, `pull_request_review`: a fork's run gets no secrets and a read-only token), `maintainers` (`push`, `schedule`, `workflow_dispatch`, a named-actor check, or an agent whose actor check needs write access) |
| `bot_merge_gate`, `bot_merge_triggers` | The merging job's actor check (`pr_author`: the commenter must be the pull request's author; `author_association`; `listed_users`; `none`) and its triggers |

**The join.** After branch protection is read, each repo's merging workflows
are joined with its approving workflows and its default-branch rules. The
bot merge needs no human review when:

- the merge uses an App token and an app bypasses every rule of the default
  branch (`branch_app_bypass=true`): `review_bypass_reason=app_bypass`;
- the merge passes `--admin` with a personal token and admins bypass the
  rules: `admin_bypass`, always possible only (gop cannot see whose token it
  is);
- the required approvals are no more than the distinct bot approvals the
  same people can trigger, and no CODEOWNERS review is required:
  `bot_approvals` (approvals with `GITHUB_TOKEN` count as possible only: they
  need the repo's "Allow GitHub Actions to create and approve pull requests"
  setting, which gop does not read);
- the default branch is not protected: `unprotected`.

The repo then gets `review_bypass=bot_self_merge` with
`review_bypass_reason`, `review_bypass_merge` and `review_bypass_approve`.
When the merge job's starter is `pr_openers` or `org_members`, the people who
can open a pull request on the repo (as for a fork trigger: anyone on the
internet for a public repo, every org's members for an internal one, the
org's members for a private one when forking is allowed) get
`principal -CAN_MERGE_VIA_BOT-> repo` with `approve_workflows`,
`merge_workflow`, `review_bypass_reason`, `trigger`, `file` and `line`.
The edge and `review_bypass` are `live` when both workflows and the bypass
list were read, and `not_visible` (with a `review_bypass` coverage entry)
when a deciding fact is unknown, such as a bypass list only admins can read.
A CODEOWNERS review with no bypass is never flagged.

**Ranking and context.** The engine treats `CAN_MERGE_VIA_BOT` like
`CAN_PUSH`: the repo is controlled, so its workflows' secrets, OIDC and
runners are reached. `bot_self_merge` on a score counts the repos a principal
lands code on this way (confirmed only); it marks the principal in
`top_risks` (`[bot_self_merge]`) and the report's risks table, and is not a
separate rank factor. A `CAN_MERGE_VIA_BOT` hop, and a `CAN_PUSH` hop into
the repo that would otherwise say "push needs N approvals", carry the note
"a PR author can get code onto `main` without human review:
`ai-review.yml` + `ai-merge.yml`" ("may", with the unknown fact, when it is
possible only). The report has an "AI approve + self-merge" section.

**Fixes** (`block_bot_merge` in `what_if`, `suggest_fixes` and `fix-plan`
removes every `CAN_MERGE_VIA_BOT` edge into the repo; any one of the first
three closes the path):

1. Require a human approval that bots cannot give: CODEOWNERS review with
   human owners.
2. Remove the App from the bypass actors of the default branch's rules (or
   drop `--admin`).
3. Do not let PR authors trigger the merge: require a maintainer
   (`author_association` `OWNER`, or a write-permission check) and an
   environment with required reviewers.
4. Do not give the reviewer write or approve rights: let it comment only.

**Merges in a script.** The merge rules often live in a repo script the
workflow runs (`run: python3 tools/merge.py`). For a `run:` step that
invokes a repo script (`python3 path.py`, `node path.js`, `bash path.sh`,
`npx tsx path.ts`, `./path.sh`, `go run ./path`) with a token or key in its
env, gop reads that file from the default branch with one read-only contents
`GET` per repo and path (through the response cache, at most 5 scripts per
workflow, 256 KiB per script) and scans its text for the same calls: `gh pr
merge`, `pulls/{n}/merge`, PyGithub `pr.merge()`, Octokit `pulls.merge`,
GraphQL `mergePullRequest`, and approvals through `create_review(event=
"APPROVE")`, `createReview` or `gh pr review --approve`. gop never runs the
script. A merge found there sets `bot_merges` with
`bot_merge_source=script:<path>` (`bot_approve_source` for an approval) and
joins the rules as above; the repo also carries `bot_merge_source`, and the
path note reads "`ai-merge.yml` (merges in `tools/merge.py`)". The token is
`app` when the script mints an App token or the step hands it a
`*PRIVATE_KEY` secret. A script gop cannot read gets a `bot_script:<path>`
coverage entry on the workflow. `gop doctor` counts these reads in its
request estimate.

**Stale approvals (heuristic).** A merge script that decides which reviews
count can keep counting an approval after later pushes. When the script
reads reviews and either counts a `DISMISSED` review next to `APPROVED`, or
compares a review's `commit_id` with the head and goes on without skipping
it, gop sets `bot_merge_stale_approvals=suspected` with
`bot_merge_stale_confidence=heuristic` on the workflow and the repo. The
attr's evidence is `not_visible` and a `bot_merge_stale_approvals` coverage
entry asks for a manual check: it is a text match, never confirmed. When an
approving workflow of the path also does not re-run on `synchronize` (its
`pull_request` or `pull_request_target` types leave it out),
`review_bypass_stale_approval=suspected` is set and the path note adds "the
approval may not cover the merged code".

**The merge key next to the AI.** When an AI agent step (a known agent
action or CLI) has the same secret in its env or `with:` as the merge's
token source (the private key of the App token step, or a secret in the
merging step's env), the repo gets `agent_holds_merge_key=true` and
`agent_merge_key_workflows`: a prompt injection can use the key to merge by
itself.

These add fixes after the four above (they narrow the path, they do not
close it): count only approvals of the head commit in the script, re-run the
AI review on every push, and keep the merge key out of the AI step.

**Limits.** gop does not know which App a token belongs to, so any app
bypass actor counts for any App token; it does not read the "allow GitHub
Actions to approve" setting; it follows only literal script paths (not
`$SCRIPT`, `python -m`, imports or a called reusable workflow), and the
stale-approval check is a text heuristic; and a scheduled job that merges
approved pull requests is not modeled.

## Limits

- gop reads workflow files, not runs: it does not see agents started from a
  called reusable workflow, a local composite action, a script file or a
  container, and it cannot tell what an agent actually did.
- The actor checks of actions other than claude-code-action and codex-action
  are unknown to gop and count as possible.
- Tool settings in a separate settings file or `config.toml` are not read.
