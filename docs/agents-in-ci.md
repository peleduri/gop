# AI coding agents in GitHub Actions

AI coding agents now run inside GitHub Actions: `claude-code-action`, the
Codex action and CLI, the Copilot coding agent, AI pull request reviewers and
"AI fix" bots. An agent reads text that other people write (issue and pull
request titles and bodies, comments, diffs) and then acts with the job's
`GITHUB_TOKEN`, secrets, OIDC token and tools. When people without push
access can start the agent, a prompt injection in their text can use all of
those. gop finds agent workflows, says who can start them and what they
reach, and ranks the exposed ones first.

Why this matters: see the *Practical Guide to Securing AI Agents*, Parts 6, 7
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
| A `run:` step invokes a known agent CLI non-interactively (a prompt flag or subcommand) | `run` | `cli` | `claude-cli` (`claude -p`), `codex-cli` (`codex exec`), `cursor-cli` (`cursor-agent -p`), `gemini-cli` (`gemini -p`), `aider` (`aider --message`), `opencode-cli` (`opencode run`), `llm-cli` (`llm "..."`) |
| Only the workflow name, the file name or a job id or name contains `ai-`, `claude`, `codex`, `copilot` or `llm` | `name` | `name_only` | `unknown` |

A name-only match is weak: it is listed in the report but never ranked, never
reported in SARIF and never makes a path agentic. A bare `claude --version`
or `npm install -g @openai/codex` is not an agent run.

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
| `agent_prompt_injection` | Attacker-controlled contexts (`${{ github.event.issue.title }}`, ...) interpolated into the agent step's `with:`, `env:` or `run:`, found by the same patterns as gop's injection heuristic |
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
`unknown` gate the edge is `not_visible`: possible reach only.

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

## Limits

- gop reads workflow files, not runs: it does not see agents started from a
  called reusable workflow, a local composite action, a script file or a
  container, and it cannot tell what an agent actually did.
- The actor checks of actions other than claude-code-action and codex-action
  are unknown to gop and count as possible.
- Tool settings in a separate settings file or `config.toml` are not read.
