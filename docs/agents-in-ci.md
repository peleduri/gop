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

## The headline

The report opens, and the MCP `gop://graph/summary` resource starts, with
one line: `N non-human actors; M can merge to a default branch without a
human (C confirmed, P possible)`. Non-human actors are the workflows below
that run a confirmed agent (not a name-only match), the workflows that
approve or merge through a bot (`CAN_MERGE_VIA_BOT`, see "AI approve +
self-merge"), the review bypass Apps and the bot accounts (`[bot]` logins),
each counted once. M counts the merging workflows: confirmed when one of
their `CAN_MERGE_VIA_BOT` edges is verified, possible when all are
`not_visible`.

## Installed GitHub Apps

For each org the token owns, gop lists the GitHub Apps installed in it
(`GET /orgs/{org}/installations`: org owner only; fine-grained tokens and
Apps need Organization Administration: read). Each App is an identity
`identity:<slug>[bot]`, the login it acts as, with `app_id`, `app_slug`,
`app_orgs`, `app_write` (the permissions it holds with write, such as
`contents`, `workflows`, `pull_requests`), `app_repos` (`all` when it is
installed on every repository of an org, else `selected`: an org token
cannot read the selected list) and `app_ai=name` when its slug names an AI
coding or review tool. An App with `contents` and `workflows` write on all
repositories can change code and CI everywhere it is installed. The org gets
`app_installations`; an org the token does not own gets `unknown`
(`not_visible`) with a coverage entry.

An installation with `contents: write` becomes `CAN_PUSH` edges from the App
(`via=app_install`), so the App appears in reach, top risks and
`who_can_reach` like any other principal:

- installed on all repositories: an edge to every repo of the org, evidence
  `inferred` (rule `app_install`), so it counts as confirmed reach;
- installed on selected repositories: GitHub lists them only to the App's own
  tokens, never to an org owner's token, so every repo of the org gets a
  `not_visible` edge (possible reach) and the org a `can_push:app_install`
  coverage entry. Check the list in the org settings (GitHub Apps, Configure).

`app_workflows=write` on the edge marks an installation that can also change
workflow files.

## What gop detects

`gop collect` marks a workflow node with `agent=<kind>` (a comma list when it
runs several) and the attrs below. The table of known agents lives in one
file, [`internal/collect/agenttable.go`](../internal/collect/agenttable.go):
add a row there to detect a new action or CLI.

| Signal | `agent_source` | `agent_confidence` | Kinds |
|---|---|---|---|
| A step `uses:` a known agent action (any ref, any letter case; matched by `owner/repo[/path]`) | `uses` | `action` | `claude-code-action`, `claude-code-base-action`, `claude-code-security-review`, `codex-action`, `gemini-cli-action`, `pr-agent`, `opencode-action`, `qwen-code-action` |
| The Copilot coding agent setup job (`copilot-setup-steps`) | `setup` | `action` | `copilot-coding-agent` |
| A `run:` step invokes a known agent CLI non-interactively (a prompt flag or subcommand) | `run` | `cli` | `claude-cli` (`claude -p`), `codex-cli` (`codex exec`), `cursor-cli` (`cursor-agent -p`), `gemini-cli` (`gemini -p`), `aider` (`aider --message`), `opencode-cli` (`opencode run`), `llm-cli` (`llm "..."`), `ollama-cli` (`ollama run MODEL "..."`, `ollama run MODEL --ask "..." < file`, or `... \| ollama run MODEL`), `agentrun-cli` (`agentrun runs start AGENT`, `agentrun template eval DIR`, also through `npx @parcha/agentrun`), `copilot-cli` (`copilot -p`, `copilot --prompt`), `qwen-cli` (`qwen -p`), `goose-cli` (`goose run`), `crush-cli` (`crush run`), `cline-cli` (`cline "task"`, `cline --json`), `continue-cli` (`cn -p`), `amp-cli` (`amp -x`, `amp --execute`), `openhands-cli` (`openhands --headless`) |
| A job runs a known agent platform image as its `container`, a `services` image or a `docker://` step (any tag or digest) | `image` | `cli` | `agentrun-server` (`ghcr.io/parcha-ai/agentrun-server`) |
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
argument, `--ask` or redirected or piped stdin. For agentrun, only
`runs start` and `template eval` start runs: `agentrun doctor`, `stop`,
`workflows validate` and a bare `npx @parcha/agentrun` are not agent runs.

### More agent CLIs

Each CLI below was checked against its own documentation (the source is
cited next to its row in `agenttable.go`). A command matches only when its
command word is exactly the CLI name or npm package (after a path or
`npx`), so `raider`, `aider-lint` or `goosebump` never match.

| Kind | Non-interactive run | Approval-skipping flags in `agent_tools` | Not an agent run |
|---|---|---|---|
| `copilot-cli` (GitHub Copilot CLI, `@github/copilot`) | `copilot -p "..."`, `--prompt` | `--allow-all-tools` and `--allow-all` give `allow_all`; `--yolo` gives `yolo`; `--allow-tool=...` gives `allowed_tools` | `copilot svc deploy` and the other commands of AWS's unrelated `copilot` CLI |
| `qwen-cli` (Qwen Code, `@qwen-code/qwen-code`) | `qwen -p "..."` | `--yolo`, `--approval-mode yolo` and `--approval-mode=yolo` give `yolo` (the same `--approval-mode` form is read for `gemini`) | `qwen --version` |
| `goose-cli` (goose) | `goose run -t "..."`, `-i file`, `--recipe` | none: headless goose already runs with `GOOSE_MODE=auto` by default | the goose database migration tool (`goose -dir ... up`) |
| `crush-cli` (Crush, `@charmland/crush`) | `crush run "..."` | `--yolo` gives `yolo` | `crush --version` |
| `cline-cli` (Cline CLI, `cline`) | `cline "task"` (a quoted first argument), `cline --json` | none: `--auto-approve` defaults to true | `cline auth` |
| `continue-cli` (Continue CLI `cn`, `@continuedev/cli`) | `cn -p "..."` | none documented | `cn ls`, `cn login`, `cn serve` |
| `amp-cli` (Amp) | `amp -x "..."`, `amp --execute` | none read: the flag that skips Amp's prompts is not in its official docs, so gop does not rely on it | `amp --version`, `amp login` |
| `openhands-cli` (OpenHands CLI) | `openhands --headless -t "..."`, `-f file` | none: headless mode always approves | `openhands --version` |

The `qwen-code-action` (`QwenLM/qwen-code-action`) is matched like
`gemini-cli-action`: it has no documented actor check, so its gate is
`unknown`, and its `settings` input is scanned for tool flags.

### One level down

An agent is often one step removed from the workflow file. For a workflow
with a risky trigger or `pull_request`, gop follows one level of
indirection (never two):

| Where the agent is | How gop reads it | `agent_source` adds |
|---|---|---|
| A local composite action a step loads (`uses: ./.github/actions/review`) | its `action.yml` (or `action.yaml`) from the default branch; the step's `with:` and `env:` values count as the agent's input | `composite` |
| A reusable workflow the job calls in the same repo (`uses: ./.github/workflows/x.yml`) or in another repo of the same org (`uses: acme/repo/.github/workflows/x.yml@ref`) | the called file (one the nested expansion already read is not read again); it runs with the caller's event, so who can start the caller starts it, and the caller's `with:` values count as input | `reusable` |
| A repo script a `run:` step invokes while holding a secret or model API key (`bash ci/ai.sh`, `python3 tools/review.py`) | the script from the default branch, scanned for a known agent CLI (as in a `run:` step) and for model API calls (provider API hosts, a local model server, SDK `messages.create`, `chat.completions.create`, `generate_content` and similar) | `script` |

A script that only calls a model API is `llm-script` with
`agent_confidence=heuristic` and `not_visible` edges, and counts only when
attacker text reaches it: a checkout of the pull request's head the step
reads, `gh pr diff` or `gh pr view` in the script, the event payload
(`GITHUB_EVENT_PATH`), or attacker contexts in the step. The same follow
finds `checkout` and `injection` patterns inside composite actions and
reusable workflows ([Triggers](schema.md#triggers)).

Each file is one read-only contents `GET` per repo, path and ref, through
the response cache, at most 10 files per workflow and 256 KiB per file; gop
never runs what it reads, and `gop doctor` counts these reads in its
request estimate. A file gop cannot read gets a `follow:<path>` coverage
entry on the workflow, which keeps the facts gop read without it. The
`CAN_TRIGGER` edge's `file` and `line` point at the agent step in the
composite action or same-repo reusable workflow, at the caller's `uses:`
line for a reusable workflow in another repo, and at the `run:` step for a
script.

A known agent step that reads a checkout of the pull request's head (the
workspace root, a directory input or working directory in it, or a path
into it such as `pr/` in its prompt) gets `pr_content` in
`agent_prompt_injection`. A bare word like "pr" in prose is not a path.

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
| `agent_prompt_injection` | Attacker-controlled contexts (`${{ github.event.issue.title }}`, ...) interpolated into the agent step's `with:`, `env:` or `run:`, found by the same patterns as gop's injection heuristic; `pr_content` when a heuristic match reads the pull request's files, diff or text, a CLI step's script reads its diff or text (`gh pr diff`, `gh pr view`), or a known agent reads a checkout of its head |
| `agent_permissions` | The agent jobs' token write scopes: `contents:write`, `pull-requests:write`, `id-token:write`, `write-all`, ..., or `default` when a job takes the repo default |
| `agent_secrets` | How many secrets the agent jobs reference (`GITHUB_TOKEN` excluded) |
| `agent_runner` | `hosted`, `self_hosted` or `unknown` |
| `agent_tools` | `allowed_tools` when a tool list is given; `dangerously_skip_permissions`, `bypass_permissions`, `yolo`, `full_auto`, `dangerously_bypass_approvals_and_sandbox`, `safety_strategy_unsafe`, `sandbox_danger_full_access`, `yes_always`, `allow_all` when the agent's own approval or sandbox is off |
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
  agent to outsiders. Its title says the kind: "untrusted text reaches an
  AI step on ..." for an agent, "untrusted code runs on ..." for a checkout
  or injection.

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
  branch (`branch_app_bypass=true`): `review_bypass_reason=app_bypass`. It is
  confirmed only when the App the merge mints for is the bypass App: the
  workflow names it literally (`app-id: 123456` on an App token step, or
  `APP_ID: "123456"` beside a `*_PRIVATE_KEY` secret in a script step's env,
  recorded as `bot_merge_apps`) and that ID or slug is in
  `branch_bypass_apps` (`review_bypass_app_match=matched`). An App the
  workflow does not name (`vars.` or `secrets.`), or one that is not in the
  bypass list, leaves it possible (`unknown` or `unmatched`);
- the merge passes `--admin` with a personal token and admins bypass the
  rules: `admin_bypass`, always possible only (gop cannot see whose token it
  is);
- the required approvals are no more than the distinct bot approvals the
  same people can trigger, and no CODEOWNERS review is required:
  `bot_approvals`. Approvals with `GITHUB_TOKEN` need the repo's "Allow
  GitHub Actions to create and approve pull requests" setting: gop reads it
  (`can_approve_pull_request_reviews`, read-only, only for a repo with such
  an approval) into `actions_can_approve_prs`. `true` confirms the approval,
  `false` drops it, and a setting gop cannot read (`unknown`, with an
  `actions_can_approve_prs` coverage entry) leaves it possible;
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

**Self-editable policy files.** In a repo with a review bypass, gop also
checks the files that steer AI agents and reviewers: `AGENTS.md`,
`CLAUDE.md`, `REVIEW.md`, `.github/copilot-instructions.md`, `.cursorrules`
and `.cursor/rules`. It reads only whether each exists on the default branch
(in the same batched query as CODEOWNERS; one contents `GET` per path over
REST, only for these repos) and checks each against CODEOWNERS (the last
matching rule must name an owner). `policy_files` lists the ones present and
`policy_files_unowned` those with no owner (`unknown`, `not_visible`, when
CODEOWNERS could not be read). A pull request can edit an unowned one, so
change the rules its own AI review follows, and still be merged by the bot.
The report's AI self-merge card names them, and the fixes gain: add
CODEOWNERS lines with human owners for those files.

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
approval may not cover the merged code". When the default branch rules
dismiss stale reviews (`branch_dismiss_stale=true`) and the script counts
`DISMISSED` reviews, gop says it plainly: `review_bypass_recounts_dismissed=
suspected` and the path note reads "the script re-counts approvals GitHub
dismissed". It stays a heuristic (`not_visible`).

**The merge key next to the AI.** When an AI agent step (a known agent
action or CLI) has the same secret in its env or `with:` as the merge's
token source (the private key of the App token step, or a secret in the
merging step's env), the repo gets `agent_holds_merge_key=true` and
`agent_merge_key_workflows`: a prompt injection can use the key to merge by
itself.

These add fixes after the four above (they narrow the path, they do not
close it): count only approvals of the head commit in the script (stop
counting `DISMISSED` reviews when it re-counts them), re-run the AI review on
every push, turn off "Allow GitHub Actions to create and approve pull
requests" when a `GITHUB_TOKEN` approval counts, and keep the merge key out
of the AI step.

**Reports.** The Markdown and HTML reports have an "AI approve + self-merge"
section per repo (who, why, the merging App, the setting, the script, the
suspected stale approvals and the fixes), and mark the principal's risk row
`[bot_self_merge]`. `gop sarif` writes one `GOP005`
`review-bypass-bot-self-merge` result per merge workflow line (see
[sarif.md](sarif.md)).

**Limits.** gop matches an App only by an ID or slug the workflow names
literally: it does not read the values of `vars.` (an App named that way is
possible, not confirmed); it follows only literal script paths (not
`$SCRIPT`, `python -m`, imports or a called reusable workflow), and the
stale-approval check is a text heuristic; and a scheduled job that merges
approved pull requests is not modeled.

## Agent memory across runs

Some agents keep what they "learned" between runs: notes, rules, skills or
workflows that the next run loads and trusts. If a run that outsiders can
start writes to that store and a later trusted run reads it, one crafted
comment or pull request plants instructions that every later run follows
(cross-run memory poisoning). gop reports one form of it that it can verify
from workflow files alone: the agent's state carried in the Actions cache.

### Where agents keep state in CI

| Store | Who can write it from an outsider-triggered job | Read by a later trusted run |
|-------|------------------------------------------------|-----------------------------|
| Instruction files in the repo: `CLAUDE.md`, `.claude/rules/`, `AGENTS.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.github/instructions/`, Cline's `memory-bank/` ([Claude Code](https://code.claude.com/docs/en/memory), [Copilot](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions), [Cline](https://docs.cline.bot/prompting/cline-memory-bank)) | only through a push: a job with `contents: write` (covered by `CAN_PUSH via=token_write` and the agent's write scopes) | yes, every run that checks out that ref |
| Agent home directories: `~/.claude` (Claude Code auto memory, `~/.claude/projects/<project>/memory/`), `$CODEX_HOME` / `~/.codex` (Codex memories, [docs](https://developers.openai.com/codex/memories)), `~/.gemini` ([Gemini CLI](https://geminicli.com/docs/tools/memory/)) | lost when a GitHub-hosted job ends; survives only through a cache, an artifact or a non-ephemeral self-hosted runner | yes, if restored |
| `actions/cache` entries | a save in the default branch's scope (below) | yes, by any branch's run whose key and paths match |
| Artifacts | any run can upload | only when a later run downloads them explicitly (`actions/download-artifact` with `run-id`); untrusted artifacts in privileged `workflow_run` jobs are a known risk ([GitHub Security Lab](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)) |
| A memory branch or committed notes | needs `contents: write` | yes, if checked out |
| Hosted memory: Copilot Memory ([docs](https://docs.github.com/en/copilot/concepts/agents/copilot-memory)), agentrun's per-agent learning repo (`corrections.md`, learned `workflow.json`; [agentrun](https://github.com/Parcha-ai/agentrun)), external stores reached with secrets | Copilot Memory: only users with write access; agentrun: the owner's corrections and replay-checked drafts; external stores: any job holding the secret | yes |

[anthropics/claude-code-action](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md)
and [openai/codex-action](https://github.com/openai/codex-action/blob/main/action.yml)
keep nothing between runs by themselves; persistence comes from what the
workflow adds around them.

### The cache rules

From GitHub's [dependency caching reference](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching):

- A run restores caches of its own branch or of the default branch, so an
  entry in the default branch's scope reaches every later run of every
  branch.
- `pull_request` runs, forks included, save to `refs/pull/N/merge`, which no
  other branch reads.
- Runs on events outsiders can cause that resolve to the default branch
  (`pull_request_target`, `issue_comment`, `workflow_run`, ...) get
  read-only access to the default branch's caches since 2026
  ([changelog](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/)),
  unless the workflow or job sets `cache-mode: write` or `write-only`
  ([changelog](https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode)).
  The mode is enforced with scoped cache tokens, so code in the job cannot
  write around it.
- A restore matches the key exactly, then by prefix of the key, then by
  prefix of each `restore-keys` entry, newest first. The cache version (the
  `path` list and compression) must match too.
- `github.ref` is not a scope under `pull_request_target`: it is always the
  default branch ([changelog](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/)).

Before these changes, any code in a default-branch job could write cache
entries with the runner's cache token and evict others
([research](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)).
The read-only default is documented for github.com only.

### What gop flags (GOP006)

gop sets `agent_memory_*` attrs on an agent workflow, and `gop sarif` reports
`GOP006`, when all of these hold:

1. **Write side:** an agent job with `agent_exposure=outsiders` runs on
   `pull_request_target`, `issue_comment`, `issues`, `workflow_run`,
   `discussion` or `discussion_comment`, its effective `cache-mode` (the
   job's, else the workflow's) is `write` or `write-only`, and it has an
   `actions/cache` or `actions/cache/save` step. On GitHub Enterprise Server a
   job with no `cache-mode` counts as possible (`not_visible`).
2. **Read side:** a job in any workflow of the same repo (the writer itself
   included: a later run started by a maintainer) restores with
   `actions/cache` or `actions/cache/restore` (not `lookup-only`, not
   `cache-mode: none` or `write-only`) and holds secrets, a `contents: write`
   or `id-token: write` token, or, for an agent job, any write scope.
3. **Match:** the same `path` list, and a key match by the rules above.
   Static keys give `live` evidence; when an expression decides it (the same
   `hashFiles(...)` on both sides, a static restore key longer than the saved
   key's static text) the evidence is `inferred` and `agent_memory_match` is
   `expression`. A saved key built from `github.run_id`, `run_number` or
   `run_attempt` never matches exactly, only by prefix.

`agent_memory_dirs` names the agent memory stores among the cached paths
(`.claude`, `.codex`, `AGENTS.md`, `memory-bank`, `.gemini`, `.agentrun`,
any `memory` segment, ...). A match without one is still reported: a
poisoned build cache runs in the privileged job too. The report's agent card
shows a "Memory across runs" line. Fix it by dropping `cache-mode: write`
from the agent job, restoring only, giving privileged jobs their own key
prefix, or rebuilding memory from reviewed files on each run.

Not covered: artifacts, memory branches and external stores (the read side
is a step gop cannot match to the write), non-ephemeral self-hosted runners,
caches saved by `setup-*` actions' `cache:` input, and agent steps one level
down.

## Limits

- gop reads workflow files, not runs: it does not see agents started from a
  called reusable workflow, a local composite action, a script file or a
  container, and it cannot tell what an agent actually did.
- The actor checks of actions other than claude-code-action and codex-action
  are unknown to gop and count as possible.
- Tool settings in a separate settings file or `config.toml` are not read.
