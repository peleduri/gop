# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Before v1.0 the graph schema and CLI
flags may change in minor releases.

## [Unreleased]
### Added
- "Agent paths" in `gop report`: for each AI agent workflow, the chain from
  who can start it, through the untrusted text it reads, the workflow and its
  token, the agent (flagged when it runs in a dangerous mode such as
  `--dangerously-skip-permissions`, `--yolo`, `--full-auto` or
  `danger-full-access`), the commands it runs, its secrets, what it can push
  or merge, to OIDC and a cloud role. Every hop shows its evidence level.
  The HTML report steps through each path (play, pause, step, keyboard
  arrows) and has "What if we fix it?" toggles that show where a fix cuts the
  path; hops the agent does not have are drawn dimmed. Built from the
  existing graph, no new collection; works offline under the report's CSP,
  respects reduced motion. The Markdown report lists one line per path.
- Re-collect some orgs into an existing graph from the CLI (#198):
  `gop collect --enterprise acme --orgs acme-actions --merge-into graph.json
  --out graph2.json`. The re-collected orgs' facts and coverage are
  replaced, every other org's are kept, cross-org paths survive, and
  `org_collected_at` records when each org was last read. The earlier graph
  is only read (`--out` may name the same file). The merged graph is checked
  against the JSON Schema before it is written; a stopped run writes a
  partial merged graph and exits 3. `--merge-force` merges graphs from
  different token modes (not supported). `--merge-into` needs `--orgs` and a
  graph of the same enterprise, checked before any request.
- `gop what-if --graph g.json | --demo` re-scores the graph with
  hypothetical fixes on the CLI: the `fix-plan` selectors (`--pin`,
  `--lower-default-perm [--to]`, `--restrict-token`, `--harden-trigger`,
  `--reduce-owners`), combinable and repeatable, print the confirmed and
  possible (principal, repo) pairs before and after, the paths that
  disappear and the top paths that remain, as text, Markdown or JSON
  (`--top`, `--limit`). The scoring moved to `internal/whatif`, which the MCP
  `what_if` tool now calls too, so both report the same numbers (#200).
- Deployment environment protection rules as conditions on edges (#202).
  For every secrets or OIDC edge whose jobs name an environment, `gop
  collect` reads the repo's environments (read-only REST) and records
  `env_gate` (`required_reviewers`, `none` or `unknown`), the rules
  (`env_protection`: reviewers, prevent self-review, wait timer, branch
  policy, custom rules), the deployable refs (`env_branches`), whether the
  default branch may deploy (`env_default_branch`) and the ungated jobs.
  Hops through a required-reviewer environment carry a `gate` note and the
  path is `gated`; gated terminals stay in the reach and the counts and are
  weighted at half in the score (`env_gated`). An environment gop cannot
  read, or one named by an expression, is `unknown` with a reason and a
  coverage entry, never gated. `fix_plan` for a risky trigger suggests a
  required reviewer on an environment that has none.
- More AI agent CLIs and one more agent action are recognized in workflows
  (#201), each checked against its own docs and backed by fixtures and
  near-miss tests: `copilot-cli` (`copilot -p`), `qwen-cli` (`qwen -p`),
  `goose-cli` (`goose run`), `crush-cli` (`crush run`), `cline-cli`
  (`cline "task"`, `cline --json`), `continue-cli` (`cn -p`), `amp-cli`
  (`amp -x`), `openhands-cli` (`openhands --headless`) and the
  `qwen-code-action`. `agent_tools` gains `allow_all` (Copilot CLI
  `--allow-all-tools` and `--allow-all`), reads `--allow-tool` as
  `allowed_tools`, and reads `--approval-mode yolo` (Qwen Code, Gemini CLI)
  as `yolo`.
- GitHub App push grants: an installed App with `contents: write` gets
  `CAN_PUSH` edges (`via=app_install`) from its identity to the repos it
  covers. Installed on all repositories: every repo of the org, `inferred`
  (rule `app_install`). Installed on selected repositories: GitHub lists them
  only to the App's own tokens, so every repo of the org gets a `not_visible`
  edge (possible reach) and the org a `can_push:app_install` coverage entry.
  `app_workflows=write` marks installations that can also change workflow
  files. Apps now count in reach, scores, totals and `who_can_reach`, once
  per (App, repo) pair across orgs (#199).
- The demo plants an AI agent in dangerous mode end to end (story 11).
  The public `acme-app/api` runs `claude-code-action@main` on
  `issue_comment` with no author check and `--dangerously-skip-permissions`,
  a token that can push, `id-token: write` and two secrets. Its App merges
  the pull request to `main` with no human review, `AGENTS.md` has no code
  owner, and a supplied AWS trust (`sub: repo:acme-app/*`) lets it assume
  `acme-prod-deploy`. A safer contrast, `acme-secure/infra`, runs
  `codex exec --full-auto` on a trigger only maintainers can start, with no
  secrets and one human review. Demo numbers change: 8 non-human actors, 2
  can merge with no human, 3 agent workflows anyone can start, and the top
  risks table gains a Cloud roles column.
- Detect the agentrun agent platform (github.com/Parcha-ai/agentrun) in
  workflows: `agentrun runs start` and `agentrun template eval` in `run:`
  steps (also through `npx @parcha/agentrun`) as `agentrun-cli`, and its
  server image `ghcr.io/parcha-ai/agentrun-server` as a job container, a
  service or a `docker://` step as `agentrun-server`, with the new
  `agent_source` value `image` (#185).

- A headline line for AI agents and bots, first in the report (HTML and
  Markdown) and as `headline` and `non_human` in the MCP
  `gop://graph/summary` resource: "N non-human actors; M can merge to a
  default branch without a human (C confirmed, P possible)". Non-human
  actors are confirmed AI agent workflows, workflows that approve or merge
  through a bot, review bypass Apps and bot accounts, each counted once (#188).

- Self-editable policy files: in a repo where a bot can approve or merge,
  gop reads which agent and review policy files exist on the default branch
  (`AGENTS.md`, `CLAUDE.md`, `REVIEW.md`, `.github/copilot-instructions.md`,
  `.cursorrules`, `.cursor/rules`; existence only, in the same batched
  query) and which of them no CODEOWNERS rule protects (`policy_files`,
  `policy_files_unowned`). A pull request can change those files, and so the
  rules its own AI review follows, and still be merged by the bot. The AI
  self-merge section, the fix plan and SARIF add a CODEOWNERS fix (#190).

- GitHub App inventory: for each org the token owns, gop lists the installed
  GitHub Apps (`GET /orgs/{org}/installations`; GitHub requires an org owner,
  and Organization Administration: read for fine-grained tokens and Apps).
  Each App becomes an identity `identity:<slug>[bot]` with `app_id`,
  `app_slug`, `app_orgs`, `app_write` (its write permissions), `app_repos`
  (`all` or `selected`) and `app_ai=name` when its slug names an AI tool. The
  org gets `app_installations` (a count, or `unknown` with a coverage entry
  for orgs the token does not own); `gop doctor` predicts it (#192).

- Project governance and community files, following the CNCF project
  template: `GOVERNANCE.md` (maintainer-led: decision making, adding and
  removing maintainers, conflict resolution, changing the governance),
  `MAINTAINERS.md` (with how to become a maintainer), a contributor ladder
  and a written test policy in `CONTRIBUTING.md`, `ADOPTERS.md` (empty, with
  how to add yourself) and a public `ROADMAP.md` without dates. The code of
  conduct is now the CNCF Code of Conduct, reported privately to the
  maintainers. New `docs/cncf.md` cites the current CNCF Sandbox and
  OpenSSF Best Practices requirements, checks the repository against them
  (met and not met, with evidence), and holds a draft Sandbox application
  that has not been submitted. The README links all of these from a new
  Community section.
- Partial graphs, request budgets and org priority for `gop collect`
  (#176). A collection stopped by Ctrl-C or SIGTERM, by
  `--max-requests N`, by an exhausted rate limit or by `--reserve` now
  writes the graph it has instead of nothing: top-level `"partial": true`
  and `partial_reason` (`interrupted`, `max_requests`, `rate_limit`,
  `reserve`; additive, still `gop.graph/v2`), everything not yet read
  `not_visible`, and one coverage entry per org and phase it did not finish
  (fact `phase:<phase>`, reason `not collected: run stopped`). It exits 3.
  `gop validate` warns at `/partial`, the report (HTML and Markdown) opens
  with a partial banner, and the MCP summary (`partial`, `partial_reason`),
  prompts and tool summaries (`[partial graph]`) say so. With `--cache-dir`,
  `--resume` completes the run. `--priority a,b` collects those orgs first;
  the rest go by member count, largest first. `--reserve N` keeps N
  requests of the hourly budget unspent for other jobs on the same token,
  waiting for the reset instead. Library: `collect.Config.MaxRequests`,
  `Reserve` and `Priority`; `Collect` returns the partial graph with a
  `*collect.PartialError`.

- Incremental collection (#175). `gop collect --cache-dir DIR --incremental`
  re-reads only what changed since the previous incremental run with the
  same directory. Org-level reads are always repeated; every per-repository
  answer (REST `/repos/{owner}/{repo}/...` and each repository's alias of
  the batched GraphQL queries) is recorded with the repository's stamp
  (`id`, `pushed_at`, `updated_at`, default branch, visibility, archived)
  and answered from the record, without a request, while the stamp is
  unchanged. A changed repository's workflow files whose blob SHA did not
  change are not downloaded again either. The collector runs on those
  answers exactly as in a full run, so the graph equals a full collection's
  and deleted repositories and workflows drop out. Reused facts keep their
  original `observed_at`. gop logs `N repos re-read, M reused`. A full run
  happens every `--full-every` days (default 7) and whenever the schema,
  enterprise, host, `--orgs` or token change. Settings GitHub does not
  reflect in `updated_at` (a new direct collaborator, a branch protection or
  org ruleset edit) are picked up by the next full run. The records live in
  `DIR/replay`, with `DIR/incremental.json` and `DIR/incremental-graph.json`
  (docs/threat-model.md).
- Plugin icon and Cursor logo, and a `version` in every plugin manifest (Claude Code, Cursor, Codex) so `claude plugin validate --strict` passes for directory submission. A test keeps the versions in step; bump them with each release.
- Parallel org collection in GitHub App mode (#174). Each org installation
  has its own hourly rate-limit budget, so `gop collect` now reads several
  orgs at once, each on its own installation token: `--parallel N` (default
  4, at most 16; `1` is sequential). Workers prefetch one org each and the
  graph is built by the usual sequential pass from their responses, so the
  output is identical byte for byte at any `--parallel`. Rate limits are
  tracked per installation: a 403 or 429 rate limit (honoring `Retry-After`)
  pauses only that installation's requests, and progress lines show the
  remaining budget of the installations closest to running out (new
  `Progress.Installations`). `gop doctor` estimates App mode with
  per-installation budgets and `--parallel`, and in token mode, when the
  estimate is above 3 hours or 2 rate-limit resets, prints a recommendation
  to use App mode with its expected time and a link to
  docs/github-app-token.md (`recommendation` in `--format json`).
  docs/github-app-token.md explains the speed-up for large enterprises.

- `NOTICE` file: the copyright line, the attribution that redistributions must keep (Apache-2.0 section 4(d)), and a note that the license grants no rights to the gop name or logo (section 6). Release archives include it.

- One-step installs in AI assistants (#163). The repository is a Claude Code
  plugin marketplace: `/plugin marketplace add peleduri/gop` and
  `/plugin install gop@gop` add the MCP server (asking for the graph.json
  path) and the gop skill. Every release attaches a Claude Desktop extension
  per platform, `gop_<version>_<os>_<arch>.mcpb` (MCPB manifest 0.3 with the
  binary bundled; in `checksums.txt`, so covered by its cosign signature and
  provenance). New `server.json`: stable releases are published to the
  official MCP Registry as `io.github.peleduri/gop` by a new `mcp-registry`
  release job that logs in with GitHub OIDC (no stored secret), listing the
  GHCR image (now labelled `io.modelcontextprotocol.server.name`) and the
  `.mcpb` bundles. Cursor install links (README, site,
  `gop mcp-config --client cursor-link`), Cursor and Codex plugin manifests
  that carry the skill, and `gop mcp-config --client codex` (a
  `codex mcp add` command). The site has `llms.txt`, `llms-full.txt` and a
  FAQ. docs/mcp-clients.md cites the client docs each format was checked
  against; docs/maintainers.md has the registry and directory steps. New
  `scripts/dist` builds the bundles and the registry `server.json`; its tests
  check them against copies of the published schemas.

- Bot self-merge in the HTML report and SARIF, the Actions-approve setting,
  App-to-bypass matching and dismissed approvals re-counted (#164). The
  redesigned HTML report gets an "AI approve + self-merge" section (who, why,
  the merging App, the setting, the script, suspected stale approvals and
  the fixes, linked from the nav) and the `[bot_self_merge]` marker on risk
  rows. `gop sarif` adds rule `GOP005` `review-bypass-bot-self-merge`: one
  result per merge workflow line, at the merging step, with
  `bot_merge_fixes` and the `block_bot_merge` fix. `gop collect` reads
  "Allow GitHub Actions to create and approve pull requests"
  (`can_approve_pull_request_reviews`, read-only, repo then org) for repos
  with a `GITHUB_TOKEN` bot approval, so that approval is confirmed or ruled
  out instead of possible (`actions_can_approve_prs`). The App a merge mints
  for (an `app-id` or slug the workflow names literally, or `APP_ID` beside
  a `*_PRIVATE_KEY` secret: `bot_merge_apps`) is matched against the bypass
  Apps of the default branch rules (`branch_bypass_apps`, from ruleset and
  classic bypass actors): only a match confirms an `app_bypass` review
  bypass, an unmatched or unnamed App leaves it possible
  (`review_bypass_app_match`). When the rules dismiss stale reviews and the
  merge script counts `DISMISSED` reviews, the path note says "the script
  re-counts approvals GitHub dismissed" (`review_bypass_recounts_dismissed`,
  still heuristic). Scores of unrelated principals are unchanged.

- Agent and exec detection one level down (#165). For workflows with a
  risky trigger or `pull_request`, `gop collect` now follows one level of
  indirection: a local composite action a step loads (its `action.yml`
  from the default branch), a reusable workflow the job calls in the same
  repo or org (it runs with the caller's event, so who can start the
  caller starts it; one the nested expansion already read is reused), and
  a repo script a `run:` step invokes while holding a secret or model API
  key (scanned for agent CLIs and model API calls; a model API call alone
  is `llm-script`, possible reach only, and needs attacker text to reach
  it). Agents found there add `composite`, `reusable` or `script` to
  `agent_source`; checkout and injection patterns inside composite actions
  and reusable workflows count too, with the edge's `file` and `line` at
  the step (or the caller's `uses:` line for another repo's workflow). Each
  file is one read-only contents GET through the response cache (at most
  10 per workflow, 256 KiB each, shared with the bot script reader); an
  unreadable file is a `follow:<path>` coverage entry. `gop doctor`'s
  request estimate counts these reads. A known agent step that reads a
  checkout of the pull request's head (directory input, working directory
  or a path such as `pr/` in its prompt) now gets `pr_content` in
  `agent_prompt_injection`. `gh pr checkout` and `git fetch origin pull/`
  count as `exec=checkout` only when a later command or step runs code
  from them (else `untrusted_checkout=read_only`), matching the rule for
  `actions/checkout`. `harden_trigger` titles now say the kind: "Harden
  <workflow> (untrusted code runs on <triggers>)" or "(untrusted text
  reaches an AI step on <triggers>)", in fix-plan, the report and MCP.

### Fixed
- `gop serve` now answers requests that arrive just before its input closes.
  A client that wrote its requests and closed stdin at once
  (`echo '...' | gop serve`, scripts, CI) got no replies and exit 0, because
  the session ended on EOF while replies were still being computed. The
  server now holds the end of input until every request read has a reply
  (at most 30 seconds).
- Consistency fixes (#166). `gop fix-plan --format text` escapes names the
  way the markdown checklist does (control, bidi and zero-width characters
  as visible `\n`, `\u202E`, ...). `sanitize.NoAutolink`, and so the
  fix-plan markdown and every other Markdown output that uses it, also
  breaks email autolinks (`alice\@example.invalid`, also after `mailto:`)
  and angle-bracket autolinks (`\<scheme:...>`, `\<alice@...>`), while a
  `<sha-of-main>` placeholder stays as written. The Cypher export's
  `GOP_REACHES` now follows the pair model of #147, like the SQL `reach`
  table: what an identity reaches only through its org membership is one
  edge from `members:X`, not one more per member (docs/cartography.md has a
  query for a person's full reach). `gop diff` computes scores and totals in
  one traversal per graph (`graph.Index.ScoresAndTotals`). The HTML report's
  Explore view shows each hop's note (branch protection, hardening, bot
  merge) next to the hop. `--advisories-live` follows `next_page_token` in
  OSV `querybatch` results, so a package with many advisories is no longer
  cut at the first page.
- skills/gop/README.md installed the skill for Codex into `~/.codex/skills`;
  Codex loads user skills from `~/.agents/skills`.

### Changed
- Direct collaborators are read in batched GraphQL queries (#177): one
  `collaborators(affiliation: DIRECT)` query per 25 repositories of an org
  replaces one REST `GET /repos/{o}/{r}/collaborators` per repository. A
  repository falls back to REST when its alias fails (no push access, not
  found), when it has more than 100 direct collaborators, or when a
  collaborator's role may be a custom or organization role, which only REST
  names; batching off (`DisableGraphQLBatch`) or an older GHES schema uses
  REST throughout. Both paths give the same graph, coverage and not-visible
  summary. On the test fixture REST requests drop from 67 to 55.
  Default-branch protection was already batched (#133); the other per-repo
  REST reads (Actions workflow permissions and access level) have no GraphQL
  equivalent. `gop collect` progress lines show the GraphQL points spent
  (each query's `rateLimit { cost }`, else 1), and the `gop doctor` estimate
  splits requests into REST requests, GraphQL queries and GraphQL points
  (new JSON fields `rest_requests`, `graphql_queries`, `graphql_points`;
  `requests` is their total) and checks the points against the GraphQL
  budget.
- The demo graph shows the newer features (#167). `gop demo` and
  `gop report --demo` now plant three more stories: carol, dave and erin own
  five or more orgs each while every org keeps two local owners, so their
  risk row is grouped by cause and the first suggested fix is
  `reduce_owners`; the public `acme-app/web` has an AI approve + self-merge
  chain (`ai-review.yml` approves with an App token, `ai-merge.yml` merges in
  `tools/merge.py` with App `77`, a bypass actor of the rules on `main`), so anyone
  who can open a pull request lands code on `main` with web's OIDC trust; and
  `acme-actions/deploy` (one approval) and `acme-actions/setup` (not
  protected) carry branch protection notes on the top paths. The small size
  is now 7 orgs and about 65 repos (was 5 and about 60), and `acme-secure`
  keeps only its two planted repos at every size. Demo goldens, the site
  figures and every report screenshot in `docs/assets` are regenerated from
  it, plus a new `report-agents.png` of the AI agents and AI approve +
  self-merge sections. Demo numbers changed: the widest confirmed reach is now the three
  owners (54 to 55 repos), and the top fix removes 42% of confirmed reach.

## [0.6.0] - 2026-11-24
### Added
- Agent-behaviour eval for the MCP server and skill (#151). New `evals/`
  (Python, outside the Go module) runs a model with `skills/gop/SKILL.md` as
  its system prompt against `gop serve` on the acme fixture and on hostile and
  semantic-injection variants of it, over 25 synthetic cases in four groups
  (correctness, no overclaiming, refusal, injection). Expected values are read
  from gop for each case, never written by hand. Deterministic checks fail a
  case whatever the judge says: `check_answerable` was called, confirmed
  numbers match gop's, no possible-plus-confirmed sum, nothing gop could not
  see called safe or off, rejected only on a `yes`, refusal when gop says
  `no`, and no write action. DeepEval's `ToolCorrectnessMetric`,
  `MCPUseMetric` and two `GEval` criteria score on top, with any
  OpenAI-compatible agent and judge (Ollama works). `python -m evals.run`
  writes `evals/out/scorecard.{json,md}` with per-group pass rates;
  `--skill-variant` removes one skill rule so `python -m evals.compare` can
  show a broken skill scores lower. `python -m evals.run --dry` needs no
  model or key: it checks the gop-derived expected values and replays
  recorded good and bad transcripts through the checks; CI runs it on every
  pull request (`evals-dry`). The live eval runs in the new
  `.github/workflows/evals.yml` by hand or weekly, never on pull requests,
  with the `EVAL_MODEL_API_KEY` secret; a test runs gop's own workflow parser
  on it and finds no `agent_exposure=outsiders`. The
  hostile and semantic graphs it serves are `testutil.HostileGraphJSON` and
  `testutil.SemanticGraphJSON` of the acme fixture, committed in
  `evals/fixtures/` and kept equal by a Go test. New `docs/evals.md`.
- Bot self-merge in scripts, stale approvals and merge keys held by AI
  steps (#152). A `run:` step that invokes a repo script (`python3
  tools/merge.py`, `node`, `bash`, `npx tsx`, `go run ./path`) with a token
  or key in its env is followed: `gop collect` reads the script from the
  default branch with one read-only contents GET (through the response
  cache, 256 KiB cap, never executed) and scans it for the merge and approve
  calls of #146 plus PyGithub `pr.merge()` and `create_review(event=
  "APPROVE")`. A merge found there feeds the same review-bypass join and is
  recorded as `bot_merge_source=script:<path>`; the path note names the
  script. A merge script that counts `DISMISSED` reviews as approvals, or
  compares a review's `commit_id` with the head and still counts it, gets
  `bot_merge_stale_approvals=suspected` with confidence `heuristic`
  (`not_visible`, with a coverage entry asking for a manual check); when the
  approving workflow also does not re-run on `synchronize`, the repo gets
  `review_bypass_stale_approval=suspected` and the path note adds "the
  approval may not cover the merged code". An AI agent step that holds the
  same secret the merge's token comes from sets `agent_holds_merge_key=true`.
  Each adds a fix after the four of `block_bot_merge` (head-commit approvals
  only, re-review on push, keep the merge key out of the AI step), in the
  report, `explain` and `fix-plan`. `gop doctor` counts the script reads in
  its request estimate.
- Semantic and lookalike prompt-injection names in the hostile-name corpus
  (#154). Beside the structural values (newlines, tags, bidi, zero-width,
  10 kB), `internal/testutil/hostile.go` now has printable names the
  sanitizer leaves unchanged: a plain-ASCII instruction repo, a repo that
  imitates gop's output fields, a workflow file holding a fake JSON tool
  result, a Markdown link login and image file name, and a mixed-script
  lookalike of `acme-app/web` added beside the real one. `TestHostileNames`
  and the report tests run every MCP tool, the markdown, drift and HTML
  reports and the fix-plan markdown on that graph and check that names stay
  inside backticks in summaries, the JSON copy decodes to exactly the
  structured output, no name starts a line or becomes a live link, and the
  lookalike stays a separate node with its own ID. The corpus is exported as
  `testdata/hostile/payloads.json` for agent evals; a test keeps it equal to
  the Go values. `docs/threat-model.md` says lookalike names are kept
  distinct but not flagged.
- AI approve + self-merge (#146). `gop collect` marks workflows whose jobs
  submit an approving review (`gh pr review --approve`, a reviews API call
  with `APPROVE`, an approve action, or an agent allowed to run
  `gh pr review`) or merge a pull request (`gh pr merge`, the merge API, an
  automerge action) with `bot_approves` / `bot_merges`, the token source
  (`app`, `pat`, `github_token`), who can make the job run (`pr_openers`,
  `org_members`, `pushers`, `maintainers`) and the merge job's actor check
  (`pr_author`, `author_association`, ...). After branch protection is read,
  a repo where a PR author can start a bot merge that needs no human review
  (the merging App is a bypass actor, `--admin` with an admin bypass, bot
  approvals cover the required reviews with no CODEOWNERS review, or no
  protection) gets `review_bypass=bot_self_merge`, and the people who can
  open a pull request get a new `CAN_MERGE_VIA_BOT` edge to it, which the
  engine treats like push: `live` when both workflows and the bypass list
  were read, `not_visible` when the bypass list or required reviews are
  unknown. `top_risks` and the report's risks table mark
  `[bot_self_merge]`, the `CAN_MERGE_VIA_BOT` hop and `CAN_PUSH` hops into
  the repo carry the note "a PR author can get code onto `main` without
  human review: <approve workflow> + <merge workflow>", the report gains an
  "AI approve + self-merge" section, and a new `block_bot_merge` fix
  (`what_if`, `suggest_fixes`, `fix-plan`) lists the four changes: require a
  human CODEOWNERS approval, remove the App from the bypass actors, stop PR
  authors from triggering the merge, and keep approve rights from the
  reviewer. Scores of principals without the edge are unchanged. See
  `docs/agents-in-ci.md` "AI approve + self-merge".
- Ollama and vLLM steps in CI (#153). A `run:` step that prompts a local
  model with `ollama run MODEL "..."`, `ollama run MODEL --ask "..." < file`
  or `... | ollama run MODEL` is the agent kind `ollama-cli` (gate `none`);
  `ollama pull`, `ollama serve` and a bare `ollama run MODEL` are not agent
  runs. `OLLAMA_API_KEY` and `VLLM_API_KEY` count as model API keys for the
  `llm-script` heuristic. A CLI step whose script reads the pull request's
  diff or text (`gh pr diff`, `gh pr view`) now gets `pr_content` in
  `agent_prompt_injection`.
- First-run onboarding (#142). The README opens with the story (AI agents in
  CI and cross-org reach), the redesigned report as the hero image, "Try it in
  60 seconds" (`gop report --demo` with no token, then `doctor`, `collect` and
  `report`), what you will see, "read-only, local, never phones home", and
  links to the site (https://peleduri.github.io/gop/), docs, agent skill and
  AI agents guide. The Roadmap lists only unshipped work; shipped items
  (branch protection and rulesets, AI agents in CI, OSV advisories,
  actions.lock, cause grouping, report redesign, `gop diff`) moved to the
  feature list, and a repeated `gop diff` paragraph is gone. New
  `docs/quickstart.md` (token or GitHub App in the fewest steps) and
  `docs/compare.md` (zizmor, poutine, Legitify, OpenSSF Scorecard, Gato-X,
  GitHub security overview and CSPM/ASPM, each claim linked to the tool's own
  docs, with where each is stronger than gop). Issue forms "I ran gop" (label
  `ran-it`) and "False positive or false negative" join the bug and feature
  forms, each with a reminder to use synthetic names and `gop redact`;
  `config.yml` links the quickstart, docs and comparison; new `SUPPORT.md`.
  `docs/demo.tape` now records `doctor`, then the demo report's verdict, AI
  agents section and fixes, with no token. The docs tests check every
  relative link in the top-level Markdown files and `docs/`, and the issue
  forms' structure.
- Project site (#141). `site/index.html` is a one-page landing page
  published to GitHub Pages by a new `pages.yml` workflow (actions pinned by
  SHA, `contents: read` for the build, `pages: write` and `id-token: write`
  only in the deploy job). It tells the story in one line, quotes the
  synthetic demo's AI agent, cross-org reach and fix figures, and embeds the
  demo report, which `site/build.sh` regenerates from the current source
  with `gop report --demo` on every publish. No scripts, web fonts, external
  assets or analytics; the page passes a strict CSP. `go test ./site/`
  checks the CSP hash, every link, and that each quoted figure still matches
  the demo report. Setup steps are in `docs/maintainers.md`.
- AI coding agents in GitHub Actions (#139). `gop collect` marks workflows
  that run a known agent action (`anthropics/claude-code-action`,
  `claude-code-base-action`, `openai/codex-action`, the Copilot coding agent
  setup job, AI reviewers) or an agent CLI in a `run:` step (`claude -p`,
  `codex exec`, `cursor-agent`, `gemini`, `aider`, `opencode`, `llm`) with
  `agent=<kind>` and risk facts: the action's actor check (`agent_gate`, read
  from inputs such as `allowed_non_write_users` and `allow-users`), who can
  start it (`agent_exposure`), untrusted contexts in the prompt, token write
  scopes, secrets, runner and tool settings such as
  `--dangerously-skip-permissions`. A name-only match is weak
  (`agent_confidence=name_only`) and never ranked. Agents that people without
  push access can start get `CAN_TRIGGER` edges with `exec=agent`
  (`not_visible` when gop does not know the action's actor check). A new rank
  factor `agent_exposed`, after advisories and poutine, puts a principal that
  can start such an agent while it holds write, secrets or OIDC first; scores
  and counts are unchanged. The report gains an "AI agents in CI" section,
  SARIF gains rule `GOP004 agent-workflow-exposed`, `top_risks` marks
  `[agent_exposed]`, `explain` adds an agent note, and the demo graph gets an
  agent story. The agent table lives in one file
  (`internal/collect/agenttable.go`). See `docs/agents-in-ci.md`.
- Top risks group by cause (#137). After the exact groups of #125, principals
  whose confirmed repos come at least 90% through the same cause (org
  ownership, one team, or membership of one org) and whose confirmed reach
  overlaps by Jaccard 0.9 or more share one row: "4 owners of 18 to 20 orgs"
  with the range of their repos and orgs ("54 to 56"). A direct collaborator
  grant is never a shared cause. The report's row expands to each member's
  own figures, and `top_risks` adds `cause`, `cause_scope`, `range` and (with
  `detail: full`) `member_scores`. When the top row is a cause group, the
  report headline and the `top_risks` summary name the cause ("4 accounts that
  own 18 or more orgs can each push code that runs in ...; the cause is
  standing org ownership"), never one member picked by tie-break. Scores,
  counts and rank order are unchanged.
- Org ownership concentration: a report block and a `gop://graph/summary`
  `org_ownership` field with how many accounts own 1, 2-4, 5-9 and 10+ orgs
  (the JSON lists them) and the share of confirmed (principal, repo) pairs
  that depend on standing org ownership.
- New fix kind `reduce_owners`: remove standing org ownership from accounts
  that own N or more orgs (default 5), keeping at least 2 owners in each org
  (the accounts over the threshold that own the most orgs stay where an org
  needs them). `what_if` and `fix_plan` take `{type: "reduce_owners",
  threshold}`, `suggest_fixes` ranks it by measured impact with a caveat that
  recommends just-in-time ownership (`owner_threshold` input), and the CLI has
  `gop fix-plan --reduce-owners N` and `gop report --owner-threshold N`.

### Fixed
- A name can no longer render as a live link or image in Markdown output
  (#154). The fix-plan markdown, the drift markdown and the markdown report
  escape the `](` of link and image syntax and break bare `http://`,
  `https://`, `ftp://` and `www.` autolinks in names that sit in prose
  (`sanitize.NoLinks`, `sanitize.NoAutolink`); the text renders the same.
  `gop fix-plan --format markdown` now escapes names like the `fix_plan`
  tool does (control, bidi and zero-width characters, backticks in code
  spans): the escaping moved into `fixplan.WriteMarkdown`.
- A `pull_request_target` or `workflow_run` job that checks out the pull
  request's head is no longer counted as running untrusted code unless a later
  step runs code from that checkout (#145). gop now counts it as execution
  when the checkout is at the workspace root (or an unresolvable path) and any
  step follows, when a `uses: ./<path>/...` local action loads from it, when a
  `run:` step works in it (`working-directory`, job `defaults.run`, `cd`), or
  when a command runs a file, script or build from it (`pr/build.sh`,
  `bash pr/x.sh`, `npm --prefix pr ci`, `make -C pr`, `pip install -e pr`,
  `go run ./pr/...`, `docker build pr`). A checkout into a subdirectory that
  only trusted base-branch code reads makes no `CAN_TRIGGER` edge and is no
  longer ranked or suggested as a `harden_trigger` fix; the workflow gets
  `untrusted_checkout=read_only` (`exec` when a job runs it). When such code
  feeds the pull request's content to a model (a step holding
  `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or a similar key that names the
  checkout, runs `gh pr diff`/`gh pr view`, or reads attacker contexts), gop
  records an `llm-script` agent with `agent_confidence=heuristic` and
  `agent_prompt_injection` including `pr_content`, with `not_visible`
  `CAN_TRIGGER` edges (possible reach only). A job `if:` that checks the
  comment or review author's `author_association` now narrows who can
  trigger it: `MEMBER` gives the org's members, `OWNER`/`COLLABORATOR` alone
  give no edge and a coverage entry, and `CONTRIBUTOR` still counts outside
  contributors; the edge records `author_association`. `harden_trigger` steps
  now say whether untrusted code runs or untrusted text reaches an AI step
  holding secrets.
- `gop doctor` no longer states a repo total for an org the token does not
  own (#135). The enterprise GraphQL `repositories { totalCount }` counts only
  the repositories the token can see there, so it could print "the org has 0"
  for an org with many private repositories. For such an org doctor now keeps
  the larger of that count and `GET /orgs/{org}` `public_repos`, prints it as
  "at least N visible to this token; the real total needs org owner" (or the
  count as unknown when the token sees none), and in `--format json` sets
  `repos_source: "visible_to_token"` and `repos_lower_bound: true`. The
  estimate says its repo count and requests are lower bounds when any org is
  not owned. An owned org keeps its exact count.
- Pair totals no longer count an org's default-permission reach once per
  member (#147). A member that is scored for another reason (a team that
  grants nothing, a grant in another org) also reached everything
  `members:X` reaches, and `what_if`, `suggest_fixes`, `fix-plan`, `gop diff`,
  the report and the SQL export summed it again for each such member, so
  "removes N of M confirmed pairs" overstated lowering a default permission
  and changed when people joined unrelated teams. Totals and fix gains now
  count reach held only through `members:X` once, on the population's row;
  a member's own grants and teams still count for the member, and individual
  scores (`blast_radius`, `top_risks`, per-principal `what_if`) still show
  the full personal reach. The SQL export's `reach` table follows the totals
  (an identity's rows leave out reach held only through its org membership),
  and `graph.Index.Totals` and `PairReach` replace `graph.TotalsOf`. On the
  demo, lowering the default permission of acme-actions now removes 50% of
  confirmed reach (34 of 68 pairs), not 58% (47 of 81).

## [0.5.0] - 2026-11-24
### Added
- Principals with identical reach share one row in the report's top risks
  table, the `top_risks` MCP tool and `gop sarif` messages. Two principals group
  only when their confirmed reach is the same set of targets and every score
  field matches, never on equal counts alone; an org's members (a population
  with its own name) never fold into a group. A row names what its members share
  ("14 principals (org owners of acme-security)", or a team), and the report
  headline names the group ("The 14 owners of acme-security can push code that
  runs in ...") instead of one owner picked by tie-break. `top N` counts rows,
  the text lists the first members and "and N more", and the JSON lists every
  member in `members` with the shared `via` and `via_scope` (brief
  `total.risks` counts rows too); the row's other
  fields are its first member's score, so the JSON shape is otherwise unchanged
  and `paths`, `explain` and `blast_radius` work on any member. A `gop sarif`
  message folds a group only when it has more members than the message names;
  its principal lists stay complete. Scores, counts and the rank order are
  unchanged: grouping is presentation only.
- Org settings and hardening context (#126). The report's Org settings
  section (HTML and Markdown) now has one row per org with SSO, 2FA, IP allow
  list, default permission, member capabilities and members; a setting gop
  could not see reads `unknown`, linked to a "Why unknown" list with the
  coverage reason and the access that fixes it. For an org owner token,
  `gop collect` adds the org attrs `ip_allow_list_entries` (active entries,
  count only, never the IP ranges) and `ip_allow_list_apps` (`on`, `off`,
  `unknown`), in the JSON Schema, `docs/schema.md` and the redaction default
  attrs, with no schema bump. A confirmed or possible path whose target repo's
  org has SSO not enforced or an IP allow list not on gets a context note: a
  line in the report's Top paths and `target_org_hardening: {org, sso,
  ip_allow_list}` in `paths`, `who_can_reach`, `explain`, `gop paths` and
  `gop who`; `top_risks` lists those orgs for the principals it returns.
  Context only: evidence levels, counts, scores and rank order do not change,
  and unknown is never shown as off. The `gop://graph/summary` resource and a
  new `org_settings` view in the SQL export carry the same per-org settings.
- Repo hardening context: `gop collect` records each non-archived repo's
  default-branch protection (classic branch protection and repo, org and
  enterprise rulesets merged into one effective view: protected, required
  reviews, code owner review, stale review dismissal, last push approval,
  status checks, signed commits, force push, push restrictions, bypass actors
  and whether admins or apps can bypass, with the source of each value),
  CODEOWNERS (present, valid, covering `.github/workflows/`) and secret
  scanning, push protection and validity checks. Protection is one batched
  GraphQL query per 25 repos (REST fallback); CODEOWNERS rides in the batched
  workflow read and secret scanning in the repo listing, so the extra cost is
  small (`gop doctor`'s estimate counts it). What the token cannot read is
  `unknown` with coverage, never unprotected. `CAN_PUSH` hops get notes ("push
  needs 2 approvals to reach `main`", "push reaches the default branch
  directly") in `paths`, `who_can_reach`, the CLI and the report; the report
  has a "Repo hardening" section with a per-org rollup and the repos on top
  paths; `explain` shows a repo's effective protection; `suggest_fixes` lists
  advisory `require_reviews` and `enable_push_protection` suggestions that
  `fix_plan` and `what_if` accept and that never count as removing reach.
  Scores, counts and rank order are unchanged. New repo attrs are additive to
  `gop.graph/v2` (JSON Schema, `docs/schema.md`, redaction defaults).
- `skills/gop/SKILL.md`: an agent skill for MCP triage. It walks the agent
  through checking the graph (`gop validate`, or `gop doctor` then
  `gop collect`), `coverage` and `check_answerable` before any claim,
  `top_risks`, `paths` and `explain` for each risk, and `fix_plan`, and makes it
  report every finding as confirmed, needs validation (possible reach, an
  `inferred`, `supplied` or stale `audit` hop, or a partial answer) or rejected,
  with gop's evidence levels, never adding possible counts to confirmed ones,
  and naming what gop could not see. It treats names and attributes in the
  graph as untrusted data. `skills/gop/README.md` covers installing it for
  Claude Code, Codex and other agents. A test in `skills/` parses the
  frontmatter and fails if the skill names an MCP tool, tool argument or field,
  or CLI command that does not exist.
- `gh gop`: gop as a precompiled GitHub CLI extension that reuses the `gh`
  login. goreleaser also builds the same program as bare `gh-gop-<os>-<arch>`
  binaries (`.exe` on Windows; the names `gh extension install` matches) on
  every release, listed in the signed `checksums.txt`; the `gop` binary,
  archives, image and cask are unchanged. Installing with
  `gh extension install peleduri/gh-gop` needs the `peleduri/gh-gop`
  repository, which does not exist yet: the one-time setup, a workflow that
  verifies and copies the binaries into its releases, is in
  `docs/maintainers.md`.
- `--use-gh-auth` on `collect`, `doctor` and `pin`: take the token of the
  `gh` login (`gh auth token --hostname HOST`) instead of `GITHUB_TOKEN` or
  `GH_TOKEN`. The order is the flag, then `GITHUB_TOKEN`, then `GH_TOKEN`,
  then, only when `gh` started gop as an extension (`GH_EXTENSION=1`), the
  `gh` login. A plain `gop` run never calls `gh` without the flag. With the
  `gh` login gop follows `GH_HOST` to a GitHub Enterprise Server
  (`--github-url` wins), prints which host's login it used and never prints
  the token. `--use-gh-auth` and GitHub App mode are mutually exclusive.
- `--verbose` on `collect` (or `GOP_VERBOSE=1`): log every per-repository
  not-visible error as it happens, as before.
- Actions pinned by a repo's `.github/workflows/actions.lock`
  ([gh actions-lock](https://github.com/github/gh-actions-lock)) count as
  pinned. `gop collect` reads the lockfile from the workflow listing (no extra
  request on the batched path; a 404 or no listing entry means no lockfile)
  and marks each workflow `USES` edge `actions_lock=locked` (with
  `locked_sha`) or `stale` (with `lock_entry` / `lock_missing` and a
  coverage entry), and the repo `actions_lock=true`. A locked edge needs the
  lockfile to pin the nested refs gop saw under the action too. The engine
  drops the control hop of a locked edge, so reach through it goes away for
  that workflow only; a stale entry counts as unpinned. `suggest_fixes` no
  longer proposes pinning an action every use of which is locked, `fix_plan`
  and `gop pin` leave lockfile-governed `uses:` lines alone and list stale
  entries ("rerun gh actions-lock"), and the report and the MCP summary
  (`action_pins`) split "pinned in workflow" from "pinned by actions.lock".
  Format and matching rules: [docs/actions-lock.md](docs/actions-lock.md).
- Known compromises from OSV GitHub Actions advisories. `gop advisories update`
  downloads the OSV `GitHub Actions` export (`all.zip`) into the user cache
  dir; `gop collect` matches every action ref against that copy, or against
  `--advisories <zip|dir>`, or the OSV API with the opt-in
  `--advisories-live` (only package names are sent); `gop enrich` takes the
  same flags for an existing graph. Tags are matched against the advisory's
  ranges and versions, full SHAs against its listed commits; a branch, an
  unlisted SHA or a moving tag that spans the fix is reported as unknown (a
  coverage entry), never as safe. Affected action_ref nodes get
  `advisories`, `advisory_severity` and `advisory_fixed` (no schema bump; in
  the default redaction attrs, with advisory IDs renamed). With no data the
  check is skipped with a coverage entry and the run goes on. Every action
  with an advisory and confirmed reach becomes its own `top_risks` and report
  entry, and any entry whose confirmed paths run through one ranks above
  every entry without (`Score.advisories`); SARIF gets rule `GOP003`
  (`action-with-known-advisory-reachable`), sorted first; `fix-plan --pin`
  on such an action moves each line to the first fixed version or a SHA after
  it. The demo graph plants one (`acme-oss/checkout-ish@v2`). See
  `docs/advisories.md`.
- `gop enrich --poutine <report.json>` imports a
  [poutine](https://github.com/boostsecurityio/poutine) JSON report (format
  checked against poutine v1.1.6; gop never runs poutine). Each finding maps
  to its workflow node by repo and file and sets `poutine_rules`,
  `poutine_severity`, `poutine_jobs` and `poutine_file`. Findings that match no
  workflow (repo outside the graph, composite action, non-GitHub purl, no
  path) are printed and listed in coverage as `poutine_finding`, never
  dropped. A new, separate rank factor `poutine_injectable` (confirmed-reached
  workflows with an `injection` or `untrusted_checkout_exec` finding) ranks
  such principals first in `top_risks` and the report; scores, counts and
  evidence are unchanged, and poutine is cited as its own source. SARIF and
  malformed files fail with a clear error. See `docs/poutine.md`.

### Changed
- The HTML report is redesigned. It opens with a verdict: the posture
  (critical, high or moderate exposure, from the worst confirmed severity in
  the top risks, as in `gop sarif`), the headline, the first fix, and six
  figures: confirmed repos and orgs, cloud OIDC trusts, secret scopes and
  self-hosted runners for the principal with the widest confirmed reach, the
  top-risk count, and coverage (orgs gop could fully see). Possible reach is a
  separate, weaker figure and is never added to a confirmed one; with no
  confirmed reach the verdict never reads as safe while anything was not
  visible. Suggested fixes are ranked choke-point cards with the share of
  confirmed reach each removes, the cumulative share and a one-line reason.
  Top risks show an impact pill ("High impact": the severity of confirmed
  reach, kept apart from an advisory's own severity), an impact bar (cloud
  roles, OIDC, secrets, runners) and the advisory and poutine markers; a
  principal with possible reach only reads "possible only", never "low". "What gop could not see" moves up and is
  grouped by the access that would close it ("Org owner needed on 1 org").
  Paths are collapsible hop chains with an evidence badge on every hop and the
  source API on hover or focus, plus the target-org hardening context note;
  they stack on narrow screens. Org settings are a heat grid over every
  setting column (strong, weak, or unknown linked to why). The report has
  light and dark themes and a print stylesheet (A4 or Letter, light, every path
  expanded, each hop's source shown), still one self-contained file under the
  same CSP. Screenshots: `docs/assets/report-*.png`.
- MCP tools `who_can_reach`, `blast_radius`, `paths`, `top_risks`,
  `suggest_fixes`, `diff` and `fix_plan` take an optional `detail` input
  (`brief` or `full`) and a `limit`. **`brief` is the new default:** it caps
  lists at `limit` (default 10; for `diff` it is shared across the whole
  report), leaves out path hops, edge attrs and a fix plan's per-principal
  scores, keeps every listed item's IDs and evidence level, and adds a `brief`
  object with `truncated`, `limit`, `total` (each list's length before the
  cut) and `omitted`. `paths` with `from` and `to` keeps its hops in brief, so
  an agent can ask for one item's details. Pass `"detail": "full"` for the
  previous answers (the `diff` per-list default of 50 is unchanged there). On a
  synthetic 2,000-repo, 50-team enterprise every brief answer stays under 8 kB.
  The `gop paths` and `gop who` commands still print full answers.
- `gop collect` no longer prints one stderr line per repository whose
  collaborators the token cannot list. It counts them and, at the end of each
  org, prints one line such as `org acme-actions: collaborators not visible on
  27 repos (HTTP 404: 26, HTTP 403: 1); see coverage`. Errors that stop or
  degrade collection still print right away, and the coverage entries are
  unchanged. `--verbose` restores the per-repository lines.

### Fixed
- Advisories: a `uses:` that `.github/workflows/actions.lock` pins is now
  checked on the locked commit (`locked_sha`), not only on the workflow's ref.
  A lock that pins a commit an OSV advisory lists as affected used to count as
  safely pinned. It now sets `lock_advisories`, `lock_advisory_severity` and
  `lock_advisory_fixed` on that `USES` edge (additive, typed in the JSON
  Schema), ranks the action first in `top_risks` with the reach of the locked
  workflows, fires SARIF GOP003 for those lines only, and `fix_plan` says
  "actions.lock pins an affected commit: rerun gh actions-lock after moving to
  `<lock_advisory_fixed>`". Other uses of the same ref, whose ref is not
  affected, get no advisory. The action pin counts gain
  `actions_lock_affected_commit`. A locked commit the advisory does not list
  is unknown and gets an `advisories` coverage entry; a fixed commit is not
  affected.
- `gop doctor` predicted no gaps for orgs the token does not own, and its repo
  count for them was 0 or 1. It now reads the token's role in each org
  (`viewerCanAdminister` and `viewerIsAMember` in the enterprise query, or
  `GET /orgs/{org}/memberships/{user}` without enterprise access). For an org
  the token does not own it adds an `owner <org>` warning with the fix collect
  uses (`org owner on <org>`, with the SSO note when SSO is enforced), lists
  the not_visible facts collect will record there (`ip_allow_list`,
  `repositories`, `outside_collaborators`, `can_push:collaborators`,
  `can_push:teams`, and `can_push:default_perm` without enterprise access),
  and returns them as `predicted_coverage` in `--format json`. Repo counts
  come from the enterprise GraphQL `repositories { totalCount }` where
  available; a `GET /orgs/{org}` count for an org the token does not own is
  marked a lower bound (`repos_source`, `repos_lower_bound`). A test checks
  that the predicted facts equal the ones collect records against the same
  fake.

### Security
- Harden MCP and report output against prompt injection through GitHub
  names (repo, workflow, team, branch, environment and file names are
  written by whoever can create them). A new `internal/sanitize` package
  escapes newlines, control characters, Unicode bidi and zero-width
  characters, tag characters and variation selectors. MCP text summaries
  wrap every name in backticks, never start a line with a name, cut names
  over 200 characters with an ellipsis (the structured JSON keeps the full
  value) and cap the line at 1024 characters; summaries now lead with fixed
  text (`blast radius:`, `paths:`, `edge:`). The JSON copy in text content
  and resources escapes invisible characters as `\uXXXX` (same decoded
  values), unknown-node suggestions are delimited, and every tool
  description and the server instructions say names may be written by an
  attacker and are data, never instructions. The fix_plan markdown, the
  prompts, `gop who` and `gop paths`, the markdown report, the drift
  markdown the Action uploads (`diff.md`) and the HTML report escape the
  same characters. `docs/threat-model.md` has a new "Prompt injection
  through names" section.

## [0.4.0] - 2026-11-24

### Added

- `contrib/ossie/`: a reviewed [Apache Ossie](https://ossie.apache.org/) semantic
  model (`gop.ossie.yaml`, Ossie 0.3.0.dev0) of the `gop export --format sql`
  schema, for Ossie-aware tools such as NVIDIA Auto Ontology. It defines the
  terms (organization, repository, workflow, action, identity, principal,
  cloud role, secret, self-hosted runner, finding, run, reach) with synonyms,
  every edge label as a join, and measures: confirmed and possible reach (kept
  apart), unpinned reachable actions, orgs with write as the default
  permission, findings, and the run-over-run reach delta. `views.sql` adds one
  view per term over the export (load it after the export). A test validates
  the model against the Ossie JSON Schema, checks every referenced column
  exists in the export schema, and runs each measure's SQL on the demo export
  against the engine's numbers. The README covers loading into Auto Ontology
  and warns that it sends schema samples and questions to its model endpoint
  (NVIDIA's hosted API by default), so self-host models for real data.
- Opt-in REST response cache for `gop collect`: `--cache-dir DIR`
  (`Config.CacheDir`, off by default) stores `GET` responses that are `200`
  with an `ETag` or `Last-Modified` and revalidates them on the next run with
  `If-None-Match` or `If-Modified-Since`; a `304` serves the cached body and
  does not count against the primary rate limit. `--resume` (`Config.Resume`)
  makes an interrupted collection of the same enterprise and orgs reuse every
  response it already fetched without a request (`DIR/run.json` records the
  run start and is removed on success). Entries are keyed by method, absolute
  URL (host included), `Accept` type and a token fingerprint, so tokens and
  hosts never share entries; the token and request headers are never written.
  GraphQL, errors and the App token mint are never cached. Edges built from a
  resumed body keep that entry's `fetched_at` as `observed_at`. The progress
  line and a final `collect: cache N hits (304), M fetched, K resumed` line
  report the counts. The cache directory is created `0700` (an existing one
  other users can read is refused) with `0600` files written atomically; it
  holds API responses as sensitive as graph.json (see
  `docs/threat-model.md`).
- `gop export --format sql graph.json [graph2.json ...] --out gop.sql` writes
  graphs as a SQL script that `sqlite3` and `duckdb` both load, for questions
  that count and group, BI tools and text-to-SQL tools. Tables: `runs`,
  `nodes`, `node_attrs`, `edges`, `edge_attrs`, `findings` (top risks and fix
  candidates with the pairs each removes) and `reach` (gop's computed reach
  per scoring principal, confirmed or possible, with the shortest path), all
  keyed by `run_id`. Several graphs load as several runs, so trends work; the
  script deletes a run's rows before inserting them, so loading it again
  changes nothing and older runs stay. Evidence is plain text. Values with
  control characters are written JSON-encoded (`'...' ->> '$'`, SQLite 3.38+),
  so the script holds no raw control characters. gop writes text
  and links no SQLite driver: the binary grows by about 50 KB, where a pure-Go
  driver would add about 5 MB. `--out` writes mode 0600; the file lists attack
  paths. Schema and example queries: `docs/sql.md`.
- MCP tool `check_answerable` (`question_kind`, `subject`): before an agent
  gives an answer, says whether gop could see the facts that answer depends
  on. Deterministic, no model: for the part of the graph the named tool's
  answer depends on (the subject and everything upstream for `who_can_reach`,
  everything the subject reaches for `blast_radius` and `paths`, the whole
  enterprise for `top_risks`, `what_if` and `fix_plan`) it reads coverage
  entries, `not_visible` edges, attributes and nodes, and stale `audit` facts
  (older than the graph's maximum audit age, so `audit_retention_days` is
  honoured; `inferred` counts as visible), and returns `answerable` (`yes`, `partial` for a lower bound,
  or `no` when the subject or its org's repositories are not visible), the
  missing facts with scope, reason and fix, and a confidence note. It never
  says `yes` when a required fact is not visible. The required facts per
  question kind live in one table, listed in `docs/mcp-clients.md`. The
  server now sends instructions on initialize, and they and the
  `explain_path` prompt ask the agent to call `check_answerable` before giving
  a security conclusion.
- Graph tab in the HTML report: the filtered paths as a layered left-to-right
  inline SVG (principal → repo → action ref → workflow → impact), laid out in
  Go (longest-path layers, barycenter order) with no third-party library and
  no CDN, under the same CSP. Hops are solid for live, dashed for audit and
  dotted with `?` for not visible; reversed hops are drawn in control
  direction and say so. Hover or focus shows `source_api`, `observed_at` and
  attrs (`file:line` when known). Selecting a node (click, or Enter on the
  focused node) filters to the paths through it (`via=` in the address);
  "Simulate a pin" greys the paths a top-10 suggested pin removes, from
  `WhatIf` data embedded by Go. Above 300 nodes it asks to narrow the filter.
  Nodes are keyboard buttons, the tabs follow the ARIA tabs pattern, and a
  text list of the drawn paths is the SVG's text alternative. Unknown
  evidence classes keep their name instead of reading "not visible".
- Action input `fail-on-reach-increase` (default `"false"`) with
  `baseline-artifact` (default `gop-posture`): compares the run's graph with
  the artifact of the previous successful run of the same workflow on the
  default branch (`gop diff --fail-on confirmed-increase`) and fails the job
  after the artifact upload when confirmed reach grew. `diff.md` and
  `diff.json` go only into the artifact; the log and step summary never name
  nodes. No baseline logs "no baseline, skipping" and passes. Needs
  `actions: read`; off, the Action is unchanged. The gate is
  `action/diff-gate.sh`, tested against a built gop.
- `gop enrich --cartography <export>` imports AWS role trusts of GitHub Actions
  from a Cartography Neo4j database. Run the shipped read-only query
  `docs/cartography/oidc-trusts.cypher` (cypher-shell plain output, Neo4j
  Browser JSON, the HTTP API shape or a plain row array are accepted); gop maps
  each `TRUSTS_AWS_PRINCIPAL` condition block to the same trust model as
  `--oidc-trust` files, so `CAN_ASSUME` edges and cloud nodes come out as with
  the equivalent trust file (evidence `supplied`, plus `source=cartography`).
  CloudTrail role use (`ASSUMED_ROLE_WITH_WEB_IDENTITY`) sets
  `observed_use`, `times_used` and `last_used` on the matching edge; an
  observation with no matching trust is a warning, never an edge. Bad rows are
  warnings, never errors. gop has no Neo4j driver and needs no Neo4j
  credentials. GCP and Azure stay on trust files: Cartography does not store the
  GCP attribute mapping or Azure federated credentials (see
  `docs/cartography.md`).
- GitHub Enterprise Server support. `gop collect`, `gop doctor` and `gop pin`
  take `--github-url https://HOST` (or `GOP_GITHUB_URL`) and read
  `https://HOST/api/v3` and `https://HOST/api/graphql`; `--api-url` and
  `--graphql-url` override them for a proxy, and `http://` needs
  `--insecure-http`. Collect reads the server version from `GET /meta` and
  records `host` and `ghes_version` on the enterprise node (`host` is
  `github.com` on github.com). Collectors the version lacks (enterprise
  ownerInfo settings, consumed licenses, the Actions access setting,
  rulesets; minimums in `docs/ghes.md`, not yet verified per version) are
  skipped with coverage `not available on GHES <version>`, and the run
  succeeds. Actions whose owner is not an org on the instance get
  `source=github.com`. See `docs/ghes.md`.
- `gop export --format cypher graph.json > gop.cypher` writes an idempotent
  Neo4j Cypher script for Cartography users: gop nodes as `:GopNode` plus a
  kind label (`:GopRepo`, `:GopWorkflow`, `:GopCloudRole`, ...), gop edges with
  their kinds and `evidence`, `confirmed` and `gop_run`, and computed
  `GOP_REACHES` edges from each scored principal to the secrets, OIDC tokens,
  runners and cloud roles it controls, with the path. `SAME_AS` links join
  `:GopOrg`, `:GopRepo` and AWS `:GopCloudRole` nodes to Cartography's
  `GitHubOrganization`, `GitHubRepository` and `AWSRole` when those exist
  (`--github-url` for GitHub Enterprise Server). A re-export replaces the
  previous run of the same enterprise. Output is sorted and byte-identical
  for the same graph; every graph value is an escaped string literal and
  labels, relationship types and keys come from fixed lists. gop writes
  text only and has no Neo4j dependency. See `docs/cartography.md`.
- The Action runs on Windows runners (x64 and ARM64): the download step
  (now `action/install-gop.sh`) fetches the `.zip` release, verifies it with
  `sha256sum` from Git Bash, extracts `gop.exe` with `unzip` (or the Windows
  `tar.exe`) and adds its directory to `GITHUB_PATH` in Windows form. The
  reach gate runs `diff-gate.sh` through `bash`, and the baseline lookup
  strips any CR from `gh` output. Steps keep `shell: bash`; self-hosted
  Windows runners need Git for Windows and `gh`. A new `action-smoke` workflow
  (PRs touching `action/`) runs the download step, `gop version` and the gate
  against the latest release on Ubuntu, macOS and Windows, with no enterprise
  credential.
- `docs/github-app-token.md`: creating a read-only GitHub App for gop, what
  each permission unlocks and what goes `not_visible` without it, installing
  it per org, App mode vs minting a token with `actions/create-github-app-token`,
  where to keep the private key, and owner-token vs App coverage. Linked from
  the README's Action section.
- `gop report --previous old.json`: the report opens with a "What changed"
  banner built from `gop diff` (the same summary sentence, the dates, the top
  principal's score delta, and new confirmed, removed, new possible, setting
  and lost-visibility changes with exact counts), each item linking to its
  filtered view or org view. Without `--previous` there is no banner. The
  Action passes `--previous` when `fail-on-reach-increase` downloaded a
  baseline. See `docs/report.md`.
- Accessibility pass on the HTML report: `header`, `nav` and `main`
  landmarks with a skip link, one `h1` and ordered headings, captions and
  `th scope` on every table, a visible keyboard focus, evidence shown as text
  plus an icon (never color alone), WCAG AA contrast checked in light and
  dark themes, and an `aria-live` result count. Tested by parsing the
  rendered HTML (`golang.org/x/net/html`, a new test-only dependency).
- Engine benchmarks on a generated 10k-repo enterprise (`BenchmarkNewIndex`,
  `BenchmarkReach`, `BenchmarkWhoCanReach`, `BenchmarkTopPaths`,
  `BenchmarkSuggestFixes`), run once per CI build as a smoke test.
- Re-collect selected orgs into an existing graph without losing cross-org
  joins: `collect.Merge(base, fresh, orgs)` (and `MergeWith` with a `Force`
  option) replaces everything `base` holds for the re-collected orgs with
  `fresh`'s facts, keeps every other org's nodes and edges as they were
  (including USES edges from their workflows into the re-collected orgs'
  actions), replaces stub repos with real ones, rebuilds RESOLVES_TO, and
  checks the result (declared or inferable endpoints, no duplicate edges).
  `collect.Config.MergeInto` with `Orgs` runs the partial collection against
  the base graph, so cross-org references resolve to its repos and actions
  other orgs use are read again; the result equals a full collection. Merging
  refuses graphs of different enterprises, schemas or hosts, and graphs from
  different token modes unless forced. New optional top-level field
  `org_collected_at` (per-org freshness); a collection fills it for every org
  it collected. The schema version is unchanged. The CLI flag is planned.
- Opt-in SARIF output: `gop sarif --graph g.json --out gop.sarif [--top N]
  [--min-severity low|medium|high|critical] [--include-possible]` writes one
  SARIF 2.1.0 result per fixable edge. `GOP001 mutable-action-ref-reachable`
  is one result per `uses:` line of a branch or tag action ref whose host repo
  a principal outside the consuming org can change, located at the consuming
  repo's workflow file and line; `GOP002 default-permission-grants-push` is one
  result per org whose default permission is a `lower_default_perm` candidate,
  with a logical `org:<login>` location. Each result carries confirmed and
  possible principals, terminal counts, evidence, the fix and the share of
  reach it removes; severity follows terminal impact (critical for OIDC or a
  cloud role, high for secrets or self-hosted runners, medium for repo CI).
  Possible-only results are dropped unless `--include-possible`, then
  `level: note`. `partialFingerprints` are stable across runs.
  `--split-by-repo DIR` writes one file per repo. gop never uploads SARIF;
  [docs/sarif.md](docs/sarif.md) warns that code scanning shows the attack
  paths to everyone with alert access on the repo.
- Container image: each release publishes `ghcr.io/peleduri/gop:<version>`
  (and `:latest` for stable releases) for linux/amd64 and linux/arm64, built
  by goreleaser from `gcr.io/distroless/static-debian12:nonroot` pinned by
  digest. The image has no shell, runs as `65532:65532` with `ENTRYPOINT
  ["/gop"]`, and carries OCI labels. The release workflow signs it keyless by
  digest with cosign (same identity as `checksums.txt`), attaches a signed
  SPDX SBOM and pushes SLSA build provenance to the registry. CI checks the
  snapshot images on every PR. See docs/install.md#container.
- `docs/architecture.md`, a contributor guide: package map, a Mermaid data
  flow from the GitHub API to `graph.json` to the MCP tools and report, the
  control-graph rules (a verbatim copy of the comment in
  `internal/graph/reach.go`, kept identical by a test), the invariants every
  change must keep, and checklists for adding a collector, an MCP tool or a
  fix type. CONTRIBUTING links it and explains the labels and the golden
  update flow.
- `.github/labels.yml` describes the label set (type, area, priority, size,
  `good first issue`, `help wanted`, `agent-ready`), and
  `scripts/sync-labels.sh` prints or applies the matching `gh label`
  commands for the maintainer. No workflow writes labels.
- Release notes grouped by change type: `.github/release.yml` categories by label
  (Security, Features, Fixes, Docs, Dependencies), and goreleaser
  `changelog.use: github` groups by conventional commit prefix (`sec`,
  `feat`, `fix`, `docs`). `docs` commits now appear in the notes.
- CI checks PR titles against Conventional Commits (`pr-title` workflow, on
  `pull_request` with only `pull-requests: read`) and every repo-relative
  Markdown link and anchor (lychee, offline).

- `gop redact --graph g.json --out shareable.json [--salt-file key]
  [--keep-attr k1,k2] [--map-out mapping.json]` pseudonymizes a graph for bug
  reports: orgs, repos, users, teams, actions, workflow files, secret names,
  runner labels, environments and cloud names become stable synthetic names
  (HMAC-SHA256 under the salt; SHAs stay 40-hex, tags become `v1.N`, branches
  `branch-N`, third-party owners `ext-NN`), member, IP allow list and
  Cartography `times_used` counts are bucketed, timestamps (including
  `last_used`) shift by one offset and coverage text is rewritten through the
  same map. Structure, evidence and reach are unchanged: reach
  counts and scores on the redacted graph equal the original's, and it passes
  `gop validate`. Attr keys gop does not define are dropped unless
  `--keep-attr` names them. A self-check fails the run, writing nothing, if an
  original name of 3+ characters is still in the output. The bug report
  template asks for `gop redact` output, never a raw graph.

### Changed

- Graph schema `gop.graph/v2` (breaking): a new evidence level `inferred` for
  facts derived from other observed facts by a documented rule, named in the
  edge's `rule` attribute. Members' push access from an org's default
  permission (`rule=default_perm`) and org owners' admin access to every repo
  (`rule=org_owner`) are now `inferred` instead of `live`; confirmed reach is
  unchanged. gop still loads and validates `gop.graph/v1` graphs (upgraded in
  memory) and rejects a v1 document that uses `inferred`. JSON Schema:
  `schema/gop.graph.v2.schema.json`. Migration notes in `docs/schema.md`.
- `audit` facts now age out: an audit edge older than the maximum audit age
  (half of the new optional `audit_retention_days`, else 90 days; override
  with `graph.Options.MaxAuditAge`) counts as not visible, so it gives
  possible reach only, is never a fix candidate, and its path is marked
  `stale` (text output `[audit, stale]`). `explain` prints the `rule` of an
  inferred edge and `age_days` and `stale` of an audit edge.
- `--github-url` on `gop doctor` and `gop pin` now takes the instance URL
  (`https://HOST`); a REST root ending in `/api/v3` still works.
- `gop diff` refuses snapshots from different GitHub hosts (enterprise
  `host` attribute) without `--force`.
- `gop enrich` matches a cloud OIDC trust only when its issuer is the token
  issuer of the graph's host (`https://token.actions.githubusercontent.com`
  for github.com, `https://HOST/_services/token` for GHES). Graphs without
  `host` match any GitHub issuer, as before.
- `SuggestFixes` (`suggest_fixes`, `fix_plan` and the report's suggested
  fixes) is incremental: the control graph is built once and each candidate
  fix is scored as an overlay of removed edges, counting only confirmed
  repos, recomputing only the principals a fix can affect, and evaluating
  principals in parallel. On the 10k-repo benchmark a budget of 10 takes
  about 1 s on 4 cores (about 27 h before, extrapolated). `WhoCanReach`
  (`who_can_reach`, `gop who`) walks back from the target first and
  traverses forward only from principals that can reach it: about 10 ms
  instead of 4 s. Output is unchanged; property tests check both against the
  previous implementations on 200 generated graphs.

### Fixed

- `fix_plan`, `gop fix-plan --pin`, `gop pin` and the report's "Pinned, still
  reachable" section now use the same `ref_immutable`/`ref_protected` gate as
  reach. A nested tag that is an immutable release (or a protected branch)
  with no matching bypass is no longer reported as a mutable ref ("pin those
  too") or as a pinned exposure, and a locked outer ref counts as pinned. A
  nested ref whose gate is not visible stays listed, labelled "possibly
  mutable (immutability not visible)", and its exposure path is possible.
  `PinnedExposure` gains `via_note`, and `Via` is also set when the path
  enters the nested ref through a `ref_bypass` push.

### Security

- The API client removes the `Authorization` header on any redirect that
  leaves the configured REST or GraphQL scheme and host. `net/http` alone
  keeps it for a subdomain, another port on the same host name, or an
  `https` to `http` downgrade.

## [0.3.0] - 2026-11-24

### Added

- Paths out of GitHub: `gop enrich --graph g.json --oidc-trust ./trust/ --out
  g2.json` (and `gop collect --oidc-trust`) reads exported AWS, GCP and Azure
  OIDC trust files offline and adds `workflow -CAN_ASSUME-> cloud:<provider>:<role>`
  where a workflow's token can assume the role, so `who_can_reach`,
  `blast_radius`, the report and `gop who`/`gop paths` show which principals
  reach which cloud roles. Matches come from the file, not the cloud: they
  carry the new evidence `supplied` (counted as confirmed, flagged on the path,
  and every summary names the file). Matches gop cannot decide (branch-scoped
  `sub` with unknown triggers, dynamic environments, unparsed conditions) are
  `not_visible` with a `reason`, so possible reach. Oidc nodes no supplied
  trust matches get a `cloud_trust` coverage entry. Each reached cloud role
  adds 13 to the blast radius score. Re-running with the same files gives a
  byte-identical graph.
- GitHub App mode in the CLI, the Action and `gop doctor`. `gop collect
  --app-id N --app-key-file PATH` (or `GOP_APP_ID` and `GOP_APP_PRIVATE_KEY`)
  mints a read-only installation token per org; it is a usage error (exit 2)
  together with `GITHUB_TOKEN`. The key is read once, never printed, and a key
  file wider than `0600` gets a warning. The Action takes `app-id` and
  `app-private-key` (masked line by line) and prefers them over `token`.
  `gop doctor --app-id/--app-key-file` lists installations, flags `--orgs`
  without one, checks that granted permissions are read-only and complete,
  and predicts what App mode leaves `not_visible`. CI runs actionlint on the
  workflows and the Action.
- Fix types `restrict_token` and `harden_trigger` in `what_if`, `suggest_fixes`
  and `fix_plan` (and `gop fix-plan --restrict-token` / `--harden-trigger`).
  `restrict_token` removes a workflow's `via=token_write` `CAN_PUSH` edges
  (`permissions: contents: read`); its plan says where to set it: a top-level
  block when the jobs take the repo's default, the listed jobs when the file
  grants write. `harden_trigger` removes every `CAN_TRIGGER` edge into a
  workflow; its plan has one step per untrusted execution with the job, line
  and change (drop the head checkout, or move attacker text into `env:`).
  `suggest_fixes` proposes each for workflows with a verified edge. Plan steps
  get an optional `change` field.
- Collector: `CAN_TRIGGER` edges carry `file`, `file_ref` and `line` (the
  checkout's `with.ref`/`with.repository`, or the `run:`/`script:` key).
- Coverage for every skipped fact. A `.github/workflows` that is not a
  directory listing gives `workflows=unknown` (`not_visible`) instead of `0`;
  a `uses:` expression (`${{ matrix.tool }}`) sets `dynamic_uses=<n>` on the
  workflow; a job whose `runs-on` is a custom label, a runner `group:` or an
  expression gets a `not_visible` `EXECUTES_WITH` edge to `runner:<org>/<repo>`
  (`classification=unknown`) instead of none; stub repos for actions outside
  the collected orgs are `not_visible` and get `members:<org> -CAN_PUSH->`
  (`not_visible`, `via=unknown`) or the org's default-permission edge, so
  reach through them is possible instead of zero. Each gets a coverage entry,
  as do archived orgs and orgs whose default permission is not visible.
  `graph.CoverageSummary` counts not_visible nodes, edges, attributes and
  coverage entries per org; the MCP `coverage` tool returns it as `orgs` and
  `gop collect` logs one line per org. `suggest_fixes` and `what_if` carry a
  caveat when a pinned action's nested references are not visible.
- HTML report filters and per-org views. The report embeds the paths, fixes,
  org settings and coverage as one JSON block and a small inline script adds a
  filter bar (evidence, terminal kind, org, principal, action ref kind) whose
  state lives in the URL hash (`#org=acme-app&ev=confirmed&kind=oidc`), plus a
  per-org view at `#/org/<org>` with settings and their evidence (unseen
  settings read "unknown", never "off"), inbound and outbound reach, fixes and
  coverage gaps. A CSP meta tag pins the one style and one script by hash, so
  the file cannot load anything remote. With JavaScript off the report reads as
  before. Embedded paths are capped at 500 per target org, with a note when cut.
- Collector and engine: risky triggers are reach. A workflow on
  `pull_request_target`, `workflow_run`, `issue_comment`, `issues`,
  `pull_request_review(_comment)` or `discussion(_comment)` that checks out
  the pull request's head or interpolates attacker text (`${{
  github.event.comment.body }}`, `github.head_ref`, ...) into a script gets
  `principal -CAN_TRIGGER-> workflow` from whoever can cause the event:
  `external:anyone` (new node kind `external`) for a public repo, every
  collected org's members for an internal one, the org's members for a
  private one when the default permission allows read. Fork triggers also
  need the org to allow private forks; an unreadable setting makes the edge
  `not_visible`. The engine treats `CAN_TRIGGER` as a control hop, so anyone
  on the internet can now reach a public repo's secrets through such a
  workflow. Workflows get `risky_triggers`; plain `pull_request` gets no edge
  (read-only token, no secrets from forks). See docs/schema.md, Triggers.
- `gop pin --action owner/repo@ref` resolves an action ref to its commit SHA
  with read-only GET requests (the commit, then whether the ref is a tag or a
  branch) and prints the pinned `uses:` value. With `--graph`, it reads each
  consuming workflow file and prints a unified diff per file that applies with
  `git apply` (`--repo` for one repo's part, `--offline` for the one-line
  hunks `fix-plan` shows), and warns about mutable refs nested in the action.
  It writes to stdout only, and its HTTP transport refuses any method but GET.
  `gop fix-plan` now points its resolve step at `gop pin`.
- MCP resources `gop://graph/summary` (enterprise, snapshot age, counts by
  node and edge kind, evidence mix, org settings, top 5 principals by
  confirmed score), `gop://graph/coverage`, `gop://graph/schema`
  (docs/schema.md) and the template `gop://node/{+id}` (a node with its in and
  out edges), plus the prompts `triage_enterprise`, `review_action` and
  `explain_path`. Prompt texts live in `internal/mcpserver/prompts/`. A
  snapshot older than 7 days is flagged in the summary and every prompt.
- MCP tool `fix_plan` and `gop fix-plan` turn a fix into concrete change
  steps: for `pin_ref`, one step per consuming workflow or nested action with
  file, line and a one-line diff (a placeholder SHA plus a step to resolve it),
  plus a caveat naming mutable refs the pinned action uses itself; for
  `lower_default_perm`, the setting's UI path and REST call (text only) and the
  repos where members lose push. Steps whose evidence is not visible are marked
  and listed last. Output as text, markdown checklist or JSON. gop never runs
  the steps or calls write APIs.
- `gop doctor --enterprise SLUG [--github-url URL] [--orgs a,b] [--format text|json]`:
  a read-only preflight for `collect`. It detects the token kind and mode
  (a/b/c), checks classic scopes (`X-OAuth-Scopes`), write scopes broader than
  gop needs and a classic token with no expiry, probes up to 100 orgs for
  SAML SSO authorization gaps (`X-GitHub-SSO`), reads `GET /rate_limit`,
  estimates requests and minutes for `collect`, and lists the predicted
  `not_visible` areas, each check with its fix. Exit 0 all pass, 1 any fail,
  3 warnings only. It never prints the token or a header value.
- Collector and engine: a workflow whose `GITHUB_TOKEN` has `contents: write`
  (explicitly, through `write-all`, or by the repo or org default workflow
  permission) controls its repo: `workflow -CAN_PUSH-> repo` with
  `via=token_write`. Whoever controls the workflow now reaches the repo's other
  workflows and the actions it hosts, not only its CI. Workflow nodes get
  `token_write` and `token_scopes`. The default is read from
  `GET /repos/{owner}/{repo}/actions/permissions/workflow`, falling back to the
  org setting (where `read` proves `read`); when neither is visible the edge is
  `not_visible` with a `default_workflow_permissions` coverage entry.
  Workflows are never principals.
- `internal/oidc` parses user-supplied cloud OIDC trust files offline into one
  model (provider, target identity, issuer, audiences, `sub` and other claim
  patterns): AWS IAM role trust policies (`aws iam get-role` / `list-roles`
  output or a bare policy document), GCP workload identity pool providers with
  optional service account IAM policies, and Azure federated identity
  credentials (including flexible `claimsMatchingExpression`). Directories are
  walked for `*.json`. Risky trusts carry warnings: no `sub` condition, wildcard
  owner, no audience check, and any condition that was not fully understood
  (kept as a `cel` pattern and treated as possible). No cloud API calls; the
  graph wiring follows separately.

- OIDC edges (`workflow -EXECUTES_WITH-> oidc`) carry the token claim inputs
  a cloud trust matches on: `jobs` (the jobs that can mint a token),
  `environments` (their `environment:` names, `*dynamic*` for an expression),
  `repository`, `repository_owner`, and `job_workflow_ref` when an id-token job
  calls an enterprise reusable workflow that mints the token. Additive; the
  engine does not read them yet.

### Changed

- OIDC detection follows job-level permissions: a job's own `permissions:`
  replace the workflow-level value, so a workflow with `permissions: write-all`
  whose jobs all set narrower permissions without `id-token: write` no longer
  gets an OIDC edge. The edge's `line` points at the key that grants the
  token (job-level when the job sets it).
- Cross-org `USES` now depends on the Actions access setting of the repo that
  hosts the action. The collector reads
  `GET /repos/{owner}/{repo}/actions/permissions/access` once per private or
  internal repo that hosts a referenced enterprise action, and records
  `actions_access` (`none`, `user`, `organization`, `enterprise`, `public` for
  public repos, or `unknown` (`not_visible`) with a coverage entry when the
  setting is refused). `USES` edges into enterprise actions carry
  `consumer_org`. The engine drops a `USES` hop the setting forbids (for
  example a workflow in `acme-app` using an action in an `acme-actions` repo
  set to `organization`), and makes a cross-org hop `not_visible` (possible,
  not confirmed) when the setting is unknown. Graphs without `actions_access`
  give the same results as before.

## [0.2.0] - 2026-11-23

### Added

- `gop mcp-config --client claude|cursor|vscode --graph PATH` prints the MCP
  client config (or the `claude mcp add` command) with the absolute graph path
  filled in. It only prints; it never writes files.
- Release config for a Homebrew cask in `peleduri/homebrew-tap` (tap coming
  soon). The upload is skipped unless `HOMEBREW_TAP_TOKEN` is set; one-time
  setup in `docs/maintainers.md`.
- `docs/install.md` (Homebrew, release archive, checksum, cosign and
  attestation verification, `go install`) and `docs/mcp-clients.md` (Claude
  Code, Cursor, VS Code and generic stdio snippets).
- Collector: per-org mode when the token cannot read the enterprise (org-scoped
  App installation tokens, non-owner PATs, no `read:enterprise`). Instead of
  failing, gop records an `enterprise` coverage entry, sets the enterprise
  `orgs=unknown`, and collects the `--orgs` list (counted as enterprise orgs)
  or the orgs discovered through `GET /user/orgs` or
  `GET /installation/repositories`. Org settings fall back to `GET /orgs/{org}`
  and members to `GET /orgs/{org}/members`; what neither returns stays
  `not_visible` with one coverage entry per setting at enterprise scope. Action
  owners outside the collected orgs get `in_enterprise=unknown` (`not_visible`)
  and one aggregated coverage entry, never `false`.
- `USES` and `EXECUTES_WITH` edges from workflow files and composite actions
  now carry their source position: `file`, `file_ref` (when known), `line` and,
  on `USES`, `col`. The `explain` summary shows `file:line`. Additive; graphs
  without these attributes still load.
- Collector: `identity:` nodes for every licensed user with `MEMBER_OF` edges,
  and `CAN_PUSH` from org owners (`via=org_owner`), direct collaborators
  (`via=direct`) and outside collaborators (`via=outside_collaborator`) with
  push, including custom repository roles. Repos whose collaborators can't be
  listed get one org-level coverage entry and `not_visible` edges for the
  repo grants listed in the consumed licenses.
- Collector: team grants. `team:<org>/<slug>` identity nodes, child team
  `MEMBER_OF` parent team, direct members `MEMBER_OF` their team, and
  `CAN_PUSH` from team repository grants with push (`via=team`, `permission`
  is the role name, custom roles included). A non-owner token gets a
  `can_push:teams` coverage entry and `teams_partial=true` on the org; a team
  whose member list is refused keeps its grants, gets `members=unknown` and a
  `team_members:<slug>` coverage entry.
- Engine: `Index.ScoringPrincipals()`. Totals in `top_paths`, `what_if` and
  `suggest_fixes` count org members plus identities with their own grants, so
  adding one identity per licensed user does not multiply pair totals.
- JSON Schema (draft 2020-12) for graph.json at
  `schema/gop.graph.v1.schema.json`, and `gop validate --graph graph.json
  [--format text|json]`: checks the schema version, JSON Schema conformance and
  that every edge endpoint is a node, and warns about `not_visible` facts with
  no coverage entry. Exit 0 valid, 1 invalid, 2 usage error.
- `docs/schema.md`: Versioning and Changelog sections.
- `gop diff OLD NEW`: posture drift between two snapshots (paths added,
  removed, upgraded, downgraded or lost to visibility; setting, edge, score and
  coverage changes) as text, Markdown or JSON, with `--only` and `--fail-on
  confirmed-increase|any-new-path` for CI. See `docs/drift.md`.
- `gop demo [--size small|medium|large] [--seed N] [--out graph.json]`:
  generates a deterministic synthetic enterprise graph with no token. It plants
  the cross-org `acme-actions/deploy@main` path, a safe SHA-pinned consumer, the
  nested-action trap (a SHA-pinned composite action that calls a branch ref in
  the same org), one not-visible hop with coverage, and a self-hosted runner.
- `gop serve --demo` and `gop report --demo`; `--graph -` reads the graph from
  stdin for `report`, `paths` and `who` (`gop demo | gop report --graph - --out -`).
- Demo graphs carry `demo=true` on the enterprise node; MCP tool summaries and
  the report title then start with `[demo data]`.
- Report section "Pinned, still reachable": SHA-pinned actions that a principal
  can still change through a nested mutable ref, with one path each.

- Collector and engine: branch protection gates mutable action refs. For
  each enterprise-internal action ref on a branch, gop reads the branch's
  active rules, its classic protection and the protecting rulesets' bypass
  actors, and sets `ref_protected` (`true`, `false`, `unknown`),
  `ref_protection` and `bypass` on the action node. Only pull request reviews
  that can't be reused after a push (stale-approval dismissal or last-push
  approval) and push restrictions count; status checks alone don't. Principals
  that can land code alone get `CAN_PUSH` edges with `via=ref_bypass` and
  `ref=<branch>`. A protected ref no longer lets every pusher to its host repo
  change it: only its bypass principals reach it, and an unreadable protection
  makes the path possible instead of confirmed. Additive; graphs without these
  attributes behave as before.

### Fixed

- The blast-radius multiplier ignores `MEMBER_OF` targets that are not orgs.
- `docs/schema.md`: the reach path example used `org_members:` IDs; the ID
  prefix is `members:`.
- `OrgOf` returns the org of a `team:<org>/<slug>` ID, so team principals get
  their org's blast-radius multiplier.

## [0.1.0] - 2026-11-23

First public version.

### Added

- `gop collect`: read-only collector for a GitHub Enterprise over REST and
  GraphQL. Reads the enterprise's orgs, default repository permission, 2FA and
  SSO policy, org settings (member repo creation, visibility changes, repo
  deletion, private forks, IP allow list), membership counts, repositories and
  workflow files. Derives `CAN_PUSH` from Write/Admin default permissions.
  Parses workflows for the Actions and reusable workflows they use,
  `id-token: write`, secrets and self-hosted runners, and expands composite
  Actions and reusable workflows recursively at the referenced ref (with a
  depth limit). `--orgs` limits collection. Token from `GITHUB_TOKEN` or
  `GH_TOKEN` only, scrubbed from errors. Retries transient errors and waits
  out rate limits.
- Evidence graph schema `gop.graph/v1` (graph.json): every node and edge
  carries `live`, `audit` or `not_visible` evidence and every edge a
  `source_api`; facts the token cannot read are recorded as `not_visible` with
  a `coverage` entry, never as "off".
- Reachability engine: shortest control paths from any principal, with
  confirmed reach (every hop live or audit) kept apart from possible reach (at
  least one not_visible hop). SHA pins block a path only when the whole nested
  Action chain is immutable.
- Blast radius score, top risks, what-if analysis (`pin_ref`,
  `lower_default_perm`) and a greedy fix planner ranked by confirmed
  (principal, repo) pairs removed. Fixes that touch only not_visible edges are
  never suggested.
- `gop serve`: MCP server over stdio with read-only tools `who_can_reach`,
  `blast_radius`, `paths`, `top_risks`, `what_if`, `suggest_fixes`, `explain`
  and `coverage`.
- `gop paths`, `gop who`: the same answers as text in the terminal.
- `gop report`: self-contained HTML or Markdown report with the headline, top
  risks, suggested fixes and top paths. Output files are written with mode
  0600.
- GitHub Action (`action/`) that downloads a release, verifies its checksum and
  (when cosign is present) its signature, runs collect and report, and uploads
  both files with a 1-day default retention.
- Release pipeline: goreleaser builds, keyless cosign signing, SPDX SBOMs, SLSA
  build provenance.
- Synthetic `acme` fixtures, threat model, schema docs.
