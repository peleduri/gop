# How gop compares

gop answers one question: **across every org in a GitHub Enterprise, which
people, teams, Actions and AI agents can make code run where, through which
hops, and with what evidence for each hop?** Other good tools answer
neighbouring questions, often better than gop does. This page says which is
which so you can pick, and in most cases combine them.

Every claim about another tool comes from that tool's own README or
documentation, linked in its section, as read on 2026-11-24. Tools change
quickly: if something here is out of date, open an issue or a pull request
with the link and we will fix it.

## Summary

| Tool | Scope | Reach paths | Evidence levels | AI agents in CI | Read-only and local | License |
|---|---|---|---|---|---|---|
| **gop** | Whole enterprise, across orgs, including Actions nested in composite Actions | Yes: principal to repo, workflow, secret, OIDC trust, runner and cloud role, hop by hop | Every hop is `live`, `inferred`, `audit`, `supplied` or `not_visible`; confirmed and possible reach are kept apart | Yes: finds agent actions and CLIs, who can start them, what reaches the prompt and what the job holds | Yes: GET and GraphQL queries only, no telemetry, output stays on disk | Apache-2.0 |
| [zizmor](#zizmor) | Workflow, action, Dependabot and pre-commit files: local, or one or more remote repos | No: findings per file and line | Per-finding severity; personas tune how noisy it is | No dedicated audit (template injection is covered in general) | Yes: offline mode needs no network; online mode only fetches with your token | MIT |
| [poutine](#poutine) | One repo or every repo of an org; GitHub Actions, GitLab CI, Azure DevOps, Tekton | No: findings per workflow | Rule level `note`, `warning` or `error` | No dedicated rule | Read-level token; a daily version check is on by default and can be turned off | Apache-2.0 |
| [Legitify](#legitify) | GitHub and GitLab orgs, repos, members, Actions settings, runner groups; an enterprise slug can be given | No: pass/fail per policy | Policy severity | Not covered; an opt-in `gpt-analysis` command sends metadata to OpenAI | Runs locally; asks for scopes including `admin:org` and `admin:org_hook` | Apache-2.0 |
| [OpenSSF Scorecard](#openssf-scorecard) | One repository per run (plus a public weekly scan of open source projects) | No: a 0-10 score per check | Score and risk level per check | No | Runs locally with a token, or read pre-computed public results | Apache-2.0 |
| [Gato-X](#gato-x) | Whatever one token can see, up to tens of thousands of repos; cross-repo reusable workflows and actions | Yes, for exploitability: reachability, gate checks, `if:` simulation | Tuned to avoid false negatives; the operator confirms | Knows `claude-code-action` as a gate check; no agent-specific analysis described | Scanning reads; attack modes write (runners, secrets) by design | Apache-2.0 |
| [GitHub security overview](#github-security-overview) | Org and enterprise views of alerts and feature coverage | No | Alert severity from each scanner | Through code scanning alerts, if CodeQL's Actions analysis flags the workflow | Hosted by GitHub; nothing to run | Part of GitHub (many views need Code Security or Secret Protection) |
| [CSPM / ASPM platforms](#cspm-and-aspm-platforms) | Usually many SCMs, clouds and pipelines in one console | Varies; some build graphs | Varies | Varies | SaaS that keeps a copy of your data | Commercial |

## Where each tool is stronger than gop

### zizmor

Sources: [README](https://github.com/zizmorcore/zizmor),
[audits](https://docs.zizmor.sh/audits/),
[usage](https://docs.zizmor.sh/usage/).

zizmor is a static analyzer for CI/CD files: template injection, credential
persistence, excessive permissions, impostor commits, unpinned uses, cache
poisoning, dangerous triggers and dozens more audits, several with auto-fixes.
It runs offline on a checkout or online against remote repos.

**Better than gop at:** finding what is wrong *inside* a workflow file, line by
line, and fixing it. gop does not lint workflow contents for injection. Run
zizmor in every repo's CI; use gop to see which of those workflows people in
other orgs can change.

### poutine

Sources: [README](https://github.com/boostsecurityio/poutine),
[rules](https://github.com/boostsecurityio/poutine/tree/main/docs/content/en/rules).

poutine scans the build pipelines of a repo or a whole org for injection,
untrusted checkout and execution, self-hosted runners on pull requests, known
vulnerable build components and more, on four CI platforms, with custom Rego
rules. By default it checks for a newer release once a day, sending its version,
an anonymous instance ID and an invocation count (no repository data);
`--disable-version-check` turns that off.

**Better than gop at:** proving a workflow is injectable, and covering GitLab,
Azure DevOps and Tekton. gop covers GitHub only. The two combine:
`gop enrich --poutine report.json` marks workflows poutine flagged, and reach
into an injectable workflow ranks first ([poutine.md](poutine.md)).

### Legitify

Sources: [README](https://github.com/Legit-Labs/legitify).

Legitify checks policies across organization, Actions, member, repository and
runner group namespaces ("2FA not enforced", "stale admin found", "code review
by at least two reviewers is not enforced"), on GitHub and GitLab, and can run
Scorecard on every repo of an org. Its README asks for a classic token with
`admin:org, read:enterprise, admin:org_hook, read:org, repo, read:repo_hook`
and says fine-grained tokens are not supported.

**Better than gop at:** breadth of configuration checks and GitLab support.
gop records many of the same settings, but only to decide reach: it tells you
that weak 2FA in one org multiplies the reach of the people in it, not every
setting that deviates from a baseline.

### OpenSSF Scorecard

Sources: [README](https://github.com/ossf/scorecard),
[checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md).

Scorecard scores a repository 0 to 10 on checks such as Branch-Protection,
Dangerous-Workflow, Token-Permissions and Pinned-Dependencies, and publishes
weekly results for open source projects through a REST API and BigQuery. Its
README notes that 2FA is not a check because the data is not public.

**Better than gop at:** a widely adopted, comparable per-repo hygiene score
that covers far more than CI (maintenance, fuzzing, SAST, signed releases),
plus public data for your open source dependencies. gop does not score
repositories against a standard.

### Gato-X

Sources: [README](https://github.com/AdnaneKhan/gato-x),
[documentation](https://adnanekhan.github.io/gato-x/),
[known gate actions in source](https://github.com/AdnaneKhan/gato-x/blob/main/gatox/workflow_graph/nodes/action.py).

Gato-X is an offensive toolkit for GitHub Actions: it finds pwn requests,
Actions injection, TOCTOU bugs and self-hosted runner takeovers at scale with
one token, including cross-repository transitive workflows and reusable
actions, and it can carry out the attack (runner-on-runner, secret dumping)
with authorization. It also ships an MCP server.

**Better than gop at:** showing that a path is exploitable now, from an
attacker's seat, including from workflow run logs. gop is not an exploitation
tool: it never writes, and it reports who *can* change what runs, from a
defender's enterprise-wide view.

### GitHub security overview

Sources: [security overview](https://docs.github.com/en/code-security/concepts/security-at-scale/security-overview),
[CodeQL code scanning](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning).

Security overview aggregates code scanning, secret scanning and Dependabot
alerts and feature coverage across an org or enterprise, with risk, coverage,
enablement and campaign views. CodeQL can analyze GitHub Actions workflows,
and those alerts show up there.

**Better than gop at:** being built in, always current, tied to alert triage
and remediation campaigns, with no tool to run. It shows alerts the scanners
raised; it does not show who can push code that a workflow in another org
runs, or which one setting change removes most of that reach.

### CSPM and ASPM platforms

Commercial cloud and application security posture platforms often connect to
GitHub alongside clouds and other source control systems, and some build an
asset graph. What they collect and how they score it varies by vendor, so
check your vendor's documentation against the columns above.

**Better than gop at:** one console across many systems, ticketing, ownership
and history. **Where gop differs:** it is local and read-only, keeps every hop's
evidence and what it could not see, and its output is a file you own. If your
platform already shows cross-org Action reach with per-hop evidence, you may
not need gop.

## Where gop is weaker

- GitHub only (github.com and GitHub Enterprise Server), no other SCM or CI.
- It does not find injection or other bugs inside workflow code; it reads the
  graph around the code. Use zizmor or poutine for that.
- It needs a broad read token (an enterprise owner's, or an App installed in
  every org) to be complete; with less it says `not_visible`, which is honest
  but less useful.
- Agent detection works from a table of known actions and CLIs
  ([agents-in-ci.md](agents-in-ci.md)); an agent it does not know is not found.
- It is young. Expect schema and flag changes before v1.0
  ([CHANGELOG.md](../CHANGELOG.md)).

## Using them together

A typical setup: zizmor or poutine in each repository's CI for workflow bugs,
Scorecard for per-repo hygiene, GitHub security overview for alert triage, and
gop on a schedule for the enterprise-wide "who can make code run where", with
poutine's findings fed in through `gop enrich --poutine`.
