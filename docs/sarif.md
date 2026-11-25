# SARIF output

> [!WARNING]
> **SARIF output is a list of attack paths.** Each result says which workflow
> line or org setting lets which principals reach which secrets, OIDC tokens,
> runners and cloud roles. If you upload it to GitHub code scanning, everyone
> with alert access on that repository can read it, and on a public repository
> that can mean anyone. Upload only to private repositories whose alert access
> you control, or keep the file as a private artifact (0600, not in a shared or
> synced folder, short retention). gop writes the file and never uploads it, and
> the gop Action has no SARIF input.

`gop sarif` writes one [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
result per fixable edge, for teams that triage in a code-scanning style queue.
It is opt-in and works offline on a graph file:

```text
gop sarif --graph graph.json --out gop.sarif [--top N] [--min-severity low|medium|high|critical] [--include-possible]
gop sarif --graph graph.json --split-by-repo DIR [same filters]
```

- `--out` writes one log (`-` for stdout). Files are written `0600`.
- `--split-by-repo DIR` writes one log per repo that owns a fix, as
  `DIR/<owner>/<repo>.sarif` (code scanning uploads are per repo), plus
  `DIR/<org>.org.sarif` for org-setting results, which have no file.
- `--top N` keeps the first N results after sorting (most severe first, then by
  the share of reach the fix removes).
- `--min-severity` drops results below a severity (default `low`: keep all).
- `--include-possible` keeps results that hold only through a `not_visible`
  hop. They are dropped by default and, when kept, get `level: note`.

## Rules

| Rule | Name | One result per | Location |
|------|------|----------------|----------|
| `GOP001` | `mutable-action-ref-reachable` | `uses:` line (USES edge) of a branch or tag action ref whose host repo a principal outside the consuming org can change | the consuming repo's workflow file and line (`artifactLocation.uri` relative to that repo, `properties.repository` names it) |
| `GOP002` | `default-permission-grants-push` | org whose default repository permission gives members push (a `lower_default_perm` candidate) | logical location `org:<login>`, no file |
| `GOP003` | `action-with-known-advisory-reachable` | `uses:` line (USES edge) of an action ref with a known compromise or vulnerability advisory (`advisories` attr, see [advisories.md](advisories.md)) | the consuming repo's workflow file and line, as for GOP001 |
| `GOP004` | `agent-workflow-exposed` | AI coding agent workflow that people without push access can start (`agent_exposure=outsiders` with a known agent action or CLI, see [agents-in-ci.md](agents-in-ci.md)) | the workflow file and the agent step's line from its `CAN_TRIGGER` edge |
| `GOP005` | `review-bypass-bot-self-merge` | merge workflow line of a repo where a pull request's author can get code onto the default branch through a bot approval and a bot merge with no human review (`review_bypass=bot_self_merge` with `CAN_MERGE_VIA_BOT` edges, see [agents-in-ci.md](agents-in-ci.md#ai-approve--self-merge)) | the merging workflow file and the merging step's line from its `CAN_MERGE_VIA_BOT` edge |
| `GOP006` | `agent-memory-poisoning-across-runs` | AI agent workflow that people without push access can start whose agent job saves an `actions/cache` entry that a job with secrets or a write token restores on a later run (`agent_memory_readers`, see [agents-in-ci.md](agents-in-ci.md#agent-memory-across-runs)) | the agent workflow file and the save step's line (`agent_memory_line`) |

GOP003 results sort before every other result, whatever their severity, and
`--top` keeps them first. Their fix is the `pin_ref` plan for the action, which
for an advisory moves the line to the first fixed version (`advisory_fixed`) or
a commit SHA after it. They have no principals: whoever compromised the version
holds the reach, so `confirmed_principals` and `possible_principals` are empty
and `reach_removed_pct` is 0.

Confirmed GOP004 results sort right after GOP003 results, matching the
`agent_exposed` rank factor. Their principals are the sources of the
workflow's `CAN_TRIGGER` edges; a result whose edges are all `not_visible`
(the agent's actor check is unknown) is possible. Severity is at least high
when the agent job holds a write scope or a secret. Their fix is the
`harden_trigger` plan; `agent_fixes` lists the agent-specific changes.

GOP005 results have the sources of the repo's `CAN_MERGE_VIA_BOT` edges as
principals; a result whose edges are all `not_visible` (a deciding fact such
as the bypass list, which App the merge mints for, or whether `GITHUB_TOKEN`
may approve is unknown) is possible. A review bypass only people with push
access can use has no result. Severity is what landing code on the repo's
default branch reaches (at least medium: the repo's CI). Their fix is the
`block_bot_merge` plan; `bot_merge_fixes` lists the changes, most effective
first, including the suspected (heuristic) stale-approval fix for a merge
script.

GOP006 results have the sources of the agent workflow's `CAN_TRIGGER` edges
as principals (who can plant the state). A result is possible when every such
edge is `not_visible` or the cache write itself is (`agent_memory_readers`
evidence `not_visible`: a GitHub Enterprise Server host with no
`cache-mode`, or an agent whose actor check is unknown). Severity is what the
restoring workflows reach, at least high: they hold secrets or a write token.
`memory_readers` names them, `memory_dirs` the agent memory stores among the
cached paths, and `memory_fixes` the changes; `fix` is the `harden_trigger`
plan for the agent workflow.

Results come from the same candidate fixes as `suggest_fixes` and `gop fix-plan`.
A fix whose edges are all `not_visible` is never a result. Each rule's
`help.markdown` describes the fix; `gop fix-plan --pin <action>` or
`gop fix-plan --lower-default-perm <org>` gives the full checklist.

A GOP001 result is about one consuming line: a principal inside the consuming
org (its members, its teams, or an identity that is a member) does not count,
so a workflow that uses an action hosted in its own org is reported only when
someone outside that org can also change the action. A GOP001 result without a
recorded file (a nested action) has only a logical location.

## Severity and level

Severity comes from the terminal impact behind the result: for GOP001, what
controlling the consuming workflow (or nested action) reaches; for GOP002, what
the affected principals lose when the base permission is read; for GOP003, what
the consuming workflow reaches, raised to the advisory's own severity
(`advisory_severity`, high when the advisory gives none) when that is higher;
for GOP004, what the agent workflow reaches, at least high when the agent job
holds a write scope or a secret; for GOP005, what controlling the repo
reaches; for GOP006, what the restoring workflows reach, at least high.

| Severity | Terminal impact | SARIF level |
|----------|-----------------|-------------|
| critical | an OIDC token or a cloud role | `error` |
| high | a secrets scope or a self-hosted runner pool | `error` |
| medium | repo CI only | `warning` |
| low | nothing beyond the edge | `note` |

Possible-only results (`--include-possible`) are always `level: note`.

## Properties

Every result carries a `properties` bag:

| Property | Meaning |
|----------|---------|
| `severity` | critical, high, medium or low |
| `repository` | GOP001, GOP003, GOP004: the repo that owns the fix, e.g. `acme-app/web` |
| `org` | GOP002: the org that owns the fix |
| `edge` | the evidence edge behind the result, as `from KIND to` |
| `evidence` | `live`, `inferred`, `audit`, `supplied` or `not_visible` |
| `possible` | true when the result holds only through a `not_visible` hop |
| `confirmed_principals` | principals with a fully verified path |
| `possible_principals` | principals whose path has a `not_visible` hop |
| `terminals` | counts of `oidc`, `secrets`, `runners`, `cloud_targets` and `repos` behind the result |
| `fix` | the fix in the shape the MCP tools take (`pin_ref` or `lower_default_perm`) |
| `reach_removed_pct` | share of all confirmed (principal, repo) pairs the fix removes on its own |
| `advisories` | GOP003: the advisory IDs behind the result |
| `agent` | GOP004: the agent kinds the workflow runs (attr `agent`) |
| `agent_fixes` | GOP004: the changes that shrink the agent's exposure, most effective first |

## Fingerprints

`partialFingerprints["gopFixableEdge/v1"]` is a SHA-256 of the rule, repo, file
and action ref (GOP001, GOP003), the rule and org (GOP002), or the rule, repo
and workflow file (GOP004). It does not include the
line, so code scanning keeps tracking an alert when the `uses:` line moves, and
it is identical across runs on the same graph.
