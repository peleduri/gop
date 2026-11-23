# Posture drift: `gop diff`

A single snapshot answers "where are we". `gop diff` answers "what got worse since last time": it compares two `graph.json` files that you collected at different times and reports what changed.

```
gop diff OLD.json NEW.json [--format text|json|markdown]
                           [--only paths,settings,edges,scores,coverage]
                           [--fail-on confirmed-increase|any-new-path]
                           [--force]
```

gop does not store history. You keep the snapshots (for example as CI artifacts) and pass two of them.

## Example

The demo snapshots in [`internal/diff/testdata`](../internal/diff/testdata) are small synthetic graphs of the `acme` enterprise. In `ref-unpinned`, `acme-app/web` switched its deploy step from `acme-actions/deploy@<sha>` back to `acme-actions/deploy@main`:

```
$ gop diff internal/diff/testdata/ref-unpinned/old.json internal/diff/testdata/ref-unpinned/new.json
Since 2026-11-13: 2 new confirmed paths (1 to OIDC).
acme (gop.graph/v1): 2026-11-13T10:00:00Z → 2026-11-20T10:00:00Z
Confirmed (principal, repo) pairs: 3 → 4 (+1). Possible pairs: 0 → 0 (+0).

Paths (2):
  identity:bob -> oidc:acme-app/web  [added: none → confirmed]
      identity:bob =[CAN_PUSH, live]=> repo:acme-actions/deploy
      repo:acme-actions/deploy =[RESOLVES_TO (reversed), live]=> action:acme-actions/deploy@main
      action:acme-actions/deploy@main =[USES (reversed), live]=> workflow:acme-app/web/.github/workflows/ci.yml
      workflow:acme-app/web/.github/workflows/ci.yml =[EXECUTES_WITH, live]=> oidc:acme-app/web
  identity:bob -> repo:acme-app/web  [added: none → confirmed]
      ...

Edges (3):
  + action:acme-actions/deploy@main RESOLVES_TO repo:acme-actions/deploy  [live]
  + workflow:acme-app/web/.github/workflows/ci.yml USES action:acme-actions/deploy@main  [live, ref_kind=branch]
  - workflow:acme-app/web/.github/workflows/ci.yml USES action:acme-actions/deploy@3f2c9a8e1b7d4c6f0a5e9d8c7b6a5f4e3d2c1b0a  [was live, ref_kind=sha]

Scores (1):
  identity:bob  confirmed 11.5 → 21 (+9.5)  possible 0 → 0 (+0)
```

In `default-perm-raised`, `acme-actions` raised its default repository permission from read to write:

```
$ gop diff internal/diff/testdata/default-perm-raised/old.json internal/diff/testdata/default-perm-raised/new.json
Since 2026-11-13: 3 new confirmed paths; acme-actions default_perm read → write.
...
```

## What is compared

| Section | What it reports |
|---|---|
| `paths` | One row per (principal, target) pair, where the target is a repo, secret, OIDC trust or self-hosted runner the principal reaches. Principals are the scoring principals (org members, plus identities with their own grants), the same set `top_paths` and `what_if` count. |
| `settings` | Node attribute changes, such as an org's `default_perm`, `two_factor` or `sso`, with the evidence on each side. |
| `edges` | Evidence edges added, removed, changed (evidence or attrs such as `ref_kind`) or lost to visibility, grouped by kind. |
| `scores` | Per-principal blast radius before and after. Confirmed and possible deltas are separate. |
| `coverage` | Coverage gaps that opened or closed. |

Totals (confirmed and possible (principal, repo) pairs) are always shown. Nodes are joined by ID, never by position in the file.

### Path statuses

| Status | Meaning |
|---|---|
| `added` | Reachable in NEW, not in OLD. Shown as confirmed or possible. |
| `upgraded` | Possible in OLD, confirmed in NEW. |
| `downgraded` | Confirmed in OLD, possible in NEW: a hop became not visible. This is an evidence change, not a fix. |
| `lost_visibility` | Reachable in OLD, absent in NEW, and NEW cannot see part of the old path (a node on it is `not_visible`, or a coverage gap covers its org or the enterprise). Reach is unknown, not removed. |
| `removed` | Reachable in OLD, absent in NEW, and NEW can see every node on the old path. |
| `gained_visibility` | Absent in OLD because OLD could not see part of the path. |

Rows are ordered by status, then severity of the target (OIDC, secret, runner, repo), then IDs.

### Lost visibility is never "off"

gop never turns "couldn't see" into "off". A setting that goes from a value to `not_visible` (by `attr_evidence`, node evidence, a value of `unknown`/`not_visible`, or a coverage gap on that setting) is reported as lost visibility, with the evidence shown:

```
$ gop diff internal/diff/testdata/lost-visibility/old.json internal/diff/testdata/lost-visibility/new.json
Since 2026-11-13: 0 new confirmed paths, 3 lost visibility; acme-actions two_factor required → not visible (lost visibility).
acme (gop.graph/v1): 2026-11-13T10:00:00Z → 2026-11-20T10:00:00Z
Confirmed (principal, repo) pairs: 3 → 1 (-2). Possible pairs: 0 → 0 (+0). 2 confirmed pairs lost visibility or became possible: unknown, not fixed.
...
Settings (1):
  acme-actions two_factor required → not visible (lost visibility)  [evidence live → not visible]
```

The same rule applies to paths and edges: when the newer token cannot see a node, the paths and edges through it are listed as lost visibility, not as removed.

## Exit codes and CI

| Code | Meaning |
|---|---|
| 0 | No `--fail-on` condition matched. |
| 1 | A `--fail-on` condition matched. |
| 2 | Usage error, a snapshot failed to load, or the snapshots are not comparable. |

`--fail-on` takes a comma-separated list:

- `confirmed-increase`: the number of confirmed (principal, repo) pairs grew.
- `any-new-path`: any `added` (confirmed or possible) or `upgraded` path.

Lost visibility and downgrades never trip `--fail-on`; watch the `coverage` section for those.

`gop diff` refuses to compare snapshots of different enterprises or different major schema versions. `--force` compares them anyway.

## Formats

- `text` (default) leads with a one-sentence summary.
- `markdown` renders the same content as tables, for a PR comment or job summary.
- `json` encodes the full `diff.Report` (see [`internal/diff/diff.go`](../internal/diff/diff.go)); it decodes back into the same type.

`--only` limits the sections shown. It does not change the leading summary (also `summary` in JSON), which always describes the full diff, or what `--fail-on` evaluates.
