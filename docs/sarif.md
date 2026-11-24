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

GOP003 results sort before every other result, whatever their severity, and
`--top` keeps them first. Their fix is the `pin_ref` plan for the action, which
for an advisory moves the line to the first fixed version (`advisory_fixed`) or
a commit SHA after it. They have no principals: whoever compromised the version
holds the reach, so `confirmed_principals` and `possible_principals` are empty
and `reach_removed_pct` is 0.

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
(`advisory_severity`, high when the advisory gives none) when that is higher.

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
| `repository` | GOP001: the repo that owns the fix, e.g. `acme-app/web` |
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

## Fingerprints

`partialFingerprints["gopFixableEdge/v1"]` is a SHA-256 of the rule, repo, file
and action ref (GOP001, GOP003) or the rule and org (GOP002). It does not include the
line, so code scanning keeps tracking an alert when the `uses:` line moves, and
it is identical across runs on the same graph.
