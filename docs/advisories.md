# Action advisories

Some actions have been compromised outright: a maintainer account or a tag was
hijacked and the action shipped code that stole secrets. gop already knows
which `uses:` lines are reachable and which secrets, OIDC tokens and cloud roles
sit behind them. With advisory data it also knows which action versions are
affected, and ranks "a compromised action version can reach a cloud role"
above everything else.

## Where the data comes from

[OSV](https://osv.dev) publishes a `GitHub Actions` ecosystem: the GitHub
Advisory Database entries for actions (GHSA IDs), in the
[OSV schema](https://ossf.github.io/osv-schema/). gop reads, per advisory, the
affected package (`owner/repo` or `owner/repo/path`), its version ranges
(`ECOSYSTEM`, `SEMVER`), the listed `versions`, the commits of `GIT` ranges and
the GitHub severity (`database_specific.severity`). Withdrawn advisories are
ignored.

The data is as fresh as your copy. OSV rebuilds the export continuously; run
`gop advisories update` before a collection (for example in the same scheduled
job) to pick up new advisories. Every run prints the source and its date
(`as of`, the file's modification time or the time of the live query).

## Modes

| Mode | How | Network |
|------|-----|---------|
| Offline (default) | `gop advisories update` downloads `https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip` to `<user cache dir>/gop/osv-github-actions.zip` (`--out` writes elsewhere). `gop collect` uses that copy when it exists. | only the download |
| A copy you supply | `--advisories PATH` on `gop collect` or `gop enrich`: the zip, or a directory of OSV JSON records (a mirror, or records you wrote) | none |
| Live (opt-in) | `--advisories-live` on `gop collect` or `gop enrich`: `POST https://api.osv.dev/v1/querybatch` with the graph's action package names (repeating a query with its `page_token` while the result has a `next_page_token`), then `GET /v1/vulns/{id}` for each advisory it names | OSV API |

Live mode sends only package names (`owner/repo[/path]` of the actions your
workflows use), never refs, repo names, workflow names or anything else from
the graph. Neither mode talks to GitHub or needs a token.

The check never fails a run. With no data (no local copy and neither flag), or
data gop cannot read, it is skipped: the graph gets one coverage entry
(`scope: enterprise:<slug>`, `fact: advisories`, reason starting
`advisory check skipped`) and stderr says so. `gop enrich --advisories ...`
annotates an existing graph without collecting again.

## Matching

Each `action_ref` node (`owner/repo[/path]@ref`) is checked against the
advisories whose package is `owner/repo/path` or `owner/repo`:

- **A tag** (`v2.3.0`, `2.3.0`) is affected when it is in `versions` or inside
  an affected span of a version range (introduced up to fixed, or up to and
  including last_affected). A partial tag such as `v2` moves across every
  `2.x.y`: affected only when all of them are, not affected when none are, and
  **unknown** when the fix falls inside it.
- **A full commit SHA** is affected when it is listed in `versions` or as an
  introduced or last_affected commit of a `GIT` range, and not affected when it
  is a fixed commit. Any other SHA is **unknown**: gop does not walk git history.
- **A branch** (`main`) or an abbreviated SHA is **unknown**.

- **A `uses:` an actions.lock pins** (`actions_lock=locked`, see
  [actions-lock.md](actions-lock.md)) runs the lockfile's commit, not the ref,
  so its `locked_sha` is matched too, with the same rules as a full commit SHA.
  An affected commit sets `lock_advisories`, `lock_advisory_severity` and
  `lock_advisory_fixed` on that `USES` edge only. The action node's attrs stay
  the match on the ref, so another repo that uses the same ref without the
  lock (or with a lock on a clean commit) is not flagged. A locked commit the
  advisory does not list is **unknown** and gets its own coverage entry
  ("actions.lock pins it to ..."); a fixed commit is not affected.

Unknown is never read as safe. Each unknown ref gets a coverage entry
(`scope: action:<ref>`, `fact: advisories`) naming the advisories and why it
could not be placed.

An affected node gets these attrs (no schema bump; see
[schema.md](schema.md#attributes)):

| Attr | Value |
|------|-------|
| `advisories` | comma list of the advisory IDs |
| `advisory_severity` | the highest: `critical`, `high`, `medium` (GitHub's `MODERATE`), `low` or `unknown` |
| `advisory_fixed` | the first fixed version that leaves every listed advisory; absent when one has no fix |

Annotating again replaces earlier advisory attrs and coverage, so a graph never
keeps a stale advisory.

## Ranking

A known compromise outranks everything else:

- **top_risks and the report.** Every action with an advisory and confirmed
  reach is listed as its own entry: whoever compromised that version controls
  every workflow that runs it, with their secrets, OIDC tokens, cloud roles and
  runners. A principal whose confirmed paths run through such an action carries
  it in `advisories`. Any entry with `advisories` ranks above every entry
  without, whatever the scores (`rankAdvisory`, the first factor of
  `graph.RanksAbove`; poutine's `poutine_injectable` comes next, then the score).
  Advisory actions are not scoring principals, so `what_if`, `suggest_fixes`,
  pair totals and `gop diff` are unchanged.
- **SARIF.** Rule `GOP003` (`action-with-known-advisory-reachable`), one result
  per `uses:` line, sorted before every other rule. See [sarif.md](sarif.md).
- **fix_plan and gop fix-plan.** `--pin <action>` on an action with an advisory
  moves each `uses:` line to the first fixed version (`advisory_fixed`, with a
  `v` when the current ref has one) or a commit SHA after it, instead of pinning
  the affected version. With no fixed version, the plan says to remove or
  replace the action. A `uses:` line whose actions.lock pins an affected
  commit is not edited: the plan's caveat for that line says "actions.lock
  pins an affected commit: rerun gh actions-lock after moving to
  `<lock_advisory_fixed>`", and GOP003 reports that line with the locked
  commit.
- **Locked affected commits.** An action whose ref is not affected but that
  an actions.lock pins to an affected commit is ranked like an affected
  action, with the reach of only those locked workflows. GOP003 and the
  fix-plan caveat name only the locked lines; the other `uses:` lines of the
  ref get neither.

For a compromise, moving off the version is not the end: rotate the secrets and
cloud credentials the workflows could reach while they ran it.

## Redaction

`gop redact` keeps the advisory attrs but renames each advisory ID to a stable
`ADV-<hex>` (a real ID names the public action), in attrs and in advisory
coverage entries, so the ranking survives and the action stays unnamed.
