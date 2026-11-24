# SQL export (SQLite and DuckDB)

gop's MCP tools and report answer path questions: who can make code run where, and how. Questions that count and group ("repos per org that members reach through an unpinned action, over the last ten runs") are easier in SQL, in a BI tool, or in a text-to-SQL tool that reads SQLite or DuckDB. `gop export --format sql` writes one or more graphs, their computed reach and their ranked findings as a SQL script that both databases load.

> **The export lists attack paths.** It holds the same facts as `graph.json` plus the computed paths. `--out` writes the script with mode 0600; keep the database file private too (`chmod 600 gop.db`), and do not commit or share either one. Use [`gop redact`](../README.md#cli) on the graph first if you need to share an export.

## Export and load

```sh
gop export --format sql graph.json --out gop.sql
sqlite3 gop.db < gop.sql        # or: duckdb gop.duckdb < gop.sql
```

Several graphs go into one script, one run each, so trends work:

```sh
gop export --format sql runs/2026-*.json --out gop.sql
```

Loading into an existing database adds runs: the script uses `CREATE TABLE IF NOT EXISTS`, then deletes the rows of each run it holds before inserting them, all in one transaction. Loading the same export twice changes nothing, and older runs stay. A run is identified by `run_id`, the graph's collection time plus a hash of its content (the same stamp as `gop_run` in the [Cypher export](cartography.md)), so the same graph always gets the same ID and any change gets a new one.

gop writes SQL text and links no database driver, which keeps the binary small and CGO-free. Load the script with the `sqlite3` or `duckdb` shell, or any client that runs a multi-statement script; a naive splitter that cuts on `;` at line ends can break on names that contain one. `--demo` exports the synthetic demo graph. `--github-url` applies to `--format cypher` only.

Values are standard SQL string literals (single quotes doubled, nothing else escaped). A value that contains a control character (a newline, carriage return, tab, escape, ...) is written JSON-encoded and decoded on load, as `('"a\r\nb"' ->> '$')`, so the script itself holds no control character and no shell's line handling can change a value; this needs JSON support (SQLite 3.38 or later, DuckDB's built-in `json` extension). Any name round-trips except NUL and invalid UTF-8, which become U+FFFD. Booleans are `INTEGER` 0 or 1. Times are RFC 3339 UTC text. Evidence is plain text (`live`, `audit`, `supplied`, `not_visible`, and any level a later schema adds), so check `confirmed` rather than listing evidence values.

## Schema

Every table has `run_id`; join on it as well as on IDs. Node, org and repo values are gop node IDs (`org:acme-app`, `repo:acme-app/web`), so they join to `nodes.id`. See [schema.md](schema.md) for ID conventions and what each edge means.

```text
runs(run_id, enterprise, collected_at, schema_version)
nodes(run_id, id, kind, name, org, repo, evidence, declared)
node_attrs(run_id, node_id, key, value, evidence)
edges(run_id, edge_id, src, dst, label, evidence, confirmed, source_api, observed_at)
edge_attrs(run_id, edge_id, key, value)
findings(run_id, rule, subject, severity, possible)
reach(run_id, principal, target, target_kind, confirmed, evidence, hops, path)
```

| Table | Rows |
|---|---|
| `runs` | One per exported graph. `schema_version` is the graph's `schema` (`gop.graph/v1`). |
| `nodes` | One per node. `org` is the org the node belongs to and `repo` its repo (an action ref's `repo` is the repo that hosts it); both are NULL when they do not apply. An edge endpoint the graph does not declare gets a row with `declared` = 0, its kind taken from the ID prefix, and NULL `evidence`. |
| `node_attrs` | One per node attribute. `evidence` is the attribute's own evidence when the graph records one (`attr_evidence`), else the node's. |
| `edges` | One per edge. `label` is the edge kind (`CAN_PUSH`, `USES`, ...). `confirmed` is 1 for `live`, `audit` and `supplied` evidence. `edge_id` numbers the edges of a run in a stable order. |
| `edge_attrs` | One per edge attribute (`via`, `ref_kind`, `file`, `line`, ...), keyed by `edge_id`. |
| `reach` | gop's computed reach, so SQL never reimplements the traversal: one row per scoring principal (org members, outside principals, and identities and teams with their own grants; see [schema.md](schema.md#principals-and-scoring)) and node it reaches (repos, workflows, action refs, secrets, OIDC, runners, cloud targets, ...). `confirmed` is 1 when every hop of the path is confirmed, 0 when the path needs a fact gop could not see (possible reach). `path` is the shortest path as a JSON array of node IDs, `hops` its length. |
| `findings` | `rule = 'top_risk'`: one row per scoring principal with any reach; `severity` is its confirmed blast-radius score (as in `top_risks` and the report) and `possible` its possible score. `rule = 'fix_pin'`, `'fix_default_perm'`, `'fix_restrict_token'`, `'fix_harden_trigger'`: one row per fix candidate, `subject` is the fix ID (`pin:action:acme-actions/deploy@main`), `severity` the confirmed (principal, repo) pairs that fix alone removes and `possible` the possible pairs it removes (each fix is evaluated on its own, unlike the greedy order of `suggest_fixes`). |

## Example queries

These run unchanged in SQLite and DuckDB. The test suite runs each one on the demo graph and checks the result.

### 1. Principals that reach the most repos (latest run)

```sql
SELECT principal, COUNT(*) AS repos
FROM reach
WHERE run_id = (SELECT run_id FROM runs ORDER BY collected_at DESC, run_id DESC LIMIT 1)
  AND target_kind = 'repo' AND confirmed = 1
GROUP BY principal
ORDER BY repos DESC, principal
LIMIT 5;
```

### 2. Secrets, OIDC tokens and runners in reach, confirmed and possible

```sql
SELECT target_kind,
       COUNT(DISTINCT CASE WHEN confirmed = 1 THEN target END) AS confirmed_targets,
       COUNT(DISTINCT CASE WHEN confirmed = 0 THEN target END) AS possible_targets,
       COUNT(DISTINCT principal) AS principals
FROM reach
WHERE run_id = (SELECT run_id FROM runs ORDER BY collected_at DESC, run_id DESC LIMIT 1)
  AND target_kind IN ('secret', 'oidc', 'runner', 'cloud_target')
GROUP BY target_kind
ORDER BY target_kind;
```

### 3. Workflows per org that use a mutable (unpinned) action ref

```sql
SELECT w.org, COUNT(DISTINCT e.src) AS workflows, COUNT(DISTINCT e.dst) AS refs
FROM edges e
JOIN edge_attrs a ON a.run_id = e.run_id AND a.edge_id = e.edge_id
JOIN nodes w ON w.run_id = e.run_id AND w.id = e.src
WHERE e.run_id = (SELECT run_id FROM runs ORDER BY collected_at DESC, run_id DESC LIMIT 1)
  AND e.label = 'USES' AND w.kind = 'workflow'
  AND a.key = 'ref_kind' AND a.value IN ('branch', 'tag')
GROUP BY w.org
ORDER BY workflows DESC, w.org;
```

### 4. Fixes that remove the most confirmed reach (latest run)

```sql
SELECT rule, subject, severity AS pairs_removed
FROM findings
WHERE run_id = (SELECT run_id FROM runs ORDER BY collected_at DESC, run_id DESC LIMIT 1)
  AND rule <> 'top_risk'
ORDER BY severity DESC, subject
LIMIT 5;
```

### 5. Confirmed and possible (principal, repo) pairs per run

```sql
SELECT r.collected_at,
       SUM(CASE WHEN x.confirmed = 1 THEN 1 ELSE 0 END) AS confirmed_pairs,
       SUM(CASE WHEN x.confirmed = 0 THEN 1 ELSE 0 END) AS possible_pairs
FROM runs r
JOIN reach x ON x.run_id = r.run_id AND x.target_kind = 'repo'
GROUP BY r.run_id, r.collected_at
ORDER BY r.collected_at, r.run_id;
```
