# Apache Ossie semantic model for the SQL export

[Apache Ossie](https://ossie.apache.org/) is an open format for semantic models: what each business term means, where its data lives, how terms join and how measures are calculated. [`gop.ossie.yaml`](gop.ossie.yaml) is a hand-written, reviewed Ossie model of gop's SQL export ([docs/sql.md](../../docs/sql.md)). Point an Ossie-aware tool such as [NVIDIA Auto Ontology](https://github.com/NVIDIA/auto-ontology) at a gop database and this model, and it starts from correct definitions instead of a generated draft that someone has to review first.

> **Privacy.** The database lists attack paths: who can make code run where. Auto Ontology sends schema samples, column values and your questions to the model endpoints it is configured with, which by default are NVIDIA's hosted API (`integrate.api.nvidia.com`, `ai.api.nvidia.com`). For real posture data, configure self-hosted models (`<ROLE>_ENDPOINT`, `<ROLE>_API_KEY` and `<ROLE>_MODEL` for every model role; see the Auto Ontology README) before you connect the database. Use the synthetic demo (`gop export --format sql --demo`) to try it with hosted models. Keep `gop.db` private (`chmod 600 gop.db`).

## What is in the model

| File | What it is |
|---|---|
| `gop.ossie.yaml` | The model: datasets (terms), relationships and metrics. |
| `views.sql` | One view per term over the export tables. Load it after the export. |
| `ossie_test.go` | Checks the model against the Ossie JSON Schema, the export schema and the engine's numbers. |
| `testdata/ossie-schema-0.3.0.dev0.json` | A verbatim copy of `core-spec/ossie-schema.json` from [apache/ossie](https://github.com/apache/ossie) (Apache-2.0), the schema the test validates against. |

**Targeted Ossie version: 0.3.0.dev0** (the `version` the core spec's JSON Schema requires). When Ossie publishes a new version, update `version`, replace the schema copy and run the tests.

**Terms** (datasets): run (one gop collection, not a GitHub Actions workflow run), organization, repository, workflow, action (an action ref as workflows consume it), identity (user or team; an outside collaborator is an identity with `is_outside_collaborator = 1`), principal, cloud_role, secret, runner (self-hosted runner pool), finding, reach, reach_trend. Each has a description, synonyms in `ai_context` and its column mappings. gop does not record GitHub App identities as nodes yet, so identity covers users and teams.

**Relationships**: ownership (repository to organization, workflow to repository, ...), reach and findings to principals and runs, and every gop edge label as a join through an edge dataset: `push_grant` (`CAN_PUSH`), `action_use` (`USES`), `action_host` (`RESOLVES_TO`), `workflow_definition` (`DEFINED_IN`), `workflow_capability` (`EXECUTES_WITH`), `membership` (`MEMBER_OF`), `trigger_grant` (`CAN_TRIGGER`), `role_assumption` (`CAN_ASSUME`). Every join includes `run_id`.

**Metrics** (all model-scoped, each reads one dataset; filter to one run or group by `run_id`):

| Metric | Meaning |
|---|---|
| `confirmed_reach_count` | Confirmed (principal, repo) pairs, the total gop's `what_if` and `top_paths` report. |
| `possible_reach_count` | Possible (principal, repo) pairs: reach that needs a fact gop could not see. Never summed with confirmed. |
| `unpinned_reachable_actions` | Action refs on a tag or branch that some principal has confirmed reach to. |
| `orgs_default_write` | Orgs whose default repository permission is write or admin. |
| `finding_count`, `max_finding_severity` | Findings; group by `finding.rule` and order by `finding.severity` for findings by severity. |
| `confirmed_reach_delta`, `possible_reach_delta` | Change in pairs from the previous run of the same enterprise (NULL for the first run). |

Confirmed means every hop of a path is confirmed: live, inferred, or an audit fact that is not stale; facts from a supplied trust file count as confirmed and are flagged. The `reach` table applies the audit age; the edge datasets' `confirmed` column reports each edge's own evidence and does not.

## Load the export and the views

```sh
gop export --format sql graph.json --out gop.sql     # or: --demo
sqlite3 gop.db < gop.sql
sqlite3 gop.db < contrib/ossie/views.sql
chmod 600 gop.db
```

Load several graphs into one database (see [docs/sql.md](../../docs/sql.md)) for the run-over-run metrics. The views read whatever runs the database holds, so load `views.sql` once; loading it again is safe. It is plain SQL that DuckDB also runs (`duckdb gop.duckdb < contrib/ossie/views.sql`).

Dataset sources are written `gop.main.<table>`: Auto Ontology names a SQLite database after its file stem and gives it the schema `main`, so keep the file name `gop.db`, or replace the `gop.` prefix with your file's stem.

## Load into Auto Ontology

1. Add the database as a connection. SQLite is connection-string only: add `sqlite:////absolute/path/to/gop.db` to `CONNECTION_STRINGS` (see Auto Ontology's `docs/connections.md`), then ingest it. Configure self-hosted models first for real data (see the privacy note above).
2. Import the model, in the UI under **Settings → Import / Export**, or with the API and an admin API token:

   ```sh
   curl --fail-with-body -X POST "$AUTO_ONTOLOGY_URL/api/model/import" \
     -H "x-api-key: $AUTO_ONTOLOGY_API_TOKEN" \
     -F file=@contrib/ossie/gop.ossie.yaml
   ```

Auto Ontology imports Ossie through the [Ossie converter for Auto Ontology](https://github.com/apache/ossie-converters/tree/main/nvidia). To check the conversion offline first, run it from a checkout of that repo:

```sh
uv run ossie-nvidia-auto-ontology export -i gop.ossie.yaml -o gop.auto_ontology.yaml --database-name gop
```

This model converts cleanly with the converter at commit `eee97db`. The converter needs each term to be one table, which is why the model reads views and not queries. It drops `ai_context` (synonyms and instructions) and dimensions; other Ossie tools keep them.

## Tests

`go test ./contrib/ossie/` loads the demo export (two runs) and `views.sql` with the `sqlite3` shell, then checks that:

- the model validates against the Ossie 0.3.0.dev0 JSON Schema;
- every dataset's table exists, every field is a column of it, and every column of it is a field, so a change to the export schema fails the test until the model follows;
- keys and relationships name declared fields, and every metric reads declared fields of one dataset;
- each metric's SQL returns the numbers gop's engine computes for the demo (and a golden file).

The tests skip without `sqlite3` locally and fail without it in CI.
