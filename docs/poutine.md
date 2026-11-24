# gop and poutine

[poutine](https://github.com/boostsecurityio/poutine) (Apache-2.0) finds flaws inside pipelines: script injection from `${{ github.event.issue.title }}`, untrusted fork code run on `pull_request_target`, self-hosted runners on pull requests, debug logging left on. gop finds who can reach a pipeline and what sits behind it (secrets, OIDC tokens, cloud roles). Together, "a principal can possibly trigger this workflow" becomes "a principal can reach a workflow that poutine found injectable, and that workflow can assume a cloud role".

gop never runs poutine. You run poutine and hand gop its JSON report. No token, no network.

## Run it

```sh
# poutine, against the same repos gop collected (GitHub Enterprise Server: add --url)
poutine analyze_org acme-app --format json > poutine.json
# or one repo
poutine analyze_repo acme-app/web --format json > poutine.json

gop enrich --graph graph.json --poutine poutine.json --out graph2.json
# with trust files or a Cartography export in the same run:
gop enrich --graph graph.json --oidc-trust ./trust/ --poutine poutine.json --out graph2.json
```

stderr reports how many findings matched how many workflows, how many of those workflows have an injection-class finding, and every unmatched finding.

## Format

Checked against poutine **v1.1.6** (released 2026-05-22): `formatters/json/json.go`, `opa/rego/poutine/format/json.rego`, `results/results.go`, and the `purl` built in `analyze/analyze.go`. The report is one JSON object:

```json
{
  "rules": {
    "injection": {"id": "injection", "title": "...", "description": "...", "level": "warning", "refs": []}
  },
  "findings": [
    {"rule_id": "injection",
     "purl": "pkg:github/acme-app/web@main?repository_url=github.acme.example",
     "meta": {"path": ".github/workflows/ci.yml", "line": 21, "job": "lint", "step": "2",
              "details": "Sources: github.event.issue.title"}}
  ],
  "packages": {"pkg:github/acme-app/web@main?...": {"dependencies": [], "commit_sha": "...", "ref": "main"}}
}
```

gop reads `findings[].rule_id`, `purl` (the repository: `pkg:github/<owner>/<repo>[@ref][?repository_url=<host>]`), `meta.path` (the repo-relative file), `meta.job` and `meta.line`, and `rules[<id>].level` (`error`, `warning` or `note`). Other keys are ignored, so new poutine fields do not break the import. SARIF (`--format sarif`) is not read: the JSON output carries the repository purl and job, which the mapping needs. A SARIF file, poutine's `pretty` output, or anything that is not a JSON object with a `findings` array is a clear error. A single finding that cannot be read is a warning; the rest still import.

## Mapping

Each finding maps to the workflow node `workflow:<owner>/<repo>/<meta.path>` (owner and repo compared without case). gop has no job nodes, so the job is recorded on the workflow. A matched workflow gets:

| Attr | Value |
|---|---|
| `poutine_rules` | Sorted comma list of the rule IDs with a finding in the file |
| `poutine_severity` | The highest rule level among them: `error`, `warning`, `note` (absent when the report has no `rules`) |
| `poutine_jobs` | Sorted comma list of the job ids the findings name |
| `poutine_file` | The report file |

A finding that matches no workflow node is never dropped. It is printed as a warning (with its job) and added to coverage with fact `poutine_finding`. The scope names what poutine pointed at: `workflow:<owner>/<repo>/<path>` when the finding has a GitHub repo and a path, `repo:<owner>/<repo>` when it has no path, `poutine:<report file>` when there is no GitHub repo. The reason gives the rule, level, line and why:

- the repo is outside the collected orgs, or the file is not a workflow gop collected (a composite `action.yml`);
- the purl is not a GitHub repository (GitLab, Azure Pipelines, `pkg:generic/...` from `analyze_local`);
- the finding has no file path (output written with blob SHAs instead of paths).

Running `gop enrich --poutine` again replaces the poutine attrs and `poutine_finding` coverage of the earlier run.

## Ranking

The rules `injection` and `untrusted_checkout_exec` are injection-class: attacker input becomes code in the workflow. For each principal, `poutine_injectable` on its score counts the confirmed-reached workflows with an injection-class finding. It is a separate rank factor, applied first: a principal whose confirmed reach includes such a workflow ranks above the same reach without one, in `top_risks` and the report. The `top_risks` summary says "N reached workflows with an injection finding from poutine (cited, not proved by gop)". Other rules (`debug_enabled`, `pr_runs_on_self_hosted`, ...) are recorded but do not change the order.

## Evidence

poutine's finding is cited, not proved. gop does not change any edge, evidence level, score or count because of it: the path is exactly as confirmed or possible as gop's own facts make it, and the score still counts confirmed reach only. A report from an older commit than the graph can name lines or jobs that changed since; run poutine and gop collect close together.
