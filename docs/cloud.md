# gop Cloud (optional)

gop Cloud is a planned hosted view of your gop results: history and trends
across runs, one page per enterprise. **The service is not live yet.** This
page documents the opt-in upload that will feed it, so you can review exactly
what would leave your network before you ever turn it on.

gop itself never phones home. Nothing is sent anywhere unless your own
workflow sets `cloud: "true"` and a `cloud-url` on the gop Action.

## What is sent

One JSON document per run, written by `gop summary` (schema
[`schema/gop.summary.v1.schema.json`](../schema/gop.summary.v1.schema.json),
`gop.summary/v1`, at most 64 KB). Every object in the schema is closed: a field
not listed below cannot appear, and adding one means a new schema version.

| Field | What it holds |
|---|---|
| `schema` | `gop.summary/v1` |
| `enterprise` | the enterprise slug you collected (for example `acme`) |
| `gop_version` | the gop version that wrote the summary |
| `run_at` | when the graph was collected (`collected_at`) |
| `names` | whether top findings carry names (`--names`, off in the Action) |
| `coverage.orgs_read` | number of orgs in the graph |
| `coverage.partial`, `coverage.partial_reason` | the collection stopped early, and why (`interrupted`, `max_requests`, `reserve`, `rate_limit`) |
| `coverage.not_visible` | number of nodes and edges the token could not read |
| `coverage.coverage_entries` | number of coverage entries |
| `headline.non_human_actors` | AI agent workflows, bot-merge workflows, review-bypass Apps and bot accounts |
| `headline.merge_without_human` (`_confirmed`, `_possible`) | workflows that can merge to a default branch with no human review |
| `headline.outsider_triggerable_agents` | confirmed AI agent workflows people without push access can start |
| `headline.dangerous_mode_agents` | confirmed AI agent workflows run with their approval or sandbox removed |
| `pairs.confirmed`, `pairs.possible` | confirmed and possible (principal, repo) pair totals |
| `severities` | confirmed findings by severity (critical, high, medium, low) |
| `rules[]` | per SARIF rule (`GOP001`...`GOP005`, the same IDs as `gop sarif`): `id`, `name`, `confirmed`, `possible`, counts by severity |
| `findings` | total findings |
| `top[]` | the most severe findings (20 by default): `id`, `rule`, `severity`, `possible`, `reach_removed_pct` |
| `top[].repository`, `top[].workflow`, `top[].org` | **only with `gop summary --names`**, sanitized and capped at 200 characters. The Action never passes `--names`. |
| `truncated` | `top` was cut to stay under 64 KB |

A finding `id` is the first 16 hex characters of SHA-256 over the rule ID and
the node IDs of the finding's edge. It has no salt, so the same finding has
the same ID on every run (that is what makes trends work). It keeps names out
of the summary, but it is not anonymization: anyone who can guess a repo and
workflow name can hash it and confirm a match.

Run `gop summary --graph graph.json --out summary.json` to see the exact
document for your own graph. The Action also keeps `summary.json` in the run's
artifact, so you can check what was sent.

## What is never sent

- graph.json, the HTML or Markdown report, the diff, SARIF.
- Tokens of any kind: the collection token, the App private key, the
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. The upload authenticates with a
  short-lived GitHub OIDC token minted for the request (below).
- Member logins, team names, emails, secret names or values, runner labels,
  IP allow lists, cloud role names.
- Repo, workflow and org names, unless you run `gop summary --names` yourself.

## How the upload works

1. Before collecting, the Action checks that `cloud-url` is `https://` and
   that the job can mint an OIDC token. Without `id-token: write` it fails
   with "this job cannot request a GitHub OIDC token" and sends nothing.
2. After the report, `gop summary` writes `summary.json`; it goes into the
   artifact with graph.json.
3. After the artifact upload, the Action requests a GitHub OIDC token with
   audience `gop-cloud` and POSTs `summary.json` to `cloud-url` with it as a
   Bearer token. The token is masked in the log and passed to curl on stdin,
   never on the command line. The log shows only the HTTP status. A failed
   upload fails the job, but the artifact is already saved.

The service will check the token's signature against GitHub's keys, its
audience, issuer and expiry, and take your tenant only from the verified
`repository_owner` claim, so no shared secret is needed.

```yaml
permissions:
  contents: read
  id-token: write # mint the OIDC token for the gop Cloud upload
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: peleduri/gop/action@<full-commit-sha> # vX.Y.Z
        with:
          enterprise: acme
          app-id: ${{ vars.GOP_APP_ID }}
          app-private-key: ${{ secrets.GOP_APP_PRIVATE_KEY }}
          cloud: "true"
          cloud-url: https://cloud.example.com/v1/ingest
```

## How to turn it off

It is off by default. To stop sending, remove `cloud: "true"` (or set
`cloud: "false"`) and drop `id-token: write` if nothing else in the job needs
it. With `cloud` off the Action makes no request outside GitHub and does not
run `gop summary`.
