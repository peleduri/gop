# gop and Cartography

[Cartography](https://github.com/cartography-cncf/cartography) loads cloud and SaaS inventory into Neo4j. gop and Cartography meet at the cloud hop: Cartography knows which AWS roles trust GitHub Actions and which repositories CloudTrail saw assume them; gop knows which workflows can mint which tokens and who can control those workflows. gop never connects to Neo4j and needs no Neo4j credentials: you run a query and hand gop the export.

## Import trusts from Cartography

`gop enrich --cartography` reads the result of [`oidc-trusts.cypher`](cartography/oidc-trusts.cypher), maps each row to the same trust model as `--oidc-trust` files and adds `workflow -CAN_ASSUME-> cloud:aws:<role ARN>` edges exactly as a trust file would.

### Run it

Run the query read-only against the Cartography database, in either tool:

```sh
# cypher-shell: plain text output is accepted as is
cypher-shell -a neo4j://localhost:7687 -u neo4j --format plain \
  < docs/cartography/oidc-trusts.cypher > cartography-export.txt

# or Neo4j Browser: paste the query, run it, then download the result as JSON
```

Then:

```sh
gop enrich --graph graph.json --cartography cartography-export.txt --out graph2.json
# trust files and an export together:
gop enrich --graph graph.json --oidc-trust ./trust/ --cartography cartography-export.json --out graph2.json
```

Accepted export shapes: a plain JSON array of row objects (`[{"kind": "trust", ...}]`), the Neo4j Browser JSON download (row objects, or driver records with `keys` and `_fields`), the Neo4j HTTP API result (`{"results": [{"columns": [...], "data": [{"row": [...]}]}]}`), and `cypher-shell --format plain` output. Rows that do not fit are printed as warnings and skipped; gop never stops on a bad row.

### What the query reads

| Row `kind` | Cartography data | Columns |
|---|---|---|
| `trust` | `(:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal)` where the principal is a GitHub Actions OIDC provider (`token.actions.githubusercontent.com`, with or without an enterprise path, or a GitHub Enterprise Server `/_services/token` issuer) | `role_arn`, `role_name`, `principal_arn`, `has_condition`, `conditions` |
| `observed` | `(:GitHubRepository)-[:ASSUMED_ROLE_WITH_WEB_IDENTITY]->(:AWSRole)`, which Cartography builds from CloudTrail `AssumeRoleWithWebIdentity` events | `role_arn`, `repo` (the repository's `fullname`), `times_used`, `first_seen`, `last_used` |

### Field mapping

- A `trust` row is one role and one OIDC provider. Cartography stores `conditions` as a JSON array of the raw `Condition` block of every `Allow` statement that grants the trust, in document order. gop turns each block into one trust statement and reads it with the same AWS parser as a trust file, so `StringEquals`, `StringLike`, `ForAnyValue:`/`IfExists` and negative operators behave as they do in [Paths out of GitHub](../README.md#paths-out-of-github). A role whose export rows match its trust policy gives the same graph as `--oidc-trust` with that policy, apart from the file name.
- `has_condition: false` means one statement grants the trust with no condition. The trust has no `sub` condition, so every workflow that can mint a token matches, and the `cloud_target` gets the `no_sub_condition` warning.
- A row whose conditions are missing (a Cartography version older than these properties) or cannot be read is kept as a trust whose matches are all possible (`not_visible` with a `reason`), with a warning. It is never read as unconditional and never dropped.
- Edges and nodes: evidence is `supplied`, as for trust files. The edge's `file` is the export, `source_api` is `supplied:<export>`, `pointer` is `/<row>` (or `/<row>/conditions/<block>`), and the edge and its `cloud_target` carry `source=cartography`. Re-running with the same export replaces its edges, so the output is byte-identical for the same inputs.
- An `observed` row sets `observed_use=true`, `times_used` and `last_used` on every `CAN_ASSUME` edge from a workflow of that repository into that role, whether the edge came from the export or from a trust file. CloudTrail only names the repository, not the workflow, so all of the repository's matching workflows get the attrs. Evidence does not change. An observation that no edge matches is a warning, never a new edge: the repository may be outside the graph, its trust may be missing from the export, or its workflows may use a custom `sub` template gop does not model. Each run clears observed-use attrs first, so the latest export's observations replace earlier ones.

### Limits

- AWS only. Cartography models GCP workload identity pools and providers (`GCPWorkloadIdentityProvider` with `attributeCondition`, `oidcIssuerUri`, `oidcAllowedAudiences`), but not the provider's `attributeMapping`. GitHub conditions and `principalSet://.../attribute.repository/...` bindings are written against mapped attributes, so gop cannot resolve them from the graph. Cartography does not collect Azure (Entra) federated identity credentials at all. For GCP and Azure, export the trust files and use `--oidc-trust`.
- Cartography applies unconditional `Deny` statements before it writes the edge, and does not export conditional ones. A trust policy with a conditional `Deny` can therefore be narrower than gop models; a trust file read with `--oidc-trust` would mark such matches as possible.
- Observed use covers only Cartography's CloudTrail lookback window, only GitHub Actions identities, and only repositories that Cartography's GitHub module loaded as `GitHubRepository` nodes: the relationship is not created without one. No observation is not evidence that a role is unused.
- The export is as fresh as the last Cartography sync. A stale export gives stale answers, as with trust files.
- cypher-shell plain output quotes strings but may not escape every character. If a row's conditions come out garbled, download JSON from Neo4j Browser instead.

## Export gop to Neo4j

Placeholder: how to load a gop graph into the same Neo4j database is documented here once the export lands.
