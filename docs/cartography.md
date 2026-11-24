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

gop computes what Cartography does not: who can make code run where, with confirmed versus possible reach. `gop export --format cypher` writes gop's graph and computed reach as a Cypher script you load into the same Neo4j, linked to Cartography's nodes. With `gop enrich --cartography` above, trusts flow from Cartography into gop; the export sends gop's paths back.

```sh
gop export --format cypher graph.json > gop.cypher
cypher-shell -a neo4j://localhost:7687 -u neo4j -f gop.cypher
```

gop only writes text. It never connects to Neo4j and has no Neo4j dependency.
Treat `gop.cypher` like `graph.json`: it is a map of your attack paths.

Flags: `--graph graph.json` works in place of the positional file, `--demo`
exports the synthetic demo graph, `--out gop.cypher` writes a file (mode 0600)
instead of stdout, and `--github-url https://ghe.acme.example` sets the web root
of the GitHub URLs when Cartography loaded a GitHub Enterprise Server.

### What the script loads

| Neo4j | From gop |
|---|---|
| `:GopNode` plus a kind label: `:GopEnterprise`, `:GopOrg`, `:GopOrgMembers`, `:GopIdentity`, `:GopRepo`, `:GopWorkflow`, `:GopActionRef`, `:GopSecret`, `:GopOIDC`, `:GopRunner`, `:GopCloudRole`, `:GopExternal` | Every node. Properties: `id` (the gop node ID, e.g. `repo:acme-app/web`), `kind`, `name`, `evidence`, `confirmed`, `gop_enterprise`, `gop_run`, and each attribute as `attr_<key>` (e.g. `attr_default_perm`, `attr_via`). An edge endpoint the graph does not declare gets `declared: false`. |
| `CAN_PUSH`, `CAN_TRIGGER`, `USES`, `RESOLVES_TO`, `DEFINED_IN`, `EXECUTES_WITH`, `MEMBER_OF`, `CAN_ASSUME` | Every gop edge, in the direction it has in `graph.json`. Properties: `kind`, `evidence`, `confirmed`, `source_api`, `observed_at`, `gop_key`, `gop_run`, and `attr_<key>`. |
| `GOP_REACHES` | Computed reach: one edge from each principal gop scores (org members, outside collaborators, teams, anyone on the internet, ...) to each secret, OIDC token, runner and cloud role it can control. Like the SQL `reach` table, it follows gop's pair model: an identity's edges leave out what it reaches only through its org membership, which is on the `members:X` edges (see [schema.md](schema.md#principals-and-scoring)); follow `MEMBER_OF` to `members:X` for a person's full reach (sample below). Properties: `confirmed` (every hop `live`, `audit` or `supplied`), `evidence` (the weakest hop), `supplied`, `hops`, `path` (node IDs in control order) and `path_kinds` (the edge kind of each hop). |
| `SAME_AS` | Links to Cartography nodes, see below. |

Use `GOP_REACHES` for "who can reach what". The raw edges are evidence, not
control order: gop walks `DEFINED_IN`, `RESOLVES_TO` and `USES` backwards and
gates some hops (protected refs, Actions access), so a variable-length pattern
over raw edges finds paths gop would not count.

### Links to Cartography

Only where the identity is unambiguous:

| gop | Cartography | Match |
|---|---|---|
| `(:GopOrg {id: 'org:acme-app'})` | `(:GitHubOrganization)` | `id = 'https://github.com/acme-app'` (the organization URL) |
| `(:GopRepo {id: 'repo:acme-app/web'})` | `(:GitHubRepository)` | `id = 'https://github.com/acme-app/web'` (the repository URL) |
| `(:GopCloudRole {id: 'cloud:aws:arn:aws:iam::111111111111:role/deploy'})` | `(:AWSRole)` | `arn = 'arn:aws:iam::111111111111:role/deploy'`; only exact role ARNs, never wildcards |

Each link is `MATCH` on both ends, then `MERGE (gop)-[:SAME_AS]->(cartography)`,
so it does nothing when Cartography has not loaded that node. Load gop after
Cartography, or export again after a Cartography sync, to pick up new links.
GCP and Azure cloud roles, and identities, are not linked.

### Re-exports and cleanup

Every node and relationship carries `gop_run`: the graph's `collected_at` and a
hash of its content. The script `MERGE`s everything (nodes on `gop_enterprise`
plus `id`, edges on `gop_key`), then deletes the `:GopNode`s and gop
relationships of the same enterprise whose `gop_run` differs. Loading the same
export twice changes nothing; loading a newer one replaces the older run.
Graphs of different enterprises live side by side. The output is sorted, so
the same graph always gives a byte-identical script.

### Safety

Every value from the graph is a single-quoted Cypher string literal with
backslash, quote, line breaks, control and format characters and `;` escaped.
Labels, relationship types and property keys come from fixed lists in gop,
never from the graph. An attribute key that is not a plain lowercase
identifier goes into the `attrs_extra` JSON string property instead of
becoming a key. Tests check that names with quotes, backslashes, backticks,
newlines and Unicode leave the script structure unchanged.

### Sample queries

AWS roles a contractor (an outside collaborator) can assume through a
workflow, with the policies Cartography sees on the role:

```cypher
MATCH (c:GopIdentity)-[:CAN_PUSH {attr_via: 'outside_collaborator'}]->(:GopRepo)
WITH DISTINCT c
MATCH (c)-[r:GOP_REACHES]->(role:GopCloudRole)
OPTIONAL MATCH (role)-[:SAME_AS]->(aws:AWSRole)
OPTIONAL MATCH (aws)-[:POLICY]->(p:AWSPolicy)
RETURN c.name AS contractor, role.id AS role, r.confirmed AS confirmed,
       r.path AS path, collect(DISTINCT p.name) AS policies
ORDER BY contractor, role
```

Everything anyone on the internet can reach (fork pull requests, issue
comments):

```cypher
MATCH (:GopExternal {id: 'external:anyone'})-[r:GOP_REACHES]->(t)
RETURN t.id, t.kind, r.confirmed, r.path_kinds
```

Public repositories (per Cartography) whose workflows can mint a cloud token:

```cypher
MATCH (w:GopWorkflow)-[:DEFINED_IN]->(:GopRepo)-[:SAME_AS]->(gr:GitHubRepository {private: false}),
      (w)-[:EXECUTES_WITH]->(:GopOIDC)
RETURN gr.fullname, w.name
```

Principals with confirmed reach to a role in a given AWS account:

```cypher
MATCH (a:AWSAccount {id: '111111111111'})-[:RESOURCE]->(aws:AWSRole)<-[:SAME_AS]-(role:GopCloudRole)
MATCH (p:GopNode)-[r:GOP_REACHES {confirmed: true}]->(role)
RETURN aws.arn, p.id, r.hops
ORDER BY aws.arn, r.hops
```

A person's full reach: their own `GOP_REACHES` edges plus those of the
org member populations they belong to:

```cypher
MATCH (i:GopIdentity {id: 'identity:alice'})
OPTIONAL MATCH (i)-[:MEMBER_OF]->(o:GopOrg)
WITH i, [x IN collect(o.id) | 'members:' + substring(x, 4)] AS pops
MATCH (p:GopNode)-[r:GOP_REACHES]->(t)
WHERE p = i OR p.id IN pops
RETURN t.id, t.kind, r.confirmed, p.id AS via
```

Possible reach only (at least one hop gop could not see), to close coverage
gaps first:

```cypher
MATCH (p)-[r:GOP_REACHES {confirmed: false}]->(t)
RETURN p.id, t.id, r.path
```

Large graphs: the script batches rows 500 per statement. On a first load of a
very large enterprise, raise the transaction memory or run the cleanup
statements at the end separately.
