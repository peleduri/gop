-- Views for the gop Ossie semantic model (contrib/ossie/gop.ossie.yaml).
--
-- Load them after the export:
--   gop export --format sql graph.json --out gop.sql
--   sqlite3 gop.db < gop.sql
--   sqlite3 gop.db < contrib/ossie/views.sql     # or: duckdb gop.duckdb < ...
--
-- Each view is one business term of the model over the tables of
-- `gop export --format sql` (docs/sql.md). Tools that map a term to exactly
-- one table, such as NVIDIA Auto Ontology, need them: the model's datasets
-- name these views and the export tables, never a query.
--
-- Every view keeps run_id. Join on it as well as on IDs, and filter or group
-- by it: a run is one exported graph, so summing over runs counts the same
-- fact once per run.
--
-- The script drops and recreates the views, so loading it again (after an
-- upgrade, or into a database with more runs) is safe. Views read whatever
-- runs the database holds; they store nothing. Plain SQL that SQLite (3.38
-- or later, as the export needs) and DuckDB both run.

DROP VIEW IF EXISTS organizations;
CREATE VIEW organizations AS
SELECT n.run_id,
       n.id AS org_id,
       n.name,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'default_perm') AS default_perm,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'sso') AS sso,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'two_factor') AS two_factor,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'ip_allow_list') AS ip_allow_list,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'members') AS members,
       n.evidence
FROM nodes n
WHERE n.kind = 'org';

DROP VIEW IF EXISTS repositories;
CREATE VIEW repositories AS
SELECT n.run_id,
       n.id AS repo_id,
       n.name,
       n.org AS org_id,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'visibility') AS visibility,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'archived') AS archived,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'actions_access') AS actions_access,
       n.evidence
FROM nodes n
WHERE n.kind = 'repo';

DROP VIEW IF EXISTS workflows;
CREATE VIEW workflows AS
SELECT n.run_id,
       n.id AS workflow_id,
       n.name,
       n.org AS org_id,
       n.repo AS repo_id,
       n.evidence
FROM nodes n
WHERE n.kind = 'workflow';

-- actions: action refs (owner/repo[/path]@ref) as workflows consume them.
-- pinned is 1 for a full commit SHA, 0 for a tag or branch, NULL when gop
-- did not record the ref kind. confirmed_reachable is 1 when some principal
-- has confirmed reach to the ref, that is can change the code it runs.
DROP VIEW IF EXISTS actions;
CREATE VIEW actions AS
SELECT x.run_id, x.action_id, x.name, x.org_id, x.host_repo_id, x.ref, x.ref_kind,
       CASE x.ref_kind WHEN 'sha' THEN 1 WHEN 'tag' THEN 0 WHEN 'branch' THEN 0 END AS pinned,
       x.ref_protected, x.ref_immutable, x.in_enterprise,
       CASE WHEN EXISTS (SELECT 1 FROM reach r WHERE r.run_id = x.run_id AND r.target = x.action_id AND r.confirmed = 1)
            THEN 1 ELSE 0 END AS confirmed_reachable,
       x.evidence
FROM (
  SELECT n.run_id,
         n.id AS action_id,
         n.name,
         n.org AS org_id,
         n.repo AS host_repo_id,
         (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'ref') AS ref,
         (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'ref_kind') AS ref_kind,
         (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'ref_protected') AS ref_protected,
         (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'ref_immutable') AS ref_immutable,
         (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'in_enterprise') AS in_enterprise,
         n.evidence
  FROM nodes n
  WHERE n.kind = 'action_ref'
) x;

-- identities: users and teams. identity_type is 'team' for team:<org>/<slug>
-- IDs, else 'user'. is_org_member is 1 when the user has a MEMBER_OF edge to
-- an org (NULL for a team). is_outside_collaborator is 1 when the user has a
-- direct push grant as an outside collaborator (CAN_PUSH via
-- outside_collaborator).
DROP VIEW IF EXISTS identities;
CREATE VIEW identities AS
SELECT n.run_id,
       n.id AS identity_id,
       n.name,
       CASE WHEN n.id LIKE 'team:%' THEN 'team' ELSE 'user' END AS identity_type,
       n.org AS org_id,
       CASE WHEN n.id LIKE 'team:%' THEN NULL
            WHEN EXISTS (SELECT 1 FROM edges e JOIN nodes d ON d.run_id = e.run_id AND d.id = e.dst
                         WHERE e.run_id = n.run_id AND e.src = n.id AND e.label = 'MEMBER_OF' AND d.kind = 'org')
            THEN 1 ELSE 0 END AS is_org_member,
       CASE WHEN EXISTS (SELECT 1 FROM edges e JOIN edge_attrs a ON a.run_id = e.run_id AND a.edge_id = e.edge_id
                         WHERE e.run_id = n.run_id AND e.src = n.id AND e.label = 'CAN_PUSH'
                           AND a.key = 'via' AND a.value = 'outside_collaborator')
            THEN 1 ELSE 0 END AS is_outside_collaborator,
       n.evidence
FROM nodes n
WHERE n.kind = 'identity';

-- principals: everything that can start an attack (org members as one
-- principal per org, identities, external:anyone). is_scoring is 1 for the
-- principals gop's totals and the reach table count: every org_members and
-- external node, plus identities with a CAN_PUSH or CAN_TRIGGER edge or a
-- MEMBER_OF edge to a team (docs/schema.md#principals-and-scoring).
DROP VIEW IF EXISTS principals;
CREATE VIEW principals AS
SELECT n.run_id,
       n.id AS principal_id,
       n.kind AS principal_kind,
       n.name,
       n.org AS org_id,
       CASE WHEN n.kind IN ('org_members', 'external') THEN 1
            WHEN EXISTS (SELECT 1 FROM edges e JOIN nodes d ON d.run_id = e.run_id AND d.id = e.dst
                         WHERE e.run_id = n.run_id AND e.src = n.id
                           AND (e.label IN ('CAN_PUSH', 'CAN_TRIGGER') OR (e.label = 'MEMBER_OF' AND d.kind <> 'org')))
            THEN 1 ELSE 0 END AS is_scoring,
       n.evidence
FROM nodes n
WHERE n.kind IN ('org_members', 'identity', 'external');

DROP VIEW IF EXISTS cloud_roles;
CREATE VIEW cloud_roles AS
SELECT n.run_id,
       n.id AS cloud_role_id,
       n.name,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'provider') AS provider,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'account') AS account,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'role') AS role_name,
       (SELECT a.value FROM node_attrs a WHERE a.run_id = n.run_id AND a.node_id = n.id AND a.key = 'warnings') AS warnings,
       n.evidence
FROM nodes n
WHERE n.kind = 'cloud_target';

DROP VIEW IF EXISTS secrets;
CREATE VIEW secrets AS
SELECT n.run_id,
       n.id AS secret_id,
       n.name,
       n.org AS org_id,
       n.repo AS repo_id,
       n.evidence
FROM nodes n
WHERE n.kind = 'secret';

DROP VIEW IF EXISTS runners;
CREATE VIEW runners AS
SELECT n.run_id,
       n.id AS runner_id,
       n.name,
       n.org AS org_id,
       n.repo AS repo_id,
       n.evidence
FROM nodes n
WHERE n.kind = 'runner';

-- Edge views: one per gop edge label, so each label is a join between two
-- terms. confirmed is the edge's own evidence (live, inferred, audit or
-- supplied); it does not age audit facts, so use the reach table for
-- confirmed reach.

-- CAN_PUSH: grantee is an org_members or identity principal, or a workflow
-- whose GITHUB_TOKEN can push to its own repo (via = token_write).
DROP VIEW IF EXISTS push_grants;
CREATE VIEW push_grants AS
SELECT e.run_id, e.edge_id,
       e.src AS grantee_id,
       e.dst AS repo_id,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'via') AS via,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'permission') AS permission,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'ref') AS ref,
       e.evidence, e.confirmed
FROM edges e
WHERE e.label = 'CAN_PUSH';

-- USES: a workflow (or, for nested actions, an action ref) uses an action ref.
DROP VIEW IF EXISTS action_uses;
CREATE VIEW action_uses AS
SELECT e.run_id, e.edge_id,
       e.src AS consumer_id,
       e.dst AS action_id,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'ref_kind') AS ref_kind,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'file') AS file,
       e.evidence, e.confirmed
FROM edges e
WHERE e.label = 'USES';

-- RESOLVES_TO: an enterprise action ref resolves to the repo that hosts it.
DROP VIEW IF EXISTS action_hosts;
CREATE VIEW action_hosts AS
SELECT e.run_id, e.edge_id,
       e.src AS action_id,
       e.dst AS repo_id,
       e.evidence, e.confirmed
FROM edges e
WHERE e.label = 'RESOLVES_TO';

-- DEFINED_IN: a workflow lives in a repo.
DROP VIEW IF EXISTS workflow_definitions;
CREATE VIEW workflow_definitions AS
SELECT e.run_id, e.edge_id,
       e.src AS workflow_id,
       e.dst AS repo_id,
       e.evidence, e.confirmed
FROM edges e
WHERE e.label = 'DEFINED_IN';

-- EXECUTES_WITH: a workflow runs with a secret scope, an OIDC token or a
-- self-hosted runner pool (capability_kind says which).
DROP VIEW IF EXISTS workflow_capabilities;
CREATE VIEW workflow_capabilities AS
SELECT e.run_id, e.edge_id,
       e.src AS workflow_id,
       e.dst AS capability_id,
       d.kind AS capability_kind,
       e.evidence, e.confirmed
FROM edges e
JOIN nodes d ON d.run_id = e.run_id AND d.id = e.dst
WHERE e.label = 'EXECUTES_WITH';

-- MEMBER_OF: an identity is a member of an org or a team, or a child team is
-- nested under a parent team. role is owner or member for org membership.
DROP VIEW IF EXISTS memberships;
CREATE VIEW memberships AS
SELECT e.run_id, e.edge_id,
       e.src AS member_id,
       e.dst AS group_id,
       CASE WHEN d.kind = 'org' THEN 'org' ELSE 'team' END AS group_kind,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'role') AS role_name,
       e.evidence, e.confirmed
FROM edges e
JOIN nodes d ON d.run_id = e.run_id AND d.id = e.dst
WHERE e.label = 'MEMBER_OF';

-- CAN_TRIGGER: a principal can cause a risky trigger of a workflow that then
-- runs attacker-controlled code.
DROP VIEW IF EXISTS trigger_grants;
CREATE VIEW trigger_grants AS
SELECT e.run_id, e.edge_id,
       e.src AS principal_id,
       e.dst AS workflow_id,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'trigger') AS trigger_event,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'exec') AS exec_kind,
       e.evidence, e.confirmed
FROM edges e
WHERE e.label = 'CAN_TRIGGER';

-- CAN_ASSUME: a workflow's OIDC token matches a cloud role's trust policy
-- (from gop enrich).
DROP VIEW IF EXISTS role_assumptions;
CREATE VIEW role_assumptions AS
SELECT e.run_id, e.edge_id,
       e.src AS workflow_id,
       e.dst AS cloud_role_id,
       (SELECT a.value FROM edge_attrs a WHERE a.run_id = e.run_id AND a.edge_id = e.edge_id AND a.key = 'observed_use') AS observed_use,
       e.evidence, e.confirmed
FROM edges e
WHERE e.label = 'CAN_ASSUME';

-- reach_trend: confirmed and possible (principal, repo) pairs per run, and
-- the change from the previous run of the same enterprise (by collected_at).
-- The deltas are NULL for an enterprise's first run.
DROP VIEW IF EXISTS reach_trend;
CREATE VIEW reach_trend AS
SELECT t.run_id, t.enterprise, t.collected_at, t.confirmed_pairs, t.possible_pairs,
       LAG(t.run_id) OVER w AS previous_run_id,
       t.confirmed_pairs - LAG(t.confirmed_pairs) OVER w AS confirmed_delta,
       t.possible_pairs - LAG(t.possible_pairs) OVER w AS possible_delta
FROM (
  SELECT r.run_id, r.enterprise, r.collected_at,
         (SELECT COUNT(*) FROM reach x WHERE x.run_id = r.run_id AND x.target_kind = 'repo' AND x.confirmed = 1) AS confirmed_pairs,
         (SELECT COUNT(*) FROM reach x WHERE x.run_id = r.run_id AND x.target_kind = 'repo' AND x.confirmed = 0) AS possible_pairs
  FROM runs r
) t
WINDOW w AS (PARTITION BY t.enterprise ORDER BY t.collected_at, t.run_id);
