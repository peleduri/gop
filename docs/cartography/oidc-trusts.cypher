// gop: GitHub Actions OIDC trusts of AWS roles, and the roles CloudTrail saw
// each GitHub repository assume, from a Cartography Neo4j database.
// Read-only. Export the result and pass it to:
//   gop enrich --graph graph.json --cartography export.json --out graph2.json
// See docs/cartography.md for how to run it and what each column means.
//
// Trust rows: one per role and GitHub OIDC provider (github.com, an
// enterprise issuer path, or GitHub Enterprise Server "/_services/token").
MATCH (r:AWSRole)-[t:TRUSTS_AWS_PRINCIPAL]->(p:AWSPrincipal)
WHERE p.arn CONTAINS ':oidc-provider/token.actions.githubusercontent.com'
   OR (p.arn CONTAINS ':oidc-provider/' AND p.arn ENDS WITH '/_services/token')
RETURN 'trust' AS kind, r.arn AS role_arn, r.name AS role_name, p.arn AS principal_arn,
       t.has_condition AS has_condition, t.conditions AS conditions,
       null AS repo, null AS times_used, null AS first_seen, null AS last_used
UNION ALL
// Observed rows: one per repository and role, from CloudTrail
// AssumeRoleWithWebIdentity events (Cartography's lookback window only).
MATCH (g:GitHubRepository)-[u:ASSUMED_ROLE_WITH_WEB_IDENTITY]->(r:AWSRole)
RETURN 'observed' AS kind, r.arn AS role_arn, r.name AS role_name, null AS principal_arn,
       null AS has_condition, null AS conditions,
       g.fullname AS repo, u.times_used AS times_used,
       toString(u.first_seen_in_time_window) AS first_seen, toString(u.last_used) AS last_used;
