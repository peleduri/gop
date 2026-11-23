// gop export --format cypher (gop.graph/v1)
// Idempotent: MERGE only. Loading it replaces every earlier gop run of the same enterprise.
// gop_run: 2026-01-01T00:00:00Z/999be1d0894e
CREATE INDEX gop_node_key IF NOT EXISTS FOR (n:GopNode) ON (n.gop_enterprise, n.id);
UNWIND [
  {gop_enterprise: 'acme', id: 'cloud:aws:arn:aws:iam::111111111111:role/deploy', kind: 'cloud_target', name: 'aws:arn:aws:iam::111111111111:role/deploy', evidence: 'supplied', confirmed: true, gop_run: '2026-01-01T00:00:00Z/999be1d0894e', attr_account: '111111111111', attr_provider: 'aws', attr_role: 'deploy', attr_warnings: 'no_aud_condition'}
] AS row MERGE (n:GopNode {gop_enterprise: row.gop_enterprise, id: row.id}) SET n = row, n:GopCloudRole;
UNWIND [
  {gop_enterprise: 'acme', id: 'oidc:acme-app/web', kind: 'oidc', name: 'acme-app/web', evidence: 'live', confirmed: true, gop_run: '2026-01-01T00:00:00Z/999be1d0894e'}
] AS row MERGE (n:GopNode {gop_enterprise: row.gop_enterprise, id: row.id}) SET n = row, n:GopOIDC;
UNWIND [
  {gop_enterprise: 'acme', id: 'workflow:acme-app/web/.github/workflows/ci.yml', kind: 'workflow', name: 'acme-app/web/.github/workflows/ci.yml', evidence: 'live', confirmed: true, gop_run: '2026-01-01T00:00:00Z/999be1d0894e'},
  {gop_enterprise: 'acme', id: 'workflow:acme-app/web/.github/workflows/release.yml', kind: 'workflow', name: 'acme-app/web/.github/workflows/release.yml', evidence: 'live', confirmed: true, gop_run: '2026-01-01T00:00:00Z/999be1d0894e'}
] AS row MERGE (n:GopNode {gop_enterprise: row.gop_enterprise, id: row.id}) SET n = row, n:GopWorkflow;
UNWIND [
  {from: 'workflow:acme-app/web/.github/workflows/ci.yml', to: 'cloud:aws:arn:aws:iam::111111111111:role/deploy', props: {gop_key: '566ebab63a872b8d', kind: 'CAN_ASSUME', evidence: 'not_visible', confirmed: false, source_api: 'supplied:trust/aws/deploy.json', observed_at: '2026-01-01T00:00:00Z', gop_run: '2026-01-01T00:00:00Z/999be1d0894e', attr_claims: 'sub', attr_file: 'trust/aws/deploy.json', attr_oidc: 'oidc:acme-app/web', attr_provider: 'aws', attr_reason: 'the ref in sub is not known: gop does not read workflow triggers'}},
  {from: 'workflow:acme-app/web/.github/workflows/release.yml', to: 'cloud:aws:arn:aws:iam::111111111111:role/deploy', props: {gop_key: '14c693ab945122a2', kind: 'CAN_ASSUME', evidence: 'supplied', confirmed: true, source_api: 'supplied:trust/aws/deploy.json', observed_at: '2026-01-01T00:00:00Z', gop_run: '2026-01-01T00:00:00Z/999be1d0894e', attr_claims: 'sub', attr_file: 'trust/aws/deploy.json', attr_matched_sub: 'repo:acme-app/web:environment:prod', attr_oidc: 'oidc:acme-app/web', attr_pointer: '/Role/AssumeRolePolicyDocument/Statement/0', attr_provider: 'aws'}}
] AS row MATCH (a:GopNode {gop_enterprise: 'acme', id: row.from}) MATCH (b:GopNode {gop_enterprise: 'acme', id: row.to}) MERGE (a)-[r:CAN_ASSUME {gop_key: row.props.gop_key}]->(b) SET r = row.props;
UNWIND [
  {from: 'workflow:acme-app/web/.github/workflows/release.yml', to: 'oidc:acme-app/web', props: {gop_key: '45918285404913b2', kind: 'EXECUTES_WITH', evidence: 'live', confirmed: true, source_api: 'contents:.github/workflows', observed_at: '2026-01-01T00:00:00Z', gop_run: '2026-01-01T00:00:00Z/999be1d0894e', attr_environments: 'prod', attr_jobs: 'deploy', attr_repository: 'acme-app/web', attr_repository_owner: 'acme-app'}}
] AS row MATCH (a:GopNode {gop_enterprise: 'acme', id: row.from}) MATCH (b:GopNode {gop_enterprise: 'acme', id: row.to}) MERGE (a)-[r:EXECUTES_WITH {gop_key: row.props.gop_key}]->(b) SET r = row.props;
UNWIND [
  {id: 'cloud:aws:arn:aws:iam::111111111111:role/deploy', target: 'arn:aws:iam::111111111111:role/deploy'}
] AS row MATCH (g:GopNode {gop_enterprise: 'acme', id: row.id}) MATCH (c:AWSRole {arn: row.target}) MERGE (g)-[r:SAME_AS]->(c) SET r.gop_run = '2026-01-01T00:00:00Z/999be1d0894e';
MATCH (:GopNode {gop_enterprise: 'acme'})-[r]->() WHERE r.gop_run IS NOT NULL AND r.gop_run <> '2026-01-01T00:00:00Z/999be1d0894e' DELETE r;
MATCH (n:GopNode {gop_enterprise: 'acme'}) WHERE n.gop_run <> '2026-01-01T00:00:00Z/999be1d0894e' DETACH DELETE n;
