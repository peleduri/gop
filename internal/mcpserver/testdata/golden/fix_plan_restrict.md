Set permissions: contents: read on the GITHUB_TOKEN of `acme-app/web/.github/workflows/ci.yml`: 1 line to edit across 1 repo; removes 0 of 25 confirmed (principal, repo) pairs (0%); confirmed workflows 27 -> 25, score 176.8 -> 174.5

## Fix plan: Set permissions: contents: read on the GITHUB_TOKEN of acme-app/web/.github/workflows/ci.yml

Confirmed (principal, repo) pairs: 25 -> 25 (0% removed); possible pairs: 1 -> 1.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Edit acme-app/web `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/web/.github/workflows/ci.yml CAN_PUSH repo:acme-app/web` (live)
  - change: add a top-level `permissions:` block with `contents: read` (plus any other scope the jobs need, such as `pull-requests: write`)
  - note: job build declares no permissions and take the repository's default workflow permissions, which allow write; a top-level block applies to exactly the jobs that declare none; this graph records no line for the permissions: key

### Caveats

- jobs that push with the GITHUB_TOKEN (tags, release commits, bot updates) stop working: move them to a workflow only trusted events start, or give them a GitHub App token scoped to that repo
- whoever controls acme-app/web/.github/workflows/ci.yml still runs code in acme-app/web's CI with its secrets, OIDC and runners; this fix removes only the push with the token
- alternative for every workflow in the repo at once: set Settings > Actions > General > Workflow permissions to "Read repository contents" on acme-app/web (or the org); workflows that need write must then declare it
