## Fix plan: Set permissions: contents: read on the GITHUB_TOKEN of acme-app/docs/.github/workflows/preview.yml

Confirmed (principal, repo) pairs: 2 -> 2 (0% removed); possible pairs: 1 -> 1.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Edit acme-app/docs `.github/workflows/preview.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/docs/.github/workflows/preview.yml CAN_PUSH repo:acme-app/docs` (live)
  - change: set `contents: read` in the `permissions:` of jobs label, preview; if `contents: write` (or `write-all`) is set in the top-level block they inherit, change it there
  - note: the file grants contents: write to jobs label, preview; job-level permissions replace the top-level block, so change only the jobs that do not need to push; this graph records no line for the permissions: key

### Caveats

- jobs that push with the GITHUB_TOKEN (tags, release commits, bot updates) stop working: move them to a workflow only trusted events start, or give them a GitHub App token scoped to that repo
- whoever controls acme-app/docs/.github/workflows/preview.yml still runs code in acme-app/docs's CI with its secrets, OIDC and runners; this fix removes only the push with the token
