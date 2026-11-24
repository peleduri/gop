## Fix plan: Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it

Confirmed (principal, repo) pairs: 24 -> 6 (75% removed); possible pairs: 1 -> 1.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Edit acme-app/admin `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/admin/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/api `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/api/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/billing `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/billing/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/docs `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/docs/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/gateway `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/gateway/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/mobile `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/mobile/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/search `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/search/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/web `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/web/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/web `.github/workflows/release.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/web/.github/workflows/release.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Edit acme-app/worker `.github/workflows/ci.yml`
  - owner: acme-app
  - evidence: `workflow:acme-app/worker/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`
- [ ] Verify acme-actions/deploy
  - owner: acme-actions
  - note: fix-plan works offline and does not know the commit main points at: run `gop pin --action acme-actions/deploy@main --graph graph.json` to resolve it with one read-only API call and print these edits as a git apply diff, or replace <sha-of-main> with the full commit SHA of main yourself. Use the same SHA in every step.

### Caveats

- 10 of 10 uses: lines have no line number in this graph (collected before line attributes); those steps say what to replace instead of a diff
