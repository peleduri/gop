Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it: 5 lines to edit across 4 repos; removes 3 of 14 confirmed (principal, repo) pairs (21%); 1 step is not visible, listed last

## Fix plan: Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it

Confirmed (principal, repo) pairs: 14 -> 11 (21% removed); possible pairs: 5 -> 4.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Edit acme-actions/tools `.github/workflows/build.yml` line 9 (read at main)
  - owner: acme-actions
  - evidence: `action:acme-actions/tools/.github/workflows/build.yml@main USES action:acme-actions/deploy@main` (live)
  - note: nested: this uses: line is inside acme-actions/tools/.github/workflows/build.yml@main; callers pick up the change only when that ref points at the new commit (a SHA or tag pin needs a new pin)

  ```diff
  --- a/.github/workflows/build.yml
  +++ b/.github/workflows/build.yml
  @@ -9 +9 @@
  -uses: acme-actions/deploy@main
  +uses: acme-actions/deploy@<sha-of-main> # main
  ```

- [ ] Edit acme-app/api `.github/workflows/deploy.yml` line 10
  - owner: acme-app
  - evidence: `workflow:acme-app/api/.github/workflows/deploy.yml USES action:acme-actions/deploy@main` (live)

  ```diff
  --- a/.github/workflows/deploy.yml
  +++ b/.github/workflows/deploy.yml
  @@ -10 +10 @@
  -uses: acme-actions/deploy@main
  +uses: acme-actions/deploy@<sha-of-main> # main
  ```

- [ ] Edit acme-app/web `.github/workflows/ci.yml` line 8
  - owner: acme-app
  - evidence: `workflow:acme-app/web/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (live)

  ```diff
  --- a/.github/workflows/ci.yml
  +++ b/.github/workflows/ci.yml
  @@ -8 +8 @@
  -uses: acme-actions/deploy@main
  +uses: acme-actions/deploy@<sha-of-main> # main
  ```

- [ ] Edit acme-app/web `.github/workflows/release.yml` line 12
  - owner: acme-app
  - evidence: `workflow:acme-app/web/.github/workflows/release.yml USES action:acme-actions/deploy@main` (live)

  ```diff
  --- a/.github/workflows/release.yml
  +++ b/.github/workflows/release.yml
  @@ -12 +12 @@
  -uses: acme-actions/deploy@main
  +uses: acme-actions/deploy@<sha-of-main> # main
  ```

- [ ] Verify acme-actions/deploy
  - owner: acme-actions
  - note: fix-plan works offline and does not know the commit main points at: run `gop pin --action acme-actions/deploy@main --graph graph.json` to resolve it with one read-only API call and print these edits as a git apply diff, or replace <sha-of-main> with the full commit SHA of main yourself. Use the same SHA in every step.
- [ ] Edit acme-legacy/old-site `.github/workflows/ci.yml`
  - owner: acme-legacy
  - evidence: `workflow:acme-legacy/old-site/.github/workflows/ci.yml USES action:acme-actions/deploy@main` (not visible)
  - note: line not recorded in this graph: replace `uses: acme-actions/deploy@main` with `uses: acme-actions/deploy@<sha-of-main> # main`; not visible to the token: confirm this exists first

### Caveats

- 1 of 5 uses: lines have no line number in this graph (collected before line attributes); those steps say what to replace instead of a diff
- diffs show the uses: entry without its indentation or list marker; keep those as they are in the file
- pinning acme-actions/deploy@main alone does not close paths through the mutable refs it uses itself: acme-actions/setup@main (acme-actions/deploy@main action.yml:6). Pin those too (for example gop fix-plan --pin action:acme-actions/setup@main)
