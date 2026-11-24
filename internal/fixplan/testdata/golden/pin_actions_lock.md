## Fix plan: Pin acme-actions/deploy@main to a commit SHA in every workflow that uses it

Confirmed (principal, repo) pairs: 5 -> 5 (0% removed); possible pairs: 0 -> 0.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Edit acme-app/api `.github/workflows/deploy.yml` line 12 (read at main)
  - owner: acme-app
  - evidence: `workflow:acme-app/api/.github/workflows/deploy.yml USES action:acme-actions/deploy@main` (live)

  ```diff
  --- a/.github/workflows/deploy.yml
  +++ b/.github/workflows/deploy.yml
  @@ -12 +12 @@
  -uses: acme-actions/deploy@main
  +uses: acme-actions/deploy@<sha-of-main> # main
  ```

- [ ] Verify acme-actions/deploy
  - owner: acme-actions
  - note: fix-plan works offline and does not know the commit main points at: run `gop pin --action acme-actions/deploy@main --graph graph.json` to resolve it with one read-only API call and print these edits as a git apply diff, or replace <sha-of-main> with the full commit SHA of main yourself. Use the same SHA in every step.

### Caveats

- acme-app/docs .github/workflows/build.yml line 9: stale actions.lock entry (it pins acme-actions/deploy@v1 instead): rerun gh actions-lock in acme-app/docs instead of editing the workflow
- acme-app/web .github/workflows/ci.yml line 8: actions.lock governs this uses: and pins it to aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: nothing to edit
- diffs show the uses: entry without its indentation or list marker; keep those as they are in the file
- pinning acme-actions/deploy@main alone does not close paths through the mutable refs it uses itself: acme-actions/setup@main (acme-actions/deploy@main action.yml:6). Pin those too (for example gop fix-plan --pin action:acme-actions/setup@main)
