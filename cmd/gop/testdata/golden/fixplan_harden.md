## Fix plan: Stop acme-app/docs/.github/workflows/preview.yml from running attacker-controlled code on its risky triggers

Confirmed (principal, repo) pairs: 2 -> 0 (100% removed); possible pairs: 1 -> 0.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Edit acme-app/docs `.github/workflows/preview.yml` line 14 (read at main)
  - owner: acme-app
  - evidence: `external:anyone CAN_TRIGGER workflow:acme-app/docs/.github/workflows/preview.yml` (live)
  - change: in job preview, remove `ref: ${{ github.event.pull_request.head.sha }}` from the actions/checkout step so it checks out the base commit, or drop the checkout
  - note: on pull_request_target; can be triggered by external:anyone, members:acme-app [not visible]
- [ ] Edit acme-app/docs `.github/workflows/preview.yml` line 23 (read at main)
  - owner: acme-app
  - evidence: `identity:bob CAN_TRIGGER workflow:acme-app/docs/.github/workflows/preview.yml` (live)
  - change: in job label, move `${{ github.event.pull_request.title }}` out of the script into `env:` (for example `env: UNTRUSTED: ${{ github.event.pull_request.title }}`) and read it as "$UNTRUSTED", so the text is data, not code
  - note: on pull_request_target; can be triggered by identity:bob

### Caveats

- make all 2 edits: gop removes the workflow's trigger edges as a whole, and one untrusted execution left in place keeps it attacker-controlled
- gop matches a narrow set of patterns: review the whole job, including scripts and local actions it runs, for other uses of the pull request's code or text
- if the job must build or test the pull request's code, do it in a separate pull_request workflow with a read-only token and no secrets, and pass results through an artifact
