## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `go vet ./...` and `go test ./... -race -count=1` pass
- [ ] Fixtures and examples are synthetic (enterprise `acme`, orgs `acme-actions`, `acme-app`); no real company, person, org, repo or token
- [ ] `scripts/leak-check.sh` prints `leak-check: clean`
- [ ] New facts carry an evidence level (`live`, `audit` or `not_visible`) and a `source_api`
- [ ] No new write calls to GitHub (gop stays read-only)
- [ ] Docs updated (README, docs/schema.md) if behavior or schema changed
- [ ] Commits are signed off (`git commit -s`)
