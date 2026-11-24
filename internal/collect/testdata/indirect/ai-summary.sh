#!/usr/bin/env bash
# Synthetic fixture: summarize a pull request with an agent CLI.
set -euo pipefail
gh pr diff "$PR" > diff.txt
claude -p "Summarize this diff" < diff.txt > summary.md
gh pr comment "$PR" --body-file summary.md
