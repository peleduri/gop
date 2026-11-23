#!/usr/bin/env bash
# Fails if any tracked or staged file contains a term from the private denylist.
# The denylist is NEVER committed: it comes from $GOP_DENYLIST (newline or comma separated,
# set as a CI secret) or ~/.config/gop/denylist locally. Missing list = fail closed in CI.
set -euo pipefail
terms="${GOP_DENYLIST:-}"
[ -z "$terms" ] && [ -f "$HOME/.config/gop/denylist" ] && terms="$(cat "$HOME/.config/gop/denylist")"
if [ -z "$terms" ]; then
  if [ -n "${CI:-}" ]; then echo "leak-check: GOP_DENYLIST secret is not set (fail closed)"; exit 1; fi
  echo "leak-check: no denylist configured, skipping locally"; exit 0
fi
pattern="$(printf '%s' "$terms" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | paste -sd'|' -)"
files="$( (git ls-files; git diff --cached --name-only) | sort -u)"
[ -z "$files" ] && exit 0
if hits="$(printf '%s\n' "$files" | xargs grep -I -n -i -E "$pattern" 2>/dev/null)"; then
  # Print file:line only, never the matched term, so CI logs don't leak the denylist.
  echo "leak-check: denylisted term found in:"; printf '%s\n' "$hits" | cut -d: -f1,2; exit 1
fi
if git log --all --format='%an %ae %s %b' | grep -q -i -E "$pattern"; then
  echo "leak-check: denylisted term found in commit metadata"; exit 1
fi
echo "leak-check: clean"
