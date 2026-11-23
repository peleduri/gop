#!/usr/bin/env bash
# Prints (default) or runs (--apply) the `gh label create --force` commands
# that make the repository's labels match .github/labels.yml. Run it locally as
# the maintainer; no workflow runs it. It creates missing labels and updates
# the color and description of existing ones. It never deletes a label.
#
#   scripts/sync-labels.sh            # print the commands
#   scripts/sync-labels.sh --apply    # run them (needs `gh auth login`)
#
# GOP_LABELS_REPO overrides the target repository (default peleduri/gop).
set -euo pipefail
cd "$(dirname "$0")/.."
repo="${GOP_LABELS_REPO:-peleduri/gop}"
apply=false
case "${1:-}" in
  "") ;;
  --apply) apply=true ;;
  *) echo "usage: $0 [--apply]" >&2; exit 2 ;;
esac

# q single-quotes a value for the printed command.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# Reads the flat `- name: / color: / description:` entries of labels.yml.
# Values may be bare or double-quoted.
awk '
  function val(s) { sub(/^[^:]*:[ ]*/, "", s); gsub(/^"|"$/, "", s); return s }
  /^- name:/        { if (name != "") print name "\t" color "\t" desc; name = val($0); color = ""; desc = "" }
  /^  color:/       { color = val($0) }
  /^  description:/ { desc = val($0) }
  END               { if (name != "") print name "\t" color "\t" desc }
' .github/labels.yml |
while IFS=$'\t' read -r name color desc; do
  if [ -z "$color" ]; then echo "sync-labels: label \"$name\" has no color" >&2; exit 1; fi
  if $apply; then
    gh label create "$name" --repo "$repo" --color "$color" --description "$desc" --force
  else
    echo "gh label create $(q "$name") --repo $(q "$repo") --color $(q "$color") --description $(q "$desc") --force"
  fi
done
