#!/usr/bin/env bash
# diff-gate.sh BASELINE_GRAPH NEW_GRAPH OUT_DIR
#
# The reach-increase gate of the gop Action. Compares the previous run's
# graph.json with this run's and writes OUT_DIR/diff.md and OUT_DIR/diff.json
# (and OUT_DIR/diff-stderr.txt when gop diff prints anything to stderr: the
# --fail-on message on an increase, the error when it cannot compare). These
# files name nodes, so they go only into the private workflow artifact: this
# script prints no node IDs, paths or counts to the log.
#
# Prints one result word on stdout and exits:
#   0  "clean"     confirmed reach did not grow
#   1  "increase"  confirmed (principal, repo) pairs grew
#   2  "error"     gop diff could not compare the graphs (see diff-stderr.txt)
# A missing baseline is handled by the caller, which skips this script.
set -uo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: diff-gate.sh BASELINE_GRAPH NEW_GRAPH OUT_DIR" >&2
  exit 2
fi
baseline="$1"
current="$2"
out="$3"
gop_bin="${GOP_BIN:-gop}"

mkdir -p "${out}" || { echo "error"; exit 2; }
errf="${out}/diff-stderr.txt"
: > "${errf}"

"${gop_bin}" diff "${baseline}" "${current}" --format json > "${out}/diff.json" 2>> "${errf}"
json_rc=$?
"${gop_bin}" diff "${baseline}" "${current}" --format markdown --fail-on confirmed-increase > "${out}/diff.md" 2>> "${errf}"
md_rc=$?

if [ ! -s "${errf}" ]; then rm -f "${errf}"; fi

# Without --fail-on, the JSON run exits 0 whenever the comparison worked, so a
# non-zero code there (or anything but 0 or 1 from the gated run) is an error,
# never a reach increase.
if [ "${json_rc}" -ne 0 ] || { [ "${md_rc}" -ne 0 ] && [ "${md_rc}" -ne 1 ]; }; then
  echo "error"
  exit 2
fi
if [ "${md_rc}" -eq 1 ]; then
  echo "increase"
  exit 1
fi
echo "clean"
exit 0
