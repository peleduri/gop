#!/usr/bin/env bash
# Builds the GitHub Pages site into a directory (default _site):
#   index.html, favicon.svg  copied from site/
#   demo/index.html          gop report --demo, built from the current source
#   demo/report.md           the same report as Markdown
# The demo report uses only the synthetic acme demo graph. Run from anywhere:
#   site/build.sh [out-dir]
# Preview: (cd _site && python3 -m http.server 8080)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/_site}"
version="${GOP_VERSION:-$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

(cd "$root" && go build -trimpath -ldflags "-X main.version=${version}" -o "$tmp/gop" ./cmd/gop)

rm -rf "$out"
mkdir -p "$out/demo"
cp "$root/site/index.html" "$root/site/favicon.svg" "$out/"
"$tmp/gop" report --demo --out "$out/demo/index.html"
"$tmp/gop" report --demo --out "$out/demo/report.md" --format md

# gop writes reports with mode 0600 (they normally hold private data). The
# demo is synthetic and Pages needs world-readable files.
chmod -R u+rwX,go+rX "$out"

for f in index.html favicon.svg demo/index.html demo/report.md; do
	if [ ! -s "$out/$f" ]; then
		echo "build: $out/$f is missing or empty" >&2
		exit 1
	fi
done
echo "build: site written to $out (gop $version)"
