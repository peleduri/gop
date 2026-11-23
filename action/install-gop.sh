#!/usr/bin/env bash
# install-gop.sh
#
# The download step of the gop Action, also run alone by CI's action-smoke job
# on Linux, macOS and Windows. Downloads the gop release named by GOP_VERSION
# ("latest" or a tag like v0.3.0) for this runner, verifies the cosign
# signature on checksums.txt when cosign is installed, verifies the archive's
# SHA-256, extracts the binary and appends its directory to GITHUB_PATH.
#
# Needs: bash, gh (GH_TOKEN set; only used to read the public release), grep,
# sha256sum or shasum, and tar (Linux, macOS) or unzip or the Windows tar.exe
# (bsdtar) for the Windows .zip. On Windows it runs in Git Bash: GitHub-hosted
# Windows runners have it; self-hosted Windows runners need Git for Windows on
# PATH (the Action's steps use "shell: bash").
set -euo pipefail

: "${GOP_VERSION:?GOP_VERSION is not set}"
: "${RUNNER_OS:?RUNNER_OS is not set}"
: "${RUNNER_ARCH:?RUNNER_ARCH is not set}"
: "${RUNNER_TEMP:?RUNNER_TEMP is not set}"
: "${GITHUB_PATH:?GITHUB_PATH is not set}"

ext=tar.gz
bin=gop
case "${RUNNER_OS}" in
  Linux) os=linux ;;
  macOS) os=darwin ;;
  Windows) os=windows; ext=zip; bin=gop.exe ;;
  *) echo "gop action: unsupported runner OS ${RUNNER_OS} (use Linux, macOS or Windows)"; exit 1 ;;
esac
case "${RUNNER_ARCH}" in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *) echo "gop action: unsupported runner arch ${RUNNER_ARCH}"; exit 1 ;;
esac

tag="${GOP_VERSION}"
if [ "${tag}" = "latest" ]; then
  tag="$(gh release view --repo peleduri/gop --json tagName --jq .tagName)"
  tag="${tag%$'\r'}"
fi
if ! printf '%s' "${tag}" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$'; then
  echo "gop action: invalid version"; exit 1
fi
ver="${tag#v}"
archive="gop_${ver}_${os}_${arch}.${ext}"
work="${RUNNER_TEMP}/gop-bin"
mkdir -p "${work}"
cd "${work}"

gh release download "${tag}" --repo peleduri/gop \
  --pattern "${archive}" --pattern checksums.txt --pattern checksums.txt.sigstore.json --clobber
if command -v cosign >/dev/null 2>&1; then
  cosign verify-blob checksums.txt \
    --bundle checksums.txt.sigstore.json \
    --certificate-identity "https://github.com/peleduri/gop/.github/workflows/release.yml@refs/tags/${tag}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  echo "gop action: cosign signature on checksums.txt verified"
else
  echo "gop action: cosign not installed, skipping signature check (checksum is still verified)"
fi

# Exactly one line for this archive, or the check fails closed.
grep -E "^[0-9a-f]{64}  ${archive}\$" checksums.txt > expected.sha256
if [ "$(wc -l < expected.sha256 | tr -d ' ')" -ne 1 ]; then
  echo "gop action: checksums.txt has no single entry for ${archive}"; exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c expected.sha256; else shasum -a 256 -c expected.sha256; fi

rm -f "${bin}"
if [ "${ext}" = "zip" ]; then
  # Git Bash's tar is GNU tar, which cannot read zip: use unzip when it is
  # there, else the bsdtar that ships with Windows as System32\tar.exe.
  if command -v unzip >/dev/null 2>&1; then
    unzip -o -q "${archive}" "${bin}"
  else
    bsdtar="${SYSTEMROOT:-C:\\Windows}\\System32\\tar.exe"
    if command -v cygpath >/dev/null 2>&1; then bsdtar="$(cygpath -u "${bsdtar}")"; fi
    if [ ! -x "${bsdtar}" ]; then
      echo "gop action: need unzip or the Windows tar.exe to extract ${archive}"; exit 1
    fi
    "${bsdtar}" -xf "${archive}" "${bin}"
  fi
else
  tar -xzf "${archive}" "${bin}"
fi
if [ ! -f "${bin}" ]; then
  echo "gop action: ${archive} has no ${bin}"; exit 1
fi
chmod +x "${bin}"

# GITHUB_PATH is read by the runner, not by bash: on Windows give it the
# Windows form of the directory so later steps in any shell find gop.exe.
dir="$(pwd)"
if [ "${os}" = "windows" ] && command -v cygpath >/dev/null 2>&1; then
  dir="$(cygpath -w "${dir}")"
fi
echo "${dir}" >> "${GITHUB_PATH}"
echo "gop action: installed ${tag} (${os}/${arch})"
