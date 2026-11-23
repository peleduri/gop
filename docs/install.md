# Installing gop

gop is one static binary. Pick one way to install it, then [verify what you run](#verify-what-you-run).

- [Homebrew](#homebrew-coming-soon) (macOS and Linux, tap coming soon)
- [Release archive](#release-archive) (every platform, with checksum, signature and provenance checks)
- [`go install`](#go-install) (builds from source)
- [Container](#container) (planned)

After installing, connect your agent: [docs/mcp-clients.md](mcp-clients.md).

## Homebrew (coming soon)

**Not available yet.** The tap repository does not exist yet, so the command below fails today. Until it works, use the [release archive](#release-archive) or [`go install`](#go-install).

```sh
brew install peleduri/tap/gop
gop version
```

The cask is published to [`peleduri/homebrew-tap`](https://github.com/peleduri/homebrew-tap) by the release workflow and points at the same signed archives as [Releases](https://github.com/peleduri/gop/releases). The binaries are signed with cosign, not with an Apple developer ID, so on macOS the cask clears the quarantine flag on the `gop` binary after install. If you would rather keep that flag and check the binary yourself, use the release archive below.

The tap goes live with the first release after the maintainer setup in [docs/maintainers.md](maintainers.md); this section will drop the "coming soon" then.

## Release archive

Download the archive for your platform plus `checksums.txt` and `checksums.txt.sigstore.json` from [Releases](https://github.com/peleduri/gop/releases). Archives are named `gop_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows), for example `gop_0.1.0_linux_amd64.tar.gz`.

With the GitHub CLI:

```sh
VERSION=0.1.0
gh release download "v${VERSION}" --repo peleduri/gop \
  --pattern "gop_${VERSION}_linux_amd64.tar.gz" \
  --pattern checksums.txt --pattern checksums.txt.sigstore.json
```

Then run the three checks in [Verify what you run](#verify-what-you-run), unpack, and put `gop` on your `PATH`:

```sh
tar -xzf "gop_${VERSION}_linux_amd64.tar.gz" gop
install -m 0755 gop ~/.local/bin/gop
```

## go install

```sh
go install github.com/peleduri/gop/cmd/gop@latest
```

This builds from source with your Go toolchain (the version in `go.mod`, fetched automatically). The result is not the signed release binary, so the checks below do not apply to it; `gop version` prints `dev`.

## Container

A signed container image is planned, see [issue #38](https://github.com/peleduri/gop/issues/38). This section will link to it once it ships.

## Verify what you run

gop reads your whole enterprise with a privileged token, so check the binary before you give it one. Every release is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) with goreleaser, from a tag, on GitHub-hosted runners. Each release ships:

| File | What it proves |
|---|---|
| `checksums.txt` | SHA-256 of every archive and SBOM. |
| `checksums.txt.sigstore.json` | A keyless cosign signature over `checksums.txt`, made with the release workflow's OIDC identity and logged in the public Sigstore transparency log. |
| SLSA build provenance (in GitHub attestations) | Which workflow, commit and runner built each archive. |
| `*.sbom.json` | SPDX SBOM of each archive. |

### 1. Checksum

```sh
sha256sum -c --ignore-missing checksums.txt          # Linux
shasum -a 256 -c --ignore-missing checksums.txt      # macOS
```

Expect `gop_<version>_<os>_<arch>.tar.gz: OK`. This only proves the archive matches `checksums.txt`; the next step proves `checksums.txt` came from the release workflow.

### 2. Signature (cosign)

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/peleduri/gop/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Expect `Verified OK`. The identity pins the signature to the release workflow at that exact tag, so a file signed by any other workflow, branch or repository fails.

### 3. Build provenance (GitHub attestations)

```sh
gh attestation verify "gop_${VERSION}_linux_amd64.tar.gz" --repo peleduri/gop
```

This checks the SLSA provenance GitHub stored for the archive: it was built by a workflow in `peleduri/gop`. Add `--signer-workflow peleduri/gop/.github/workflows/release.yml` to pin the workflow too.

### Homebrew installs

The cask downloads the same archives and checks their SHA-256 against the value goreleaser wrote into the cask. To run the cosign and attestation checks on a Homebrew install, download the matching archive and `checksums.txt` for `gop version` and verify them as above; the binary inside must match the one Homebrew installed (`shasum -a 256 "$(command -v gop)"`).

## For maintainers

The one-time setup that turns on the Homebrew tap (tap repository, scoped token, `HOMEBREW_TAP_TOKEN` secret) is in [docs/maintainers.md](maintainers.md).
