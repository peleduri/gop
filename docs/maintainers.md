# Maintainer notes

## Releasing

Push a `vX.Y.Z` tag. [`.github/workflows/release.yml`](../.github/workflows/release.yml) runs goreleaser, which builds the archives, signs `checksums.txt` keyless with cosign, attaches SBOMs, creates the GitHub release, and (once the tap is set up) pushes the Homebrew cask. The `release-snapshot` job in CI builds the same config on every PR with `--snapshot` and publishes nothing.

The same run pushes the container image `ghcr.io/peleduri/gop` (multi-arch index from the root `Dockerfile`), then signs it by digest with cosign, attaches a signed SPDX SBOM (`cosign attest`) and pushes SLSA provenance to the registry. Only the release job has `packages: write`. The CI snapshot job loads the per-arch images locally and checks that the amd64 image runs `gop version` as `65532:65532` with no shell.

### Container image: one-time setup

GHCR creates the `gop` package on the first release that pushes it. If it shows as private, open the package settings (your profile, Packages, `gop`, Package settings), set visibility to **Public**, and check that `peleduri/gop` is listed under "Manage Actions access" with the **Write** role. Anonymous `docker pull` and `cosign verify` fail until the package is public.

### Release notes

Two configs produce release notes, both from PR titles and labels:

- goreleaser writes the notes of every tag release (`changelog` in [`.goreleaser.yaml`](../.goreleaser.yaml), `use: github`). It groups commits by conventional commit prefix: Security (`sec`), Features (`feat`), Fixes (`fix`), Docs (`docs`), then Other changes; `test` and `chore` commits are left out. Because PRs are squash-merged, the commit message is the PR title, which [`.github/workflows/pr-title.yml`](../.github/workflows/pr-title.yml) checks. Fix a wrong title before merging; after merging it is in the notes.
- GitHub's "Generate release notes" button (and the API) groups merged PRs by label with [`.github/release.yml`](../.github/release.yml): Security, Features, Fixes, Docs, Dependencies, Other changes. Label a PR `skip-changelog` to leave it out.

Keep `CHANGELOG.md` by hand: move the `Unreleased` entries under the new version in the release PR.

## GitHub CLI extension (`peleduri/gh-gop`): one-time setup

`gh extension install OWNER/gh-NAME` only installs from a repository whose name starts with `gh-`, so `gh gop` needs a small `peleduri/gh-gop` repository next to this one. It holds no code: its releases carry copies of the `gh-gop-<os>-<arch>[.exe]` binaries that goreleaser builds into every gop release (build and archive `gh-gop` in [`.goreleaser.yaml`](../.goreleaser.yaml)). gh picks the asset of the **latest** release whose name ends in `<os>-<arch>` (`.exe` on Windows), so the binaries are bare files, not archives, and the copy must be a full (not pre-) release for `gh extension install` and `gh extension upgrade` to see it.

goreleaser publishes to one repository only, so the copy runs in `peleduri/gh-gop` itself, with that repository's own `GITHUB_TOKEN`. No new secret or cross-repository token is needed.

1. **Create the repository.** Public, named `peleduri/gh-gop`, Apache-2.0 license, with a README that says it is the `gh` extension for [gop](https://github.com/peleduri/gop) and points at [docs/install.md](install.md#github-cli-extension-gh-gop-coming-soon). Initialize it so it has a default branch.
2. **Add `.github/workflows/mirror.yml`** (the action SHAs are the ones `release.yml` pins):

   ```yaml
   name: mirror
   on:
     workflow_dispatch:
       inputs:
         tag:
           description: gop release tag to copy, e.g. v0.5.0
           required: true
   permissions: {}
   jobs:
     mirror:
       runs-on: ubuntu-latest
       permissions:
         contents: write # create the release in peleduri/gh-gop
       steps:
         - uses: step-security/harden-runner@aebdcf6156ab6691adf63218240e476564a1ed4c # v2.23.0
           with:
             egress-policy: audit
         - uses: sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532 # v4.1.3
         - name: download, verify and publish
           env:
             GH_TOKEN: ${{ github.token }}
             TAG: ${{ inputs.tag }}
           run: |
             set -euo pipefail
             case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "bad tag $TAG" >&2; exit 1 ;; esac
             gh release download "$TAG" --repo peleduri/gop --dir dl \
               --pattern 'gh-gop-*' --pattern checksums.txt --pattern checksums.txt.sigstore.json
             cd dl
             cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
               --certificate-identity "https://github.com/peleduri/gop/.github/workflows/release.yml@refs/tags/${TAG}" \
               --certificate-oidc-issuer https://token.actions.githubusercontent.com
             sha256sum -c --ignore-missing checksums.txt
             prerelease=()
             case "$TAG" in *-*) prerelease=(--prerelease) ;; esac
             gh release create "$TAG" --repo "$GITHUB_REPOSITORY" "${prerelease[@]}" \
               --title "gh-gop $TAG" \
               --notes "Copies of the gh-gop binaries of https://github.com/peleduri/gop/releases/tag/${TAG}; verify them with that release's checksums.txt." \
               gh-gop-*
   ```

3. **Turn it on per release.** After each gop release finishes, run the workflow with that tag: Actions, mirror, Run workflow, or `gh workflow run mirror.yml --repo peleduri/gh-gop -f tag=vX.Y.Z`. Then check it from a machine logged in to `gh`:

   ```sh
   gh extension install peleduri/gh-gop
   gh gop version     # prints the release version
   ```

4. **Drop "coming soon".** After the first copied release installs, remove the "coming soon" notes from the `gh gop` section of [docs/install.md](install.md) and the README install block.

### Why it is wired this way

- Precompiled binaries, not a script extension: a script extension would download gop at run time on every machine with its own code; the precompiled one is the same signed build as the release, installed and upgraded by `gh` itself, and works on Windows without a shell.
- The mirror verifies the cosign signature on `checksums.txt` and every binary's checksum before it publishes, so the `gh-gop` release can only carry binaries the gop release workflow built.
- It needs only `contents: write` on `peleduri/gh-gop`; this repository's release job gets no new permission or secret. Anyone with write access to `peleduri/gh-gop` can change what `gh extension install peleduri/gh-gop` installs, so keep that access to the gop maintainers.

## Labels

The label set is described in [`.github/labels.yml`](../.github/labels.yml): type labels (which also pick the release notes category), area, priority (`p0` to `p2`), size (`S`, `M`, `L`), `good first issue`, `help wanted` and `agent-ready`. No workflow syncs them, because that needs a token that can write to the repository. Sync them from your machine after changing the file:

```sh
scripts/sync-labels.sh            # print the gh commands, change nothing
scripts/sync-labels.sh --apply    # create missing labels, update colors and descriptions
```

The script needs `gh auth login` with access to the repository. It never deletes a label: remove one by hand with `gh label delete <name> --repo peleduri/gop` after moving its issues to the replacement.

When you triage, mark a few small, self-contained issues `good first issue` and keep their description specific about which files to touch.

## Homebrew tap: one-time setup

`.goreleaser.yaml` has a `homebrew_casks` block for `peleduri/homebrew-tap`. Its `skip_upload` is templated on the `HOMEBREW_TAP_TOKEN` environment variable: without it, goreleaser still renders the cask into `dist/homebrew/Casks/gop.rb` but never pushes it. So releases keep working before this setup, in forks, and in the snapshot CI job.

To turn it on:

1. **Create the tap repository.** A public repository named `peleduri/homebrew-tap` (Homebrew maps `brew install peleduri/tap/gop` to `github.com/peleduri/homebrew-tap`). Initialize it with a README so it has a default branch. goreleaser writes `Casks/gop.rb` into it.
2. **Create a fine-grained personal access token** (Settings, Developer settings, Fine-grained tokens):
   - Resource owner: `peleduri`.
   - Repository access: **Only select repositories**, `peleduri/homebrew-tap` only.
   - Repository permissions: **Contents: Read and write**. Nothing else (Metadata: read is added automatically).
   - Expiration: the shortest you are willing to rotate, for example 90 days. Put the rotation date in your calendar.
3. **Store it as a secret** in `peleduri/gop`: Settings, Secrets and variables, Actions, New repository secret, name `HOMEBREW_TAP_TOKEN`. If you use a `release` environment, store it there instead so only the release job can read it.
4. **Release.** The next tag push uploads the cask. Check the commit in `peleduri/homebrew-tap`, then:

   ```sh
   brew install peleduri/tap/gop
   gop version
   ```

### Why it is wired this way

- Only the goreleaser step in `release.yml` receives `HOMEBREW_TAP_TOKEN`; the attestation step and every CI job do not.
- The token can write to the tap repository and nothing else. Whoever holds it can change what `brew install peleduri/tap/gop` installs, so treat it like a release credential and rotate it on expiry or when a maintainer leaves.
- The cask only references archives on this repository's releases, with their SHA-256, so users can still run the cosign and attestation checks in [docs/install.md](install.md#verify-what-you-run).

### Rotating or revoking

Create a new token with the same scope, replace the `HOMEBREW_TAP_TOKEN` secret, then delete the old token. To stop publishing, delete the secret: the next release skips the cask upload.
