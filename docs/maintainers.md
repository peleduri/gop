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

## Project site (GitHub Pages): one-time setup

`.github/workflows/pages.yml` publishes `site/` to <https://peleduri.github.io/gop/>: the landing page (`site/index.html`) and the demo report, rebuilt from the current source with `gop report --demo` on every publish. It runs on pushes to `main` that touch `site/`, `cmd/`, `internal/`, `go.mod`, `go.sum` or the workflow, and on manual dispatch.

1. Settings, Pages, Build and deployment, Source: **GitHub Actions**. The first run creates the `github-pages` environment.
2. Run the workflow once (Actions, pages, Run workflow) or push a change under `site/`.
3. Settings, General (the repository's About panel, gear icon): set **Website** to `https://peleduri.github.io/gop/`. With the GitHub CLI: `gh repo edit peleduri/gop --homepage https://peleduri.github.io/gop/`.

Local preview: `site/build.sh` writes `_site/`, then `(cd _site && python3 -m http.server 8080)`. The page carries a strict CSP with the hash of its one `<style>` block, and `go test ./site/` checks the hash, every link, and that each figure the page quotes (the `data-n` elements) still matches `gop report --demo`. After editing the style block, put the hash the test prints into the CSP `<meta>`.

## AI assistant distribution

Formats and the docs they were checked against: [mcp-clients.md, Sources](mcp-clients.md#sources). Nothing below has been published or submitted yet; each step that needs a maintainer login is written out so it can be done by hand.

### What every release does on its own

- **Claude Desktop extensions.** The gop build in [`.goreleaser.yaml`](../.goreleaser.yaml) has a post hook that runs `go run ./scripts/dist mcpb` per target and writes `dist/mcpb/gop_<version>_<os>_<arch>.mcpb` (MCPB manifest 0.3 plus the binary and the 512 and 1024 px icons embedded from `brand/logo/png`; the tools list is read from the server). The bundles are added to `checksums.txt`, so the cosign signature covers them, get SLSA provenance, and are uploaded with the release. The CI `release-snapshot` job checks that a snapshot build produces all six.
- **MCP Registry.** The `mcp-registry` job in [`release.yml`](../.github/workflows/release.yml) runs after goreleaser on stable tags (no `-` in the tag). It builds the published `server.json` from the committed one (`go run ./scripts/dist server-json`: version and image tag from the tag, plus one `mcpb` package per bundle with the sha256 from `checksums.txt`), validates it, then runs `mcp-publisher login github-oidc` and `mcp-publisher publish`. The registry grants the `io.github.peleduri/*` namespace to this repository's OIDC token, so no secret is stored. The job has `contents: read` and `id-token: write` only. `mcp-publisher` is pinned to a release (`MCP_PUBLISHER_VERSION`) and checked by sha256 and its Sigstore bundle; bump both together, deliberately.
- **Plugins.** `.claude-plugin/`, `.cursor-plugin/` and `.codex-plugin/` are read from the default branch by the clients; there is nothing to release. The plugins have no `version`, so they follow the default branch.

### MCP Registry: first publish

Prerequisites: the GHCR package `gop` is public ([Container image](#container-image-one-time-setup)), and the release carries the `io.modelcontextprotocol.server.name` image label (added in [`.goreleaser.yaml`](../.goreleaser.yaml); the registry reads it from the image config and rejects the image without it).

1. Push the next stable tag. Watch the `mcp-registry` job of the release run.
2. Check the entry: `curl https://registry.modelcontextprotocol.io/v0.1/servers/io.github.peleduri%2Fgop/versions/latest`.
3. If the job fails with `invalid audience`, `mcp-publisher` is too old: bump `MCP_PUBLISHER_VERSION` and `MCP_PUBLISHER_SHA256`. If it fails on package validation, the image label or the public visibility of the package is missing.

Manual fallback (the same result, from a maintainer machine, for a release whose job failed). Use a checkout of the release tag and the official `mcp-publisher` binary from https://github.com/modelcontextprotocol/registry/releases (verify its `.sigstore.json` with cosign):

```sh
gh release download vX.Y.Z --repo peleduri/gop --pattern checksums.txt --dir rel
go run ./scripts/dist server-json --version X.Y.Z --checksums rel/checksums.txt > server.release.json
mv server.release.json server.json
mcp-publisher validate server.json
mcp-publisher login github     # device flow in the browser, as the peleduri account
mcp-publisher publish
git checkout server.json
```

`login github` grants the personal namespace `io.github.peleduri/*`, which is the one gop uses. A version can be published once; to fix a bad entry publish the next version, or mark one deprecated with `mcp-publisher status`.

### Claude Code plugin: Anthropic's directory (drafted, not submitted)

`/plugin marketplace add peleduri/gop` works without any listing. To list gop in [Anthropic's directory](https://claude.ai/directory) as well (it then also reaches claude.ai and Cowork users):

1. Needs a paid claude.ai plan on the submitting account.
2. Validate: `claude plugin validate . --strict`. The directory wants a square PNG (512 to 2048 px, under 2 MB) at `.claude-plugin/icon.png`, and the first one submitted becomes the listing icon. It is a copy of `brand/logo/png/gop-mark-1024.png` (`go test ./scripts/dist` fails if the two differ).
3. Run the [pre-submission checklist](https://claude.com/docs/plugins/pre-submission-checklist#run-the-checks-before-you-submit).
4. Submit the repository from the developer portal, https://claude.ai/directory/manage, following [Submit a plugin](https://claude.com/docs/plugins/submit#submit-a-plugin). Suggested listing text: name `gop`; summary "gop reads a GitHub Enterprise read-only and shows which AI agents and people can make code run where, with evidence per hop and fixes ranked." (the 25-word description in BRAND.md); note for reviewers that the server is local (`gop serve`), reads only a local graph.json, and needs the gop binary on `PATH`.

### Claude Desktop extension: directory

Anthropic's directory no longer accepts local MCP servers packaged as desktop extensions (MCPB); a local server is listed by including it in a plugin bundle ([Directory publishing](https://claude.com/docs/directory/publish), read 2026-11-24). So the `.mcpb` files are distributed through GitHub releases and the MCP Registry only, and the directory listing is the plugin submission above. Optional: sign the bundles with `mcpb sign` (from `@anthropic-ai/mcpb`) once there is a signing certificate; until then clients show them as unsigned, and their integrity rests on the cosign-signed `checksums.txt`.

### Cursor (drafted, not submitted)

- **Cursor Marketplace.** The repository is a Cursor plugin (`.cursor-plugin/plugin.json`, the skill only). Submit `https://github.com/peleduri/gop` at https://cursor.com/marketplace/publish after testing it from `~/.cursor/plugins/local/gop` (copy, not a symlink). Their checklist also asks for a logo committed to the repo and referenced by relative path: `logo` in the manifest is `.cursor-plugin/logo.png`, the same 1024 PNG as the Claude plugin icon.
- **cursor.directory** (community MCP servers and plugins). Sign in at https://cursor.directory and use its add-a-server form. Draft listing: name `gop`; description "Read-only evidence graph of which AI agents and people can make code run where in a GitHub Enterprise: AI agents in CI, cross-org Actions, OIDC trusts, and the fewest fixes that remove the most reach."; install link `https://cursor.com/link/mcp/install?name=gop&config=eyJjb21tYW5kIjoiZ29wIiwiYXJncyI6WyJzZXJ2ZSIsIi0tZ3JhcGgiLCIke3VzZXJIb21lfS9nb3AvZ3JhcGguanNvbiJdfQ%3D%3D`; repository `https://github.com/peleduri/gop`; tags security, github, github-actions, supply-chain. (The site's submission page could not be read on 2026-11-24, so confirm the form's fields there.)

### Codex

`codex plugin marketplace add peleduri/gop` reads `.claude-plugin/marketplace.json` and installs the plugin from `.codex-plugin/plugin.json` (the skill only; checked with Codex CLI 0.163.0). OpenAI's public plugin directory has no self-serve submission documented today; revisit when it does.

## Plugin versions

Before tagging a release, set `version` in `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.cursor-plugin/plugin.json` and `.codex-plugin/plugin.json` to the new release number. `TestPluginVersionsAgree` fails if they drift apart.
