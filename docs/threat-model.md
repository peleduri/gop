# Threat model

gop maps who can make code run where in a GitHub Enterprise. That makes its input (a privileged token) and its output (the graph) both sensitive. This document says what gop touches and how to handle both.

## What gop reads

Read-only calls to the GitHub REST and GraphQL APIs:

- Enterprise ownerInfo: member orgs, enterprise default repository permissions, 2FA and SSO policy
- Org settings: default permission, member repo creation, visibility changes, repo deletion, private forks, IP allow list, 2FA and SSO state
- Members, teams, apps and their repository permissions
- Repositories and their workflow files (`.github/workflows/*`), to find the Actions they use, the secrets scopes, `id-token: write` and self-hosted runners they run with
- The enterprise audit log, for facts the current-state API does not expose (evidence `audit`)

Anything the token cannot read is recorded as `not_visible` with a `coverage` entry, never as absent.

## What gop never does

- **No writes.** gop makes no POST, PATCH, PUT or DELETE calls that change GitHub state. A guard in the API client refuses every non-GET REST request before it is sent, and refuses GraphQL mutations. The one allowlisted exception is GitHub App mode's `POST /app/installations/{id}/access_tokens`, which mints a short-lived read-only installation token and changes no repository or org state. A test walks a full App-mode collection and fails on any other write-method request.
- **No telemetry.** gop sends nothing to the maintainer or any third party. The only network traffic is read requests to the GitHub API host you configure.
- **No hidden storage.** gop writes only the files you ask for (graph.json, report.html). It does not cache the token.

`gop serve` speaks MCP over stdio. Its answers go to the agent you connect and, through it, to that agent's model provider. That flow is your choice; gop does not make it.

## Token modes

| Mode | Coverage | Risk |
|---|---|---|
| (a) Enterprise-owner token, run locally | Full enterprise settings plus everything the owner can see | The most powerful credential. Keep it on the operator's machine, short-lived, never in CI secrets. |
| (b) GitHub App (`gop collect --app-id N --app-key-file PATH`, `GOP_APP_ID` + `GOP_APP_PRIVATE_KEY`, or the Action's `app-id` + `app-private-key`): gop mints a read-only installation token per org | Enterprise APIs are not called. `not_visible` in this mode: enterprise ownerInfo settings (SSO state, enterprise 2FA policy and the other per-org settings lists, filled per org from `GET /orgs/{org}` where it returns them), the enterprise org list, consumed licenses (members and owners come from each org's members API instead) and the enterprise membership of `uses:` owners outside the installed orgs (`in_enterprise=unknown`). A selected org without an installation is a `not_visible` org node with coverage `installation`; a 403 from a missing App permission gives coverage naming it (`grant the App members:read`). | Installation tokens last an hour and are requested with read permissions only; gop refuses a token GitHub grants with any non-read permission. The App private key is the high-value credential: whoever holds it can mint tokens with every permission the App was granted. |
| (c) A repository's `GITHUB_TOKEN` | One repository | Low risk, but gop is not useful in this mode. |

## Token storage guidance

- Prefer short-lived credentials: a fine-grained or SSO-authorized token with an expiry for local runs, or an App installation token minted per run in CI.
- Grant read scopes only (`read:enterprise`, `read:org`, `read:audit_log`, `repo` for workflow contents). gop needs no write scope; a token that has one is broader than necessary.
- Pass the token through the environment (`GITHUB_TOKEN`) from a secret manager, not on the command line, where it lands in shell history and process listings.
- **Do not store an enterprise-owner PAT in GitHub Actions secrets.** Anyone who can edit a workflow in that repository, or push to an Action it uses, can exfiltrate it. That is precisely the cross-repo code-execution path gop reports.
- If you run the Action, use a dedicated private repository, restrict who can edit its workflows, pin the Action to a commit SHA, and keep the App private key there only.

## GitHub App private key handling

- The key reaches gop only from the file `--app-key-file` names or the `GOP_APP_PRIVATE_KEY` environment variable (PEM contents), never as a flag value. gop reads it once, holds it in memory and never logs, prints or writes it; key parse errors never echo key material, and the CLI redacts every key line from any error it prints. It warns when the key file's mode is wider than `0600`. App credentials and `GITHUB_TOKEN` are mutually exclusive (exit 2).
- The Action masks every line of `app-private-key` (and the token) before running anything, and passes the key only to the `gop collect` process.
- The JWT is signed with the Go standard library (RS256, `iat` 60 seconds back, `exp` 9 minutes ahead) and sent only to `/app/*`; the JWT client refuses any other path.
- Installation tokens are minted per org, requested with `metadata`, `contents`, `members`, `administration`, `actions` and `organization_administration` set to `read` (configurable, but every value must be `read`), re-minted when fewer than 5 minutes remain, and never logged or written to graph.json.
- Grant the App read permissions only, and install it only on the orgs you want covered. Keep the key in a dedicated private repository or secret manager with restricted access.

## graph.json is sensitive

graph.json (and the HTML report built from it) **maps your attack paths**: which org's members can push code that runs with which secrets, OIDC trusts and runners, and where your visibility gaps are. Treat it like a penetration test report:

- Never commit it. The repository `.gitignore` excludes `/graph.json` and `/report.html`; add the same to any repository where you run gop.
- Store it encrypted at rest and delete it when you are done.
- When produced by the Action, the artifact is readable by anyone with read access to that repository. Run the Action only in a private repository and keep artifact retention at 1 day.
- Do not paste it into issues, chats or bug reports. Reduce problems to synthetic data (`acme`, `acme-actions`, `acme-app`).

## Supply chain

Releases are built by `.github/workflows/release.yml` with goreleaser, signed keyless with cosign (Sigstore bundles next to each artifact), shipped with SPDX SBOMs and checksums, and attested with SLSA build provenance. Verify before running; see the README Install section.
