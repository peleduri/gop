# GitHub Enterprise Server

gop reads a GitHub Enterprise Server (GHES) instance the same way it reads github.com: read-only REST and GraphQL calls with a token you supply. Point it at the instance:

```sh
export GITHUB_TOKEN=...   # read-only token on the instance
gop doctor  --enterprise acme --github-url https://github.acme.example
gop collect --enterprise acme --github-url https://github.acme.example --out graph.json
gop pin     --action acme-actions/deploy@main --github-url https://github.acme.example
```

`--github-url` (or the `GOP_GITHUB_URL` environment variable; the flag wins) takes the instance URL. gop derives the endpoints from it:

| Endpoint | URL |
| --- | --- |
| REST | `https://HOST/api/v3` |
| GraphQL | `https://HOST/api/graphql` |

An empty value, `https://github.com` or `https://api.github.com` means github.com. A URL ending in `/api/v3` is read as the REST root (the form `gop doctor --github-url` and `gop pin --github-url` took in 0.3 and earlier). Behind a proxy, `--api-url` and `--graphql-url` override either endpoint; the graph still records the host `--github-url` names.

`http://` URLs are refused, because the token would travel unencrypted. `--insecure-http` allows them for local test servers only.

## The token stays on the instance

Every request goes to the configured REST or GraphQL host. Pagination links that point anywhere else are refused. On a redirect to any other scheme or host (including a subdomain, another port, or an `https` to `http` downgrade, which `net/http` alone would keep the header for) gop removes the `Authorization` header before following it.

## Supported versions

gop reads the server version from `GET /api/v3/meta` (`installed_version`) and records it on the enterprise node as `ghes_version`, next to `host`. Collectors that need a newer version are skipped: the facts they would have read are `not_visible`, with a coverage entry such as

```json
{"scope": "repo:acme-actions/deploy", "fact": "actions_access",
 "reason": "not available on GHES 3.3.0 (rest:GET /repos/{owner}/{repo}/actions/permissions/access needs GHES 3.4)",
 "needs_fix": "upgrade to GHES >= 3.4 or run as site admin"}
```

The run still succeeds. When the version can't be read, `ghes_version` is `unknown` (`not_visible`) and every collector runs; APIs the server lacks then fail into coverage as they would on github.com.

| Collector | Minimum GHES | When skipped |
| --- | --- | --- |
| Enterprise per-org settings (GraphQL `enterprise.ownerInfo` lists: SSO, 2FA, default permission, repo creation, visibility, deletion and forking) | 3.0 | Each org's setting is `unknown` (`not_visible`), coverage on the enterprise |
| Enterprise consumed licenses (`GET /enterprises/{enterprise}/consumed-licenses`) | not available | Members and owners come from each org's members API |
| Actions access setting (`GET /repos/{owner}/{repo}/actions/permissions/access`) | 3.4 | `actions_access=unknown`: cross-org paths through the action stay possible |
| Repository rulesets (`GET /repos/{owner}/{repo}/rules/branches/{branch}`, `/rulesets`) | 3.11 | Branch protection comes from classic protection only (one `rulesets` coverage entry on the enterprise); tag immutability is `unknown` unless the release is immutable |

Every other collector (orgs, repositories, collaborators, teams, workflow and action files, classic branch protection, refs, releases) uses APIs present in every GHES 3.x release.

The minimums come from GitHub's public GHES documentation (`https://docs.github.com/en/enterprise-server@<version>/rest` and `/graphql`) and release notes. **None of them is verified against a running server of each version yet**; the table in `internal/collect/ghes.go` marks them so. If you see a collector skipped on a version that has the API, or failing on one that lacks it, please open an issue with the version and the coverage entry.

## Token scopes

The same as on github.com (see `gop doctor`): a classic token with `repo`, `read:org` and `read:enterprise` (enterprise owner), or a fine-grained token or GitHub App installation with read permissions. `gop doctor --github-url https://HOST` checks them against the instance. gop never needs site admin; the GHES site admin APIs are not used.

## Actions from github.com

On GHES, `uses: actions/checkout@v4` usually resolves through GitHub Connect or a local mirror of github.com actions. gop records an action whose owner is not an org on the instance as `in_enterprise=false` with `source=github.com`. As on github.com, gop does not model reach through such actions: their code is outside the enterprise.

## OIDC

GHES issues Actions OIDC tokens from `https://HOST/_services/token`, not `https://token.actions.githubusercontent.com`. `gop enrich` (and `gop collect --oidc-trust`) matches a supplied cloud trust only when its issuer is the token issuer of the graph's `host`: trusts for a GHES issuer match a graph from that instance, and trusts for github.com's issuer match a github.com graph. A graph without `host` (written by an older gop) matches any GitHub issuer, as before.

## Known gaps

- Enterprise consumed licenses are not read on GHES, so repository-scoped license grants are not available; members and owners come from the org members APIs.
- The capability table is unverified (see above).
- GHES site admin APIs (`/enterprise/...`, `/admin/...`) are out of scope.
- `gop diff` refuses to compare graphs from different hosts without `--force`.
