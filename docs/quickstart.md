# Quickstart

The fewest steps from nothing to a report of your own enterprise. Every
command only reads. The examples use the synthetic enterprise `acme`; replace
it with your enterprise slug.

## 0. See it first, no token

```sh
go install github.com/peleduri/gop/cmd/gop@latest    # or brew, a signed archive, a container: see install.md
gop report --demo --out report.html                  # synthetic enterprise, no token, no network
```

Open `report.html`. Everything below gives you the same report for your own
enterprise. Other install options and how to verify a release are in
[install.md](install.md).

## 1. Pick a credential

| You are | Use | Why |
|---|---|---|
| An enterprise owner, running once on your laptop | A classic personal access token (option A) | Sees enterprise settings and every org: the fullest graph |
| Running on a schedule, or in CI | A read-only GitHub App (option B) | Tokens last an hour and can only read; no owner PAT sits in a secret |
| An org owner, not an enterprise owner | Either, with `--orgs` | Enterprise-level settings come out `not_visible`; each org you own is complete |

gop takes the token only from `GITHUB_TOKEN` or `GH_TOKEN` (or your `gh`
login with `--use-gh-auth`), never as a flag, and never prints it.

### Option A: classic token from an enterprise owner

1. GitHub, Settings, Developer settings, Personal access tokens, Tokens
   (classic), Generate new token.
2. Scopes: `read:enterprise`, `read:org` and `repo`. Set an expiry.
   (`repo` is the only classic scope that can read workflow files in private
   and internal repositories; gop still sends only read requests, see
   [threat-model.md](threat-model.md).)
3. If your orgs enforce SAML SSO, authorize the token for each org
   (Configure SSO next to the token).

What each scope unlocks, and what goes `not_visible` without it, is in the
README's [Token and permissions](../README.md#token-and-permissions) table.

### Option B: read-only GitHub App

1. Create an App with webhooks off and these permissions, each **Read-only**:
   repository Metadata, Contents, Administration and Actions; organization
   Members and Administration.
2. Install it on every org to cover, generate a private key, and keep the key
   file at mode `0600`.
3. Pass `--app-id` and `--app-key-file` to `doctor` and `collect` (below)
   instead of setting `GITHUB_TOKEN`. gop mints one read-only token per org.

The full walkthrough, including running it from GitHub Actions and the
coverage you get compared with an owner token, is
[github-app-token.md](github-app-token.md). On GitHub Enterprise Server add
`--github-url https://HOST` ([ghes.md](ghes.md)).

## 2. Check, collect, report

```sh
export GITHUB_TOKEN=...                                  # option A; for option B use --app-id N --app-key-file app.pem
gop doctor  --enterprise acme                            # token, scopes, SSO gaps, rate limit, time estimate
gop collect --enterprise acme --out graph.json           # read-only; prints progress to stderr
gop report  --graph graph.json --out report.html         # the HTML report
```

`doctor` exits 0 when everything passes, 3 with warnings only and 1 on a
failure, each with the fix. Fix what it reports before a long first collection.

`graph.json` and `report.html` are a map of who can run code where in your
enterprise. They are written with mode `0600`; keep them local and never
commit them.

## 3. Next

- Ask questions from an AI agent over MCP: `gop mcp-config --client claude --graph /abs/path/graph.json`,
  then see [mcp-clients.md](mcp-clients.md) and the [agent skill](../skills/gop/README.md).
- Read the report: [report.md](report.md). AI coding agents in CI:
  [agents-in-ci.md](agents-in-ci.md).
- Share a problem without leaking names: `gop redact --graph graph.json --out shareable.json`,
  then open an issue with the "I ran gop" or "False positive or false negative" form.
- How gop compares with other tools: [compare.md](compare.md).
