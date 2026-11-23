# gop

gop builds a read-only evidence graph of a GitHub Enterprise that answers one question: **who can make code run where?** It joins org settings (default repository permissions, 2FA, SSO), push access, workflows and the Actions they consume, so it can follow reach across org boundaries: members of one org push to a shared Action, and that Action runs inside another org's workflows with that org's secrets, OIDC and runners. You query the graph from an AI agent over MCP, from the CLI, or from a GitHub Action that produces an HTML report.

> Members of **acme-actions** can push code that runs in **10 repos across 2 orgs**, including one with cloud OIDC.
> Pin `acme-actions/deploy@main` to a SHA to remove **75%** of that reach.

## No half truths

Every node and edge in the graph carries an evidence level:

| Evidence | Meaning |
|---|---|
| `live` | Read from current state through the GitHub API. |
| `audit` | Inferred from the enterprise audit log. Retention is bounded, so it may be stale or incomplete. |
| `not_visible` | The token cannot read this fact. The hop is **unknown, not absent**. |

gop never turns "couldn't see" into "off". If a setting or an org is out of reach, the answer says so, and `coverage` lists the access that would close the gap.

## Install

From [Releases](https://github.com/peleduri/gop/releases): download the archive for your platform, then verify it.

```sh
sha256sum -c --ignore-missing checksums.txt
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/peleduri/gop/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify gop_X.Y.Z_linux_amd64.tar.gz --repo peleduri/gop   # SLSA build provenance
```

With Go:

```sh
go install github.com/peleduri/gop/cmd/gop@latest
```

## Quick start

```sh
# 1. Collect. Read-only. Writes graph.json locally.
export GITHUB_TOKEN=...            # see "Token and permissions"
gop collect --enterprise acme --out graph.json

# 2. Ask questions from your agent over MCP (stdio).
gop serve --graph graph.json

# 3. Or produce a static HTML report.
gop report --graph graph.json --out report.html
```

MCP config for Claude Code (`.mcp.json`) or Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "gop": {
      "command": "gop",
      "args": ["serve", "--graph", "/path/to/graph.json"]
    }
  }
}
```

Then ask: "Who can make code run in acme-app/web?" or "What happens if we pin acme-actions/deploy to a SHA?"

### MCP tools

| Tool | Answers |
|---|---|
| `who_can_reach` | Which principals can make code run in a target repo, workflow, secret scope, OIDC trust or runner pool. |
| `blast_radius` | Everything a principal (an org's members, a user, a team, an app) can make code run in. |
| `paths` | The concrete hops from a principal to a target, each with its evidence level and API source. |
| `what_if` | How reach changes under a hypothetical fix (pin an Action to a SHA, change a default permission, require 2FA). |
| `suggest_fixes` | Fixes ranked by how much reach they remove. |
| `explain` | Why an edge exists: the setting, API source and observation time behind it. |
| `coverage` | What the token could not see, and the access that would fix it. |

## Token and permissions

gop only reads. Use a classic token from an **enterprise owner** with these scopes, or the equivalent read permissions on a GitHub App:

| Scope | Used for | If missing |
|---|---|---|
| `read:enterprise` | Enterprise ownerInfo: org list, enterprise-level default permissions, 2FA and SSO policy | Enterprise settings are `not_visible`; orgs are discovered only where the token is a member |
| `read:org` | Org settings, members, teams, repository permissions, IP allow lists | That org's settings and `CAN_PUSH` edges are `not_visible` |
| `read:audit_log` | Facts that only the audit log records | No `audit` evidence; those facts are `not_visible` |
| `repo` | Workflow file contents in private and internal repositories (`USES`, `EXECUTES_WITH` edges) | Workflows in those repos are `not_visible`, so cross-org paths through them are unknown |

Under SAML SSO enforcement the token must also be authorized for each org.

### Token modes

| Mode | What gop sees |
|---|---|
| (a) Enterprise-owner token, run locally | Full enterprise settings plus every org and repo the owner can see. **The headline numbers above assume this mode.** |
| (b) Per-org GitHub App installation tokens | No enterprise ownerInfo: enterprise settings collectors are skipped and marked `not_visible`. The App must be installed in every org you want covered; uninstalled orgs are `not_visible`. In CI the App private key is itself a high-value credential. |
| (c) A repository's `GITHUB_TOKEN` | One repository only. gop is not useful in this mode. |

### Rate limits

A token gets 5,000 REST requests per hour (GitHub Apps scale with installation size). Large enterprises take a while to collect. Collection is sequential today; resuming an interrupted collection is planned.

## Running in GitHub Actions: token risk

The Action (`uses: peleduri/gop/action@<sha>`) downloads a release, verifies its checksum (and cosign signature when cosign is installed), runs `gop collect` and `gop report`, and uploads both files as an artifact.

```yaml
permissions:
  contents: read
jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: peleduri/gop/action@<full-commit-sha> # vX.Y.Z
        with:
          enterprise: acme
          token: ${{ steps.app-token.outputs.token }}
          retention-days: 1
```

Read this before you set it up:

- **Prefer a read-only GitHub App installation token per org**, minted per run, over a PAT. An enterprise-owner PAT stored in Actions secrets creates exactly the high-value CI path gop reports: anyone who can change a workflow in that repository can use it.
- With App tokens, enterprise settings and any org the App is not installed in show as `not_visible` in the report (mode b above). The App private key in secrets is a high-value credential; keep it in a dedicated private repository with restricted workflow edit access.
- **Artifacts are readable by anyone with read access to the repository.** graph.json and report.html are an attack map. Run the Action only in a **private** repository, and keep `retention-days` at 1 (the default).
- For full coverage, run gop locally with an enterprise-owner token (mode a) instead.

## Security and privacy

- **Read-only.** gop makes no write calls to GitHub.
- **No telemetry.** gop sends nothing anywhere except read requests to the GitHub API you point it at.
- **Data stays local.** graph.json and the report are written to your disk. Treat them as sensitive and never commit them.
- **MCP answers go to your agent.** When you connect `gop serve` to an agent, its answers flow to that agent and to whichever model provider it uses. gop itself sends nothing anywhere.

See [docs/threat-model.md](docs/threat-model.md) and [docs/schema.md](docs/schema.md). Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Status

Alpha. The graph schema (`gop.graph/v1`) and CLI flags may change before v1.0.

## License

[Apache-2.0](LICENSE)
