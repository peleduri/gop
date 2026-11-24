# Connecting an MCP client

`gop serve --graph <file>` is an MCP server over stdio. Every tool it exposes is read-only. The fastest way to get a config with the right absolute path is to let gop print it:

```sh
gop mcp-config --client claude --graph ./graph.json        # a `claude mcp add` command
gop mcp-config --client codex --graph ./graph.json         # a `codex mcp add` command
gop mcp-config --client cursor --graph ./graph.json        # .cursor/mcp.json
gop mcp-config --client cursor-link --graph ./graph.json   # a Cursor install link
gop mcp-config --client vscode --graph ./graph.json        # .vscode/mcp.json
```

`gop mcp-config` only prints. It never writes or edits a config file; copy the output where it belongs. An unknown `--client` exits 2 and lists the valid ones.

The snippets below use `/path/to/graph.json`; replace it with the absolute path to your file.

One-step installs: a [Claude Code plugin](#claude-code), a [Claude Desktop extension](#claude-desktop), [Cursor install links](#cursor), [Codex](#codex), and the [MCP Registry](#other-clients-the-mcp-registry) for other clients. The formats are checked against the client docs listed under [Sources](#sources).

## Before you connect

- **Use an absolute graph path.** Clients start the server from a working directory you do not control, so a relative path breaks or, worse, opens a different file.
- **The graph is sensitive.** graph.json is a map of who can make code run where in your enterprise. Keep it out of shared, synced or backed-up folders (cloud drives, a shared repository checkout, a dotfiles repo), and never commit it. gop writes it with file mode 0600; keep it that way.
- **Answers go to your model provider.** gop sends nothing anywhere, but the client passes each tool answer to the model it uses. Only connect gop to a client and provider your organization allows for this data.
- **`gop` must be on the client's `PATH`.** GUI clients often do not see your shell's `PATH`. If the server fails to start, replace `"gop"` with the absolute path from `command -v gop`.

## Claude Code

**Plugin (MCP server and skill in one step).** This repository is a Claude Code plugin marketplace. In Claude Code:

```text
/plugin marketplace add peleduri/gop
/plugin install gop@gop
```

Claude Code 2.1.275 or later also takes one line: `/plugin install gop --marketplace peleduri/gop`. From your shell, the same is `claude plugin marketplace add peleduri/gop` then `claude plugin install gop@gop --config graph=/path/to/graph.json`.

The plugin adds the `gop` MCP server and the [gop skill](../skills/gop/README.md). Claude Code asks for one setting, **gop graph file** (`graph`): the absolute path to your graph.json. It runs `gop serve --graph <that path>`, so install `gop` first ([install.md](install.md)) and make sure it is on your `PATH`. Change the path later with `/plugin configure gop@gop`. The plugin follows this repository's default branch; run `/plugin marketplace update gop` after you upgrade gop so the skill matches your server.

**Server only.**

```sh
claude mcp add gop -- gop serve --graph /path/to/graph.json
```

This adds gop for you in the current project. Add `--scope user` to make it available in every project. To share the server definition with a project instead, use a `.mcp.json` file in the project root:

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

A checked-in `.mcp.json` should not contain a real path to a graph; keep the graph outside the repository and let each person run `claude mcp add` with their own path.

Check it with `claude mcp list`; gop should show as connected.

## Claude Desktop

Every release after v0.6.0 attaches a Claude Desktop extension per platform: `gop_<version>_<os>_<arch>.mcpb` (`darwin`, `windows` or `linux`; `arm64` or `amd64`). It bundles the gop binary, so you do not need gop on your `PATH`.

1. Download the bundle for your machine from the [latest release](https://github.com/peleduri/gop/releases/latest), for example `gop_0.7.0_darwin_arm64.mcpb` on an Apple silicon Mac.
2. Check it like any release asset: it is listed in `checksums.txt`, which is signed with cosign ([install.md](install.md)).
3. Open the file (double-click, or drag it onto Claude Desktop's **Settings > Extensions**) and choose **Install**.
4. Claude Desktop asks for **Graph file**: pick the graph.json written by `gop collect` (or `gop demo --out demo.json` to try it).

The extension runs `gop serve --graph <your file>` from the bundle. It is not code-signed by Apple or Microsoft; its integrity comes from the cosign-signed `checksums.txt` and the SLSA provenance of the release. To configure Claude Desktop by hand instead, add the `mcpServers` entry shown for Cursor below to `claude_desktop_config.json`.

## Cursor

**Install link.** Click a link and Cursor asks to add the server:

- [Add gop to Cursor](https://cursor.com/link/mcp/install?name=gop&config=eyJjb21tYW5kIjoiZ29wIiwiYXJncyI6WyJzZXJ2ZSIsIi0tZ3JhcGgiLCIke3VzZXJIb21lfS9nb3AvZ3JhcGguanNvbiJdfQ%3D%3D): runs `gop serve --graph ${userHome}/gop/graph.json`. Write your graph there (`gop collect ... --out ~/gop/graph.json`) or edit the path in Cursor's MCP settings after installing.
- [Try gop on the demo graph in Cursor](https://cursor.com/link/mcp/install?name=gop-demo&config=eyJjb21tYW5kIjoiZ29wIiwiYXJncyI6WyJzZXJ2ZSIsIi0tZGVtbyJdfQ%3D%3D): runs `gop serve --demo` (synthetic data, server name `gop-demo`).

`gop mcp-config --client cursor-link --graph ./graph.json` prints the same kind of link (`cursor://anysphere.cursor-deeplink/mcp/install?name=gop&config=...`) with your absolute path in it; open it in a browser. Both need `gop` on your `PATH`.

**By hand.** `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for every project:

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

Then enable the server under Cursor Settings, MCP.

**Skill.** Cursor loads skills from `~/.cursor/skills/` (every project) or `.cursor/skills/` (one project): copy `skills/gop` there ([skills/gop/README.md](../skills/gop/README.md)). The repository is also a Cursor plugin (`.cursor-plugin/plugin.json`) that carries the skill; it declares no MCP server, because a Cursor plugin variable is set by a team admin, not per user, and the graph path is personal. Add the server with the link above.

## Codex

**Server.**

```sh
codex mcp add gop -- gop serve --graph /path/to/graph.json
```

`gop mcp-config --client codex --graph ./graph.json` prints that command with the absolute path. Or add it to `~/.codex/config.toml` (or a trusted project's `.codex/config.toml`):

```toml
[mcp_servers.gop]
command = "gop"
args = ["serve", "--graph", "/path/to/graph.json"]
```

Check it with `codex mcp list`, or `/mcp` in the Codex TUI.

**Skill.** Codex loads user skills from `~/.agents/skills/`:

```sh
mkdir -p ~/.agents/skills
cp -R /tmp/gop-src/skills/gop ~/.agents/skills/
```

Or install it as a plugin from this repository's marketplace: `codex plugin marketplace add peleduri/gop`, then `codex plugin add gop@gop`. Codex reads the plugin from `.codex-plugin/plugin.json`, which carries the skill only; add the server with `codex mcp add` as above.

## VS Code

`.vscode/mcp.json` in the workspace (or run **MCP: Open User Configuration** for every workspace):

```json
{
  "servers": {
    "gop": {
      "type": "stdio",
      "command": "gop",
      "args": ["serve", "--graph", "/path/to/graph.json"]
    }
  }
}
```

VS Code uses `servers`, not `mcpServers`, and needs `"type": "stdio"`. Start the server from the CodeLens above the entry or with **MCP: List Servers**, then use the tools from Copilot Chat in agent mode.

## Other clients: the MCP Registry

gop is published to the [official MCP Registry](https://registry.modelcontextprotocol.io) as `io.github.peleduri/gop` (from [`server.json`](../server.json), on every stable release after v0.6.0). Clients and catalogs that read the registry offer two install options:

- **The container image** `ghcr.io/peleduri/gop:<version>`. The client asks for the folder that holds your graph.json and the file name (default `graph.json`), mounts the folder read-only at `/data` and runs `gop serve --graph /data/graph.json`. The image runs as user 65532: on Linux, make the graph readable by that user or have your client add `--user "$(id -u)"`.
- **The `.mcpb` bundles** of the release, each with its sha256, for clients that install MCPB.

Look it up with `curl https://registry.modelcontextprotocol.io/v0.1/servers/io.github.peleduri%2Fgop/versions/latest`.

## Any other stdio client

gop speaks MCP over stdin and stdout and logs nothing to stdout. Configure your client to run:

```
command: gop
args:    serve --graph /path/to/graph.json
```

Most clients accept the `mcpServers` shape shown for Cursor. To check the server by hand, start it and send an `initialize` request followed by `tools/list`; it answers with its name, version and the read-only tools. `resources/list` and `prompts/list` show the context resources (`gop://graph/summary`, `gop://graph/coverage`, `gop://graph/schema`, `gop://node/{+id}`) and the prompts (`triage_enterprise`, `review_action`, `explain_path`).

## Cause groups and standing ownership

`top_risks` groups rows in two tiers. Principals with identical confirmed reach share a row first. Then principals whose confirmed repos come at least 90% through the same cause and whose confirmed reach overlaps by Jaccard 0.9 or more share a row: `cause` is `org_owner` (each member owns orgs), `team` (through the team in `cause_scope`) or `org_members` (as members of the org in `cause_scope`). A direct collaborator grant is never a shared cause, so an owner and a heavy direct collaborator with similar counts stay apart. A cause group carries `range` (`repos`, `orgs` and, for `org_owner`, `owned_orgs`, each `{min, max}`) and `member_scores` (each member's own score, in `detail: full`). The row's other fields are its first member's: scores, counts and rank order are unchanged. The summary names the cause and the range, never one member.

`gop://graph/summary` has `org_ownership` when an account owns an org: `owners`, `buckets` (1, 2-4, 5-9 and 10+ orgs owned, each with its `accounts` count and `members`), and `owner_pairs`, `confirmed_pairs` and `owner_pct`: the confirmed (principal, repo) pairs that go away when every org owner grant is removed.

`what_if`, `fix_plan` and `suggest_fixes` model `{type: "reduce_owners", threshold: N}` (default 5): remove the `org_owner` grants of every account that owns N or more orgs, keeping at least 2 owners in each org. Owners under the threshold always stay; when an org would keep fewer than 2, the accounts over it that own the most orgs stay (ties by ID), listed in the fix's `kept` and the plan's caveats. `suggest_fixes` ranks it by measured impact like any other fix (`owner_threshold` changes its threshold) with a caveat recommending just-in-time ownership over standing ownership. `fix_plan` lists one role change per account, with the orgs and the REST call as text.

## Brief and full answers

On a large enterprise a full answer from a list-returning tool can run to tens of thousands of tokens. So `who_can_reach`, `blast_radius`, `paths`, `top_risks`, `suggest_fixes`, `diff` and `fix_plan` take an optional `detail` input, and **`brief` is the default**:

- **`brief`** caps lists at `limit` (default 10) and leaves out bulky per-item fields: the hops of listed paths, the attrs of listed edges, and a fix plan's per-principal scores. Every listed item keeps its IDs and its evidence level (confirmed and possible stay apart). The answer adds a `brief` object: `truncated` (anything was cut), `limit`, `total` (each list's length before the cut) and `omitted` (the fields left out). For `diff`, `limit` is the number of entries in the whole report, shared so every section with changes shows at least one. For `top_risks`, `total.risks` counts every ranked row (principals with identical confirmed reach share one row, listed in its `members`; so do principals grouped by cause, see below), and brief leaves out a cause group's `member_scores` (`total.member_scores` counts them).
- **`full`** returns every item and field, exactly as before this option existed. `diff` keeps its per-list `limit` (default 50).

Ask for the short answer first, then details for one item: `paths` with `from` and `to` returns that one path with its hops (even in brief), and `explain` returns one edge with its attrs.

Brief is the default because the agent clients gop serves read answers as context, and a brief answer only removes data and adds the optional `brief` object, so the structured output still matches the tool's output schema. A client that relied on complete lists by default must now pass `"detail": "full"`. The `gop paths` and `gop who` commands are not affected: they always print full answers.

## Check before you answer

gop's server instructions and the `explain_path` prompt ask the agent to call `check_answerable` before it gives a security conclusion to a human. Pass `question_kind` (the query tool whose answer you want to give) and `subject` (the node ID or org the question is about). It is deterministic and uses no language model: it reads the coverage entries and the `not_visible` facts (and audit facts too old to trust) in the part of the graph the answer depends on, and returns `answerable`:

- `yes`: every required fact was visible there. It never says `yes` when a required fact is `not_visible`.
- `partial`: the answer is a lower bound. Confirmed reach in it is real, but more may exist.
- `no`: gop could not see the subject itself or its org's repositories. Ask for the access instead of answering.

`missing` lists each required fact gop could not see, with its scope (a repo, org or the enterprise), the reason, and the access that fixes it when known. The required facts per question kind:

<!-- check_answerable table: generated from requiredFacts -->
| Question kind | Graph checked | Required facts |
|---|---|---|
| `who_can_reach` | the subject (a node, or every repo of an org) and every node with a path into it | `repositories`, `members`, `teams`, `collaborators`, `default_permission`, `branch_protection`, `rulesets`, `workflows`, `actions`, `token_permissions`, `triggers`, `oidc`, `runners_and_secrets`, `other` |
| `blast_radius` | the subject principal (an org means its members) and everything it reaches | `repositories`, `members`, `teams`, `collaborators`, `default_permission`, `branch_protection`, `rulesets`, `workflows`, `actions`, `token_permissions`, `triggers`, `oidc`, `runners_and_secrets`, `org_settings`, `other` |
| `paths` | the subject principal (an org means its members) and everything it reaches | `repositories`, `members`, `teams`, `collaborators`, `default_permission`, `branch_protection`, `rulesets`, `workflows`, `actions`, `token_permissions`, `triggers`, `oidc`, `runners_and_secrets`, `other` |
| `top_risks` | the whole enterprise | `repositories`, `members`, `teams`, `collaborators`, `default_permission`, `branch_protection`, `rulesets`, `workflows`, `actions`, `token_permissions`, `triggers`, `oidc`, `runners_and_secrets`, `org_settings`, `other` |
| `what_if` | the whole enterprise (before and after totals are enterprise-wide) | `repositories`, `members`, `teams`, `collaborators`, `default_permission`, `branch_protection`, `rulesets`, `workflows`, `actions`, `token_permissions`, `triggers`, `oidc`, `runners_and_secrets`, `other` |
| `fix_plan` | the whole enterprise (the plan reports the enterprise-wide reach it removes) | `repositories`, `members`, `teams`, `collaborators`, `default_permission`, `branch_protection`, `rulesets`, `workflows`, `actions`, `token_permissions`, `triggers`, `oidc`, `runners_and_secrets`, `other` |

| Fact | Covers |
|---|---|
| `repositories` | the org itself and its repository list (org, installation, archived, enterprise membership, host repos gop did not list) |
| `members` | org members and owners, and owners' admin access |
| `teams` | teams, team members and team repository grants |
| `collaborators` | direct and outside collaborators and custom repository roles |
| `default_permission` | the org's default repository permission and the push access it grants members |
| `branch_protection` | branch protection and branch rulesets of mutable action refs, and their bypass actors |
| `rulesets` | tag rulesets and immutable releases that lock an action tag |
| `workflows` | workflow files: the list, their contents and parse errors, expression `uses:` |
| `actions` | action refs: nested `uses:`, ref kind, the actions access of the host repo, whether the owner is in the enterprise |
| `token_permissions` | `GITHUB_TOKEN` write permission of workflows |
| `triggers` | who can cause a risky trigger, and repo visibility |
| `oidc` | OIDC tokens, their claims (environments) and cloud trust matches |
| `runners_and_secrets` | self-hosted runners and secret scopes a workflow runs with |
| `org_settings` | org security settings that weight scores: SSO, two-factor, IP allow list and member privileges |
| `repo_hardening` | default-branch protection, CODEOWNERS and secret scanning of repos: context on paths only, so no question requires it |
| `other` | any gap gop cannot classify |
<!-- end check_answerable table -->

To measure how well an agent keeps to these rules, see the agent-behaviour eval in [evals.md](evals.md).

## Try it

Ask your agent: "Who can make code run in acme-app/web?", "What happens if we pin acme-actions/deploy@main to a SHA?", or "What couldn't the token see?" No enterprise handy? Point `--graph` at the synthetic fixture, `testdata/acme/graph.json` in a checkout of this repository.

## Sources

Every install format above was checked against the client's own documentation on 2026-11-24. If a client changes its format, update the file and this table.

| What | Format in this repository | Documentation (read 2026-11-24) |
|---|---|---|
| MCP Registry entry | [`server.json`](../server.json), schema `2025-12-11`; image label `io.modelcontextprotocol.server.name` in [`.goreleaser.yaml`](../.goreleaser.yaml) | https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md, https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/package-types.mdx, https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json |
| Registry publishing (GitHub OIDC, `mcp-publisher` v1.8.8) | `mcp-registry` job in [`release.yml`](../.github/workflows/release.yml) | https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/github-actions.mdx, https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/authentication.mdx |
| Claude Code plugin and marketplace | [`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json), [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json) | https://code.claude.com/docs/en/plugins/manifest-reference, https://code.claude.com/docs/en/plugins/marketplace-reference, https://code.claude.com/docs/en/plugin-marketplaces |
| Claude Desktop extension (MCPB manifest 0.3) | built by [`scripts/dist`](../scripts/dist/main.go) | https://github.com/modelcontextprotocol/mcpb/blob/main/MANIFEST.md, https://github.com/modelcontextprotocol/mcpb/blob/main/schemas/mcpb-manifest-v0.3.schema.json |
| Cursor install links | `gop mcp-config --client cursor-link`, the links above | https://cursor.com/docs/mcp/install-links, https://cursor.com/docs/reference/deeplinks |
| Cursor plugin and skills | [`.cursor-plugin/plugin.json`](../.cursor-plugin/plugin.json) | https://cursor.com/docs/reference/plugins, https://cursor.com/docs/skills |
| Codex MCP, skills and plugins | `gop mcp-config --client codex`, [`.codex-plugin/plugin.json`](../.codex-plugin/plugin.json) | https://learn.chatgpt.com/docs/extend/mcp, https://learn.chatgpt.com/docs/build-skills, https://developers.openai.com/plugins/build/plugins |

`go test ./scripts/dist/` checks `server.json` and the generated MCPB manifests against copies of the published schemas, and the plugin manifests against the documented fields. `claude plugin validate .` and `mcpb validate` (from `@anthropic-ai/mcpb`) are the clients' own checks.
