# Connecting an MCP client

`gop serve --graph <file>` is an MCP server over stdio. Every tool it exposes is read-only. The fastest way to get a config with the right absolute path is to let gop print it:

```sh
gop mcp-config --client claude --graph ./graph.json   # a `claude mcp add` command
gop mcp-config --client cursor --graph ./graph.json   # .cursor/mcp.json
gop mcp-config --client vscode --graph ./graph.json   # .vscode/mcp.json
```

`gop mcp-config` only prints. It never writes or edits a config file; copy the output where it belongs. An unknown `--client` exits 2 and lists the valid ones.

The snippets below use `/path/to/graph.json`; replace it with the absolute path to your file.

## Before you connect

- **Use an absolute graph path.** Clients start the server from a working directory you do not control, so a relative path breaks or, worse, opens a different file.
- **The graph is sensitive.** graph.json is a map of who can make code run where in your enterprise. Keep it out of shared, synced or backed-up folders (cloud drives, a shared repository checkout, a dotfiles repo), and never commit it. gop writes it with file mode 0600; keep it that way.
- **Answers go to your model provider.** gop sends nothing anywhere, but the client passes each tool answer to the model it uses. Only connect gop to a client and provider your organization allows for this data.
- **`gop` must be on the client's `PATH`.** GUI clients often do not see your shell's `PATH`. If the server fails to start, replace `"gop"` with the absolute path from `command -v gop`.

## Claude Code

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

## Cursor

`.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for every project:

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

## Any other stdio client

gop speaks MCP over stdin and stdout and logs nothing to stdout. Configure your client to run:

```
command: gop
args:    serve --graph /path/to/graph.json
```

Most clients accept the `mcpServers` shape shown for Cursor. To check the server by hand, start it and send an `initialize` request followed by `tools/list`; it answers with its name, version and the read-only tools. `resources/list` and `prompts/list` show the context resources (`gop://graph/summary`, `gop://graph/coverage`, `gop://graph/schema`, `gop://node/{+id}`) and the prompts (`triage_enterprise`, `review_action`, `explain_path`).

## Brief and full answers

On a large enterprise a full answer from a list-returning tool can run to tens of thousands of tokens. So `who_can_reach`, `blast_radius`, `paths`, `top_risks`, `suggest_fixes`, `diff` and `fix_plan` take an optional `detail` input, and **`brief` is the default**:

- **`brief`** caps lists at `limit` (default 10) and leaves out bulky per-item fields: the hops of listed paths, the attrs of listed edges, and a fix plan's per-principal scores. Every listed item keeps its IDs and its evidence level (confirmed and possible stay apart). The answer adds a `brief` object: `truncated` (anything was cut), `limit`, `total` (each list's length before the cut) and `omitted` (the fields left out). For `diff`, `limit` is the number of entries in the whole report, shared so every section with changes shows at least one. For `top_risks`, `total.risks` counts every ranked row (principals with identical confirmed reach share one row, listed in its `members`).
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
| `other` | any gap gop cannot classify |
<!-- end check_answerable table -->

## Try it

Ask your agent: "Who can make code run in acme-app/web?", "What happens if we pin acme-actions/deploy@main to a SHA?", or "What couldn't the token see?" No enterprise handy? Point `--graph` at the synthetic fixture, `testdata/acme/graph.json` in a checkout of this repository.
