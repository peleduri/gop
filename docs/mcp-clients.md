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

Most clients accept the `mcpServers` shape shown for Cursor. To check the server by hand, start it and send an `initialize` request followed by `tools/list`; it answers with its name, version and the read-only tools.

## Try it

Ask your agent: "Who can make code run in acme-app/web?", "What happens if we pin acme-actions/deploy@main to a SHA?", or "What couldn't the token see?" No enterprise handy? Point `--graph` at the synthetic fixture, `testdata/acme/graph.json` in a checkout of this repository.
