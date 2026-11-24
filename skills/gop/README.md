# gop agent skill

[`SKILL.md`](SKILL.md) teaches an agent the gop triage flow over MCP: check the
graph, read `coverage` and `check_answerable` before any claim, rank with
`top_risks`, prove each risk with `paths` and `explain`, plan it with
`fix_plan`, and report every finding as **confirmed**, **needs validation** or
**rejected** without adding possible reach to confirmed reach.

The skill only tells the agent how to use gop. It needs the gop MCP server
connected first: see [docs/mcp-clients.md](../../docs/mcp-clients.md), or run
`gop mcp-config --client claude --graph /abs/path/graph.json`.

## Install

**As a plugin (with the MCP server).** In Claude Code, `/plugin marketplace add
peleduri/gop` then `/plugin install gop@gop` installs this skill and the gop MCP
server together. Codex installs the skill from the same marketplace
(`codex plugin marketplace add peleduri/gop`, `codex plugin add gop@gop`). See
[docs/mcp-clients.md](../../docs/mcp-clients.md).

**By hand.** A skill is a folder with a `SKILL.md`. Copy `skills/gop` into the folder your
agent loads skills from. Get it from a shallow clone:

```sh
gh repo clone peleduri/gop /tmp/gop-src -- --depth 1   # or: git clone --depth 1 https://github.com/peleduri/gop /tmp/gop-src
```

### Claude Code

```sh
mkdir -p ~/.claude/skills
cp -R /tmp/gop-src/skills/gop ~/.claude/skills/
```

For one project only, copy it to `.claude/skills/gop` in that project instead.
Claude Code picks the skill up from its description when you ask about GitHub
Enterprise reach, or you can ask for it by name.

### Codex

Codex loads user skills from `~/.agents/skills` (and, for one repository,
`.agents/skills` in it):

```sh
mkdir -p ~/.agents/skills
cp -R /tmp/gop-src/skills/gop ~/.agents/skills/
```

### Cursor

Cursor loads skills from `~/.cursor/skills` (every project) or
`.cursor/skills` in a project:

```sh
mkdir -p ~/.cursor/skills
cp -R /tmp/gop-src/skills/gop ~/.cursor/skills/
```

### Any other agent

Copy the `gop` folder into the agent's skills directory, keeping the folder name
(it must match `name` in the frontmatter). Agents without skill support can be
given `SKILL.md` as an instruction file.

## Keep it in step with gop

The skill names gop's MCP tools, their arguments and CLI commands. A test
(`go test ./skills/`) fails if any of them is renamed or removed, so the copy in
a release matches that release's server. Copy the skill again when you upgrade
gop.

The agent-behaviour eval ([docs/evals.md](../../docs/evals.md)) runs a model with
this skill as its system prompt and scores its answers against gop's own
output. Run it after changing a rule here.
