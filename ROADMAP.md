# Roadmap

This is where gop is heading. It is a direction, not a schedule: no dates are promised, items can move or be dropped, and the order inside a theme is roughly the order the maintainers plan to take them. Each item has (or will get) a [GitHub issue](https://github.com/peleduri/gop/issues); comment there if you need it, or pick it up (see [CONTRIBUTING.md](CONTRIBUTING.md#finding-something-to-work-on)). What already shipped is in [CHANGELOG.md](CHANGELOG.md) and [What gop collects today](README.md#what-gop-collects-today).

The roadmap is kept by the maintainers under [GOVERNANCE.md](GOVERNANCE.md#decision-making): adding or dropping a theme is proposed on an issue first.

## Where gop is today

gop is alpha (v0.x). Since the first release it has grown from a cross-org Actions and OIDC reach graph into a tool that finds AI coding agents in CI that untrusted users can start, follows one level of composite actions, reusable workflows and scripts, explains bot self-merge review bypasses, and ships as a signed CLI, container image, GitHub Action and MCP server with installs for several AI assistants. Collection now scales: parallel App-mode orgs, incremental runs, partial graphs under a request budget, batched GraphQL and re-collecting some orgs into an existing graph (theme 1, shipped in Unreleased). The graph schema is `gop.graph/v2`; it and the CLI flags may still change before v1.0.

## Themes

### 1. Collection that scales to large enterprises

A full collection of a large enterprise takes many more requests than one token's hourly rate limit allows. The goal is a first run that finishes in hours, not days, and cheap daily runs after that, without losing the evidence guarantees.

Shipped in Unreleased (see [CHANGELOG.md](CHANGELOG.md)):

- Parallel collection across orgs, with a separate budget per GitHub App installation, and a `gop doctor` recommendation to use App mode when a token-mode run would be slow ([#174](https://github.com/peleduri/gop/issues/174)).
- Incremental collection: re-read only what changed since the previous graph, with periodic full re-reads ([#175](https://github.com/peleduri/gop/issues/175)).
- A partial graph on stop or budget exhaustion, with `--max-requests`, `--priority` and `--reserve`, so a capped run covers the most important orgs first and says clearly what it did not read ([#176](https://github.com/peleduri/gop/issues/176)).
- Batched GraphQL for per-repo collaborators and branch protection, to cut REST requests ([#177](https://github.com/peleduri/gop/issues/177)).
- `gop collect --orgs a,b --merge-into graph.json` re-collects some orgs into an existing graph ([#198](https://github.com/peleduri/gop/issues/198)).

### 2. AI agent detection

Finding AI coding agents that run in CI with secrets and write tokens, and who can start them, is gop's sharpest use case. The goal is fewer misses and fewer false alarms.

- Recognize more agent CLIs, agent Actions and model API call patterns as they appear, each backed by fixtures.
- Follow indirection deeper than one level where it changes who can start an agent, and keep confirmed and possible reach apart.
- Tighten the bot self-merge and review-bypass findings with more of the settings GitHub exposes.
- Use the "I ran gop" and "False positive or false negative" reports to tune the rules; every rule change keeps a documented evidence level.

### 3. More of the control graph

- GitHub App push grants.
- Enterprise audit log collection, so more facts carry `audit` evidence.
- Environment protection rules as conditions on edges.

### 4. Distribution

Make gop easy to install and verify wherever people already work, with every channel carrying the same signed build.

- First publish to the official MCP Registry, and a public container image.
- The Homebrew tap and the `gh gop` GitHub CLI extension.
- Listings in AI assistant plugin directories and marketplaces (the plugin icon and Cursor logo they ask for are in place).
- See [docs/maintainers.md](docs/maintainers.md#ai-assistant-distribution) for the state of each channel.

### 5. Project health

- Grow the maintainer group beyond one person, with maintainers from more than one organization ([MAINTAINERS.md](MAINTAINERS.md#becoming-a-maintainer)).
- Collect adopters ([ADOPTERS.md](ADOPTERS.md)).
- Register for the OpenSSF Best Practices badge and keep the Scorecard high.
- A stable v1.0 graph schema and CLI, with a deprecation policy.
- Prepare for a possible CNCF Sandbox application: see [docs/cncf.md](docs/cncf.md).

## Not planned

These would break gop's design rules and are out of scope: write calls to GitHub (gop only reads and recommends), telemetry or a hosted service that receives your graph, and posture checklists that duplicate what tools such as OpenSSF Scorecard already do ([docs/compare.md](docs/compare.md)).
