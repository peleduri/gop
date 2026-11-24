# Getting help with gop

## Start here

- [Quickstart](docs/quickstart.md): install, the read-only token or GitHub App, and the first report.
- [README](README.md) and the [docs](docs/): the report, AI agents in CI, MCP clients, the graph schema and the threat model.
- [How gop compares](docs/compare.md) with other GitHub security tools.
- The site: <https://peleduri.github.io/gop/>.
- `gop doctor --enterprise <slug>` explains most token, scope, SSO and rate limit problems, each with the fix.

## Where to ask

| You want to | Go to |
|---|---|
| Tell us how a run went, what it found, what was confusing | [Open an "I ran gop" issue](https://github.com/peleduri/gop/issues/new?template=i_ran_gop.yml) |
| Report a path that is wrong, or one gop missed | [Open a "False positive or false negative" issue](https://github.com/peleduri/gop/issues/new?template=false_positive_negative.yml) |
| Report something else that is broken | [Open a bug report](https://github.com/peleduri/gop/issues/new?template=bug_report.yml) |
| Suggest a feature | [Open a feature request](https://github.com/peleduri/gop/issues/new?template=feature_request.yml) |
| Ask a question or share an idea | [Discussions](https://github.com/peleduri/gop/discussions) |
| Report a vulnerability in gop | Private vulnerability reporting, see [SECURITY.md](SECURITY.md). Never a public issue. |

gop is maintained in spare time. There is no support SLA; issues with a
synthetic reproduction get answered first.

## Share a problem, not your enterprise

Issues and discussions are public. A graph.json, a report or a SARIF file is a
map of who can make code run where in your enterprise.

- Never paste or attach a raw graph.json, report, SARIF file or the
  `--cache-dir` contents, and never a token.
- Do not write real org, repo, team, user, secret or runner names. Use the
  synthetic names from the demo (`acme-actions`, `acme-app`, `alice`, `bob`).
- If the problem depends on your graph, run
  `gop redact --graph graph.json --out shareable.json` and attach
  `shareable.json`. It renames every org, repo, user, team, secret and runner
  and fails if an original name is left. Never attach the `--map-out`
  mapping file.
- Better still, reproduce it on `gop demo` or `testdata/acme/graph.json`.

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).
