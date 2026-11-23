# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/peleduri/gop/security/advisories/new)). Do not open a public issue, and do not include real graph.json files, tokens or org names; a synthetic reproduction is enough.

You should get an acknowledgement within 7 days.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No. Upgrade to the latest release. |

## Scope

In scope:

- The `gop` binary (collect, serve, report) and the MCP server
- The GitHub Action in `action/`
- Release integrity: signatures, checksums, SBOMs and provenance
- Anything that makes gop write to GitHub, send data off the machine, leak a token, or report a `not_visible` fact as `live` or as absent

Out of scope:

- Misconfigurations gop finds in your own enterprise (that is the tool working)
- Vulnerabilities in GitHub itself (report them to GitHub's bug bounty)
- Risks of the agent or model provider you connect to `gop serve`

## Disclosure policy

We follow coordinated disclosure with a 90-day deadline. We aim to ship a fix and publish a GitHub Security Advisory within 90 days of the report, sooner when a fix is ready. If a fix needs longer, we agree a date with the reporter. Reporters are credited unless they ask not to be.
