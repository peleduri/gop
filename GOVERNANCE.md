# gop governance

gop is a read-only evidence graph of who can make code run where in a GitHub Enterprise. This document explains how the project is run: who decides, how, and how that changes. It follows the maintainer-council model of the [CNCF project template](https://github.com/cncf/project-template/blob/main/GOVERNANCE-maintainer.md), scaled to a project that has one maintainer today.

- [Values](#values)
- [Roles](#roles)
- [Maintainers](#maintainers)
- [Decision making](#decision-making)
- [Adding a maintainer](#adding-a-maintainer)
- [Removing a maintainer](#removing-a-maintainer)
- [Conflict resolution](#conflict-resolution)
- [Code of conduct](#code-of-conduct)
- [Security response](#security-response)
- [Changing this governance](#changing-this-governance)

## Values

- **Openness.** Discussion and decisions happen in public, in issues, pull requests and [Discussions](https://github.com/peleduri/gop/discussions), so they can be found later. Only security reports and conduct reports are handled privately.
- **Fairness.** Anyone can propose a change, and it is judged on its merits.
- **Community over any company.** Contributors take part as individuals. Project direction, maintainer selection and releases are not controlled by any single organization.
- **Evidence over opinion.** The project's design rules (read-only, no telemetry, every fact carries an evidence level) are the tie-breaker for technical arguments. They are listed in [CONTRIBUTING.md](CONTRIBUTING.md#design-rules) and [docs/architecture.md](docs/architecture.md).
- **Participation.** Responsibility is earned through contribution, along the [contributor ladder](CONTRIBUTING.md#contributor-ladder).

## Roles

The roles (participant, contributor, reviewer, maintainer), what each can do and how to move up are described in the [contributor ladder](CONTRIBUTING.md#contributor-ladder). The current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Maintainers

Maintainers have write access to the repository and its release, package and site settings. Together they are the maintainer council, the governing body of the project. They:

- review and merge pull requests, triage issues and keep the [roadmap](ROADMAP.md) current;
- cut releases (see [docs/maintainers.md](docs/maintainers.md#releasing));
- handle security reports under [SECURITY.md](SECURITY.md) and conduct reports under [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md);
- hold the project's accounts and credentials (release signing identity, package registries, the Homebrew tap token), and rotate them when a maintainer leaves.

While gop has a single maintainer, that maintainer is the maintainer council, and every rule below that needs a vote is decided by them, in public, with the reasoning written down on the issue or pull request. The rules are written for several maintainers so they keep working as the council grows.

## Decision making

1. **Lazy consensus by default.** Most decisions (merging a pull request, labelling, small roadmap changes) are made by [lazy consensus](https://community.apache.org/committers/lazyConsensus.html): a proposal on an issue or pull request is accepted when no maintainer objects within a reasonable time, normally 3 working days for anything larger than a fix.
2. **Pull requests** need approval from one maintainer other than the author once there are two or more maintainers. With one maintainer, the maintainer may merge their own pull requests after CI passes.
3. **Significant changes** (a breaking change to the graph schema or the CLI, a new data source, anything that touches the read-only or no-telemetry rules, a new runtime dependency) start as an issue that states the problem and the proposed design, so others can comment before code is written.
4. **Votes.** Any maintainer may call a vote when consensus is not reached. Votes are held on a public issue (or privately for security and conduct matters) and stay open for at least 7 days or until every maintainer has voted. A simple majority of all maintainers decides, except where this document says two-thirds.
5. **Organization balance.** Once maintainers come from more than one employer, the maintainers employed by any one organization may cast at most half of the votes on any decision; if they hold more seats, their votes are scaled down to that share.

## Adding a maintainer

A contributor becomes a maintainer when they meet the maintainer requirements in the [contributor ladder](CONTRIBUTING.md#maintainer) and:

1. an existing maintainer nominates them on a public issue (or privately first, with the nominee's agreement);
2. a simple majority of the maintainers approves, and no maintainer objects with a reason within 7 days.

Nominations are judged on contribution, not on employer or demographics, and should improve the organizational diversity of the maintainer group. The new maintainer is added to [MAINTAINERS.md](MAINTAINERS.md) and [.github/CODEOWNERS](.github/CODEOWNERS) and given repository access in the same change.

## Removing a maintainer

- A maintainer may step down at any time by opening a pull request that moves them to the emeritus list in [MAINTAINERS.md](MAINTAINERS.md).
- A maintainer who has been inactive for 12 months, with no stated plan to return, is moved to emeritus after a maintainer asks them on a public issue and they do not reply within 30 days.
- A maintainer may be removed for a serious or repeated violation of the code of conduct, or for acting against the project's design rules or interests, by a two-thirds vote of the other maintainers. The maintainer concerned does not vote.

On removal or stepping down, their access to the repository, releases, registries and secrets is revoked and any credential they held is rotated the same day. Emeritus maintainers can return through the normal nomination process.

## Conflict resolution

1. Disagreements are resolved first on the issue or pull request, by the people involved, with reference to the design rules and the evidence.
2. If that fails, any participant can ask the maintainers to decide. The maintainers discuss it in public and decide by lazy consensus, or by a vote if a maintainer asks for one.
3. A maintainer who is a party to the conflict does not vote on it. If that leaves no maintainer able to decide (as it does while there is one maintainer), the decision is still made in public with the reasoning written down, and the other party may ask for it to be reviewed again once there is another maintainer. If gop is accepted into the CNCF, either side may escalate to the CNCF as its processes allow.
4. Conduct issues are not technical conflicts: they follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Code of conduct

The project follows the [CNCF Code of Conduct](CODE_OF_CONDUCT.md). Reports are handled privately by the maintainers. If a maintainer is involved in a report, they take no part in handling it; if that leaves no maintainer to handle it, the reporter is pointed to the CNCF Code of Conduct Committee once gop is a CNCF project.

## Security response

The maintainers are the security response team. They handle reports under [SECURITY.md](SECURITY.md) and review that assignment once a year. When there are enough maintainers, they may appoint a team of at least two people for it.

## Changing this governance

Changes to this document, [MAINTAINERS.md](MAINTAINERS.md), the contributor ladder and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) are made by pull request, left open for comment for at least 7 days, and need approval from two-thirds of the maintainers. While there is one maintainer, the change is announced in [Discussions](https://github.com/peleduri/gop/discussions) when the pull request opens.

As the project grows, the maintainers should revisit this model: add reviewer or area-owner roles when one group cannot review everything, and move to an elected model if one organization holds most seats.
