# CNCF Sandbox readiness

This page tracks what gop would need to apply to the [CNCF Sandbox](https://github.com/cncf/sandbox), what is already in place, and what is missing. **Nothing has been submitted.** The application at the end is a draft for the maintainer to finish and submit when the gaps are closed.

- [Sources](#sources)
- [Readiness checklist](#readiness-checklist)
- [OpenSSF Best Practices: passing criteria](#openssf-best-practices-passing-criteria)
- [Steps for the maintainer](#steps-for-the-maintainer)
- [Draft Sandbox application](#draft-sandbox-application)

## Sources

All read on 2026-11-24. Requirements change; re-read them before applying and update this page.

| Source | What it gives | Version read |
|---|---|---|
| Sandbox application form, [cncf/sandbox `.github/ISSUE_TEMPLATE/application.yml`](https://github.com/cncf/sandbox/blob/main/.github/ISSUE_TEMPLATE/application.yml) | Every field of the application, and the pre-submission checklist (critical requirements that close an application) | `main`, last commit 2026-10-29 |
| [cncf/sandbox README](https://github.com/cncf/sandbox/blob/main/README.md) | How applications are reviewed; common reasons applications are closed | `main`, last commit 2026-10-29 |
| [cncf/toc `process/README.md`](https://github.com/cncf/toc/blob/main/process/README.md) (Project Lifecycle and Process v1.6) and [`process/archiving.md`](https://github.com/cncf/toc/blob/main/process/archiving.md) | Project stages, naming conventions (trademarks, `kube`/`k8s`), review timelines | `process/README.md` last commit 2026-11-24 |
| [contribute.cncf.io/projects/lifecycle](https://contribute.cncf.io/projects/lifecycle/) | The lifecycle page as published, including the minimum maintainer and MAINTAINERS file rules | v1.6, no date on the page |
| [cncf/project-template](https://github.com/cncf/project-template) (README, GOVERNANCE-maintainer.md, MAINTAINERS.md, CODE_OF_CONDUCT.md, ADOPTERS.md, CONTRIBUTOR_LADDER.md) | Required and recommended files and their templates | `main`, last commit 2026-08-11 |
| [OpenSSF Best Practices criteria, passing level](https://www.bestpractices.dev/en/criteria/0) | The passing-level badge criteria | as published on 2026-11-24 |

The sources disagree on one point. The application form and the sandbox README (October 2026) say organization diversity is **not a requirement** for Sandbox but is considered in review; the lifecycle page on contribute.cncf.io and the MAINTAINERS template say a **minimum of 3 maintainers from 2 or more organizations**. This page takes the stricter reading and counts it as a gap.

## Readiness checklist

Status as of this commit. "Critical" marks the requirements the application form says close an application without review.

| Requirement | Source | Status | Evidence |
|---|---|---|---|
| Apache-2.0 license (critical) | form, sandbox README | Met | [LICENSE](../LICENSE); GitHub detects `Apache-2.0` |
| Dependencies on the CNCF license allowlist | form | Met | Linked modules: MIT (`google/jsonschema-go`, `segmentio/asm`, `segmentio/encoding`, `yaml.v3`, which is MIT and Apache-2.0), Apache-2.0 (`modelcontextprotocol/go-sdk`), BSD-3-Clause (`golang.org/x/*`, `yosida95/uritemplate`). Re-check with a license scanner before applying. |
| Repository 6+ months old with active development (critical) | form | **Not met** | Repository created 2026-11-23. Earliest date it qualifies: 2027-05-23. Development is active (six releases, v0.1.0 to v0.6.0). |
| MAINTAINERS file with Name, GitHub ID and Company/Organization columns, linked by a direct `/blob/` URL (critical) | form, lifecycle page | Met | [MAINTAINERS.md](../MAINTAINERS.md) |
| At least 3 maintainers from 2+ organizations (employers) | lifecycle page, template; "considered" in the form | **Not met** | One maintainer (`peleduri`, independent). |
| Reusable project, not a reference architecture (critical) | form | Met | A general-purpose CLI, MCP server and GitHub Action for any GitHub Enterprise; see [README](../README.md). |
| Not a subproject separating from a parent project (critical if it is one) | form | Met (not applicable) | Standalone repository under a personal account. |
| Name does not use an existing trademark; no `kube`/`k8s` prefix (critical) | form, toc process | **Not checked** | No `kube`/`k8s`. "gop" is a short acronym ("GitHub Enterprise Org Posture") that is also used elsewhere with other meanings; a trademark search has not been done. See [steps](#steps-for-the-maintainer). |
| Code of conduct | form, template | Met | [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md), the CNCF Code of Conduct |
| Contributing guide | form, template | Met | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Contributor ladder | template (recommended) | Met | [CONTRIBUTING.md, Contributor ladder](../CONTRIBUTING.md#contributor-ladder) |
| Governance | template | Met | [GOVERNANCE.md](../GOVERNANCE.md), maintainer-council model |
| Security policy | form, template | Met | [SECURITY.md](../SECURITY.md): private vulnerability reporting, 7-day acknowledgement, 90-day disclosure |
| Public roadmap | form | Met | [ROADMAP.md](../ROADMAP.md) |
| Website | form | Met | <https://peleduri.github.io/gop/> |
| Adopters, ideally in production | form (recommended), template | **Not met** | [ADOPTERS.md](../ADOPTERS.md) exists but lists no adopters. |
| Release process documented | template (recommended; required at incubation) | Met | [docs/maintainers.md](maintainers.md#releasing); signed releases with SBOMs and provenance ([docs/install.md](install.md)) |
| Issue and pull request templates | template (recommended) | Met | [.github/ISSUE_TEMPLATE](../.github/ISSUE_TEMPLATE), [.github/pull_request_template.md](../.github/pull_request_template.md) |
| CODEOWNERS matches governance | template (recommended) | Met | [.github/CODEOWNERS](../.github/CODEOWNERS) lists the one maintainer |
| No dependency on paid services | form | Met | Uses only free GitHub features for public repositories (Actions, Pages, GHCR, Discussions). |
| OpenSSF Best Practices badge | toc guide posts, common expectation | **Not met** | Not registered. Most passing criteria have evidence; see [below](#openssf-best-practices-passing-criteria). |
| OpenSSF Scorecard | common expectation | Met | [scorecard.yml](../.github/workflows/scorecard.yml) and the README badge |
| Listed on the Cloud Native Landscape | form asks | **Not met** | Not listed. Optional before applying. |
| Listed on LFX Insights | form asks | **Not met** | Not listed. Optional before applying. |
| Domain technical review or General Technical Review (Day 0) | form (optional) | **Not met** | Not done. Optional; a TAG Security presentation would help. |
| Contribution Agreement signatory | form | **Not met** | The maintainer provides contact and signatory details only at submission; they are not stored in the repository. |

### Gaps, in order of how much they block

1. **Repository age.** The form closes applications for repositories younger than 6 months. Do not apply before 2027-05-23.
2. **Maintainers.** One maintainer from one organization. Aim for at least 3 maintainers from at least 2 employers.
3. **Adopters.** None listed. Applications are stronger with named users, ideally in production.
4. **Name check.** No trademark search has been done for "gop".
5. **OpenSSF Best Practices badge.** Not registered; a few criteria need history that a new repository cannot show yet.
6. **Optional visibility.** Landscape and LFX Insights listings, and a technical review or TAG presentation.

## OpenSSF Best Practices: passing criteria

Each passing-level criterion mapped to evidence in this repository. MUST criteria decide the badge; SHOULD and SUGGESTED ones are listed for completeness. "Self-attest" means the badge form asks the maintainer to confirm it, and the repository can only support it.

### Basics

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `description_good` | MUST | Met | [README](../README.md) opening and the [site](https://peleduri.github.io/gop/) |
| `interact` | MUST | Met | Install ([docs/install.md](install.md)), feedback ([SUPPORT.md](../SUPPORT.md)), contributing ([CONTRIBUTING.md](../CONTRIBUTING.md)) |
| `contribution` | MUST | Met | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| `contribution_requirements` | SHOULD | Met | [CONTRIBUTING.md](../CONTRIBUTING.md): design rules, tests, DCO, PR title format |
| `floss_license` | MUST | Met | Apache-2.0 |
| `floss_license_osi` | SUGGESTED | Met | Apache-2.0 is OSI approved |
| `license_location` | MUST | Met | [LICENSE](../LICENSE) at the root |
| `documentation_basics` | MUST | Met | [docs/quickstart.md](quickstart.md), [README](../README.md) |
| `documentation_interface` | MUST | Met | CLI reference in the README, [docs/schema.md](schema.md), the JSON Schema in [schema/](../schema), MCP tools in the README |
| `sites_https` | MUST | Met | GitHub and GitHub Pages, HTTPS only |
| `discussion` | MUST | Met | GitHub issues and [Discussions](https://github.com/peleduri/gop/discussions): searchable, open to new participants, no proprietary client needed |
| `english` | SHOULD | Met | All docs in English |
| `maintained` | MUST | Met | Regular releases and merged pull requests |

### Change control

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `repo_public`, `repo_track`, `repo_interim`, `repo_distributed` | MUST / SUGGESTED | Met | Public git repository on GitHub with every commit between releases |
| `version_unique`, `version_semver`, `version_tags` | MUST / SUGGESTED | Met | `vX.Y.Z` git tags, Semantic Versioning ([CHANGELOG.md](../CHANGELOG.md)) |
| `release_notes` | MUST | Met | [CHANGELOG.md](../CHANGELOG.md) and generated GitHub release notes ([docs/maintainers.md](maintainers.md#release-notes)) |
| `release_notes_vulns` | MUST | Met | Release notes have a Security group (`sec` commits); CHANGELOG has Security sections |

### Reporting

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `report_process`, `report_tracker`, `report_archive` | MUST / SHOULD | Met | GitHub issues with forms ([.github/ISSUE_TEMPLATE](../.github/ISSUE_TEMPLATE)), public and searchable |
| `report_responses` | MUST | **Gap: not enough history** | Needs most bug reports of the last 2 to 12 months acknowledged; the repository is too new to show a track record. Answer every report. |
| `enhancement_responses` | SHOULD | **Gap: not enough history** | As above, for feature requests. |
| `vulnerability_report_process`, `vulnerability_report_private` | MUST | Met | [SECURITY.md](../SECURITY.md), GitHub private vulnerability reporting |
| `vulnerability_report_response` | MUST | Met (no reports yet) | SECURITY.md promises acknowledgement within 7 days, inside the 14 days required |

### Quality

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `build`, `build_common_tools`, `build_floss_tools` | MUST / SUGGESTED / SHOULD | Met | `go build ./cmd/gop`; goreleaser for releases; all FLOSS |
| `test`, `test_invocation` | MUST / SHOULD | Met | `go test ./...`, documented in [CONTRIBUTING.md](../CONTRIBUTING.md#tests) |
| `test_most` | SUGGESTED | Partly | Unit, golden and fuzz tests across packages; no coverage target is published |
| `test_continuous_integration` | SUGGESTED | Met | [ci.yml](../.github/workflows/ci.yml) on every pull request |
| `test_policy` | MUST | Met | [CONTRIBUTING.md, Tests](../CONTRIBUTING.md#tests): new functionality and fixes come with tests (added in this change) |
| `tests_are_added` | MUST | Met | Recent feature pull requests add tests and goldens (see [CHANGELOG.md](../CHANGELOG.md) entries) |
| `tests_documented_added` | SUGGESTED | Met | The test policy is in CONTRIBUTING.md and the [pull request template](../.github/pull_request_template.md) checklist |
| `warnings`, `warnings_fixed`, `warnings_strict` | MUST / SUGGESTED | Met | `go vet` and golangci-lint in CI ([.golangci.yml](../.golangci.yml)); CI fails on findings |

### Security

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `know_secure_design`, `know_common_errors` | MUST | Self-attest | [docs/threat-model.md](threat-model.md), the read-only guard in the API client, fuzzing of the parsers that read attacker-controlled input |
| `crypto_published`, `crypto_call`, `crypto_floss` | MUST / SHOULD | Met | gop implements no cryptography; it uses the Go standard library (`crypto/rsa` and `crypto/sha256` to sign GitHub App JWTs, `crypto/rand`, `crypto/hmac` for redaction) |
| `crypto_keylength`, `crypto_working`, `crypto_weaknesses` | MUST / SHOULD | Met | RS256 with the GitHub App key GitHub issues; SHA-256; no weak algorithms |
| `crypto_pfs` | SHOULD | Met | TLS to the GitHub API through Go's `crypto/tls` defaults |
| `crypto_password_storage` | MUST | N/A | gop stores no passwords |
| `crypto_random` | MUST | Met | `crypto/rand` |
| `delivery_mitm`, `delivery_unsigned` | MUST | Met | Releases over HTTPS, `checksums.txt` signed keyless with cosign, SLSA provenance ([docs/install.md](install.md)) |
| `vulnerabilities_fixed_60_days`, `vulnerabilities_critical_fixed` | MUST / SHOULD | Met | govulncheck in CI, Dependabot ([.github/dependabot.yml](../.github/dependabot.yml)); no known open vulnerabilities |
| `no_leaked_credentials` | MUST | Met | `scripts/leak-check.sh` in CI and pre-commit; synthetic data only |

### Analysis

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `static_analysis`, `static_analysis_common_vulnerabilities`, `static_analysis_often` | MUST / SUGGESTED | Met | CodeQL ([codeql.yml](../.github/workflows/codeql.yml)), golangci-lint and govulncheck on every pull request |
| `static_analysis_fixed` | MUST | Met | CI fails on CodeQL, golangci-lint and govulncheck findings; they are fixed before merge |
| `dynamic_analysis`, `dynamic_analysis_enable_assertions` | SUGGESTED | Met | Go fuzz targets run in CI (`fuzz` job in [ci.yml](../.github/workflows/ci.yml)); tests run with `-race` |
| `dynamic_analysis_unsafe` | SUGGESTED | N/A | Go is memory safe; gop does not import `unsafe` |
| `dynamic_analysis_fixed` | MUST | Met | Fuzz crashers are committed under `testdata/fuzz/` and fixed |

**Gaps:** register the project at bestpractices.dev; `report_responses` and `enhancement_responses` need months of answered issues; the security knowledge criteria are self-attested.

## Steps for the maintainer

Nothing below has been done. In rough order:

1. **Wait for the repository to be 6 months old** (2027-05-23) and keep releasing.
2. **Find a second and third maintainer**, at least one from another organization. Use the [contributor ladder](../CONTRIBUTING.md#contributor-ladder), label `good first issue` and `help wanted` work, and nominate people under [GOVERNANCE.md](../GOVERNANCE.md#adding-a-maintainer). Update [MAINTAINERS.md](../MAINTAINERS.md) and [.github/CODEOWNERS](../.github/CODEOWNERS).
3. **Collect adopters.** Ask users who report runs ("I ran gop" issues, Discussions) to add themselves to [ADOPTERS.md](../ADOPTERS.md). Never add one without their pull request or written permission.
4. **Register for the OpenSSF Best Practices badge** at <https://www.bestpractices.dev/> with the GitHub account, fill it from the table above, and add the badge to the README.
5. **Check the name.** Search the USPTO, EUIPO and WIPO trademark databases for "gop" in software classes, read the [Linux Foundation trademark usage policy](https://www.linuxfoundation.org/legal/trademark-usage), and be ready to rename. If accepted, the name and project accounts (repository, GHCR package, MCP Registry namespace, Homebrew tap, site) would be transferred to the CNCF/Linux Foundation, so record which accounts exist.
6. **Set up a shared maintainers' contact** for conduct reports and replace the placeholder in [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).
7. **Optional, before applying:** present to TAG Security, complete the Day 0 part of the [General Technical Review](https://github.com/cncf/toc/blob/main/toc_subprojects/project-reviews-subproject/general-technical-questions.md), and request listings on the Cloud Native Landscape and LFX Insights.
8. **Re-read the sources** in [Sources](#sources), update this page and the draft, then submit the form at <https://github.com/cncf/sandbox/issues/new?template=application.yml> yourself, with the contact and signatory details filled in at that point.

## Draft Sandbox application

> **DRAFT, NOT SUBMITTED.** Field names are those of the form as read on 2026-11-24. Fields marked `TODO` need the maintainer. Do not submit before the gaps above are closed.

**Title:** `[Sandbox] gop`

### Basic project information

**Project summary**
Read-only evidence graph of who, and which AI agents, can make code run where in a GitHub Enterprise.

**Project description**
gop collects a read-only graph of a GitHub Enterprise (orgs, teams, members, apps, repositories, workflows, the Actions they use, self-hosted runners, secrets scopes and OIDC trusts to cloud accounts) and answers one question: who can make code run where. It finds the paths that posture checklists miss because they look at one repository or one org at a time: an AI coding agent in CI that anyone can start with a comment while it holds a write token and secrets; an Action that members of one org can push to and that runs in another org's workflows with that org's OIDC trust into the cloud; a bot that approves and merges its own pull requests past branch protection. Every node and edge carries an evidence level (live, inferred by a documented rule, audit, or not visible), so gop never reports something it could not read as absent. It ranks the fewest changes that remove the most reach and explains each hop. gop runs locally or in GitHub Actions, sends no telemetry and never writes to GitHub. It ships as a signed CLI, a container image, a GitHub Action and an MCP server, so security teams and AI agents can query the same graph. Supply-chain attacks increasingly go through CI configuration and, now, through AI agents running in CI; gop gives platform and security teams a way to see and shrink that reach across a whole enterprise.

**Project vs Reference Architecture/Implementation**
[x] This is a reusable open source project designed for broad adoption, not a reference architecture, reference implementation, or demonstration of patterns.

### Project details

| Field | Draft answer |
|---|---|
| Org repo URL | N/A |
| Project repo URL in scope | https://github.com/peleduri/gop |
| Additional repos in scope | None today. If created: `peleduri/gh-gop` (GitHub CLI extension mirror) and `peleduri/homebrew-tap`. |
| Website URL | https://peleduri.github.io/gop/ |
| Roadmap | https://github.com/peleduri/gop/blob/main/ROADMAP.md |
| Contributing guide | https://github.com/peleduri/gop/blob/main/CONTRIBUTING.md |
| Code of Conduct (CoC) | https://github.com/peleduri/gop/blob/main/CODE_OF_CONDUCT.md |
| Adopters | https://github.com/peleduri/gop/blob/main/ADOPTERS.md (`TODO`: needs adopters) |
| Maintainers file | https://github.com/peleduri/gop/blob/main/MAINTAINERS.md (`TODO`: needs more maintainers) |
| Security policy file | https://github.com/peleduri/gop/blob/main/SECURITY.md |
| Standard or specification? | N/A. gop publishes a versioned JSON Schema for its graph format (`gop.graph/v2`), but it is a project data format, not a standard. |
| Business product or service to project separation | This project is unrelated to any product or service. |
| Dependency on paid cloud, community, and SaaS services or subscriptions | N/A. The project uses only free GitHub features for public repositories (Actions, Pages, Packages, Discussions). |

**Roadmap context**
Near-term work is collection that scales to large enterprises (parallel collection per GitHub App installation, incremental and budgeted runs, batched GraphQL), better AI agent detection, more of the control graph (App push grants, audit log evidence, environment protection rules), and distribution. gop is alpha; a stable v1.0 schema and CLI is a goal. Full list: ROADMAP.md.

### Cloud native context

**Why CNCF?**
gop answers a supply-chain question that sits next to CNCF's security work: how code gets from a repository into CI and from there into cloud accounts and clusters. Neutral governance would let organizations that compete with each other contribute detection rules and collectors to one shared evidence model, and would give adopters confidence that the project will outlive one maintainer. TAG Security's supply-chain guidance and the community around SLSA, Sigstore and in-toto are the people gop most needs feedback from.

**Benefit to the landscape**
Existing tools check settings one repository or org at a time (OpenSSF Scorecard, Legitify), or scan workflow files for injection patterns (poutine, zizmor). gop joins those facts across a whole enterprise into a graph with evidence levels and computes reach: who can start which workflow, which secrets and OIDC trusts it holds, and which fixes cut the most paths. It also covers AI coding agents in CI, a new and growing class of exposure.

**Cloud native 'fit'**
gop secures the delivery path of cloud native software: the CI that builds images and the OIDC trusts that let workflows deploy to cloud accounts. It is a single static binary and a distroless container image, runs as a scheduled GitHub Action or locally, emits SARIF and a documented JSON graph, and exposes an MCP server so automation and agents can query it. Releases are signed with Sigstore cosign and carry SBOMs and SLSA provenance.

**Cloud native 'integration'**
Cartography (CNCF Sandbox): gop reads Cartography's AWS OIDC trust data (`gop enrich --cartography`) and exports its own graph as a Neo4j script that links to Cartography's GitHub and AWS nodes. Sigstore (cosign) signs gop's releases and container image. gop's SARIF output feeds code scanning tools.

**Cloud native overlap**
Some overlap with Cartography, which also ingests GitHub data into a graph; gop focuses on computing code-execution reach with evidence levels and fix plans, and integrates with Cartography rather than replacing it. `TODO`: check the current CNCF project list for other overlap before submitting.

**Similar projects**
OpenSSF Scorecard and Legitify (posture checks per repository or org), poutine and zizmor (workflow file scanners), and Cartography (infrastructure graph). See https://github.com/peleduri/gop/blob/main/docs/compare.md.

**Landscape**
No. `TODO`: request a listing first, or answer "No".

**Insights**
No. `TODO`: answer at submission.

### CNCF policies

| Field | Draft answer |
|---|---|
| Trademark and accounts | `TODO`: the maintainer ticks this at submission. |
| IP policy | `TODO`: the maintainer ticks this at submission. |
| Project naming | `TODO`: tick only after the name check in [step 5](#steps-for-the-maintainer). |
| Does the project name use "kube", "k8s", or another existing project's prefix/suffix? | N/A. The project name does not use a prefix or suffix of an existing project. |
| Will the project require a license exception? | N/A. Project uses the Apache 2.0 license. |
| Dependencies with licenses not on the allowlist or an approved exception? | N/A. All dependencies are MIT, BSD-3-Clause or Apache-2.0 (re-check before submitting). |
| Project "Domain Technical Review" | `TODO`: link a TAG Security presentation or a Day 0 General Technical Review if done; otherwise leave empty. |

### Contact information

| Field | Draft answer |
|---|---|
| Application contact email(s) | `TODO`: the maintainer adds this at submission. Do not commit it here. |
| Contributing or sponsoring entity signatory information | `TODO`: individual(s) table (name, country, email) filled in at submission. Do not commit it here. |

### Additional information

| Field | Draft answer |
|---|---|
| CNCF contacts | `TODO` |
| Additional information | gop is maintained independently and is not affiliated with any company. It has been read-only and telemetry-free since its first release, and its tests run against fakes, never against a real enterprise. |
