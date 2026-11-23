# Running gop with a GitHub App

This guide sets up a read-only GitHub App for gop, so that scheduled runs in
GitHub Actions (or local runs) do not need an enterprise-owner personal access
token. An enterprise-owner PAT stored in Actions secrets is exactly the
high-value CI path gop reports: anyone who can change a workflow in that
repository can use it. A read-only App whose tokens last an hour is a much
smaller target.

The examples use the enterprise `acme` with the orgs `acme`, `acme-actions`
and `acme-app`.

## 1. Create the App

Create the App under the enterprise (Enterprise settings, GitHub Apps) or under
a dedicated org that holds only security tooling (Org settings, Developer
settings, GitHub Apps, New GitHub App).

- **Webhook:** turn it off. gop does not receive events.
- **Callback URL, setup URL, device flow, user authorization:** leave empty or
  off. gop authenticates as the App, never as a user.
- **Where can this App be installed:** "Only on this account" for an
  enterprise-owned App. For an org-owned App that must be installed in the
  other orgs of the enterprise, choose "Any account" (installation still needs
  an owner of each org to approve it).
- **Permissions:** grant only the ones below, each as **Read-only**. Grant no
  write permission: gop requests read-only tokens and refuses a token GitHub
  grants with anything but read, but the private key can mint tokens with
  every permission the App holds.

| Permission | Level | What it unlocks in gop | Without it (`not_visible`) |
|---|---|---|---|
| Repository: Metadata | Read-only | Repository list, direct collaborators and their push permission, rulesets and branches (`CAN_PUSH` edges from collaborators, `ref_protected`/`ref_bypass` from rulesets) | Repositories, direct collaborators, rulesets and branches. GitHub makes this permission mandatory for every App, so it is always granted. |
| Repository: Contents | Read-only | Workflow files and nested `action.yml` contents (`USES` and `EXECUTES_WITH` edges, `uses:` refs and their pinning) | Workflow and action file contents, so every path through those workflows is unknown and cross-org `uses:` paths do not join |
| Repository: Administration | Read-only | Repository Actions settings: whether workflows in other repositories may use this repository's actions (`actions/permissions/access`) and the default `GITHUB_TOKEN` permission (`actions/permissions/workflow`), plus branch protection | Repository Actions access settings and branch protection, so cross-repo `uses:` reach and protected-ref gates are possible, not confirmed; the default token permission falls back to the org setting |
| Repository: Actions | Read-only | Actions metadata for the repository | Actions metadata |
| Organization: Members | Read-only | Org members, owners, teams with their repository grants, and outside collaborators (`MEMBER_OF` and team `CAN_PUSH` edges) | Org members, teams and outside collaborators, so team push grants are missing |
| Organization: Administration | Read-only | The org's default `GITHUB_TOKEN` workflow permission (`actions/permissions/workflow`), used when a repository's own setting is not readable | Org Actions workflow permissions, so a repository whose own setting is not readable has an unknown default token permission |

These are the permissions gop requests for every installation token
(`metadata`, `contents`, `administration`, `actions`, `members` and
`organization_administration`, all `read`). When the App lacks one, the
affected nodes get a coverage entry naming it, for example `grant the App
members:read`, and `gop doctor` predicts the gap before you collect.

Org settings that `GET /orgs/{org}` returns (default repository permission,
2FA requirement, repository creation, private forks) need no extra permission
and stay `live`.

Custom repository roles: gop reads an org's custom roles only to label a
collaborator's base role. App tokens do not request Organization: Custom
repository roles, so that label is a coverage entry; reach is not affected,
because the push decision comes from the repository's collaborator API.

After creating the App, note its **App ID** (numeric, for gop) and its
**Client ID** (for `actions/create-github-app-token`, below), and generate a
**private key**.

## 2. Install it in every org to cover

Install the App on each org (App settings, Install App, choose the org, "All
repositories"). With "Only select repositories", the repositories left out are
invisible to gop.

An org without an installation is reported as a `not_visible` org node with
coverage "install the App on acme-app with read-only permissions" when you name
it in `--orgs`; an org you do not name and the App is not installed in is not
discovered. Check before the first run:

```sh
gop doctor --enterprise acme --orgs acme,acme-actions,acme-app \
  --app-id 123456 --app-key-file gop-app.pem
```

doctor lists the installations, flags each `--orgs` entry without one, checks
that every granted permission is `read` and that none of the six above is
missing, mints one token per org to probe it, and lists what App mode will
leave `not_visible`.

## 3. Mint one token per org per run

### Recommended: let gop mint them (App mode)

Give gop the App ID and private key. It signs an App JWT, lists the App's
installations and mints one read-only installation token per org, re-minting
when less than 5 minutes remain. Each org's requests carry that org's token,
so one run covers every installed org and cross-org paths still join in one
graph. This is the only way today to cover several orgs in one graph without
an owner token.

In the Action:

```yaml
permissions:
  contents: read
jobs:
  posture:
    runs-on: ubuntu-latest # windows-latest and macos-latest work too
    environment: gop-posture # required reviewers, see step 4
    steps:
      - uses: peleduri/gop/action@<full-commit-sha> # vX.Y.Z
        with:
          enterprise: acme
          app-id: ${{ vars.GOP_APP_ID }}
          app-private-key: ${{ secrets.GOP_APP_PRIVATE_KEY }}
          retention-days: 1
```

Locally: `gop collect --enterprise acme --out graph.json --app-id 123456
--app-key-file gop-app.pem`, or set `GOP_APP_ID` and `GOP_APP_PRIVATE_KEY`
(the PEM contents). App credentials and `GITHUB_TOKEN` are mutually exclusive.

### Alternative: mint the token yourself with `actions/create-github-app-token`

If the private key must not reach gop at all, mint the installation token in a
separate step and pass only the token. `gop collect` takes one token, and an
installation token covers one org, so each run covers one org:

```yaml
permissions:
  contents: read
jobs:
  posture:
    runs-on: ubuntu-latest
    environment: gop-posture
    steps:
      - id: app-token
        uses: actions/create-github-app-token@f418cff399f7aef4c2f0ad47e25ca7a6abbdd6fc # v3.4.0
        with:
          client-id: ${{ vars.GOP_APP_CLIENT_ID }}
          private-key: ${{ secrets.GOP_APP_PRIVATE_KEY }}
          owner: acme-app # the org this token covers
          permission-metadata: read
          permission-contents: read
          permission-administration: read
          permission-actions: read
          permission-members: read
          permission-organization-administration: read
      - uses: peleduri/gop/action@<full-commit-sha> # vX.Y.Z
        with:
          enterprise: acme
          token: ${{ steps.app-token.outputs.token }}
          retention-days: 1
```

Limitations of this pattern:

- One org per graph. A path from a workflow in `acme-app` through an action in
  `acme-actions` does not join, because the other org's files are not readable
  with this token. Use App mode above to cover several orgs in one graph.
- The Action always uploads its artifact as `gop-posture`, so a `matrix` over
  orgs in one workflow run collides on the artifact name. Use one workflow (or
  one job in separate runs) per org until the Action takes an artifact name.
- Multi-token support in `gop collect` (one token per org from outside) is not
  planned while App mode covers the multi-org case; open an issue if you need it.

Without App credentials, a single installation token passed as `token` works
for its one org in the same way locally.

## 4. Where to keep the private key

The private key is a **high-value credential**: whoever holds it can mint
installation tokens with every permission the App was granted, in every org it
is installed in, for as long as the key is valid. Treat it like an enterprise
admin credential, even though the App is read-only.

- **Dedicated private repository.** Run gop from a private repository that
  holds only the posture workflow, not from an application repository. Its
  artifacts are an attack map of the enterprise and are readable by anyone with
  read access to the repository.
- **Environment with required reviewers.** Store the key as an environment
  secret (for example in an environment named `gop-posture`) rather than a
  repository secret, add required reviewers or a deployment branch rule that
  allows only the default branch, and reference the environment from the job.
  A pull request workflow then cannot read the key.
- **Restricted workflow edit rights.** Anyone who can push a workflow change to
  the default branch can exfiltrate the key. Limit write access to the
  repository to the security team, require reviews on `.github/workflows/`
  through a ruleset or CODEOWNERS, and do not allow Actions to create or
  approve pull requests there.
- Rotate the key on a schedule and when someone with access leaves; delete old
  keys in the App settings. Locally, keep the key file at mode `0600` (gop
  warns when it is wider).
- Do not grant the App write permissions "for later". gop never needs them, and
  they turn the key into a write credential.

## 5. Expected coverage: owner token vs App

| | (a) Enterprise-owner token, run locally | (b) GitHub App, one installation token per org |
|---|---|---|
| Enterprise org list | `live` (enterprise API) | `not_visible`; orgs are the App's installations plus `--orgs` |
| Enterprise settings: SSO state, enterprise 2FA policy, enterprise default permissions | `live` | `not_visible` (enterprise APIs are not called) |
| Org settings from `GET /orgs/{org}` (default permission, 2FA, repo creation, private forks) | `live` | `live` in installed orgs |
| Org members, owners, teams, outside collaborators | `live` | `live` in installed orgs with Members: read; consumed licenses `not_visible` |
| Repositories, collaborators, rulesets, branch protection | `live` | `live` in installed orgs (for the repositories the installation covers) |
| Workflow and action file contents | `live` | `live` in installed orgs |
| Org and repository Actions settings | `live` | `live` with Administration: read |
| `uses:` owner outside the covered orgs | `in_enterprise` decided from the enterprise org list | `in_enterprise=unknown` |
| An org not covered | Not applicable: the owner sees every org | `not_visible` org node with an "install the App" coverage entry (when named in `--orgs`) |
| Credential risk | Long-lived enterprise-wide credential; keep it off CI | Private key in one restricted repository; tokens last an hour and are read-only |

For full coverage, run gop locally with an enterprise-owner token (mode a).
For a scheduled run in CI, App mode (b) is the safer choice; the report's
coverage list names every gap it leaves. See also
[README: Token modes](../README.md#token-modes) and
[the threat model](threat-model.md).
