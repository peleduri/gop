Lower the default repository permission of `acme-actions` to `read`: 1 setting to change; removes 5 of 14 confirmed (principal, repo) pairs (36%); 1 step is not visible, listed last

## Fix plan: Lower the default repository permission of acme-actions to read

Confirmed (principal, repo) pairs: 14 -> 9 (36% removed); possible pairs: 5 -> 2.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Verify acme-actions/deploy
  - owner: acme-actions
  - evidence: `members:acme-actions CAN_PUSH repo:acme-actions/deploy` (live)
  - note: before the change: members of acme-actions lose push to acme-actions/deploy (granted only by the base permission); give a team push first if members need it; other push grants kept: team:acme-actions/platform
- [ ] Verify acme-actions/setup
  - owner: acme-actions
  - evidence: `members:acme-actions CAN_PUSH repo:acme-actions/setup` (live)
  - note: before the change: members of acme-actions lose push to acme-actions/setup (granted only by the base permission); give a team push first if members need it; other push grants kept: identity:bob
- [ ] Change setting in org acme-actions: Organization settings > Member privileges > Base permissions: Read
  - API (text only): `PATCH /orgs/acme-actions {"default_repository_permission": "read"}`
  - evidence: live
  - note: current base permission: write; an org owner of acme-actions makes this change; the API call is shown as text only, gop never calls it
- [ ] Verify acme-actions/tools
  - owner: acme-actions
  - evidence: `members:acme-actions CAN_PUSH repo:acme-actions/tools` (not visible)
  - note: before the change: members of acme-actions lose push to acme-actions/tools (granted only by the base permission); give a team push first if members need it; not visible to the token: confirm this exists first

### Caveats

- members who rely on the default write permission lose push to every acme-actions repo where they have no team, direct or owner grant
- repos where members of acme-actions have push only through the base permission: acme-actions/deploy, acme-actions/setup, acme-actions/tools [not visible]
