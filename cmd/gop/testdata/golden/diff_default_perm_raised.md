# gop posture drift

Since 2026-11-13: 3 new confirmed paths; acme-actions default_perm read → write.

`acme (gop.graph/v2): 2026-11-13T10:00:00Z → 2026-11-20T10:00:00Z`

| | Old | New | Change |
|---|---|---|---|
| Confirmed (principal, repo) pairs | 3 | 5 | +2 |
| Possible (principal, repo) pairs | 0 | 0 | +0 |

## Paths

| Status | Principal | Target | Old | New |
|---|---|---|---|---|
| added | `members:acme-actions` | `secret:acme-app/api` | none | confirmed |
| added | `members:acme-actions` | `repo:acme-actions/deploy` | none | confirmed |
| added | `members:acme-actions` | `repo:acme-app/api` | none | confirmed |

## Settings

| Change | Old evidence | New evidence |
|---|---|---|
| acme-actions default_perm read → write | live | live |

## Edges

| Status | Edge |
|---|---|
| added | `members:acme-actions CAN_PUSH repo:acme-actions/deploy  [live, via=default_perm]` |

## Scores

| Principal | Confirmed | Possible |
|---|---|---|
| `members:acme-actions` | 0 → 11.5 (+11.5) | 0 → 0 (+0) |
