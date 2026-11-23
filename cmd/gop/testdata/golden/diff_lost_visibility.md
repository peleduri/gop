# gop posture drift

Since 2026-11-13: 0 new confirmed paths, 3 lost visibility; acme-actions two_factor required → not visible (lost visibility).

`acme (gop.graph/v2): 2026-11-13T10:00:00Z → 2026-11-20T10:00:00Z`

| | Old | New | Change |
|---|---|---|---|
| Confirmed (principal, repo) pairs | 3 | 1 | -2 |
| Possible (principal, repo) pairs | 0 | 0 | +0 |

## Paths

| Status | Principal | Target | Old | New |
|---|---|---|---|---|
| lost visibility (the newer snapshot cannot see part of this path; reach unknown, not fixed) | `identity:bob` | `secret:acme-app/api` | confirmed | none |
| lost visibility (the newer snapshot cannot see part of this path; reach unknown, not fixed) | `identity:bob` | `repo:acme-actions/deploy` | confirmed | none |
| lost visibility (the newer snapshot cannot see part of this path; reach unknown, not fixed) | `identity:bob` | `repo:acme-app/api` | confirmed | none |

## Settings

| Change | Old evidence | New evidence |
|---|---|---|
| acme-actions two_factor required → not visible (lost visibility) | live | not visible |

## Edges

| Status | Edge |
|---|---|
| lost visibility | `identity:bob CAN_PUSH repo:acme-actions/deploy  [was live, via=direct]` |

## Scores

| Principal | Confirmed | Possible |
|---|---|---|
| `identity:bob` | 11.5 → 0 (-11.5) | 0 → 0 (+0) |

## Coverage

| Gap | Scope | Fact | Reason | Needs |
|---|---|---|---|---|
| opened | `org:acme-actions` | repositories | token is not an org owner | org owner on acme-actions |
| opened | `org:acme-actions` | two_factor | token is not an org owner | org owner on acme-actions |
