## Fix plan: Remove standing org ownership from 3 accounts that own 19 or more orgs (keep at least 2 owners per org)

Confirmed (principal, repo) pairs: 510 -> 344 (33% removed); possible pairs: 0 -> 0.

> gop never runs these steps or calls write APIs: make each change with your own access.

### Steps

- [ ] Change setting: in 20 orgs (acme-o01, acme-o02, acme-o03, acme-o04, acme-o05, acme-o06, acme-o07, acme-o08, acme-o09, acme-o10, acme-o11, acme-o12, acme-o13, acme-o14, acme-o15, acme-o16, acme-o17, acme-o18, acme-o19, acme-o20): Organization settings > People > admin-a > Change role: Member
  - API (text only): `PUT /orgs/{org}/memberships/admin-a {"role": "member"}, once per org`
  - evidence: `identity:admin-a CAN_PUSH repos of org:acme-o01, org:acme-o02, org:acme-o03, org:acme-o04, org:acme-o05, org:acme-o06, org:acme-o07, org:acme-o08, org:acme-o09, org:acme-o10, org:acme-o11, org:acme-o12, org:acme-o13, org:acme-o14, org:acme-o15, org:acme-o16, org:acme-o17, org:acme-o18, org:acme-o19, org:acme-o20 (via org_owner)` (inferred)
  - note: admin-a owns 20 orgs and keeps 0; another owner of each org makes the change and grants owner access again only when a task needs it; the API call is shown as text only, gop never calls it
- [ ] Change setting: in 19 orgs (acme-o01, acme-o02, acme-o03, acme-o04, acme-o05, acme-o06, acme-o07, acme-o08, acme-o09, acme-o10, acme-o11, acme-o12, acme-o13, acme-o14, acme-o15, acme-o16, acme-o17, acme-o18, acme-o19): Organization settings > People > admin-b > Change role: Member
  - API (text only): `PUT /orgs/{org}/memberships/admin-b {"role": "member"}, once per org`
  - evidence: `identity:admin-b CAN_PUSH repos of org:acme-o01, org:acme-o02, org:acme-o03, org:acme-o04, org:acme-o05, org:acme-o06, org:acme-o07, org:acme-o08, org:acme-o09, org:acme-o10, org:acme-o11, org:acme-o12, org:acme-o13, org:acme-o14, org:acme-o15, org:acme-o16, org:acme-o17, org:acme-o18, org:acme-o19 (via org_owner)` (inferred)
  - note: admin-b owns 19 orgs and keeps 0; another owner of each org makes the change and grants owner access again only when a task needs it; the API call is shown as text only, gop never calls it
- [ ] Change setting: in 19 orgs (acme-o01, acme-o02, acme-o03, acme-o04, acme-o05, acme-o06, acme-o07, acme-o08, acme-o09, acme-o10, acme-o11, acme-o12, acme-o13, acme-o14, acme-o15, acme-o16, acme-o17, acme-o18, acme-o20): Organization settings > People > admin-c > Change role: Member
  - API (text only): `PUT /orgs/{org}/memberships/admin-c {"role": "member"}, once per org`
  - evidence: `identity:admin-c CAN_PUSH repos of org:acme-o01, org:acme-o02, org:acme-o03, org:acme-o04, org:acme-o05, org:acme-o06, org:acme-o07, org:acme-o08, org:acme-o09, org:acme-o10, org:acme-o11, org:acme-o12, org:acme-o13, org:acme-o14, org:acme-o15, org:acme-o16, org:acme-o17, org:acme-o18, org:acme-o20 (via org_owner)` (inferred)
  - note: admin-c owns 19 orgs and keeps 0; another owner of each org makes the change and grants owner access again only when a task needs it; the API call is shown as text only, gop never calls it

### Caveats

- Prefer just-in-time ownership: grant owner access on demand for the task and remove it after, instead of standing ownership. The kept owners, and anyone given owner access later, still hold this reach.
