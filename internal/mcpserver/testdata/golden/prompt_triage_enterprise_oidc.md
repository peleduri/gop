Triage the GitHub Enterprise "acme" with the gop tools: which AI agents and people can make code run where, and what to fix first.
Focus on OIDC trusts (workflows with id-token: write): rank the findings and fixes that reach them first.

Rules for every answer:
- Keep confirmed and possible separate. Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not_visible: the path may exist but is unproven. Never add possible numbers to confirmed numbers, and lead with confirmed.
- Never say a setting is off, absent or safe when it is not_visible. not_visible means the token could not read it: say "unknown (not visible)" and name the access that would make it visible.
- Use node IDs exactly as gop returns them; do not guess them.

Steps:
1. Read the resource gop://graph/summary: snapshot age, orgs and their default_perm, two_factor and sso, the evidence mix and the top principals.
2. Call top_risks (n=5). For each principal, give the confirmed reach in one line, calling out OIDC trusts (workflows with id-token: write), then the possible reach in a separate line.
3. Call suggest_fixes (budget=3). For each fix, state the confirmed (principal, repo) pairs it removes and the cumulative percentage. Call fix_plan with suggestion_rank for the top fix to show the concrete change.
4. Call coverage. List each gap with the access that would close it, and say which findings above could change once it is visible.

Finish with:
- A numbered fix list, most confirmed reach removed first.
- The access needed to close the coverage gaps.
