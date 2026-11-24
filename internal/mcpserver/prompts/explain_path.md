Explain how {{.From}} can make code run in {{.To}}, one hop at a time, with the gop tools.

Rules for every answer:
- Keep confirmed and possible separate. Confirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not_visible: the path may exist but is unproven. Say which one each path is.
- Never say a hop or setting is off or absent when it is not_visible. not_visible means the token could not read it: say "unknown (not visible)" and name the access that would make it visible (see the coverage tool).

Steps:
1. Call paths with from {{.From}} and to {{.To}}. If there is no path, say so and stop; do not invent one.
2. For each hop of the shortest confirmed path (or the possible path when there is no confirmed one), call explain with the hop's from, to and kind. For each hop, say in one line what it means (e.g. "members of acme-actions can push to repo acme-actions/deploy"), its evidence and its source_api, and the file and line when explain gives them.
3. Name the weakest hop: the one a single fix would cut (pin an action ref, lower an org's default permission), and check it with what_if.
4. Before you give the conclusion, call check_answerable with question_kind paths and subject {{.From}}. If it says partial, say the answer is a lower bound and name the missing facts; if it says no, ask for the missing access instead of concluding.

Finish with the path as one line per hop, then the fix that cuts it.
