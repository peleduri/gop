package graph

import "sort"

// Fix is a hypothetical remediation. Each Fix is one grouped change (a set of
// edges) with cost 1. Implementations: PinRef, LowerDefaultPerm, RestrictToken,
// HardenTrigger, ReduceOwners.
type Fix interface {
	// ID is stable and unique, e.g. "pin:action:acme-actions/deploy@main".
	ID() string
	apply(*fixSet)
	// edges returns the evidence edges this fix changes.
	edges(ix *Index) []Edge
}

type fixSet struct {
	pinned     map[string]bool // action IDs treated as sha-pinned
	lowered    map[string]bool // org IDs whose default-perm CAN_PUSH edges are removed
	restricted map[string]bool // workflow IDs whose via=token_write CAN_PUSH edges are removed
	hardened   map[string]bool // workflow IDs whose incoming CAN_TRIGGER edges are removed
	unowned    map[string]bool // ownerKey(principal, org) pairs whose via=org_owner CAN_PUSH edges are removed
	botBlocked map[string]bool // repo IDs whose incoming CAN_MERGE_VIA_BOT edges are removed
}

func (fs *fixSet) removesPush(e Edge) bool {
	switch e.Attrs[AttrVia] {
	case ViaDefaultPerm:
		return fs.lowered[OrgOf(e.From)] && KindFromID(e.From) == KindOrgMembers
	case ViaTokenWrite:
		return fs.restricted[e.From]
	case ViaOrgOwner:
		return fs.unowned[ownerKey(e.From, OrgOf(e.To))]
	}
	return false
}

func (fs *fixSet) removesTrigger(e Edge) bool { return fs.hardened[e.To] }

func (fs *fixSet) removesBotMerge(e Edge) bool { return fs.botBlocked[e.To] }

func setFlag(m *map[string]bool, id string) {
	if *m == nil {
		*m = map[string]bool{}
	}
	(*m)[id] = true
}

// PinRef pins an action ref to a commit SHA: pushing to the action's host repo
// no longer changes it. Nested mutable USES under the action still apply.
type PinRef struct {
	Action string `json:"action"` // "action:O/R@ref"
}

func (f PinRef) ID() string { return "pin:" + f.Action }

func (f PinRef) apply(fs *fixSet) { setFlag(&fs.pinned, f.Action) }

func (f PinRef) edges(ix *Index) []Edge {
	var out []Edge
	for _, e := range ix.out[f.Action] {
		if e.Kind == ResolvesTo {
			out = append(out, e)
		}
	}
	return out
}

// LowerDefaultPerm lowers an org's base repository permission. When To is "read"
// or "none" it removes the members:X CAN_PUSH edges that came from the default
// permission (Attrs["via"] == "default_perm"). Owner, direct and outside
// collaborator grants (via org_owner, direct, outside_collaborator) are kept.
// Other values of To are a no-op.
type LowerDefaultPerm struct {
	Org string `json:"org"` // "org:X"
	To  string `json:"to"`  // read | none
}

func (f LowerDefaultPerm) ID() string { return "default_perm:" + f.Org + "->" + f.To }

func (f LowerDefaultPerm) lowers() bool { return f.To == "read" || f.To == "none" }

func (f LowerDefaultPerm) apply(fs *fixSet) {
	if !f.lowers() {
		return
	}
	setFlag(&fs.lowered, f.Org)
}

func (f LowerDefaultPerm) edges(ix *Index) []Edge {
	if !f.lowers() {
		return nil
	}
	var out []Edge
	members := ix.membersOf(f.Org)
	for _, e := range ix.out[members] {
		if e.Kind == CanPush && e.Attrs[AttrVia] == ViaDefaultPerm {
			out = append(out, e)
		}
	}
	return out
}

// RestrictToken sets permissions: contents: read on a workflow's GITHUB_TOKEN:
// it removes the workflow's via=token_write CAN_PUSH edges. Whoever controls
// the workflow keeps its secrets, OIDC and runners and its repo's CI, but can
// no longer push to the repo with the token.
type RestrictToken struct {
	Workflow string `json:"workflow"` // "workflow:O/R/.github/workflows/x.yml"
}

func (f RestrictToken) ID() string { return "restrict_token:" + f.Workflow }

func (f RestrictToken) apply(fs *fixSet) { setFlag(&fs.restricted, f.Workflow) }

func (f RestrictToken) edges(ix *Index) []Edge {
	var out []Edge
	for _, e := range ix.out[f.Workflow] {
		if e.Kind == CanPush && e.Attrs[AttrVia] == ViaTokenWrite {
			out = append(out, e)
		}
	}
	return out
}

// HardenTrigger stops a workflow from running attacker-controlled code on a
// risky trigger (drop the checkout of the pull request's head, or move
// attacker text out of the script into env:): it removes every CAN_TRIGGER
// edge into the workflow.
type HardenTrigger struct {
	Workflow string `json:"workflow"` // "workflow:O/R/.github/workflows/x.yml"
}

func (f HardenTrigger) ID() string { return "harden_trigger:" + f.Workflow }

func (f HardenTrigger) apply(fs *fixSet) { setFlag(&fs.hardened, f.Workflow) }

func (f HardenTrigger) edges(ix *Index) []Edge {
	var out []Edge
	for _, e := range ix.in[f.Workflow] {
		if e.Kind == CanTrigger {
			out = append(out, e)
		}
	}
	return out
}

// Totals sums scores across the scoring principals (see ScoringPrincipals).
// ConfirmedPairs is the number of (principal, repo) pairs with a fully verified
// path; PossiblePairs the pairs that exist only through a not_visible hop.
// Reach an identity holds only through an org_members population it belongs
// to (members:X, via its MEMBER_OF org edge) is counted once, on the
// population's row, not again for each member (see Index.pairReach); every
// count and score in Totals follows that rule. A member's own grants and
// teams still count for the member.
type Totals struct {
	Principals     int     `json:"principals"`
	Confirmed      Counts  `json:"confirmed"`
	Possible       Counts  `json:"possible"`
	ConfirmedPairs int     `json:"confirmed_pairs"`
	PossiblePairs  int     `json:"possible_pairs"`
	Score          float64 `json:"score"`
	PossibleScore  float64 `json:"possible_score"`
}

func totalsOf(scores []Score) Totals {
	t := Totals{Principals: len(scores)}
	for _, s := range scores {
		t.Confirmed.add(s.Confirmed)
		t.Possible.add(s.Possible)
		t.Score += s.Score
		t.PossibleScore += s.PossibleScore
	}
	t.ConfirmedPairs = t.Confirmed.Repos
	t.PossiblePairs = t.Possible.Repos
	return t
}

// PrincipalDelta is one principal's score before and after the fixes. The
// scores are the principal's full reach, including what it reaches through
// an org_members population, so PerPrincipal does not sum to the Totals.
type PrincipalDelta struct {
	Principal string `json:"principal"`
	Before    Score  `json:"before"`
	After     Score  `json:"after"`
}

// Delta is the result of WhatIf. PerPrincipal covers every scoring principal, sorted by ID.
type Delta struct {
	Fixes        []string         `json:"fixes"`
	Before       Totals           `json:"before"`
	After        Totals           `json:"after"`
	PerPrincipal []PrincipalDelta `json:"per_principal"`
	// Caveats name fixes whose effect may be smaller than computed because
	// part of what they change is not visible, as "<fix id>: <caveat>".
	Caveats []string `json:"caveats,omitempty"`
}

// WhatIf applies fixes hypothetically and compares blast radius before and after.
func WhatIf(g *Graph, fixes []Fix) Delta { return NewIndex(g).WhatIf(fixes) }

// WhatIf on a prebuilt index.
func (ix *Index) WhatIf(fixes []Fix) Delta {
	before, beforePairs := ix.scoresAndPairs(ix.base)
	after, afterPairs := ix.scoresAndPairs(ix.control(fixes, 0))
	d := Delta{Before: totalsOf(beforePairs), After: totalsOf(afterPairs), Caveats: fixCaveats(ix, fixes)}
	for _, f := range fixes {
		d.Fixes = append(d.Fixes, f.ID())
	}
	for i := range before {
		d.PerPrincipal = append(d.PerPrincipal, PrincipalDelta{Principal: before[i].Principal, Before: before[i], After: after[i]})
	}
	return d
}

// FixSuggestion is one pick of SuggestFixes. Removed is the marginal number of
// confirmed (principal, repo) pairs, summed over ScoringPrincipals as Totals
// counts them, that this fix removes on top of earlier picks.
type FixSuggestion struct {
	Fix               Fix      `json:"fix"`
	FixID             string   `json:"fix_id"`
	Edges             []string `json:"edges"` // "from KIND to" of the evidence edges it changes
	Removed           int      `json:"removed"`
	CumulativeRemoved int      `json:"cumulative_removed"`
	Remaining         int      `json:"remaining"`
	CumulativePct     float64  `json:"cumulative_pct"` // of the baseline confirmed pairs, 0..100
	// Caveat says what gop could not see that may make the fix less
	// effective than Removed suggests, e.g. unknown nested references.
	Caveat string `json:"caveat,omitempty"`
}

// Candidates returns every fix SuggestFixes considers, sorted by ID: a PinRef for
// each mutable (branch/tag/unknown) action ref (for a ref_protected=true or
// ref_immutable=true ref it only removes the remaining via=ref_bypass paths,
// which the greedy's marginal gain accounts for; with no such edge and known
// bypass actors there is no candidate), LowerDefaultPerm{To:"read"} for each
// org with default_perm write/admin or default-perm CAN_PUSH edges, a
// RestrictToken for each workflow with a via=token_write CAN_PUSH edge, and a
// HardenTrigger for each workflow with a CAN_TRIGGER edge into it, a
// BlockBotMerge for each repo with a CAN_MERGE_VIA_BOT edge into it, and one
// ReduceOwners at DefaultOwnerThreshold when it cuts an ownership. No PinRef
// is proposed for an action that every use of is pinned by an actions.lock
// (LockCovered). A
// candidate whose changed edges are all not_visible or stale audit facts (or
// that changes nothing) is dropped: gop does not recommend a fix for an edge
// it cannot confirm exists.
func (ix *Index) Candidates() []Fix { return ix.candidates(DefaultOwnerThreshold) }

// candidates is Candidates with ReduceOwners at ownerThreshold.
func (ix *Index) candidates(ownerThreshold int) []Fix {
	var cands []Fix
	seen := map[string]bool{}
	push := func(f Fix) {
		if seen[f.ID()] {
			return
		}
		seen[f.ID()] = true
		es := f.edges(ix)
		ok := false
		for _, e := range es {
			if ix.EdgeVerified(e) {
				ok = true
				break
			}
		}
		if ok {
			cands = append(cands, f)
		}
	}
	for _, e := range ix.g.Edges {
		switch e.Kind {
		case ResolvesTo:
			if ix.actionMutable(e.From) && !ix.lockedNoBypass(e) && !ix.LockCovered(e.From) {
				push(PinRef{Action: e.From})
			}
		case CanPush:
			switch e.Attrs[AttrVia] {
			case ViaDefaultPerm:
				if KindFromID(e.From) == KindOrgMembers {
					push(LowerDefaultPerm{Org: OrgOf(e.From), To: "read"})
				}
			case ViaTokenWrite:
				push(RestrictToken{Workflow: e.From})
			}
		case CanTrigger:
			push(HardenTrigger{Workflow: e.To})
		case CanMergeViaBot:
			push(BlockBotMerge{Repo: e.To})
		}
	}
	for _, n := range ix.g.Nodes {
		if n.Kind == KindOrg && (n.Attrs[AttrDefaultPerm] == "write" || n.Attrs[AttrDefaultPerm] == "admin") {
			push(LowerDefaultPerm{Org: n.ID, To: "read"})
		}
	}
	if ro := ix.ReduceOwners(ownerThreshold); len(ro.Cuts) > 0 {
		push(ro)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ID() < cands[j].ID() })
	return cands
}

// SuggestFixes is a budgeted greedy over grouped fixes, NOT an exact min-cut.
// Each round it evaluates every remaining candidate on top of the fixes already
// picked and takes the one with the largest marginal reduction in confirmed
// (principal, repo) pairs (ties broken by fix ID). It stops at the budget or when
// no candidate removes a confirmed pair. Possible (not_visible) reach is ignored
// when scoring, and fixes that touch only not_visible edges are never candidates.
func SuggestFixes(g *Graph, budget int) []FixSuggestion { return NewIndex(g).SuggestFixes(budget) }

// SuggestFixes on a prebuilt index. The control graph is built once and each
// candidate is scored as an overlay on it (see suggestFixes in suggest.go).
func (ix *Index) SuggestFixes(budget int) []FixSuggestion {
	return ix.suggestFixes(budget, ix.Candidates())
}

// SuggestFixesOwners is SuggestFixes with the ReduceOwners candidate at
// ownerThreshold (DefaultOwnerThreshold when <= 0) instead of the default.
func (ix *Index) SuggestFixesOwners(budget, ownerThreshold int) []FixSuggestion {
	if ownerThreshold <= 0 {
		ownerThreshold = DefaultOwnerThreshold
	}
	return ix.suggestFixes(budget, ix.candidates(ownerThreshold))
}

// Totals is the pair totals of the graph as collected (see Totals).
func (ix *Index) Totals() Totals {
	_, pairs := ix.scoresAndPairs(ix.base)
	return totalsOf(pairs)
}

// Scores returns the blast radius of every scoring principal (ScoringPrincipals),
// sorted by principal ID: the set TopPaths, WhatIf and Totals use.
func (ix *Index) Scores() []Score { return ix.allScores(ix.base) }

// ScoresAndTotals returns Scores and Totals from one traversal of the graph
// as collected: the same values as calling both, with each scoring
// principal walked once instead of twice.
func (ix *Index) ScoresAndTotals() ([]Score, Totals) {
	full, pairs := ix.scoresAndPairs(ix.base)
	return full, totalsOf(pairs)
}

// FixEdges returns the evidence edges a fix changes: the RESOLVES_TO edge of a
// PinRef's action, the via=default_perm CAN_PUSH edges a LowerDefaultPerm
// removes, the via=token_write CAN_PUSH edges a RestrictToken removes, the
// CAN_TRIGGER edges a HardenTrigger removes, or the via=org_owner CAN_PUSH
// edges a ReduceOwners removes.
func FixEdges(ix *Index, f Fix) []Edge { return f.edges(ix) }

// MutableRef reports whether an action ref can change without a new pin: its
// RefState is RefMutable or RefPossiblyMutable. A SHA pin, or a tag or branch
// that refLock locks with no bypass, is not mutable; a ref whose gate is not
// visible counts as mutable (see MutabilityNote for its label).
func (ix *Index) MutableRef(action string) bool {
	st := ix.RefState(action)
	return st == RefMutable || st == RefPossiblyMutable
}
