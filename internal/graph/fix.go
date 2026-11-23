package graph

import (
	"sort"
	"strings"
)

// Fix is a hypothetical remediation. Each Fix is one grouped change (a set of
// edges) with cost 1. Implementations: PinRef, LowerDefaultPerm, RestrictToken,
// HardenTrigger.
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
}

func (fs *fixSet) removesPush(e Edge) bool {
	switch e.Attrs[AttrVia] {
	case ViaDefaultPerm:
		return fs.lowered[OrgOf(e.From)] && KindFromID(e.From) == KindOrgMembers
	case ViaTokenWrite:
		return fs.restricted[e.From]
	}
	return false
}

func (fs *fixSet) removesTrigger(e Edge) bool { return fs.hardened[e.To] }

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

// PrincipalDelta is one principal's score before and after the fixes.
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
	before := ix.allScores(ix.base)
	after := ix.allScores(ix.buildControl(fixes))
	d := Delta{Before: totalsOf(before), After: totalsOf(after), Caveats: fixCaveats(ix, fixes)}
	for _, f := range fixes {
		d.Fixes = append(d.Fixes, f.ID())
	}
	for i := range before {
		d.PerPrincipal = append(d.PerPrincipal, PrincipalDelta{Principal: before[i].Principal, Before: before[i], After: after[i]})
	}
	return d
}

// FixSuggestion is one pick of SuggestFixes. Removed is the marginal number of
// confirmed (principal, repo) pairs, summed over ScoringPrincipals, that this fix
// removes on top of earlier picks.
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
// HardenTrigger for each workflow with a CAN_TRIGGER edge into it. A
// candidate whose changed edges are all not_visible (or that changes nothing) is
// dropped: gop does not recommend a fix for an edge it cannot confirm exists.
func (ix *Index) Candidates() []Fix {
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
			if Verified(e.Evidence) {
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
			if ix.actionMutable(e.From) && !ix.lockedNoBypass(e) {
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
		}
	}
	for _, n := range ix.g.Nodes {
		if n.Kind == KindOrg && (n.Attrs[AttrDefaultPerm] == "write" || n.Attrs[AttrDefaultPerm] == "admin") {
			push(LowerDefaultPerm{Org: n.ID, To: "read"})
		}
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

// SuggestFixes on a prebuilt index.
func (ix *Index) SuggestFixes(budget int) []FixSuggestion {
	pairs := func(fixes []Fix) int {
		cg := ix.control(fixes)
		n := 0
		for _, p := range ix.ScoringPrincipals() {
			n += len(ix.reach(cg, p).Confirmed.Repos)
		}
		return n
	}
	baseline := pairs(nil)
	cands := ix.Candidates()
	var (
		picked []Fix
		out    []FixSuggestion
	)
	current := baseline
	used := map[string]bool{}
	for len(out) < budget && current > 0 {
		bestIdx, bestAfter := -1, current
		for i, c := range cands {
			if used[c.ID()] {
				continue
			}
			after := pairs(append(append([]Fix{}, picked...), c))
			if after < bestAfter {
				bestIdx, bestAfter = i, after
			}
		}
		if bestIdx < 0 {
			break
		}
		f := cands[bestIdx]
		used[f.ID()] = true
		picked = append(picked, f)
		var es []string
		for _, e := range f.edges(ix) {
			es = append(es, strings.Join([]string{e.From, string(e.Kind), e.To}, " "))
		}
		removedTotal := baseline - bestAfter
		out = append(out, FixSuggestion{
			Fix: f, FixID: f.ID(), Edges: es,
			Removed: current - bestAfter, CumulativeRemoved: removedTotal, Remaining: bestAfter,
			CumulativePct: 100 * float64(removedTotal) / float64(baseline),
			Caveat:        fixCaveat(ix, f),
		})
		current = bestAfter
	}
	return out
}

// TotalsOf sums a set of scores (see Totals).
func TotalsOf(scores []Score) Totals { return totalsOf(scores) }

// Scores returns the blast radius of every scoring principal (ScoringPrincipals),
// sorted by principal ID: the set TopPaths, WhatIf and Totals use.
func (ix *Index) Scores() []Score { return ix.allScores(ix.base) }

// FixEdges returns the evidence edges a fix changes: the RESOLVES_TO edge of a
// PinRef's action, the via=default_perm CAN_PUSH edges a LowerDefaultPerm
// removes, the via=token_write CAN_PUSH edges a RestrictToken removes, or the
// CAN_TRIGGER edges a HardenTrigger removes.
func FixEdges(ix *Index, f Fix) []Edge { return f.edges(ix) }

// MutableRef reports whether an action ref can change without a new pin: its
// ref_kind is branch or tag, or it is unknown and the ref does not look like a
// commit SHA. It is the test Candidates uses for PinRef.
func (ix *Index) MutableRef(action string) bool { return ix.actionMutable(action) }
