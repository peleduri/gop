package graph

import "strings"

// HasAdvisory reports whether an action_ref node carries a known-compromise
// or vulnerability advisory (attr advisories, see docs/advisories.md).
func HasAdvisory(n Node) bool {
	return n.Kind == KindActionRef && n.Attrs[AttrAdvisories] != ""
}

// AdvisoryIDs splits a node's advisories attr.
func AdvisoryIDs(n Node) []string {
	if n.Attrs[AttrAdvisories] == "" {
		return nil
	}
	return strings.Split(n.Attrs[AttrAdvisories], ",")
}

// AdvisoryActions lists the action_ref nodes with an advisory on the ref
// (HasAdvisory) or on a commit an actions.lock pins it to (LockAffected
// uses), sorted by ID.
func (ix *Index) AdvisoryActions() []string {
	set := map[string]bool{}
	for id, n := range ix.nodes {
		if HasAdvisory(n) {
			set[id] = true
		}
	}
	for _, e := range ix.g.Edges {
		if LockAffected(e) && ix.Kind(e.To) == KindActionRef {
			set[e.To] = true
		}
	}
	return sortedKeys(set)
}

// advisoriesOn lists the actions with an advisory that a confirmed path of r
// runs through: an intermediate hop, so the compromised action leads on to
// something it controls (a workflow that runs it). Sorted; nil when none.
func (ix *Index) advisoriesOn(r Result) []string {
	if !ix.hasAdvisories() {
		return nil
	}
	set := map[string]bool{}
	for _, p := range r.Paths {
		if p.Unverified {
			continue
		}
		for _, h := range p.Hops[:max(len(p.Hops)-1, 0)] {
			if HasAdvisory(ix.nodes[h.To]) {
				set[h.To] = true
			}
		}
	}
	return sortedKeys(set)
}

// hasAdvisories reports whether any node carries an advisory (cached).
func (ix *Index) hasAdvisories() bool {
	ix.advOnce.Do(func() {
		for _, n := range ix.nodes {
			if HasAdvisory(n) {
				ix.advAny = true
				return
			}
		}
	})
	return ix.advAny
}

// advisoryScores scores every action with an advisory as if it were a
// principal: whoever holds the compromised version controls every workflow
// that runs it, so its reach is what the advisory exposes. Actions with no
// confirmed reach are left out. These entries join TopPaths only; they are
// not ScoringPrincipals, so WhatIf, SuggestFixes and pair totals are
// unchanged.
//
// The reach of an affected ref is the action's own. An actions.lock that
// pins an affected commit adds only the workflows of those uses: lines
// (each with what it reaches): a use the lock does not cover runs the ref,
// which the advisory does not name.
func (ix *Index) advisoryScores(cg *controlGraph) []Score {
	var out []Score
	for _, a := range ix.AdvisoryActions() {
		r := Result{From: a, Paths: map[string]Path{}}
		if HasAdvisory(ix.nodes[a]) {
			r = ix.reach(cg, a)
		}
		for _, e := range ix.LockAffectedUses(a) {
			var w Result
			w.Paths = map[string]Path{}
			if Verified(e.Evidence) {
				w.Confirmed.Workflows = []string{e.From}
			} else {
				w.Possible.Workflows = []string{e.From}
			}
			mergeResult(&r, w)
			wr := ix.reach(cg, e.From)
			if !Verified(e.Evidence) {
				wr.Possible = mergeReached(wr.Confirmed, wr.Possible)
				wr.Confirmed = Reached{}
			}
			mergeResult(&r, wr)
		}
		s := ix.scoreOf(a, r)
		if s.Score == 0 {
			continue
		}
		if len(s.Advisories) == 0 || s.Advisories[0] != a {
			s.Advisories = append([]string{a}, s.Advisories...)
		}
		out = append(out, s)
	}
	return out
}

// rankAdvisory is the TopPaths rank factor for known compromises: an entry
// with confirmed reach through an action that has an advisory ranks above
// every entry without one, whatever their scores.
func rankAdvisory(s Score) int {
	if len(s.Advisories) > 0 && s.Score > 0 {
		return 1
	}
	return 0
}

// mergeResult adds b's reach to a: confirmed stays confirmed, and possible
// keeps only what neither side confirms. Paths already in a are kept.
func mergeResult(a *Result, b Result) {
	a.Confirmed = mergeReached(a.Confirmed, b.Confirmed)
	a.Possible = mergeReached(a.Possible, b.Possible)
	a.Possible = minusReached(a.Possible, a.Confirmed)
	if a.Paths == nil {
		a.Paths = map[string]Path{}
	}
	for id, p := range b.Paths {
		if _, ok := a.Paths[id]; !ok {
			a.Paths[id] = p
		}
	}
}

func reachedFields(r *Reached) []*[]string {
	return []*[]string{&r.Repos, &r.Workflows, &r.Actions, &r.Secrets, &r.OIDC, &r.Runners, &r.Orgs, &r.CloudTargets}
}

// mergeReached is the sorted union of a and b, list by list.
func mergeReached(a, b Reached) Reached {
	var out Reached
	la, lb, lo := reachedFields(&a), reachedFields(&b), reachedFields(&out)
	for i := range lo {
		set := map[string]bool{}
		for _, id := range *la[i] {
			set[id] = true
		}
		for _, id := range *lb[i] {
			set[id] = true
		}
		if len(set) > 0 {
			*lo[i] = sortedKeys(set)
		}
	}
	return out
}

// minusReached drops from a every ID that b lists.
func minusReached(a, b Reached) Reached {
	var out Reached
	la, lb, lo := reachedFields(&a), reachedFields(&b), reachedFields(&out)
	for i := range lo {
		drop := map[string]bool{}
		for _, id := range *lb[i] {
			drop[id] = true
		}
		for _, id := range *la[i] {
			if !drop[id] {
				*lo[i] = append(*lo[i], id)
			}
		}
	}
	return out
}
