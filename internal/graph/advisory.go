package graph

import (
	"sort"
	"strings"
)

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

// AdvisoryActions lists the action_ref nodes with an advisory, sorted by ID.
func (ix *Index) AdvisoryActions() []string {
	var out []string
	for id, n := range ix.nodes {
		if HasAdvisory(n) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
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
func (ix *Index) advisoryScores(cg *controlGraph) []Score {
	var out []Score
	for _, a := range ix.AdvisoryActions() {
		s := ix.score(cg, a)
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
