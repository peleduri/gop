package graph

import "sort"

// LockCovered reports whether every use of action is pinned by an
// actions.lock: it has at least one incoming USES edge and each carries
// actions_lock=locked. Pinning the action in workflow files then changes no
// reach, so suggest_fixes does not propose it and the report does not list it
// as a pinned exposure.
func (ix *Index) LockCovered(action string) bool {
	n := 0
	for _, e := range ix.in[action] {
		if e.Kind != Uses {
			continue
		}
		if e.Attrs[AttrActionsLock] != LockLocked {
			return false
		}
		n++
	}
	return n > 0
}

// LockAffected reports whether e is a USES edge an actions.lock pins to a
// commit that an advisory lists as affected (lock_advisories).
func LockAffected(e Edge) bool {
	return e.Kind == Uses && e.Attrs[AttrActionsLock] == LockLocked && e.Attrs[AttrLockAdvisories] != ""
}

// LockAffectedUses lists the USES edges into action that LockAffected,
// sorted by the using workflow.
func (ix *Index) LockAffectedUses(action string) []Edge {
	var out []Edge
	for _, e := range ix.in[action] {
		if LockAffected(e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out
}

// PinStats counts the USES edges from workflows (one per workflow and
// action ref) by how they are pinned.
type PinStats struct {
	// InWorkflow: the workflow's uses: names a full commit SHA.
	InWorkflow int `json:"pinned_in_workflow"`
	// ByLock: the ref is a tag or branch, and the repo's actions.lock pins it
	// (actions_lock=locked) to a commit no advisory lists as affected.
	ByLock int `json:"pinned_by_actions_lock"`
	// LockAffected: the repo's actions.lock pins the ref to a commit an
	// advisory lists as affected (lock_advisories). Not counted in ByLock.
	LockAffected int `json:"actions_lock_affected_commit"`
	// Stale: the repo has an actions.lock that does not pin this uses: as
	// written (actions_lock=stale). Not counted as pinned.
	Stale int `json:"stale_actions_lock"`
	// Unpinned: every other tag or branch ref.
	Unpinned int `json:"unpinned"`
	// Locks is the number of repos with actions_lock=true.
	Locks int `json:"repos_with_actions_lock"`
}

// HasLock reports whether the graph records any actions.lock fact.
func (s PinStats) HasLock() bool {
	return s.Locks > 0 || s.ByLock > 0 || s.LockAffected > 0 || s.Stale > 0
}

// PinStats counts how the graph's workflow uses: references are pinned:
// in the workflow file (a commit SHA), by an actions.lock, or not at all.
// A stale lockfile entry is counted on its own, never as pinned.
func (ix *Index) PinStats() PinStats {
	var s PinStats
	for _, n := range ix.g.Nodes {
		if n.Kind == KindRepo && n.Attrs[AttrActionsLock] == "true" {
			s.Locks++
		}
	}
	for _, e := range ix.g.Edges {
		if e.Kind != Uses || ix.Kind(e.From) != KindWorkflow {
			continue
		}
		switch {
		case !ix.edgeRefMutable(e):
			s.InWorkflow++
		case LockAffected(e):
			s.LockAffected++
		case e.Attrs[AttrActionsLock] == LockLocked:
			s.ByLock++
		case e.Attrs[AttrActionsLock] == LockStale:
			s.Stale++
		default:
			s.Unpinned++
		}
	}
	return s
}

// edgeRefMutable reports whether a USES edge's own ref is a tag or branch:
// its ref_kind attr, else the target node's ref (40 hex = sha).
func (ix *Index) edgeRefMutable(e Edge) bool {
	switch e.Attrs[AttrRefKind] {
	case "sha":
		return false
	case "tag", "branch":
		return true
	}
	if n, ok := ix.nodes[e.To]; ok {
		return !shaRe.MatchString(actionRef(n))
	}
	return true
}
