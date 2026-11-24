package graph

import (
	"strings"
	"testing"
)

// testdata/actionslock/graph.json: members:acme-actions can push to the
// action repos. acme-app/web's ci.yml uses deploy@main and lint@v2, both
// pinned by web's actions.lock; its release.yml uses deploy@<sha>, whose
// nested setup@main only the lock pins. acme-app/api has no lockfile.
// acme-app/docs has a stale lock entry for deploy@main.
const lockGraph = "../../testdata/actionslock/graph.json"

func lockIndex(t *testing.T) *Index {
	t.Helper()
	g, err := LoadFile(lockGraph)
	if err != nil {
		t.Fatal(err)
	}
	return NewIndex(g)
}

func TestActionsLockReach(t *testing.T) {
	ix := lockIndex(t)
	r := ix.Reach("members:acme-actions", Options{})
	for target, want := range map[string]bool{
		"secret:acme-app/api":  true,  // no lockfile
		"secret:acme-app/docs": true,  // stale lock: counts as unpinned
		"secret:acme-app/web":  false, // deploy@main and lint@v2 locked
		"oidc:acme-app/web":    false, // deploy@sha, nested setup@main pinned only by the lock
		"action:acme-actions/deploy@0123456789abcdef0123456789abcdef01234567": true, // the node itself is still controllable
	} {
		if _, got := r.Paths[target]; got != want {
			t.Errorf("%s reached = %v, want %v", target, got, want)
		}
	}
}

func TestActionsLockPinStats(t *testing.T) {
	got := lockIndex(t).PinStats()
	want := PinStats{InWorkflow: 1, ByLock: 2, Stale: 1, Unpinned: 1, Locks: 2}
	if got != want || !got.HasLock() {
		t.Errorf("PinStats = %+v, want %+v", got, want)
	}
	if (PinStats{InWorkflow: 3, Unpinned: 2}).HasLock() {
		t.Error("HasLock without any lock fact")
	}
}

func TestActionsLockCoveredAndFixes(t *testing.T) {
	ix := lockIndex(t)
	for a, want := range map[string]bool{
		"action:acme-actions/lint@v2":                                         true,
		"action:acme-actions/deploy@main":                                     false, // api and docs still use it unpinned
		"action:acme-actions/setup@main":                                      false, // used by actions, never locked edges
		"action:acme-actions/deploy@0123456789abcdef0123456789abcdef01234567": true,
		"action:acme-actions/nothing@v1":                                      false,
	} {
		if got := ix.LockCovered(a); got != want {
			t.Errorf("LockCovered(%s) = %v, want %v", a, got, want)
		}
	}
	for _, f := range ix.Candidates() {
		if p, ok := f.(PinRef); ok && p.Action == "action:acme-actions/lint@v2" {
			t.Error("pin of an action every use of which actions.lock pins is a candidate")
		}
	}
	for _, s := range ix.SuggestFixes(10) {
		if strings.Contains(s.FixID, "lint@v2") {
			t.Errorf("suggested %s", s.FixID)
		}
	}
	// deploy@sha runs the mutable setup@main, but its only consumer is
	// locked: not a pinned exposure.
	for _, pe := range ix.PinnedExposures() {
		if strings.Contains(pe.Action, "deploy@0123") {
			t.Errorf("pinned exposure %+v", pe)
		}
	}
}
