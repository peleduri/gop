package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// TestRenderActionsLock: the report splits pins by source, lists the stale
// lock entry in coverage, and neither suggests pinning lint@v2 (every use is
// locked) nor lists deploy@sha (its only consumer is locked) as a pinned
// exposure.
func TestRenderActionsLock(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/actionslock/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, g, "md")
	testutil.Golden(t, "actions_lock.md", []byte(out), "v0.0.0-test")
	want := "Action pins (workflow uses: lines): 1 pinned in the workflow file, 2 pinned by actions.lock (2 repos have a lockfile), 1 with a stale actions.lock entry (counted as unpinned, listed below), 1 unpinned."
	if !strings.Contains(out, md(want)) {
		t.Errorf("markdown lacks the pin line")
	}
	if !strings.Contains(out, "actions\\_lock:acme-actions/deploy@main") && !strings.Contains(out, "actions_lock:acme-actions/deploy@main") {
		t.Errorf("stale lock entry not in coverage")
	}
	for _, bad := range []string{"lint@v2 to a commit", "Pinned, still reachable"} {
		if strings.Contains(out, bad) {
			t.Errorf("markdown contains %q", bad)
		}
	}
	if html := render(t, g, "html"); !strings.Contains(html, "pinned by actions.lock (2 repos have a lockfile)") {
		t.Error("html lacks the pin line")
	}
	if strings.Contains(render(t, loadAcme(t), "md"), "Action pins") {
		t.Error("pin line shown for a graph without any actions.lock")
	}
}
