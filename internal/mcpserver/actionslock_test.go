package mcpserver

import (
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

func TestSummaryActionPins(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/actionslock/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	s := NewEngine(g).Summary(time.Now())
	want := graph.PinStats{InWorkflow: 1, ByLock: 2, Stale: 1, Unpinned: 1, Locks: 2}
	if s.ActionPins == nil || *s.ActionPins != want {
		t.Errorf("action_pins = %+v, want %+v", s.ActionPins, want)
	}
	acme, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if s := NewEngine(acme).Summary(time.Now()); s.ActionPins != nil {
		t.Errorf("action_pins without a lockfile: %+v", s.ActionPins)
	}
	if f := factOfName("actions_lock:acme-actions/deploy@main", "workflow:x"); f != factActions {
		t.Errorf("stale lock coverage classified as %q", f)
	}
}
