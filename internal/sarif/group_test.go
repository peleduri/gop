package sarif

import (
	"fmt"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// A result's message folds principals with identical confirmed reach into
// the group's name; principals with equal counts over different repos stay
// apart.
func TestWhoPhraseFoldsIdenticalReach(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/owners/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	ix := graph.NewIndex(g)
	en := &engine{ix: ix, reach: map[string]graph.Result{}, princs: ix.Principals()}
	ps := []string{"identity:alice", "identity:bob", "identity:carol"}
	for i := 1; i <= 14; i++ {
		ps = append(ps, fmt.Sprintf("identity:owner%02d", i))
	}
	if got, want := en.whoPhrase(ps, 3), "identity:alice, identity:bob, identity:carol and 1 more"; got != want {
		t.Errorf("whoPhrase = %q, want %q", got, want)
	}
	if got, want := en.whoPhrase(ps[2:], 3), "identity:carol, the 14 owners of acme-security"; got != want {
		t.Errorf("whoPhrase = %q, want %q", got, want)
	}
	// A group that fits in max names is listed by name.
	if got := en.whoPhrase(ps[3:6], 3); got != "identity:owner01, identity:owner02, identity:owner03" {
		t.Errorf("whoPhrase = %q", got)
	}
}
