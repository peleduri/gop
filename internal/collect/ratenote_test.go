package collect

import (
	"testing"
	"time"
)

// TestNoteGraphQLRateKeepsLowerCount: a query body's rateLimit never raises
// the remaining count the same response's headers reported, and never moves
// the reset later, so --reserve sees the conservative value.
func TestNoteGraphQLRateKeepsLowerCount(t *testing.T) {
	c := &Client{rate: newRateTracker()}
	early := time.Date(2030, 1, 1, 14, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)

	c.noteGraphQLRate(4900, late) // unknown before: taken as is
	if got := c.rate.s.GraphQLRemaining; got != 4900 {
		t.Fatalf("first note: remaining %d, want 4900", got)
	}
	c.rate.s.GraphQLRemaining, c.rate.s.GraphQLReset = 15, early // headers of the next response
	c.noteGraphQLRate(4900, late)                                // optimistic body
	if got := c.rate.s.GraphQLRemaining; got != 15 {
		t.Errorf("remaining %d after an optimistic body, want 15", got)
	}
	if got := c.rate.s.GraphQLReset; !got.Equal(early) {
		t.Errorf("reset %v after a later body reset, want %v", got, early)
	}
	c.noteGraphQLRate(10, early.Add(-time.Minute)) // lower body: taken
	if got := c.rate.s.GraphQLRemaining; got != 10 {
		t.Errorf("remaining %d after a lower body, want 10", got)
	}
}
