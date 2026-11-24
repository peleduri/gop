package collect

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Stop causes: a run that ends with one of these (or with its context
// cancelled) writes a partial graph instead of none (partial.go).
var (
	// ErrMaxRequests: the run sent Config.MaxRequests requests.
	ErrMaxRequests = errors.New("request budget (--max-requests) spent")
	// ErrReserve: the next request would dip into Config.Reserve and the
	// collector cannot wait for the rate limit to reset.
	ErrReserve = errors.New("rate limit reserve (--reserve) reached and the reset time is unknown or too far")
	// ErrRateLimited: GitHub's rate limit ran out and its reset is further
	// away than the client waits.
	ErrRateLimited = errors.New("rate limit exhausted")
)

// maxReserveWait is the longest wait for a rate-limit reset that keeps
// Config.Reserve unspent. GitHub's budgets reset hourly, so a longer wait
// means a wrong clock or a wrong header: the run stops partial instead.
const maxReserveWait = time.Hour + time.Minute

// requestBudget enforces Config.MaxRequests and Config.Reserve on every
// request a Client sends, and stops the run (stop, a context cancel with a
// cause) when the budget or the rate limit runs out. Client copies share it.
type requestBudget struct {
	max     int // 0: unlimited
	reserve int // 0: none
	stop    func(error)

	mu   sync.Mutex
	sent int
}

// Sent returns how many requests went out through the budget.
func (b *requestBudget) Sent() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}

// halt stops the run with cause and returns cause, for the caller to return.
func (b *requestBudget) halt(cause error) error {
	if b != nil && b.stop != nil {
		b.stop(cause)
	}
	return cause
}

// withBudget returns a copy of c whose requests go through b.
func (c *Client) withBudget(b *requestBudget) *Client {
	cp := *c
	cp.budget = b
	return &cp
}

// beforeSend runs before every HTTP attempt that leaves the process (not
// before a response the cache serves without a request). It refuses the
// attempt once MaxRequests went out, and waits for the rate limit to reset
// when the last remaining count seen would dip below Reserve. The lock is
// held while waiting, so every request waits for the same reset.
func (c *Client) beforeSend(ctx context.Context, graphql bool) error {
	b := c.budget
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.max > 0 && b.sent >= b.max {
		return b.halt(ErrMaxRequests)
	}
	if b.reserve > 0 {
		if err := c.keepReserve(ctx, b, graphql); err != nil {
			return err
		}
	}
	b.sent++
	return nil
}

// keepReserve waits for the rate limit to reset when the remaining count is
// at or below the reserve, and counts the request about to go out against
// the remaining count, so the estimate stays conservative until the next
// response reports the real value.
func (c *Client) keepReserve(ctx context.Context, b *requestBudget, graphql bool) error {
	if c.rate == nil {
		return nil
	}
	c.rate.mu.Lock()
	rem, reset := c.rate.s.RESTRemaining, c.rate.s.RESTReset
	if graphql {
		rem, reset = c.rate.s.GraphQLRemaining, c.rate.s.GraphQLReset
	}
	c.rate.mu.Unlock()
	if rem >= 0 && rem <= b.reserve {
		wait := reset.Sub(c.now()) + time.Second
		dl, hasDL := ctx.Deadline()
		switch {
		case reset.IsZero(), wait > maxReserveWait, hasDL && dl.Before(c.now().Add(wait)):
			return b.halt(fmt.Errorf("%w (%d left, reserve %d)", ErrReserve, rem, b.reserve))
		case wait > 0:
			api := "rest"
			if graphql {
				api = "graphql"
			}
			c.logf("collect: %s: %d requests left, keeping %d in reserve: waiting %s for the reset at %s",
				api, rem, b.reserve, wait.Round(time.Second), reset.UTC().Format(time.RFC3339))
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
		}
		// The budget has reset; the next response reports the new count.
		rem = -1
	}
	c.rate.mu.Lock()
	defer c.rate.mu.Unlock()
	switch {
	case rem < 0 && graphql:
		c.rate.s.GraphQLRemaining = -1
	case rem < 0:
		c.rate.s.RESTRemaining = -1
	case graphql:
		c.rate.s.GraphQLRemaining = rem - 1
	default:
		c.rate.s.RESTRemaining = rem - 1
	}
	return nil
}

// partialReason maps the error a stopped run ended with (and its context's
// cause) to a graph.PartialReason value, or "" when the run did not stop
// for a reason that writes a partial graph.
func partialReason(ctx context.Context, err error) string {
	cause := context.Cause(ctx)
	for _, e := range []error{err, cause} {
		switch {
		case e == nil:
		case errors.Is(e, ErrMaxRequests):
			return graph.PartialMaxRequests
		case errors.Is(e, ErrReserve):
			return graph.PartialReserve
		case errors.Is(e, ErrRateLimited):
			return graph.PartialRateLimit
		}
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return graph.PartialInterrupted
	}
	return ""
}

// PartialError is returned by Collect, together with the partial graph,
// when the run stopped before the end. Callers that only check the error
// keep treating the run as failed; callers that want the partial graph write
// it.
type PartialError struct {
	// Reason is a graph.PartialReason value.
	Reason string
	// Err is what stopped the run.
	Err error
}

func (e *PartialError) Error() string {
	return "collection stopped early (" + e.Reason + "): " + e.Err.Error()
}

func (e *PartialError) Unwrap() error { return e.Err }
