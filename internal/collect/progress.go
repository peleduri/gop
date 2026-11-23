package collect

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Progress phases, in the order a run goes through them.
const (
	PhaseOrgs      = "orgs"
	PhaseSettings  = "settings"
	PhaseMembers   = "members"
	PhaseRepos     = "repos"
	PhaseWorkflows = "workflows"
	PhaseNested    = "nested"
)

// progressInterval is the shortest gap between two default progress lines.
const progressInterval = 5 * time.Second

// Progress is one progress update of a collection run. Done never decreases
// within a phase. Total is the number of units known so far (for nested, it
// grows as new references are found). A remaining count of -1 means no
// response has reported it yet.
type Progress struct {
	Phase            string
	Done, Total      int
	RESTRemaining    int
	GraphQLRemaining int
	// ResetAt is when the REST budget resets (zero when unknown).
	ResetAt time.Time
	// Cache holds the response cache counts; nil when the cache is off.
	Cache *CacheStats
}

// phaseUnits names what a phase counts, for the default progress line.
var phaseUnits = map[string]string{
	PhaseOrgs:      "orgs",
	PhaseSettings:  "steps",
	PhaseMembers:   "steps",
	PhaseRepos:     "orgs",
	PhaseWorkflows: "repos",
	PhaseNested:    "refs",
}

// String renders p as one log line, for example
// "workflows 1200/3000 repos | graphql 4100 left | rest 4870 left, resets 14:05Z".
func (p Progress) String() string {
	var b strings.Builder
	b.WriteString(p.Phase + " " + strconv.Itoa(p.Done) + "/" + strconv.Itoa(p.Total))
	if u := phaseUnits[p.Phase]; u != "" {
		b.WriteString(" " + u)
	}
	if p.GraphQLRemaining >= 0 {
		b.WriteString(" | graphql " + strconv.Itoa(p.GraphQLRemaining) + " left")
	}
	if p.RESTRemaining >= 0 {
		b.WriteString(" | rest " + strconv.Itoa(p.RESTRemaining) + " left")
		if !p.ResetAt.IsZero() {
			b.WriteString(", resets " + p.ResetAt.UTC().Format("15:04") + "Z")
		}
	}
	if p.Cache != nil {
		b.WriteString(" | cache " + strconv.Itoa(p.Cache.Hits) + " hits, " + strconv.Itoa(p.Cache.Fetched) + " fetched")
		if p.Cache.Resumed > 0 {
			b.WriteString(", " + strconv.Itoa(p.Cache.Resumed) + " resumed")
		}
	}
	return b.String()
}

// progressFunc returns cfg.Progress, else a throttled logger on cfg.Logf
// (stderr in the CLI), else nil.
func progressFunc(cfg Config) func(Progress) {
	if cfg.Progress != nil {
		return cfg.Progress
	}
	if cfg.Logf == nil {
		return nil
	}
	return newProgressLogger(cfg.Logf, time.Now)
}

// newProgressLogger logs at most one progress line every progressInterval.
func newProgressLogger(logf func(string, ...any), now func() time.Time) func(Progress) {
	var (
		mu   sync.Mutex
		last time.Time
	)
	return func(p Progress) {
		mu.Lock()
		defer mu.Unlock()
		t := now()
		if !last.IsZero() && t.Sub(last) < progressInterval {
			return
		}
		last = t
		logf("collect: %s", p.String())
	}
}

// progress reports one update with the client's last seen rate budget.
func (k *collector) progress(phase string, done, total int) {
	if k.progressFn == nil {
		return
	}
	rs := k.c.RateState()
	p := Progress{
		Phase: phase, Done: done, Total: total,
		RESTRemaining: rs.RESTRemaining, GraphQLRemaining: rs.GraphQLRemaining, ResetAt: rs.RESTReset,
	}
	if k.c.cache != nil {
		st := k.c.cache.Stats()
		p.Cache = &st
	}
	k.progressFn(p)
}
