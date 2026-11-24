package advisory

import (
	"strconv"
	"strings"
)

// version is a parsed action tag such as v44, v1.2 or 2.0.1-rc.1: up to four
// numeric components and an optional pre-release. parts is how many
// components the tag names; v44 (parts 1) stands for every 44.x.y.
type version struct {
	nums  [4]int
	parts int
	pre   string
}

// parseVersion reads a tag or an OSV version. A leading v is optional. It
// fails on anything that is not dotted numbers (a branch name, a SHA).
func parseVersion(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "v"), "V")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata does not order
	}
	core, pre, _ := strings.Cut(s, "-")
	if core == "" {
		return version{}, false
	}
	var v version
	for _, p := range strings.Split(core, ".") {
		if v.parts == len(v.nums) || p == "" {
			return version{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, false
		}
		v.nums[v.parts] = n
		v.parts++
	}
	v.pre = pre
	return v, true
}

// cmp orders two versions: numeric components (missing ones are 0), then a
// release after any of its pre-releases, then pre-releases by text.
func (v version) cmp(o version) int {
	for i := range v.nums {
		if v.nums[i] != o.nums[i] {
			if v.nums[i] < o.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.pre == o.pre:
		return 0
	case v.pre == "":
		return 1
	case o.pre == "":
		return -1
	case v.pre < o.pre:
		return -1
	}
	return 1
}

// next is the first version after every version a partial tag stands for:
// 45 for v44, 44.3 for v44.2. A full tag (parts >= 3) stands for itself and
// has no next.
func (v version) next() (version, bool) {
	if v.parts >= 3 || v.pre != "" {
		return version{}, false
	}
	n := version{parts: v.parts}
	copy(n.nums[:v.parts], v.nums[:v.parts])
	n.nums[v.parts-1]++
	return n, true
}

// interval is one affected span of an OSV range: [lo, hi) or [lo, hi] when
// hiIncl (last_affected), unbounded above when !hasHi. fixed is the version
// that closes it, when a fixed event does.
type interval struct {
	lo     version
	hasHi  bool
	hi     version
	hiIncl bool
	fixed  string
}

func (iv interval) contains(v version) bool {
	if v.cmp(iv.lo) < 0 {
		return false
	}
	if !iv.hasHi {
		return true
	}
	c := v.cmp(iv.hi)
	return c < 0 || (c == 0 && iv.hiIncl)
}

// covers reports whether every version in [lo, hi) is inside iv.
func (iv interval) covers(lo, hi version) bool {
	if lo.cmp(iv.lo) < 0 {
		return false
	}
	return !iv.hasHi || hi.cmp(iv.hi) <= 0
}

// misses reports whether no version in [lo, hi) is inside iv.
func (iv interval) misses(lo, hi version) bool {
	if hi.cmp(iv.lo) <= 0 {
		return true
	}
	if !iv.hasHi {
		return false
	}
	c := iv.hi.cmp(lo)
	return c < 0 || (c == 0 && !iv.hiIncl)
}

// intervals turns the events of an ECOSYSTEM or SEMVER range into affected
// spans, following the OSV evaluation order: events sorted by version, an
// introduced event opens a span, fixed or limit closes it before the
// version, last_affected closes it after. ok is false when an event version
// does not parse: the range cannot be evaluated.
func intervals(events []Event) (out []interval, ok bool) {
	type ev struct {
		kind string
		raw  string
		v    version
		zero bool
	}
	var evs []ev
	for _, e := range events {
		var x ev
		switch {
		case e.Introduced != "":
			x = ev{kind: "introduced", raw: e.Introduced}
		case e.Fixed != "":
			x = ev{kind: "fixed", raw: e.Fixed}
		case e.LastAffected != "":
			x = ev{kind: "last_affected", raw: e.LastAffected}
		case e.Limit != "":
			x = ev{kind: "limit", raw: e.Limit}
		default:
			continue
		}
		if x.raw == "0" && x.kind == "introduced" {
			x.zero = true
		} else {
			v, good := parseVersion(x.raw)
			if !good {
				return nil, false
			}
			x.v = v
		}
		evs = append(evs, x)
	}
	less := func(a, b ev) bool {
		if a.zero != b.zero {
			return a.zero
		}
		return a.v.cmp(b.v) < 0
	}
	// Insertion sort: ranges have a handful of events.
	for i := 1; i < len(evs); i++ {
		for j := i; j > 0 && less(evs[j], evs[j-1]); j-- {
			evs[j], evs[j-1] = evs[j-1], evs[j]
		}
	}
	var open *interval
	for _, e := range evs {
		switch e.kind {
		case "introduced":
			if open == nil {
				open = &interval{lo: e.v}
			}
		case "fixed", "limit", "last_affected":
			if open == nil {
				continue
			}
			open.hasHi, open.hi = true, e.v
			open.hiIncl = e.kind == "last_affected"
			if e.kind == "fixed" {
				open.fixed = e.raw
			}
			out = append(out, *open)
			open = nil
		}
	}
	if open != nil {
		out = append(out, *open)
	}
	return out, true
}
