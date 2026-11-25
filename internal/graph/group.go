package graph

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// RiskGroup is one row of a ranked risk list: the principals whose confirmed
// reach is the same set of nodes (not just equal counts) and whose scores are
// equal. Grouping is presentation only: it never changes a score, a count or
// the rank order (see RanksAbove via TopPaths); a group takes the rank of its
// best-ranked member.
//
// The embedded Score is the first member's, so a one-member group marshals
// exactly like a Score. Members is set only for a group of two or more and
// lists every member in rank order, the first one included.
type RiskGroup struct {
	GroupScore
	Members []string `json:"members,omitempty"`
	// Via is the provenance every member shares, when there is one:
	// org_owner (every member owns the same orgs) or team (every member is
	// in the same team, or is that team). "" when the members share none.
	Via string `json:"via,omitempty"`
	// ViaScope names what Via is shared through: the org IDs for org_owner,
	// the team ID for team.
	ViaScope []string `json:"via_scope,omitempty"`

	// Cause is set on a cause group: principals whose reach is not the same
	// set but comes mostly (CauseShare) through one cause and overlaps by
	// Jaccard CauseJaccard or more. org_owner (each member owns orgs),
	// team (through one team, CauseScope) or org_members (as members of one
	// org, CauseScope). "" for an exact group or a single principal.
	Cause      string   `json:"cause,omitempty"`
	CauseScope []string `json:"cause_scope,omitempty"`
	// Range is the spread of the members' own figures; MemberScores lists
	// each member's own score in rank order. Both only on a cause group.
	Range        *GroupRange `json:"range,omitempty"`
	MemberScores []Score     `json:"member_scores,omitempty"`
}

// Cause group kinds (RiskGroup.Cause).
const (
	CauseOrgOwner   = ViaOrgOwner
	CauseTeam       = ViaTeam
	CauseOrgMembers = "org_members"
)

// Cause grouping thresholds: at least 90% of a member's confirmed repos come
// through the cause, and its confirmed reach overlaps the group's first
// member's by Jaccard 0.9 or more. Integer tenths, so the test is exact.
const (
	CauseShareTenths   = 9
	CauseJaccardTenths = 9
)

// GroupRange is the spread of a cause group's members' own figures.
type GroupRange struct {
	Repos MinMax `json:"repos"`
	Orgs  MinMax `json:"orgs"`
	// OwnedOrgs is how many orgs each member owns (org_owner only).
	OwnedOrgs *MinMax `json:"owned_orgs,omitempty"`
}

// MinMax is a closed range of counts.
type MinMax struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

func (m *MinMax) add(n int, first bool) {
	if first || n < m.Min {
		m.Min = n
	}
	if first || n > m.Max {
		m.Max = n
	}
}

// GroupScore is Score under a name that does not shadow Score.Score when
// embedded, so RiskGroup marshals (and its JSON schema reads) every Score
// field flat, including score.
type GroupScore = Score

// Size is the number of principals in the group (1 for a single principal).
func (g RiskGroup) Size() int {
	if len(g.Members) == 0 {
		return 1
	}
	return len(g.Members)
}

// MemberIDs lists the group's principals in rank order.
func (g RiskGroup) MemberIDs() []string {
	if len(g.Members) == 0 {
		return []string{g.Principal}
	}
	return g.Members
}

// TopGroups ranks every scoring principal with TopPaths, groups identical
// reach with GroupRisks and returns the first n groups (all when n <= 0).
// n counts groups, not principals.
func (ix *Index) TopGroups(n int) []RiskGroup {
	out := ix.GroupRisks(ix.TopPaths(0))
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out
}

// GroupRisks folds a ranked score list into groups, keeping the order: a
// group sits where its first member was. It applies two tiers.
//
// Exact groups (GroupRisksExact) first: two principals group only when their
// Scores are equal in every field but Principal (so every column of the row
// is true for every member) and their confirmed reach is the same set of
// node IDs (see GroupKey).
//
// Then cause groups: a later row joins an earlier one when both first
// members' confirmed repos come at least 90% through the same cause (org
// ownership, one team, or membership of one org; see causeOf) and their
// confirmed reach overlaps by Jaccard 0.9 or more. A direct collaborator
// grant is never a shared cause. The row keeps its first member's score;
// Range and MemberScores carry each member's own figures.
//
// Equal counts over different targets never group, and neither does a
// population (an org's members, external). Scores, counts and the rank
// order of principals are unchanged: grouping is presentation only.
func (ix *Index) GroupRisks(ranked []Score) []RiskGroup {
	return ix.groupCauses(ranked, ix.GroupRisksExact(ranked))
}

// GroupRisksExact is GroupRisks with exact groups only.
func (ix *Index) GroupRisksExact(ranked []Score) []RiskGroup {
	// Bucket by the score without its principal; only buckets with two or
	// more members need a reach walk.
	skey := make([]string, len(ranked))
	bucket := map[string][]int{}
	for i, s := range ranked {
		skey[i] = scoreKey(s)
		bucket[skey[i]] = append(bucket[skey[i]], i)
	}
	sig := make([]string, len(ranked))
	var need []int
	for _, idx := range bucket {
		if len(idx) >= 2 {
			need = append(need, idx...)
		}
	}
	parallelFor(len(need), workers(), func(_, k int) {
		i := need[k]
		sig[i] = ix.confirmedSig(ranked[i].Principal)
	})
	type key struct{ score, sig string }
	at := map[key]int{}
	var out []RiskGroup
	for i, s := range ranked {
		gk := key{skey[i], sig[i]}
		if j, ok := at[gk]; ok && sig[i] != "" {
			if out[j].Members == nil {
				out[j].Members = []string{out[j].Principal}
			}
			out[j].Members = append(out[j].Members, s.Principal)
			continue
		}
		at[gk] = len(out)
		out = append(out, RiskGroup{GroupScore: s})
	}
	for i := range out {
		if len(out[i].Members) > 1 {
			out[i].Via, out[i].ViaScope = ix.SharedVia(out[i].Members)
		}
	}
	return out
}

// scoreKey is every Score field but Principal, as one comparable string.
func scoreKey(s Score) string {
	s.Principal = ""
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Sprintf("%#v", s) // unreachable: Score is plain data
	}
	return string(b)
}

// confirmedSig stands for a principal's GroupKey: a SHA-256 digest of it
// (the same targets give the same digest), "" when the key is "". The
// digest is streamed from the sorted targets, so the long key string is
// never built: GroupRisksExact holds one per principal it compares.
func (ix *Index) confirmedSig(principal string) string {
	r := ix.reach(ix.base, principal)
	if k := ix.Kind(r.From); k == KindOrgMembers || k == KindExternal {
		return ""
	}
	ids := confirmedTargets(r)
	if len(ids) == 0 {
		return ""
	}
	h := sha256.New()
	for i, id := range ids {
		if i > 0 {
			_, _ = io.WriteString(h, "\n")
		}
		_, _ = io.WriteString(h, id)
	}
	return string(h.Sum(nil))
}

// confirmedTargets lists the targets ConfirmedKey joins, sorted. The strings
// are the result's own, so the list costs only its slice.
func confirmedTargets(r Result) []string {
	c := r.Confirmed
	n := 0
	lists := [][]string{c.Repos, c.Orgs, c.Workflows, c.Actions, c.Secrets, c.OIDC, c.Runners, c.CloudTargets}
	for _, l := range lists {
		n += len(l)
	}
	ids := make([]string, 0, n)
	for _, l := range lists {
		ids = append(ids, l...)
	}
	sort.Strings(ids)
	return ids
}

// GroupKey is the key principals with identical reach share: the result's
// ConfirmedKey, or "" (never grouped) when the principal is a population
// (an org's members, or anyone on the internet). A population row already
// stands for many people under its own name, which says more than "2
// principals with identical reach" would.
func (ix *Index) GroupKey(r Result) string {
	if k := ix.Kind(r.From); k == KindOrgMembers || k == KindExternal {
		return ""
	}
	return r.ConfirmedKey()
}

// ConfirmedKey is the confirmed reach as one string: every reached target
// (repos, orgs, workflows, actions, secrets, OIDC trusts, runners and cloud
// roles) through a fully verified path, sorted. Principals a path passes
// through (a team, an org's members) are not targets, so a team and its
// members can share a key. Two results reach the same targets exactly when
// their keys are equal. "" when nothing is confirmed, which never groups
// (such rows have nothing in common to say).
func (r Result) ConfirmedKey() string {
	ids := confirmedTargets(r)
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, "\n")
}

// SharedVia finds the provenance every member shares: org_owner when each
// member is an org owner (via=org_owner CAN_PUSH edges) of the same orgs,
// else team when each member is MEMBER_OF one team or is that team. Org
// ownership wins: it is the broader grant.
func (ix *Index) SharedVia(members []string) (string, []string) {
	var owned []string
	for i, m := range members {
		set := map[string]bool{}
		for _, e := range ix.out[m] {
			if e.Kind == CanPush && e.Attrs[AttrVia] == ViaOrgOwner {
				if o := OrgOf(e.To); o != "" {
					set[o] = true
				}
			}
		}
		orgs := sortedKeys(set)
		if len(orgs) == 0 || (i > 0 && strings.Join(orgs, ",") != strings.Join(owned, ",")) {
			owned = nil
			break
		}
		owned = orgs
	}
	if len(owned) > 0 {
		return ViaOrgOwner, owned
	}
	var common map[string]bool
	for _, m := range members {
		teams := map[string]bool{}
		if strings.HasPrefix(m, "team:") {
			teams[m] = true
		}
		for _, e := range ix.out[m] {
			if e.Kind == MemberOf && strings.HasPrefix(e.To, "team:") {
				teams[e.To] = true
			}
		}
		if common == nil {
			common = teams
			continue
		}
		for t := range common {
			if !teams[t] {
				delete(common, t)
			}
		}
	}
	if ts := sortedKeys(common); len(ts) > 0 {
		return ViaTeam, ts[:1]
	}
	return "", nil
}

// causeRow is what cause grouping knows about a row's first member.
type causeRow struct {
	cause string   // causeOf key, "" when the row has no single cause
	ids   []string // confirmed targets, sorted
}

// groupCauses merges exact-group rows into cause groups (see GroupRisks).
func (ix *Index) groupCauses(ranked []Score, rows []RiskGroup) []RiskGroup {
	info := make([]causeRow, len(rows))
	parallelFor(len(rows), workers(), func(_, i int) {
		g := rows[i]
		if g.Confirmed.Repos == 0 || !ix.mayHaveCause(g.Principal) {
			return
		}
		r := ix.reach(ix.base, g.Principal)
		if k := ix.Kind(r.From); k == KindOrgMembers || k == KindExternal {
			return // GroupKey "": never grouped
		}
		ids := confirmedTargets(r)
		if len(ids) == 0 {
			return
		}
		if c := ix.causeOf(g.Principal, r); c != "" {
			info[i] = causeRow{cause: c, ids: ids}
		}
	})
	byCause := map[string][]int{}
	for i := range rows {
		if c := info[i].cause; c != "" {
			byCause[c] = append(byCause[c], i)
		}
	}
	if len(byCause) == 0 {
		return rows
	}
	into := make([]int, len(rows)) // row index absorbed into, -1 when kept
	for i := range into {
		into[i] = -1
	}
	merged := map[int][]int{}
	for _, idx := range byCause {
		for a, i := range idx {
			if into[i] >= 0 {
				continue
			}
			for _, j := range idx[a+1:] {
				if into[j] >= 0 || !jaccardAtLeast(info[i].ids, info[j].ids, CauseJaccardTenths) {
					continue
				}
				into[j] = i
				merged[i] = append(merged[i], j)
			}
		}
	}
	if len(merged) == 0 {
		return rows
	}
	byP := make(map[string]Score, len(ranked))
	for _, s := range ranked {
		byP[s.Principal] = s
	}
	out := make([]RiskGroup, 0, len(rows))
	for i, g := range rows {
		if into[i] >= 0 {
			continue
		}
		js, ok := merged[i]
		if !ok {
			out = append(out, g)
			continue
		}
		members := append([]string{}, g.MemberIDs()...)
		for _, j := range js {
			members = append(members, rows[j].MemberIDs()...)
		}
		g.Members = members
		g.Via, g.ViaScope = ix.SharedVia(members)
		key := info[i].cause
		switch {
		case key == CauseOrgOwner:
			g.Cause, g.CauseScope = CauseOrgOwner, nil
		case strings.HasPrefix(key, "members:"):
			g.Cause, g.CauseScope = CauseOrgMembers, []string{key}
		default:
			g.Cause, g.CauseScope = CauseTeam, []string{key}
		}
		rg := &GroupRange{}
		if g.Cause == CauseOrgOwner {
			rg.OwnedOrgs = &MinMax{}
		}
		for k, m := range members {
			s := byP[m]
			g.MemberScores = append(g.MemberScores, s)
			rg.Repos.add(s.Confirmed.Repos, k == 0)
			rg.Orgs.add(s.Confirmed.Orgs, k == 0)
			if rg.OwnedOrgs != nil {
				rg.OwnedOrgs.add(len(ix.OwnedOrgs(m)), k == 0)
			}
		}
		g.Range = rg
		out = append(out, g)
	}
	return out
}

// mayHaveCause is a cheap filter before causeOf: the principal owns an org,
// is in a team or an org, or is a team.
func (ix *Index) mayHaveCause(p string) bool {
	if k := ix.Kind(p); k == KindOrgMembers || k == KindExternal {
		return false
	}
	if strings.HasPrefix(p, "team:") {
		return true
	}
	for _, e := range ix.out[p] {
		if e.Kind == MemberOf || (e.Kind == CanPush && e.Attrs[AttrVia] == ViaOrgOwner) {
			return true
		}
	}
	return false
}

// causeOf is the cause behind a principal's confirmed repos, read from the
// first hop of each confirmed path: org_owner when the hop is a push the
// principal holds as an org owner, the team ID when it goes into a team (or
// the principal is that team), members:X when it goes in as a member of org
// X. It returns the cause of at least 90% of the confirmed repos, else "".
func (ix *Index) causeOf(p string, r Result) string {
	repos := r.Confirmed.Repos
	if len(repos) == 0 {
		return ""
	}
	owned := map[string]bool{}
	for _, e := range ix.out[p] {
		if e.Kind == CanPush && e.Attrs[AttrVia] == ViaOrgOwner && ix.EdgeVerified(e) {
			owned[e.To] = true
		}
	}
	count := map[string]int{}
	for _, id := range repos {
		hops := r.Paths[id].Hops
		if len(hops) == 0 {
			continue
		}
		h := hops[0]
		key := ""
		switch {
		case h.Kind == CanPush && owned[h.To]:
			key = CauseOrgOwner
		case h.Kind == CanPush && strings.HasPrefix(p, "team:"):
			key = p
		case h.Kind == MemberOf && strings.HasPrefix(h.To, "team:"):
			key = h.To
		case h.Kind == MemberOf && ix.Kind(h.To) == KindOrgMembers:
			key = h.To
		}
		if key != "" {
			count[key]++
		}
	}
	best, n := "", 0
	for k, c := range count {
		if c > n || (c == n && k < best) {
			best, n = k, c
		}
	}
	if n*10 >= CauseShareTenths*len(repos) {
		return best
	}
	return ""
}

// jaccardAtLeast reports whether |a ∩ b| / |a ∪ b| >= tenths/10 for two
// sorted sets.
func jaccardAtLeast(a, b []string, tenths int) bool {
	small, big := min(len(a), len(b)), max(len(a), len(b))
	if big == 0 || small*10 < tenths*big {
		return false // |a ∩ b| <= small and |a ∪ b| >= big
	}
	inter, i, j := 0, 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			inter++
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	union := len(a) + len(b) - inter
	return inter*10 >= tenths*union
}
