package graph

import (
	"encoding/json"
	"fmt"
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
// group sits where its first member was. Two principals group only when
// their Scores are equal in every field but Principal (so every column of
// the row is true for every member) and their confirmed reach is the same
// set of node IDs (see GroupKey). Equal counts over different targets never
// group, and neither does a population (an org's members, external).
func (ix *Index) GroupRisks(ranked []Score) []RiskGroup {
	// Bucket by the score without its principal; only buckets with two or
	// more members need a reach walk.
	skey := make([]string, len(ranked))
	bucket := map[string][]int{}
	for i, s := range ranked {
		skey[i] = scoreKey(s)
		bucket[skey[i]] = append(bucket[skey[i]], i)
	}
	sig := make([]string, len(ranked))
	for _, idx := range bucket {
		if len(idx) < 2 {
			continue
		}
		for _, i := range idx {
			sig[i] = ix.confirmedSig(ranked[i].Principal)
		}
	}
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

// confirmedSig is a principal's GroupKey.
func (ix *Index) confirmedSig(principal string) string {
	return ix.GroupKey(ix.reach(ix.base, principal))
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
	c := r.Confirmed
	var ids []string
	for _, l := range [][]string{c.Repos, c.Orgs, c.Workflows, c.Actions, c.Secrets, c.OIDC, c.Runners, c.CloudTargets} {
		ids = append(ids, l...)
	}
	if len(ids) == 0 {
		return ""
	}
	sort.Strings(ids)
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
