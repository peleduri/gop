package mcpserver

import (
	"fmt"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// MaxGroupMembersText is how many members a group's text lists before
// "and N more"; JSON always lists every member.
const MaxGroupMembersText = 3

// orgNames turns org IDs into a phrase: "acme" or "acme, acme-app".
func orgNames(ids []string) string {
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = strings.TrimPrefix(id, "org:")
	}
	return strings.Join(names, ", ")
}

// GroupWho is the subject a sentence about the group starts with: the
// principal's Display for a single principal, else "the 14 owners of
// acme-security", "the 3 members of team acme/sec" or "4 principals with
// identical reach". It never names one member picked by tie-break.
func GroupWho(ix *graph.Index, g graph.RiskGroup) string {
	n := g.Size()
	if n == 1 {
		return Display(ix, g.Principal)
	}
	if who := causeWho(g); who != "" {
		return who
	}
	switch g.Via {
	case graph.ViaOrgOwner:
		return fmt.Sprintf("the %d owners of %s", n, orgNames(g.ViaScope))
	case graph.ViaTeam:
		return fmt.Sprintf("the %d principals of %s", n, g.ViaScope[0])
	}
	return fmt.Sprintf("%d principals with identical reach", n)
}

// GroupKind is the short label for a group's row: "14 principals (org owners
// of acme-security)", "3 principals (team:acme/sec)" or "4 principals
// (identical reach)". "" for a single principal.
func GroupKind(g graph.RiskGroup) string {
	n := g.Size()
	if n == 1 {
		return ""
	}
	if k := causeKind(g); k != "" {
		return k
	}
	switch g.Via {
	case graph.ViaOrgOwner:
		return fmt.Sprintf("%d principals (org owners of %s)", n, orgNames(g.ViaScope))
	case graph.ViaTeam:
		return fmt.Sprintf("%d principals (%s)", n, g.ViaScope[0])
	}
	return fmt.Sprintf("%d principals (identical reach)", n)
}

// MembersText lists the first max members, then "and N more".
func MembersText(members []string, max int) string {
	if max <= 0 || len(members) <= max {
		return strings.Join(members, ", ")
	}
	return strings.Join(members[:max], ", ") + fmt.Sprintf(" and %d more", len(members)-max)
}

// Num formats a count with thousands separators: 1009 -> "1,009".
func Num(n int) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return "-" + Num(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// RangeText is "1,009 to 1,079", or one number when the range is a point.
func RangeText(m graph.MinMax) string {
	if m.Min == m.Max {
		return Num(m.Min)
	}
	return Num(m.Min) + " to " + Num(m.Max)
}

// RangePlural is RangeText with a unit: "18 to 20 orgs", "1 org".
func RangePlural(m graph.MinMax, one, many string) string {
	if m.Min == m.Max && m.Min == 1 {
		return "1 " + one
	}
	return RangeText(m) + " " + many
}

// causeWho is the subject for a cause group: "4 accounts that own 18 or more
// orgs", "5 principals that reach mostly through team:acme/sec" or "6
// members of acme-app". "" when g is not a cause group.
func causeWho(g graph.RiskGroup) string {
	n := g.Size()
	switch g.Cause {
	case graph.CauseOrgOwner:
		if r := g.Range; r != nil && r.OwnedOrgs != nil {
			if r.OwnedOrgs.Min == r.OwnedOrgs.Max {
				return fmt.Sprintf("%d accounts that each own %s", n, RangePlural(*r.OwnedOrgs, "org", "orgs"))
			}
			return fmt.Sprintf("%d accounts that own %s or more orgs", n, Num(r.OwnedOrgs.Min))
		}
		return fmt.Sprintf("%d org owners", n)
	case graph.CauseTeam:
		return fmt.Sprintf("%d principals that reach mostly through %s", n, g.CauseScope[0])
	case graph.CauseOrgMembers:
		return fmt.Sprintf("%d members of %s", n, strings.TrimPrefix(g.CauseScope[0], "members:"))
	}
	return ""
}

// causeKind is the row label for a cause group: "4 owners of 18 to 20
// orgs", "5 principals (mostly through team:acme/sec)" or "6 principals
// (mostly as members of acme-app)". "" when g is not a cause group.
func causeKind(g graph.RiskGroup) string {
	n := g.Size()
	switch g.Cause {
	case graph.CauseOrgOwner:
		if r := g.Range; r != nil && r.OwnedOrgs != nil {
			return fmt.Sprintf("%d owners of %s", n, RangePlural(*r.OwnedOrgs, "org", "orgs"))
		}
		return fmt.Sprintf("%d org owners", n)
	case graph.CauseTeam:
		return fmt.Sprintf("%d principals (mostly through %s)", n, g.CauseScope[0])
	case graph.CauseOrgMembers:
		return fmt.Sprintf("%d principals (mostly as members of %s)", n, strings.TrimPrefix(g.CauseScope[0], "members:"))
	}
	return ""
}

// GroupReachSentence is ReachSentence with the group as the subject; a group
// lists its first members in parentheses. A cause group states the range of
// its members' reach: each member's own figures differ.
func GroupReachSentence(ix *graph.Index, g graph.RiskGroup) string {
	if g.Size() == 1 {
		return ReachSentence(g.GroupScore)
	}
	if g.Cause != "" && g.Range != nil {
		who := fmt.Sprintf("%s (%s)", GroupWho(ix, g), MembersText(g.Members, MaxGroupMembersText))
		out := fmt.Sprintf("%s can each control %s across %s (confirmed); ranked by its first member, %s",
			q(who), RangePlural(g.Range.Repos, "repo", "repos"), RangePlural(g.Range.Orgs, "org", "orgs"), ReachSentence(g.GroupScore))
		return out
	}
	s := g.GroupScore
	s.Principal = fmt.Sprintf("%s (%s)", GroupWho(ix, g), MembersText(g.Members, MaxGroupMembersText))
	return ReachSentence(s)
}
