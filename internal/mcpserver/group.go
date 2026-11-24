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

// GroupReachSentence is ReachSentence with the group as the subject; a group
// lists its first members in parentheses.
func GroupReachSentence(ix *graph.Index, g graph.RiskGroup) string {
	if g.Size() == 1 {
		return ReachSentence(g.GroupScore)
	}
	s := g.GroupScore
	s.Principal = fmt.Sprintf("%s (%s)", GroupWho(ix, g), MembersText(g.Members, MaxGroupMembersText))
	return ReachSentence(s)
}
