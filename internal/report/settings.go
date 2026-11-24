package report

import (
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// The Org settings section: one row per org with the settings gop already
// records. A setting gop could not see reads "unknown", linked to why (the
// coverage reason and the access that fixes it); it is never shown as off.

// settingCols are the Org settings columns, in order. The IP allow list cell
// also carries ip_allow_list_entries and ip_allow_list_apps when known.
var settingCols = []struct{ Key, Title string }{
	{graph.AttrSSO, "SSO"},
	{graph.AttrTwoFactor, "2FA"},
	{graph.AttrIPAllowList, "IP allow list"},
	{graph.AttrDefaultPerm, "Default permission"},
	{graph.AttrMembersCreate, "Members can create repos"},
	{graph.AttrChangeVisiblity, "Members can change visibility"},
	{graph.AttrDeleteRepos, "Members can delete repos"},
	{graph.AttrPrivateForks, "Members can fork private repos"},
	{graph.AttrMembers, "Members"},
}

// settingTitles are the column titles after Org.
func settingTitles() []string {
	out := make([]string, len(settingCols))
	for i, c := range settingCols {
		out[i] = c.Title
	}
	return out
}

// orgRow is one org's settings row.
type orgRow struct {
	Org   string
	Cells []cell
}

// cell is one setting. NV is true when the value is unknown; Ref is then the
// anchor of the org's "why unknown" entry.
type cell struct {
	Value string
	NV    bool
	Ref   string
}

// orgWhy explains an org's unknown settings, one item per reason.
type orgWhy struct {
	Org    string
	Anchor string
	Items  []whyItem
}

type whyItem struct {
	Settings string // comma list of column titles
	Reason   string
	Fix      string // "" when no coverage entry names one
}

// coverageFacts are the coverage facts that explain an attribute, besides
// the attribute's own name: the ip_allow_list entry covers its details.
var coverageFacts = map[string][]string{
	graph.AttrIPAllowEntries:     {graph.AttrIPAllowList},
	graph.AttrIPAllowListEntries: {graph.AttrIPAllowList},
	graph.AttrIPAllowListApps:    {graph.AttrIPAllowList},
}

// orgSettings builds the Org settings rows and the why-unknown entries,
// sorted by org name.
func orgSettings(g *graph.Graph) ([]orgRow, []orgWhy) {
	var rows []orgRow
	var whys []orgWhy
	for _, n := range g.Nodes {
		if n.Kind != graph.KindOrg {
			continue
		}
		name := n.Name
		if name == "" {
			name = n.ID
		}
		anchor := "why-" + anchorSafe(name)
		r := orgRow{Org: name}
		w := orgWhy{Org: name, Anchor: anchor}
		byReason := map[[2]string]int{}
		for _, col := range settingCols {
			v := graph.OrgSetting(n, col.Key)
			if v == graph.HardeningUnknown {
				r.Cells = append(r.Cells, cell{Value: graph.HardeningUnknown, NV: true, Ref: anchor})
				reason, fix := unknownReason(g, n, col.Key)
				k := [2]string{reason, fix}
				if i, ok := byReason[k]; ok {
					w.Items[i].Settings += ", " + col.Title
				} else {
					byReason[k] = len(w.Items)
					w.Items = append(w.Items, whyItem{Settings: col.Title, Reason: reason, Fix: fix})
				}
				continue
			}
			if col.Key == graph.AttrIPAllowList {
				v = ipCell(n, v)
			}
			r.Cells = append(r.Cells, cell{Value: v})
		}
		rows = append(rows, r)
		if len(w.Items) > 0 {
			whys = append(whys, w)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Org < rows[j].Org })
	sort.Slice(whys, func(i, j int) bool { return whys[i].Org < whys[j].Org })
	return rows, whys
}

// ipCell adds the known IP allow list details to its value: "on (4 active
// entries, installed apps on)".
func ipCell(n graph.Node, v string) string {
	var extra []string
	if e := graph.OrgSetting(n, graph.AttrIPAllowListEntries); e != graph.HardeningUnknown {
		if e == "1" {
			extra = append(extra, "1 active entry")
		} else {
			extra = append(extra, e+" active entries")
		}
	}
	if a := graph.OrgSetting(n, graph.AttrIPAllowListApps); a != graph.HardeningUnknown {
		extra = append(extra, "installed apps "+a)
	}
	if len(extra) == 0 {
		return v
	}
	return v + " (" + strings.Join(extra, ", ") + ")"
}

// unknownReason finds the coverage entry that explains why an org setting is
// unknown: one scoped to the org first, then one scoped to the enterprise.
func unknownReason(g *graph.Graph, n graph.Node, key string) (reason, fix string) {
	facts := append([]string{key}, coverageFacts[key]...)
	for _, scope := range []func(string) bool{
		func(s string) bool { return s == n.ID },
		func(s string) bool { return strings.HasPrefix(s, "enterprise:") },
	} {
		for _, f := range facts {
			for _, c := range g.Coverage {
				if c.Fact == f && scope(c.Scope) {
					return "not visible: " + c.Reason, c.NeedsFix
				}
			}
		}
	}
	ev := n.Evidence
	if e, ok := n.AttrEvidence[key]; ok {
		ev = e
	}
	if _, ok := n.Attrs[key]; ok || ev == graph.NotVisible {
		return "not visible to the token (no coverage entry names why)", ""
	}
	return "not collected in this graph", ""
}

// anchorSafe keeps an org name usable in an HTML id and URL fragment.
func anchorSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
