package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/sanitize"
)

// The HTML report embeds the data its filters and per-org views need as one
// JSON block. The static sections never depend on it: with JavaScript off
// the report reads the same, only without filtering.

// maxPathsPerOrg caps the embedded paths that end in one org. Large graphs
// keep the best-ranked paths per target org and the report says so.
const maxPathsPerOrg = 500

// dataVersion is the shape of the embedded JSON, for anyone parsing it.
const dataVersion = 1

type embedded struct {
	V          int           `json:"v"`
	Orgs       []embOrg      `json:"orgs"`
	Principals []embPrinc    `json:"principals"`
	Paths      []embPath     `json:"paths"`
	Fixes      []embFix      `json:"fixes"`
	Coverage   []embCoverage `json:"coverage"`
	// Truncated lists target orgs whose paths were cut to MaxPerOrg.
	Truncated []embTrunc `json:"truncated"`
	MaxPerOrg int        `json:"max_per_org"`
	// Graph is the Graph tab's layout and what-if data over Paths.
	Graph embGraph `json:"graph"`
}

type embOrg struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Settings []embAttr `json:"settings"`
}

// embAttr is one org setting. Value is "unknown" whenever the setting was not
// visible or not collected; it is never turned into "off" or "none".
type embAttr struct {
	Key      string `json:"key"`
	Title    string `json:"title"`
	Value    string `json:"value"`
	Evidence string `json:"evidence"` // live | audit | not visible | not collected
	Known    bool   `json:"known"`
}

type embPrinc struct {
	ID       string       `json:"id"`
	Kind     string       `json:"kind"`
	Orgs     []string     `json:"orgs"`
	Score    float64      `json:"score"`
	Conf     graph.Counts `json:"confirmed"`
	Possible graph.Counts `json:"possible"`
}

type embPath struct {
	From     string   `json:"from"`
	FromOrgs []string `json:"from_orgs"`
	To       string   `json:"to"`
	ToKind   string   `json:"to_kind"` // repo | oidc | secret | runner | cloud
	ToOrg    string   `json:"to_org"`
	Ev       string   `json:"ev"` // confirmed | possible
	Refs     []string `json:"refs"`
	Hops     []embHop `json:"hops"`
	Note     string   `json:"note,omitempty"` // supplied trust file caveat (graph.Path.SuppliedNote)
}

type embHop struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Ev   string `json:"ev"` // live | inferred | audit | audit, stale | supplied file | not visible
	API  string `json:"api,omitempty"`
	Rev  bool   `json:"rev,omitempty"`
	Why  string `json:"why,omitempty"`  // why an undecided CAN_ASSUME match is possible only
	Note string `json:"note,omitempty"` // hardening context on a CAN_PUSH hop (graph.Index.HopNote)

	raw   graph.Evidence // the hop's own evidence, for the Graph tab's label
	stale bool           // an audit fact too old to confirm (graph.Hop.Stale)
}

type embFix struct {
	N       int      `json:"n"`
	ID      string   `json:"id"`
	Desc    string   `json:"desc"`
	Removed int      `json:"removed"`
	Pct     string   `json:"pct"`
	Orgs    []string `json:"orgs"`
}

type embCoverage struct {
	Scope    string `json:"scope"`
	Org      string `json:"org"`
	Fact     string `json:"fact"`
	Reason   string `json:"reason"`
	NeedsFix string `json:"needs_fix"`
}

type embTrunc struct {
	Org   string `json:"org"`
	Total int    `json:"total"`
}

// orgViewCols are the settings the per-org view lists, in order.
var orgViewCols = []struct{ Key, Title string }{
	{graph.AttrDefaultPerm, "Default permission"},
	{graph.AttrTwoFactor, "2FA"},
	{graph.AttrSSO, "SSO"},
	{graph.AttrIPAllowList, "IP allow list"},
	{graph.AttrMembersCreate, "Members can create repos"},
	{graph.AttrChangeVisiblity, "Members can change visibility"},
	{graph.AttrDeleteRepos, "Members can delete repos"},
	{graph.AttrPrivateForks, "Private forks allowed"},
	{graph.AttrMembers, "Members"},
}

func orgName(id string) string { return strings.TrimPrefix(id, "org:") }

// orgAttr is orgCell for the org view: an unseen setting reads "unknown" with
// its evidence, never a value.
func orgAttr(n graph.Node, key, title string) embAttr {
	ev := n.Evidence
	if e, ok := n.AttrEvidence[key]; ok {
		ev = e
	}
	a := embAttr{Key: key, Title: title, Value: "unknown", Evidence: mcpserver.EvidenceLabel(ev)}
	v, ok := n.Attrs[key]
	switch {
	case ev == graph.NotVisible || v == "unknown":
		a.Evidence = "not visible"
	case !ok || v == "":
		a.Evidence = "not collected"
	default:
		a.Value, a.Known = v, true
	}
	return a
}

// principalOrgs are the orgs a principal belongs to: X for members:X and
// team:X/slug, and every org or team org an identity is a member of.
func principalOrgs(ix *graph.Index, p string) []string {
	set := map[string]bool{}
	switch ix.Kind(p) {
	case graph.KindOrgMembers:
		set[orgName(graph.OrgOf(p))] = true
	default:
		if strings.HasPrefix(p, "team:") {
			set[orgName(graph.OrgOf(p))] = true
		}
		for _, e := range ix.Out(p) {
			if e.Kind != graph.MemberOf {
				continue
			}
			if o := graph.OrgOf(e.To); o != "" {
				set[orgName(o)] = true
			}
		}
	}
	return sortedSet(set)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var shaRef = regexp.MustCompile(`@[0-9a-f]{40}$`)

// refKind of an action_ref node: its ref_kind attr, else sha when the ref is
// 40 hex, else "" (unknown: not guessed).
func refKind(ix *graph.Index, id string) string {
	if n, ok := ix.Node(id); ok {
		switch k := n.Attrs[graph.AttrRefKind]; k {
		case "sha", "tag", "branch":
			return k
		}
	}
	if shaRef.MatchString(id) {
		return "sha"
	}
	return ""
}

// targetKind maps an embedded path end to its filter kind.
func targetKind(k graph.NodeKind) string {
	switch k {
	case graph.KindRepo:
		return "repo"
	case graph.KindOIDC:
		return "oidc"
	case graph.KindSecret:
		return "secret"
	case graph.KindRunner:
		return "runner"
	case graph.KindCloudTarget:
		return "cloud"
	}
	return ""
}

func termRank(kind string) int {
	switch kind {
	case "oidc", "cloud":
		return 0
	case "secret":
		return 1
	case "runner":
		return 2
	}
	return 3
}

func buildEmbedded(ix *graph.Index, g *graph.Graph, scores []graph.Score, fixes []graph.FixSuggestion, maxPerOrg int) embedded {
	e := embedded{V: dataVersion, MaxPerOrg: maxPerOrg,
		Orgs: []embOrg{}, Principals: []embPrinc{}, Paths: []embPath{}, Fixes: []embFix{},
		Coverage: []embCoverage{}, Truncated: []embTrunc{}}
	for _, n := range g.Nodes {
		if n.Kind != graph.KindOrg {
			continue
		}
		o := embOrg{ID: n.ID, Name: orgName(n.ID)}
		for _, c := range orgViewCols {
			o.Settings = append(o.Settings, orgAttr(n, c.Key, c.Title))
		}
		e.Orgs = append(e.Orgs, o)
	}
	sort.Slice(e.Orgs, func(i, j int) bool { return e.Orgs[i].Name < e.Orgs[j].Name })

	byOrg := map[string][]embPath{}
	for _, s := range scores {
		p := s.Principal
		porgs := principalOrgs(ix, p)
		e.Principals = append(e.Principals, embPrinc{ID: p, Kind: string(ix.Kind(p)), Orgs: porgs,
			Score: s.Score, Conf: s.Confirmed, Possible: s.Possible})
		r := ix.Reach(p, graph.Options{})
		for _, to := range sortedPathKeys(r.Paths) {
			tk := targetKind(ix.Kind(to))
			if tk == "" {
				continue
			}
			path := r.Paths[to]
			ep := embPath{From: p, FromOrgs: porgs, To: to, ToKind: tk, ToOrg: orgName(graph.OrgOf(to)),
				Ev: "confirmed", Refs: []string{}, Note: path.SuppliedNote()}
			if tk == "cloud" && len(path.Hops) > 0 {
				// A cloud role has no org: file it under the org of the workflow that assumes it.
				ep.ToOrg = orgName(graph.OrgOf(path.Hops[len(path.Hops)-1].From))
			}
			if path.Unverified {
				ep.Ev = "possible"
			}
			refs := map[string]bool{}
			for _, h := range ix.Annotate(path).Hops {
				ep.Hops = append(ep.Hops, embHop{From: h.From, To: h.To, Kind: string(h.Kind),
					Ev: mcpserver.HopEvidenceLabel(h), API: h.SourceAPI, Rev: h.Reverse, Why: h.Reason, Note: h.Note, raw: h.Evidence, stale: h.Stale})
				for _, id := range []string{h.From, h.To} {
					if ix.Kind(id) == graph.KindActionRef {
						refs[refKind(ix, id)] = true
					}
				}
			}
			ep.Refs = sortedSet(refs)
			byOrg[ep.ToOrg] = append(byOrg[ep.ToOrg], ep)
		}
	}
	orgKeys := make([]string, 0, len(byOrg))
	for k := range byOrg {
		orgKeys = append(orgKeys, k)
	}
	sort.Strings(orgKeys)
	for _, o := range orgKeys {
		ps := byOrg[o]
		if len(ps) > maxPerOrg {
			sort.SliceStable(ps, func(i, j int) bool {
				a, b := ps[i], ps[j]
				if a.Ev != b.Ev {
					return a.Ev == "confirmed"
				}
				if termRank(a.ToKind) != termRank(b.ToKind) {
					return termRank(a.ToKind) < termRank(b.ToKind)
				}
				return len(a.Hops) < len(b.Hops)
			})
			e.Truncated = append(e.Truncated, embTrunc{Org: o, Total: len(ps)})
			ps = ps[:maxPerOrg]
		}
		e.Paths = append(e.Paths, ps...)
	}
	sort.SliceStable(e.Paths, func(i, j int) bool {
		a, b := e.Paths[i], e.Paths[j]
		if a.Ev != b.Ev {
			return a.Ev == "confirmed"
		}
		if termRank(a.ToKind) != termRank(b.ToKind) {
			return termRank(a.ToKind) < termRank(b.ToKind)
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})

	for i, f := range fixes {
		_, desc := mcpserver.DescribeFix(f.Fix)
		e.Fixes = append(e.Fixes, embFix{N: i + 1, ID: f.FixID, Desc: desc, Removed: f.Removed,
			Pct: fmt.Sprintf("%.0f%%", f.CumulativePct), Orgs: fixOrgs(ix, f.Fix)})
	}
	for _, c := range g.Coverage {
		e.Coverage = append(e.Coverage, embCoverage{Scope: c.Scope, Org: orgName(graph.OrgOf(c.Scope)),
			Fact: c.Fact, Reason: c.Reason, NeedsFix: c.NeedsFix})
	}
	e.Graph = buildGraphView(ix, e.Paths, nil)
	return e
}

func sortedPathKeys(m map[string]graph.Path) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fixOrgs are the orgs a fix touches: the orgs of every evidence edge it
// changes, the org it reconfigures, and for a pin the orgs of the workflows
// that must change their uses: line.
func fixOrgs(ix *graph.Index, f graph.Fix) []string {
	set := map[string]bool{}
	for _, e := range graph.FixEdges(ix, f) {
		set[orgName(graph.OrgOf(e.From))] = true
		set[orgName(graph.OrgOf(e.To))] = true
	}
	switch v := f.(type) {
	case graph.LowerDefaultPerm:
		set[orgName(v.Org)] = true
	case graph.PinRef:
		set[orgName(graph.OrgOf(v.Action))] = true
		for _, e := range ix.In(v.Action) {
			if e.Kind == graph.Uses {
				set[orgName(graph.OrgOf(e.From))] = true
			}
		}
	}
	return sortedSet(set)
}

// marshalEmbedded encodes the data for a <script type="application/json">
// block. json.Marshal escapes <, > and & as < etc., so "</script>" or
// "<!--" in graph data can never end the block; the check below keeps that
// guarantee explicit.
func marshalEmbedded(e embedded) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	// Bidi, zero-width and C1 characters become \u escapes: the same values,
	// no raw invisible characters in the page source.
	s := string(sanitize.JSON(b))
	if strings.Contains(s, "</") || strings.Contains(s, "<!--") {
		return "", fmt.Errorf("report: embedded data is not script-safe")
	}
	return s, nil
}
