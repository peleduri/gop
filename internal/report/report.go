// Package report renders a gop graph as one self-contained HTML file or as
// Markdown. Headlines use confirmed reach only; a not_visible fact is always
// labeled "not visible", never shown as off or absent.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/sanitize"
)

// Options tune the report.
type Options struct {
	Format    string // "html" (default) or "md"
	Top       int    // principals in the risks table and paths section (default 10)
	FixBudget int    // suggested fixes (default 5)
	Version   string // gop version for the footer
	// OwnerThreshold is the reduce_owners candidate's threshold (0:
	// graph.DefaultOwnerThreshold).
	OwnerThreshold int
	// Changes is diff.Compare(previous, current) (gop report --previous):
	// the report opens with a "what changed" banner. Nil means no banner.
	Changes *diff.Report
	// Rows caps the long sections (AI agents in CI, pinned actions, repos
	// on the top paths): 0 is DefaultRows, negative lists every row. A
	// capped section keeps its best rows, says how many it left out, and
	// its counts stay exact.
	Rows int
}

// DefaultRows is how many rows each long section lists by default.
const DefaultRows = 25

// moreHint is how to list a capped section in full.
const moreHint = "gop report --rows 0 lists every one"

// moreLine is the note under a capped section: "40 more agent workflows
// are not listed here (the counts above include them): ...", "" when
// nothing was left out.
func moreLine(n int, one, many string) string {
	if n <= 0 {
		return ""
	}
	what, verb, them := many, "are", "them"
	if n == 1 {
		what, verb, them = one, "is", "it"
	}
	return fmt.Sprintf("%s more %s %s not listed here (the counts above include %s): %s.", mcpserver.Num(n), what, verb, them, moreHint)
}

// rowsCap returns how many rows to keep of n under limit (negative: all).
func rowsCap(n, limit int) int {
	if limit < 0 || n <= limit {
		return n
	}
	return limit
}

const maxPathsPerPrincipal = 3

// Render writes the report for g to w.
func Render(w io.Writer, g *graph.Graph, opts Options) error {
	if opts.Top <= 0 {
		opts.Top = 10
	}
	if opts.FixBudget <= 0 {
		opts.FixBudget = 5
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	d := build(g, opts)
	switch strings.ToLower(opts.Format) {
	case "", "html":
		if err := addEmbedded(&d, g); err != nil {
			return err
		}
		decorate(&d, g)
		// html/template escapes markup; sanitize.HTML also turns raw
		// control, bidi and zero-width characters from names into
		// character references.
		var page bytes.Buffer
		if err := pageTmpl.Execute(&page, d); err != nil {
			return err
		}
		_, err := w.Write(sanitize.HTML(page.Bytes()))
		return err
	case "md", "markdown":
		return writeMarkdown(w, d)
	}
	return fmt.Errorf("report: unknown format %q (want html or md)", opts.Format)
}

type data struct {
	Demo bool // synthetic graph from gop demo: the title says so
	// Partial is graph.PartialNote: set when the collection stopped early,
	// shown as a banner at the top.
	Partial     string
	Version     string
	Enterprise  string
	CollectedAt string
	Headline    string
	// NonHumanLine is the first line of the report: the non-human actors
	// and how many can merge to a default branch without a human.
	NonHumanLine string
	FixLine      string
	// HasCloud is true when the graph has CAN_ASSUME edges (gop enrich
	// --oidc-trust): the risks table gains a cloud roles column and the
	// notes explain supplied evidence.
	HasCloud bool
	Risks    []riskRow
	Fixes    []fixRow
	PinLine  string
	Pinned   []pinnedRow
	// PinnedMore counts the pinned actions left out by Options.Rows.
	PinnedMore int
	// Agents is the "AI agents in CI" section, AgentLine its summary;
	// empty when no workflow runs an agent. AgentsMore counts the rows
	// left out by Options.Rows (AgentLine counts them all).
	Agents     []agentRow
	AgentLine  string
	AgentsMore int
	// Funnel is the AI agents funnel under the headline, Stats the small
	// figures beside it (funnel.go).
	Funnel funnel
	Stats  []statWidget
	// AgentPaths is the "Agent paths" view, AgentPathsLine its lede.
	AgentPaths     []agentPath
	AgentPathsLine string
	// BotMerge is the "AI approve + self-merge" section, BotMergeLine its
	// lede; empty when no repo has a review bypass.
	BotMerge     []botMergeRow
	BotMergeLine string
	// LockLine counts workflow uses: lines pinned in the workflow file, by
	// an actions.lock, stale in one, and unpinned; set only when the graph
	// has an actions.lock fact.
	LockLine string
	Paths    []principalPaths
	Orgs     []orgRow
	OrgWhy   []orgWhy // why each unknown org setting is unknown
	// RepoHardening is the per-org repo hardening rollup; HardenRepos the
	// repos on the top paths with their protection state; HardenFixes the
	// advisory hardening suggestions. Context only: no score depends on them.
	RepoHardening []hardeningRow
	HardenRepos   []hardenRepoRow
	HardenFixes   []hardenFixRow
	// HardenReposMore counts the top-path repos left out by Options.Rows.
	HardenReposMore int
	// AgentsMoreLine, PinnedMoreLine and HardenReposMoreLine say how many
	// rows a capped section left out and how to list them; "" when none.
	AgentsMoreLine, PinnedMoreLine, HardenReposMoreLine string
	Coverage                                            []graph.Coverage
	Banner                                              *banner // set only with Options.Changes
	// Ownership is the org ownership concentration; nil when no account
	// owns an org in this graph.
	Ownership *ownership
	// Ranged is true when a risk row is a cause group with ranges.
	Ranged bool

	// HTML only: the data the filters and org views read, the org names
	// for the filter bar, and a note when embedded paths were cut.
	DataJSON  template.JS
	OrgNames  []string
	Truncated string

	// HTML view model (view.go): the verdict hero and coverage groups.
	Verdict, VerdictLabel, PickWho string
	KPIs                           []kpi
	CovGroups                      []covGroup

	ix     *graph.Index
	sugg   []graph.FixSuggestion
	budget int
	// ownerThreshold is Options.OwnerThreshold.
	ownerThreshold int
}

// whatIfFixes are the top suggested fixes the Graph tab can simulate: the
// report's own picks when the budget covers them, else a longer greedy run
// (its first picks are the same, the greedy is deterministic).
func (d *data) whatIfFixes() []graph.FixSuggestion {
	if len(d.sugg) >= graphWhatIfFixes || d.budget >= graphWhatIfFixes {
		return d.sugg
	}
	return d.ix.SuggestFixesOwners(graphWhatIfFixes, d.ownerThreshold)
}

// addEmbedded fills the HTML-only fields from the graph.
func addEmbedded(d *data, g *graph.Graph) error {
	e := buildEmbedded(d.ix, g, d.ix.Scores(), d.sugg, maxPathsPerOrg)
	e.Graph.WhatIf = whatIfPaths(d.ix, e.Paths, d.whatIfFixes())
	js, err := marshalEmbedded(e)
	if err != nil {
		return err
	}
	d.DataJSON = template.JS(js) // #nosec G203 -- json.Marshal output, checked script-safe by marshalEmbedded
	seen := map[string]bool{}
	for _, o := range d.Orgs {
		seen[o.Org] = true
	}
	for _, p := range e.Paths {
		seen[p.ToOrg] = true
		for _, o := range p.FromOrgs {
			seen[o] = true
		}
	}
	d.OrgNames = sortedSet(seen)
	if n := len(e.Truncated); n > 0 {
		parts := make([]string, 0, n)
		for _, t := range e.Truncated {
			parts = append(parts, fmt.Sprintf("%s (%s)", t.Org, mcpserver.Num(t.Total)))
		}
		d.Truncated = fmt.Sprintf("To keep this file small, the filters below hold the top %d paths per target org (%d of %s paths); %s cut: %s. The counts and rankings above cover every path; gop paths --from <principal> lists a principal's paths.",
			e.MaxPerOrg, len(e.Paths), mcpserver.Num(e.total), plural(n, "org was", "orgs were"), strings.Join(parts, ", "))
	}
	return nil
}

type riskRow struct {
	Principal string
	// Group is set for a row of two or more principals with identical
	// confirmed reach: "14 principals (org owners of acme)". Members lists
	// every member; MembersText is the truncated list the row shows.
	Group       string
	Members     []string
	MembersText string
	// ReposRange and OrgsRange are the spread of a cause group's members
	// ("1,009 to 1,079"); MemberRows each member's own figures. Set only on
	// a cause group (graph.RiskGroup.Cause).
	ReposRange, OrgsRange        string
	MemberRows                   []memberRow
	Repos, Orgs                  int
	Cloud                        int
	OIDC, Secrets, Runners       int
	PossibleRepos, PossibleOther int
	Score                        string
	// Advisory is set when the row ranks first for a known advisory: the
	// action's advisories, or the advisory actions its paths run through.
	Advisory string

	Rank int      // 1-based position
	Sev  string   // critical | high | medium | low from confirmed terminal impact; unknown for possible reach only
	Bar  []barSeg // the impact bar segments, cloud roles, OIDC, secrets, runners
	// Poutine counts the confirmed-reached workflows with an injection-class
	// poutine finding (Score.PoutineInjectable); 0 without a poutine import.
	Poutine int
	// Agent counts the AI agent workflows the principal can start without
	// push access while they hold write, secrets or OIDC (Score.AgentExposed).
	Agent int
	// BotMerge counts the repos the principal confirmed-lands code on with
	// no human review through a bot approve + merge (Score.BotSelfMerge).
	BotMerge int
}

// ownership is the org ownership concentration block: how many accounts own
// 1, 2-4, 5-9 and 10 or more orgs, and how much confirmed reach depends on
// standing ownership. Counts only: the members are in the JSON.
type ownership struct {
	Line    string
	Note    string
	Buckets []ownerBucket
	Tone    string // crit when an account owns 10 or more orgs, high for 5-9
}

type ownerBucket struct {
	Label    string
	Accounts int
	Width    string // bar width class, share of the largest bucket
	Tone     string // crit for 10+, high for 5-9
}

func ownershipView(o graph.OrgOwnership) *ownership {
	v := &ownership{
		Line: fmt.Sprintf("%.0f%% of confirmed reach depends on standing org ownership: removing every org owner grant would remove %s of %s confirmed (principal, repo) pairs.",
			o.OwnerPct, mcpserver.Num(o.OwnerPairs), mcpserver.Num(o.ConfirmedPairs)),
		Note: fmt.Sprintf("%s own at least one org. An org owner is admin on every repo of the org, so an account that owns many orgs can push code that runs across all of them. gop counts owners from org owner grants on repos: an org with no repos shows no owners. The gop://graph/summary resource lists the accounts in each bucket.",
			plural(o.Owners, "account", "accounts")),
	}
	most := 0
	for _, b := range o.Buckets {
		most = max(most, b.Accounts)
	}
	for _, b := range o.Buckets {
		ob := ownerBucket{Label: strings.Replace(b.Label, "-", "–", 1), Accounts: b.Accounts, Width: "w0"}
		if most > 0 {
			ob.Width = widthClass(float64(b.Accounts) / float64(most))
		}
		switch {
		case b.Min >= 10:
			ob.Tone = "crit"
		case b.Min >= graph.DefaultOwnerThreshold:
			ob.Tone = "high"
		}
		if b.Accounts > 0 && (v.Tone == "" || ob.Tone == "crit") && ob.Tone != "" {
			v.Tone = ob.Tone
		}
		v.Buckets = append(v.Buckets, ob)
	}
	return v
}

// memberRow is one member of a cause group with its own figures.
type memberRow struct {
	Principal          string
	Repos, Orgs, Owned int
	Score              string
}

type fixRow struct {
	N             int
	Description   string
	FixID         string
	Removed       int
	CumulativePct string

	// HTML only: this fix's share of the baseline confirmed pairs, the
	// width classes of the earlier fixes' and this fix's bar segments, the
	// one-line reason and the engine's caveat.
	Pct, PrevWidth, Width string
	Why, Caveat           string
}

// pinnedRow is a SHA-pinned action that is still controllable through a
// nested mutable action.
type pinnedRow struct {
	Action, Via string
	ViaNote     string // set when Via is only possibly mutable
	Consumers   int
	Path        pathView
	Principal   string
}

type principalPaths struct {
	Principal string
	Group     string // the row's group label when Principal stands for a group
	Paths     []pathView
}

type pathView struct {
	To        string
	Confirmed bool
	Hops      []hopView
	Note      string // supplied-file caveat, "" for paths read only from GitHub
	// Hardening is the target org's weak or unknown SSO and IP allow list
	// (graph.OrgHardening.Line): context only, never part of the score.
	Hardening string
	// PushNote joins the repo hardening notes of the path's CAN_PUSH hops
	// (graph.Index.HopNote): context only, never part of the score.
	PushNote string
}

type hopView struct {
	From, To, Kind, SourceAPI string
	Reason                    string // why an undecided CAN_ASSUME match is possible only
	Note                      string // hardening context (graph.Index.HopNote), never evidence
	Reverse                   bool
	Evidence                  string // live | inferred | audit | audit, stale | supplied file | not visible
	Class                     string // live | audit | supplied | nv
}

// hcell is one heat-grid cell of the repo hardening table: good when every
// repo has the fact, weak when one does not, unk when only unknowns are
// missing.
type hcell struct {
	Value, Tone string
}

func shareCell(sh graph.Share) hcell {
	c := hcell{Value: sh.String()}
	switch {
	case sh.No > 0:
		c.Tone = "weak"
	case sh.Unknown > 0:
		c.Tone = "unk"
	case sh.Yes > 0:
		c.Tone = "good"
	}
	return c
}

type hardeningRow struct {
	Cells                                                  []hcell
	Org                                                    string
	Repos                                                  int
	Protected, Reviews, CodeownersWF, SecretScan, PushProt string
}

type hardenRepoRow struct {
	Repo, State string
}

type hardenFixRow struct {
	Description, Reason string
}

func build(g *graph.Graph, opts Options) data {
	if opts.Rows == 0 {
		opts.Rows = DefaultRows
	}
	ix := graph.NewIndex(g)
	d := data{Demo: graph.IsDemo(g), Partial: graph.PartialNote(g), Version: opts.Version, Enterprise: g.Enterprise, ix: ix}
	d.NonHumanLine = ix.NonHuman().Headline()
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume {
			d.HasCloud = true
			break
		}
	}
	if !g.CollectedAt.IsZero() {
		d.CollectedAt = g.CollectedAt.UTC().Format(time.RFC3339)
	}
	top := ix.TopGroups(opts.Top)
	var pick *graph.Score
	if len(top) > 0 && (top[0].Confirmed.Repos > 0 || top[0].Score > 0) {
		g := headlinePick(ix, top)
		pick = &g.GroupScore
		d.Headline = headline(ix, g)
	} else {
		d.Headline = "No principal has confirmed reach into any repository in this graph."
	}
	for _, g := range top {
		s := g.GroupScore
		c, p := s.Confirmed, s.Possible
		row := riskRow{Principal: s.Principal, Repos: c.Repos, Orgs: c.Orgs,
			Cloud: c.CloudTargets, OIDC: c.OIDC, Secrets: c.Secrets, Runners: c.Runners,
			PossibleRepos: p.Repos, PossibleOther: p.CloudTargets + p.OIDC + p.Secrets + p.Runners,
			Score: fmt.Sprintf("%.1f", s.Score), Advisory: advisoryNote(ix, s)}
		if g.Size() > 1 {
			row.Group, row.Members = mcpserver.GroupKind(g), g.Members
			row.MembersText = mcpserver.MembersText(g.Members, mcpserver.MaxGroupMembersText)
		}
		if g.Range != nil {
			d.Ranged = true
			row.ReposRange, row.OrgsRange = mcpserver.RangeText(g.Range.Repos), mcpserver.RangeText(g.Range.Orgs)
			for _, m := range g.MemberScores {
				row.MemberRows = append(row.MemberRows, memberRow{Principal: m.Principal, Repos: m.Confirmed.Repos,
					Orgs: m.Confirmed.Orgs, Owned: len(ix.OwnedOrgs(m.Principal)), Score: fmt.Sprintf("%.1f", m.Score)})
			}
		}
		d.Risks = append(d.Risks, row)
		if pp := pickPaths(ix, s.Principal); len(pp) > 0 {
			d.Paths = append(d.Paths, principalPaths{Principal: s.Principal, Group: row.Group, Paths: pp})
		}
	}
	d.sugg, d.budget, d.ownerThreshold = ix.SuggestFixesOwners(opts.FixBudget, opts.OwnerThreshold), opts.FixBudget, opts.OwnerThreshold
	for i, f := range d.sugg {
		_, desc := mcpserver.DescribeFix(ix, f.Fix)
		d.Fixes = append(d.Fixes, fixRow{N: i + 1, Description: desc, FixID: f.FixID, Removed: f.Removed,
			CumulativePct: fmt.Sprintf("%.0f%%", f.CumulativePct)})
	}
	if len(d.Fixes) > 0 {
		d.FixLine = fmt.Sprintf("%s to remove %s of confirmed reach.", d.Fixes[0].Description, d.Fixes[0].CumulativePct)
	}
	pes := ix.PinnedExposures()
	if keep := rowsCap(len(pes), opts.Rows); keep < len(pes) {
		// Keep the ones to act on first: confirmed, then most consumers.
		sort.SliceStable(pes, func(i, j int) bool {
			a, b := pes[i], pes[j]
			if a.Path.Unverified != b.Path.Unverified {
				return !a.Path.Unverified
			}
			return a.Consumers > b.Consumers
		})
		d.PinnedMore = len(pes) - keep
		pes = pes[:keep]
	}
	for _, pe := range pes {
		d.Pinned = append(d.Pinned, pinnedRow{Action: strings.TrimPrefix(pe.Action, "action:"),
			Via: strings.TrimPrefix(pe.Via, "action:"), ViaNote: pe.ViaNote, Consumers: pe.Consumers,
			Principal: pe.Path.From, Path: viewPath(ix, pe.Path)})
	}
	if n := len(d.Pinned) + d.PinnedMore; n > 0 {
		verb := "run"
		if n == 1 {
			verb = "runs"
		}
		d.PinLine = fmt.Sprintf("Pinning is not enough: %s pinned to a commit SHA still %s a mutable ref that someone can push to.",
			plural(n, "action", "actions"), verb)
	}
	if st := ix.PinStats(); st.HasLock() {
		d.LockLine = lockLine(st)
	}
	var stages [funnelStages + 1]int
	d.Agents, d.AgentLine, d.AgentsMore, stages = agentRows(ix, opts.Rows)
	d.Funnel = buildFunnel(stages)
	if d.AgentPaths = buildAgentPaths(ix); len(d.AgentPaths) > 0 {
		d.AgentPathsLine = agentPathsLine(d.AgentPaths)
	}
	if d.BotMerge = botMergeRows(ix); len(d.BotMerge) > 0 {
		d.BotMergeLine = botMergeLine(d.BotMerge)
	}
	if o, ok := ix.Ownership(); ok {
		d.Ownership = ownershipView(o)
	}
	d.Orgs, d.OrgWhy = orgSettings(g)
	d.Stats = statWidgets(g, ix, d.BotMerge)
	addHardening(&d, ix, opts.Top, opts.Rows)
	d.AgentsMoreLine = moreLine(d.AgentsMore, "agent workflow", "agent workflows")
	d.PinnedMoreLine = moreLine(d.PinnedMore, "pinned action", "pinned actions")
	d.HardenReposMoreLine = moreLine(d.HardenReposMore, "repo", "repos")
	d.Coverage = g.Coverage
	if opts.Changes != nil {
		d.Banner = buildBanner(opts.Changes, pick)
	}
	return d
}

// headlinePick is the top-ranked row; among equal ranks a population wins
// over a single identity: an org's members, or a group of principals with
// identical reach.
func headlinePick(ix *graph.Index, top []graph.RiskGroup) graph.RiskGroup {
	population := func(g graph.RiskGroup) bool {
		return g.Size() > 1 || ix.Kind(g.Principal) == graph.KindOrgMembers
	}
	best := top[0]
	for _, g := range top[1:] {
		if g.Score != best.Score || g.PoutineInjectable != best.PoutineInjectable || g.AgentExposed != best.AgentExposed || (len(g.Advisories) > 0) != (len(best.Advisories) > 0) {
			break
		}
		if population(g) && !population(best) {
			best = g
		}
	}
	return best
}

func headline(ix *graph.Index, g graph.RiskGroup) string {
	if g.Cause != "" && g.Range != nil {
		return causeHeadline(ix, g)
	}
	s := g.GroupScore
	c := s.Confirmed
	who := mcpserver.GroupWho(ix, g)
	if strings.HasPrefix(who, "members of ") || strings.HasPrefix(who, "the ") {
		who = strings.ToUpper(who[:1]) + who[1:]
	}
	out := fmt.Sprintf("%s can push code that runs in %s across %s (confirmed)", who,
		plural(c.Repos, "repo", "repos"), plural(c.Orgs, "org", "orgs"))
	if len(s.Advisories) > 0 && s.Advisories[0] == s.Principal {
		what := "a version with a known advisory"
		if n, _ := ix.Node(s.Principal); !graph.HasAdvisory(n) {
			what = "as an actions.lock pins it (a commit with a known advisory)"
		}
		out = fmt.Sprintf("%s, %s (%s), runs in %s across %s (confirmed)",
			strings.TrimPrefix(s.Principal, "action:"), what, advisoryLabel(ix, s.Principal), plural(c.Repos, "repo", "repos"), plural(c.Orgs, "org", "orgs"))
	}
	var term []string
	if c.CloudTargets > 0 {
		term = append(term, plural(c.CloudTargets, "cloud role", "cloud roles"))
	}
	if c.OIDC > 0 {
		term = append(term, plural(c.OIDC, "cloud OIDC trust", "cloud OIDC trusts"))
	}
	if c.Secrets > 0 {
		term = append(term, plural(c.Secrets, "secret scope", "secret scopes"))
	}
	if c.Runners > 0 {
		term = append(term, plural(c.Runners, "self-hosted runner pool", "self-hosted runner pools"))
	}
	if len(term) > 0 {
		out += ", including " + strings.Join(term, ", ")
	}
	out += "."
	if s.Possible.Repos > 0 {
		out += fmt.Sprintf(" %s more possible through facts gop could not see.", plural(s.Possible.Repos, "repo", "repos"))
	}
	if c.CloudTargets > 0 {
		out += suppliedSentence(ix, []string{s.Principal})
	}
	return out
}

// suppliedSentence names the supplied trust files behind the principals'
// confirmed cloud roles, "" when there are none.
func suppliedSentence(ix *graph.Index, principals []string) string {
	var files []string
	seen := map[string]bool{}
	for _, p := range principals {
		r := ix.Reach(p, graph.Options{})
		for _, id := range r.Confirmed.CloudTargets {
			for _, f := range r.Paths[id].SuppliedFiles() {
				if !seen[f] {
					seen[f] = true
					files = append(files, f)
				}
			}
		}
	}
	if len(files) == 0 {
		return ""
	}
	sort.Strings(files)
	return " Cloud hops from supplied trust files " + strings.Join(files, ", ") + ", not read from the cloud."
}

// causeHeadline names a cause group's cause, never one member: "4 accounts
// that own 18 or more orgs can each push code that runs in 1,009 to 1,079
// repos across 18 to 20 orgs (confirmed)". The impact terms give the most
// any member reaches ("up to" when members differ).
func causeHeadline(ix *graph.Index, g graph.RiskGroup) string {
	who := mcpserver.GroupWho(ix, g)
	r := g.Range
	out := fmt.Sprintf("%s can each push code that runs in %s across %s (confirmed)", who,
		mcpserver.RangePlural(r.Repos, "repo", "repos"), mcpserver.RangePlural(r.Orgs, "org", "orgs"))
	span := func(get func(graph.Score) int) graph.MinMax {
		var m graph.MinMax
		for i, s := range g.MemberScores {
			n := get(s)
			if i == 0 || n < m.Min {
				m.Min = n
			}
			if i == 0 || n > m.Max {
				m.Max = n
			}
		}
		return m
	}
	var term []string
	for _, t := range []struct {
		get       func(graph.Score) int
		one, many string
	}{
		{func(s graph.Score) int { return s.Confirmed.CloudTargets }, "cloud role", "cloud roles"},
		{func(s graph.Score) int { return s.Confirmed.OIDC }, "cloud OIDC trust", "cloud OIDC trusts"},
		{func(s graph.Score) int { return s.Confirmed.Secrets }, "secret scope", "secret scopes"},
		{func(s graph.Score) int { return s.Confirmed.Runners }, "self-hosted runner pool", "self-hosted runner pools"},
	} {
		m := span(t.get)
		if m.Max == 0 {
			continue
		}
		txt := plural(m.Max, t.one, t.many)
		if m.Min != m.Max {
			txt = "up to " + txt
		}
		term = append(term, txt)
	}
	if len(term) > 0 {
		out += ", including " + strings.Join(term, ", ")
	}
	out += "."
	switch g.Cause {
	case graph.CauseOrgOwner:
		out += " The cause is standing org ownership: an org owner is admin on every repo of each org it owns."
	case graph.CauseTeam:
		out += " The cause is one team: " + g.CauseScope[0] + "."
	case graph.CauseOrgMembers:
		out += " The cause is membership of " + strings.TrimPrefix(g.CauseScope[0], "members:") + "."
	}
	if span(func(s graph.Score) int { return s.Confirmed.CloudTargets }).Max > 0 {
		out += suppliedSentence(ix, g.Members)
	}
	if m := span(func(s graph.Score) int { return s.Possible.Repos }); m.Max > 0 {
		if m.Min == m.Max {
			out += fmt.Sprintf(" %s more possible each through facts gop could not see.", plural(m.Max, "repo", "repos"))
		} else {
			out += fmt.Sprintf(" Up to %s more possible through facts gop could not see.", plural(m.Max, "repo", "repos"))
		}
	}
	return out
}

// advisoryLabel is "GHSA-a, GHSA-b; severity critical; fixed in 2.0.1" for
// an action with advisories on its ref. Advisories on commits an
// actions.lock pins it to follow as "actions.lock pins an affected commit in
// N uses: ..." with the same fields, read from those edges.
func advisoryLabel(ix *graph.Index, action string) string {
	n, _ := ix.Node(action)
	var parts []string
	if graph.HasAdvisory(n) {
		parts = append(parts, labelOf(graph.AdvisoryIDs(n), n.Attrs[graph.AttrAdvisorySeverity], n.Attrs[graph.AttrAdvisoryFixed]))
	}
	if lock := ix.LockAffectedUses(action); len(lock) > 0 {
		ids, fixed := map[string]bool{}, map[string]bool{}
		sev, noFix := "", false
		for _, e := range lock {
			for _, id := range strings.Split(e.Attrs[graph.AttrLockAdvisories], ",") {
				ids[id] = true
			}
			if v := e.Attrs[graph.AttrLockAdvisorySeverity]; sev == "" || sevRank[v] > sevRank[sev] {
				sev = v
			}
			if f := e.Attrs[graph.AttrLockAdvisoryFixed]; f != "" {
				fixed[f] = true
			} else {
				noFix = true
			}
		}
		f := ""
		if !noFix {
			f = strings.Join(sortedSet(fixed), ", ")
		}
		parts = append(parts, fmt.Sprintf("actions.lock pins an affected commit in %s: %s",
			plural(len(lock), "uses: line", "uses: lines"), labelOf(sortedSet(ids), sev, f)))
	}
	return strings.Join(parts, "; ")
}

var sevRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

func labelOf(ids []string, sev, fixed string) string {
	out := strings.Join(ids, ", ")
	if sev != "" {
		out += "; severity " + sev
	}
	if fixed != "" {
		out += "; fixed in " + fixed
	} else {
		out += "; no fixed version"
	}
	return out
}

// advisoryNote is the risks-table note for a row with Score.Advisories.
func advisoryNote(ix *graph.Index, s graph.Score) string {
	if len(s.Advisories) == 0 {
		return ""
	}
	if s.Advisories[0] == s.Principal {
		return "known advisory: " + advisoryLabel(ix, s.Principal)
	}
	names := make([]string, len(s.Advisories))
	for i, a := range s.Advisories {
		names[i] = strings.TrimPrefix(a, "action:")
	}
	return "paths run through an action with a known advisory: " + strings.Join(names, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// pickPaths chooses a principal's most telling paths: terminal impact (OIDC,
// secrets, runners) first, confirmed before possible; else the longest
// confirmed repo path; plus one possible path when it has any.
func pickPaths(ix *graph.Index, principal string) []pathView {
	r := ix.Reach(principal, graph.Options{})
	rank := func(id string) int {
		switch ix.Kind(id) {
		case graph.KindCloudTarget:
			return -1
		case graph.KindOIDC:
			return 0
		case graph.KindSecret:
			return 1
		case graph.KindRunner:
			return 2
		}
		return 9
	}
	var terms, repos, possible []graph.Path
	for _, p := range r.Paths {
		switch {
		case rank(p.To) < 9:
			terms = append(terms, p)
		case ix.Kind(p.To) == graph.KindRepo && !p.Unverified:
			repos = append(repos, p)
		}
		if p.Unverified {
			possible = append(possible, p)
		}
	}
	sort.Slice(terms, func(i, j int) bool {
		a, b := terms[i], terms[j]
		if a.Unverified != b.Unverified {
			return !a.Unverified
		}
		if rank(a.To) != rank(b.To) {
			return rank(a.To) < rank(b.To)
		}
		return a.To < b.To
	})
	sort.Slice(repos, func(i, j int) bool {
		if len(repos[i].Hops) != len(repos[j].Hops) {
			return len(repos[i].Hops) > len(repos[j].Hops)
		}
		return repos[i].To < repos[j].To
	})
	sort.Slice(possible, func(i, j int) bool { return possible[i].To < possible[j].To })
	chosen := terms
	if len(chosen) == 0 && len(repos) > 0 {
		chosen = repos[:1]
	}
	if len(chosen) > maxPathsPerPrincipal {
		chosen = chosen[:maxPathsPerPrincipal]
	}
	hasPossible := false
	for _, p := range chosen {
		hasPossible = hasPossible || p.Unverified
	}
	if !hasPossible && len(possible) > 0 {
		chosen = append(chosen, possible[0])
	}
	out := make([]pathView, 0, len(chosen))
	for _, p := range chosen {
		pv := viewPath(ix, p)
		if h := ix.TargetOrgHardening(p); h != nil {
			pv.Hardening = h.Line()
		}
		out = append(out, pv)
	}
	return out
}

func viewPath(ix *graph.Index, p graph.Path) pathView {
	pv := pathView{To: p.To, Confirmed: !p.Unverified, Note: p.SuppliedNote(), PushNote: strings.Join(ix.PathNotes(p), "; ")}
	for _, h := range ix.Annotate(p).Hops {
		pv.Hops = append(pv.Hops, hopView{From: h.From, To: h.To, Kind: string(h.Kind), SourceAPI: h.SourceAPI, Reason: h.Reason, Note: h.Note,
			Reverse: h.Reverse, Evidence: mcpserver.HopEvidenceLabel(h), Class: evClass(h.Evidence)})
	}
	return pv
}

func evClass(ev graph.Evidence) string {
	switch ev {
	case graph.Live:
		return "live"
	case graph.Inferred:
		return "inferred"
	case graph.Audit:
		return "audit"
	case graph.Supplied:
		return "supplied"
	}
	return "nv"
}

const footer = "This file maps attack paths in your organization. Treat it as sensitive."

// lockLine is the coverage note that splits workflow uses: lines by how they
// are pinned. A stale actions.lock entry is never counted as pinned.
func lockLine(st graph.PinStats) string {
	affected := ""
	if st.LockAffected > 0 {
		affected = fmt.Sprintf(", %d pinned by actions.lock to a commit with a known advisory (listed under risks)", st.LockAffected)
	}
	return fmt.Sprintf("Action pins (workflow uses: lines): %d pinned in the workflow file, %d pinned by actions.lock (%s)%s, %d with a stale actions.lock entry (counted as unpinned, listed below), %d unpinned.",
		st.InWorkflow, st.ByLock, plural(st.Locks, "repo has a lockfile", "repos have a lockfile"), affected, st.Stale, st.Unpinned)
}

// hardeningFixes caps the advisory hardening suggestions the report lists.
const hardeningFixes = 5

// addHardening fills the repo hardening section: the per-org rollup, the
// state of the repos the top principals push to, and advisory fixes.
func addHardening(d *data, ix *graph.Index, top, rows int) {
	for _, r := range ix.HardeningRollups() {
		d.RepoHardening = append(d.RepoHardening, hardeningRow{Org: orgName(r.Org), Repos: r.Repos,
			Protected: r.Protected.String(), Reviews: r.Reviews.String(), CodeownersWF: r.CodeownersWF.String(),
			SecretScan: r.SecretScanning.String(), PushProt: r.PushProtection.String(),
			Cells: []hcell{shareCell(r.Protected), shareCell(r.Reviews), shareCell(r.CodeownersWF),
				shareCell(r.SecretScanning), shareCell(r.PushProtection)}})
	}
	if len(d.RepoHardening) == 0 {
		return
	}
	for _, repo := range ix.TopPathRepos(top) {
		n, _ := ix.Node(repo)
		h, ok := graph.RepoHardening(n)
		if !ok {
			continue
		}
		if rows >= 0 && len(d.HardenRepos) >= rows {
			d.HardenReposMore++
			continue
		}
		d.HardenRepos = append(d.HardenRepos, hardenRepoRow{Repo: strings.TrimPrefix(repo, "repo:"), State: h.Summary()})
	}
	for _, s := range ix.SuggestHardening(top, hardeningFixes) {
		_, desc := mcpserver.DescribeFix(ix, s.Fix)
		d.HardenFixes = append(d.HardenFixes, hardenFixRow{Description: desc, Reason: s.Reason})
	}
}
