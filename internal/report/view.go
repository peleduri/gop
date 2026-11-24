package report

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// The HTML view model: the verdict hero, the choke-point fix cards, the
// impact bars of the risks list, the org settings heat grid and the coverage
// groups. Everything here is derived from the facts build already holds;
// nothing adds a fact. Confirmed and possible stay separate figures.

// kpi is one tile of the verdict hero. Possible is the matching possible
// figure, shown apart and styled weaker, never added to Value.
type kpi struct {
	Label, Value, Unit, Sub, Possible string
	Tone                              string // crit | high | med | unk | ok | "" (neutral)
	Href                              string
}

// covGroup is the coverage gaps that one kind of access would close, for
// example "Org owner needed on 2 orgs".
type covGroup struct {
	Title   string
	Targets []string
	Facts   int
}

// barSeg is one segment of a risk row's impact bar: Width is a CSS class
// (w0..w100 in steps of 4), the number is shown as text beside the bar.
type barSeg struct {
	Kind, Label string
	N           int
	Width       string
}

// severity maps confirmed terminal impact to a band, the same way gop sarif
// does: critical for cloud OIDC trust or a cloud role, high for secrets or
// self-hosted runners, medium for CI in repos only, low for nothing.
func severity(r riskRow) string {
	switch {
	case r.OIDC > 0 || r.Cloud > 0:
		return "critical"
	case r.Secrets > 0 || r.Runners > 0:
		return "high"
	case r.Repos > 0:
		return "medium"
	}
	return "low"
}

// widthClass rounds a share in 0..1 to a width class (w0..w100 in steps of
// 4); any non-zero share stays visible.
func widthClass(share float64) string {
	if share <= 0 || math.IsNaN(share) {
		return "w0"
	}
	n := int(math.Round(share*25)) * 4
	if n < 4 {
		n = 4
	}
	if n > 100 {
		n = 100
	}
	return fmt.Sprintf("w%d", n)
}

// decorate fills the HTML view model from what build computed.
func decorate(d *data, g *graph.Graph) {
	decorateRisks(d)
	decorateFixes(d)
	d.CovGroups = coverageGroups(g.Coverage)
	gapOrgs := map[string]bool{}
	for _, c := range g.Coverage {
		if o := strings.TrimPrefix(graph.OrgOf(c.Scope), "org:"); o != "" {
			gapOrgs[o] = true
		}
	}
	allOrgs := map[string]bool{}
	for i, o := range d.Orgs {
		allOrgs[o.Org] = true
		for j := range o.Cells {
			c := &d.Orgs[i].Cells[j]
			c.Tone = settingTone(settingCols[j].Key, c)
		}
	}
	for o := range gapOrgs {
		allOrgs[o] = true
	}
	d.Verdict, d.VerdictLabel = verdict(d, len(g.Coverage))
	top, who := widest(d)
	d.PickWho = who
	d.KPIs = kpis(d, top, len(allOrgs), len(gapOrgs), len(g.Coverage))
	// A cause group's tiles are its first member's figures: say so, and
	// give the group's range.
	for _, r := range d.Risks {
		if top != nil && r.Principal == top.Principal && r.ReposRange != "" && len(d.KPIs) > 0 && d.KPIs[0].Label == "Confirmed reach" {
			d.KPIs[0].Sub = fmt.Sprintf("across %s for its widest member; %s repos across the %d members", plural(top.Confirmed.Orgs, "org", "orgs"), r.ReposRange, len(r.Members))
		}
	}
}

func decorateRisks(d *data) {
	max := 0
	for _, r := range d.Risks {
		if t := r.Cloud + r.OIDC + r.Secrets + r.Runners; t > max {
			max = t
		}
	}
	poutine, agent, bot := map[string]int{}, map[string]int{}, map[string]int{}
	for _, s := range d.ix.Scores() {
		if s.PoutineInjectable > 0 {
			poutine[s.Principal] = s.PoutineInjectable
		}
		if s.AgentExposed > 0 {
			agent[s.Principal] = s.AgentExposed
		}
		if s.BotSelfMerge > 0 {
			bot[s.Principal] = s.BotSelfMerge
		}
	}
	for i := range d.Risks {
		r := &d.Risks[i]
		r.Poutine = poutine[r.Principal]
		r.Agent = agent[r.Principal]
		r.BotMerge = bot[r.Principal]
		r.Rank, r.Sev = i+1, severity(*r)
		if r.Sev == "low" && r.PossibleRepos+r.PossibleOther > 0 {
			r.Sev = "unknown" // possible reach only: never shown as low
		}
		r.Bar = nil
		for _, s := range []struct {
			kind, one, many string
			n               int
		}{{"cloud", "cloud role", "cloud roles", r.Cloud}, {"oidc", "OIDC trust", "OIDC trusts", r.OIDC},
			{"secret", "secret", "secrets", r.Secrets}, {"runner", "runner pool", "runner pools", r.Runners}} {
			if s.n == 0 {
				continue
			}
			r.Bar = append(r.Bar, barSeg{Kind: s.kind, Label: unit(s.n, s.one, s.many), N: s.n, Width: widthClass(float64(s.n) / float64(max))})
		}
	}
}

func decorateFixes(d *data) {
	for i := range d.Fixes {
		if i >= len(d.sugg) {
			break
		}
		s := d.sugg[i]
		f := &d.Fixes[i]
		base := s.CumulativeRemoved + s.Remaining
		if base <= 0 {
			continue
		}
		share := float64(s.Removed) / float64(base)
		prev := float64(s.CumulativeRemoved-s.Removed) / float64(base)
		f.Pct = fmt.Sprintf("%.0f%%", 100*share)
		f.PrevWidth, f.Width = widthClass(prev), widthClass(share)
		f.Why = fixWhy(d.ix, s.Fix)
		f.Caveat = s.Caveat
	}
}

// fixWhy is the one-line reason a fix removes reach, from the fix's shape.
func fixWhy(ix *graph.Index, f graph.Fix) string {
	switch v := f.(type) {
	case graph.PinRef:
		a := strings.TrimPrefix(v.Action, "action:")
		repo := a
		if i := strings.LastIndex(repo, "@"); i > 0 {
			repo = repo[:i]
		}
		return "A branch or tag ref can be moved: whoever can push to " + repo + " changes the code every workflow that uses it runs."
	case graph.LowerDefaultPerm:
		org := strings.TrimPrefix(v.Org, "org:")
		cur := ""
		if n, ok := ix.Node(v.Org); ok {
			cur = n.Attrs[graph.AttrDefaultPerm]
		}
		if cur == "" || cur == "unknown" {
			return "Every member of " + org + " inherits the default permission on its repos."
		}
		return "Every member of " + org + " inherits " + cur + " access to its repos by default, so any member account can push code that CI runs."
	case graph.RestrictToken:
		return "The workflow's GITHUB_TOKEN can write, so code it runs can push to the repo."
	case graph.HardenTrigger:
		return "The workflow runs code an outsider controls on a trigger that holds the repo's credentials."
	case graph.BlockBotMerge:
		return "A bot approves and merges a pull request its author can steer, so anyone who can open a pull request gets code onto the default branch with no human review."
	case graph.ReduceOwners:
		return "An org owner is admin on every repo of the org, so an account that owns many orgs can push code that runs across all of them; standing ownership of many orgs makes one account an enterprise-wide push key."
	}
	return ""
}

// settingTone classes an org setting cell: good, weak, unknown or neutral.
// Unknown is never good: a setting gop could not see is its own tone. A
// member capability left on (members can create, delete, fork or change the
// visibility of repos) reads weak, off reads strong.
func settingTone(key string, c *cell) string {
	if c.NV {
		return "unk"
	}
	v := strings.ToLower(c.Value)
	switch key {
	case graph.AttrDefaultPerm:
		switch v {
		case "none", "read":
			return "good"
		case "write", "admin":
			return "weak"
		}
	case graph.AttrTwoFactor:
		switch v {
		case "required", "true", "enabled":
			return "good"
		case "not_required", "false", "disabled":
			return "weak"
		}
	case graph.AttrSSO:
		switch v {
		case "enforced":
			return "good"
		case "configured", "none":
			return "weak"
		}
	case graph.AttrIPAllowList:
		if i := strings.Index(v, " ("); i > 0 {
			v = v[:i] // "on (4 active entries, installed apps on)"
		}
		switch v {
		case "on", "true", "enabled":
			return "good"
		case "off", "false", "disabled":
			return "weak"
		}
	case graph.AttrMembersCreate, graph.AttrChangeVisiblity, graph.AttrDeleteRepos, graph.AttrPrivateForks:
		// A member capability the org leaves on is the more permissive setting.
		switch v {
		case "false":
			return "good"
		case "true":
			return "weak"
		}
	}
	return ""
}

// coverageGroups groups gaps by the access that closes them: "org owner on
// acme-legacy (SAML ...)" and "org owner on acme-x" both become "Org owner
// needed on 2 orgs".
func coverageGroups(cov []graph.Coverage) []covGroup {
	type acc struct {
		targets map[string]bool
		facts   int
		allOrgs bool
	}
	by := map[string]*acc{}
	var order []string
	for _, c := range cov {
		need := c.NeedsFix
		if i := strings.Index(need, " ("); i > 0 {
			need = need[:i]
		}
		role, target := need, c.Scope
		if i := strings.Index(need, " on "); i > 0 {
			role, target = need[:i], need[i+4:]
		}
		if role == "" {
			role = "More access"
		}
		a := by[role]
		if a == nil {
			a = &acc{targets: map[string]bool{}, allOrgs: true}
			by[role] = a
			order = append(order, role)
		}
		a.targets[target] = true
		a.facts++
		if !strings.HasPrefix(c.Scope, "org:") {
			a.allOrgs = false
		}
	}
	out := make([]covGroup, 0, len(order))
	for _, role := range order {
		a := by[role]
		ts := sortedSet(a.targets)
		unit := plural(len(ts), "scope", "scopes")
		if a.allOrgs {
			unit = plural(len(ts), "org", "orgs")
		}
		out = append(out, covGroup{Title: strings.ToUpper(role[:1]) + role[1:] + " needed on " + unit, Targets: ts, Facts: a.facts})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Facts > out[j].Facts })
	return out
}

// verdict is the hero's posture pill: the worst severity among the top
// risks, from confirmed reach only. With no confirmed reach it never reads
// as safe while gop saw possible reach or had coverage gaps.
func verdict(d *data, gaps int) (tone, label string) {
	rank := map[string]int{"critical": 3, "high": 2, "medium": 1}
	worst := ""
	for _, r := range d.Risks {
		if rank[r.Sev] > rank[worst] {
			worst = r.Sev
		}
	}
	switch worst {
	case "critical":
		return "critical", "Critical exposure"
	case "high":
		return "high", "High exposure"
	case "medium":
		return "medium", "Moderate exposure"
	}
	possible := false
	for _, r := range d.Risks {
		possible = possible || r.PossibleRepos+r.PossibleOther > 0
	}
	if possible || gaps > 0 {
		return "unk", "No confirmed reach, but gop could not see everything"
	}
	return "ok", "No confirmed reach found"
}

// widest is the top-risk row with the largest confirmed blast radius
// (score) and how the hero names it; among equal scores a population (an
// org's members or a group of principals) wins over one identity. The hero's
// reach tiles are its figures. It can differ from the headline principal,
// which ranks advisories and poutine findings first.
func widest(d *data) (*graph.Score, string) {
	by := map[string]graph.Score{}
	for _, s := range d.ix.Scores() {
		by[s.Principal] = s
	}
	population := func(r riskRow) bool { return r.Group != "" || d.ix.Kind(r.Principal) == graph.KindOrgMembers }
	var best *graph.Score
	var row riskRow
	for _, r := range d.Risks {
		s, ok := by[r.Principal]
		if !ok || s.Score <= 0 {
			continue
		}
		if best == nil || s.Score > best.Score || (s.Score == best.Score && population(r) && !population(row)) {
			s := s
			best, row = &s, r
		}
	}
	if best == nil {
		return nil, ""
	}
	if row.Group != "" {
		return best, row.Group
	}
	return best, mcpserver.Display(d.ix, best.Principal)
}

func kpis(d *data, top *graph.Score, orgs, gapOrgs, gaps int) []kpi {
	var out []kpi
	if top != nil {
		c, p := top.Confirmed, top.Possible
		poss := func(n int, one, many string) string {
			if n == 0 {
				return ""
			}
			return "+" + plural(n, one, many) + " possible"
		}
		tone := func(n int, t string) string {
			if n > 0 {
				return t
			}
			return ""
		}
		out = append(out, kpi{Label: "Confirmed reach", Value: fmt.Sprint(c.Repos), Unit: unit(c.Repos, "repo", "repos"),
			Sub: "across " + plural(c.Orgs, "org", "orgs"), Possible: poss(p.Repos, "repo", "repos"), Tone: tone(c.Repos, "med"), Href: "#top-paths"})
		oidc := kpi{Label: "Cloud OIDC trusts", Value: fmt.Sprint(c.OIDC), Unit: unit(c.OIDC, "trust", "trusts"),
			Sub: "cloud credentials CI can mint", Possible: poss(p.OIDC, "trust", "trusts"), Tone: tone(c.OIDC+c.CloudTargets, "crit"), Href: "#top-paths"}
		if d.HasCloud {
			oidc.Sub = plural(c.CloudTargets, "cloud role", "cloud roles") + " from supplied trust files"
		}
		out = append(out, oidc,
			kpi{Label: "Secret scopes", Value: fmt.Sprint(c.Secrets), Unit: unit(c.Secrets, "scope", "scopes"),
				Sub: "repo, environment or org secrets", Possible: poss(p.Secrets, "scope", "scopes"), Tone: tone(c.Secrets, "high"), Href: "#top-paths"},
			kpi{Label: "Self-hosted runners", Value: fmt.Sprint(c.Runners), Unit: unit(c.Runners, "pool", "pools"),
				Sub: "runner pools jobs land on", Possible: poss(p.Runners, "pool", "pools"), Tone: tone(c.Runners, "high"), Href: "#top-paths"})
	}
	// Counted in principals: a grouped row stands for all its members.
	crit, high, principals := 0, 0, 0
	for _, r := range d.Risks {
		n := len(r.Members)
		if n == 0 {
			n = 1
		}
		principals += n
		switch r.Sev {
		case "critical":
			crit += n
		case "high":
			high += n
		}
	}
	rt := ""
	if crit > 0 {
		rt = "crit"
	} else if high > 0 {
		rt = "high"
	}
	out = append(out, kpi{Label: "Top risks", Value: fmt.Sprint(principals), Unit: unit(principals, "principal", "principals"),
		Sub: fmt.Sprintf("%d critical · %d high", crit, high), Tone: rt, Href: "#top-risks"})
	cov := kpi{Label: "Coverage", Href: "#coverage"}
	switch {
	case orgs > 0:
		cov.Value, cov.Unit = fmt.Sprintf("%d/%d", orgs-gapOrgs, orgs), "orgs fully visible"
	case gaps == 0:
		cov.Value, cov.Unit = "—", "no orgs in this graph"
	default:
		cov.Value, cov.Unit = fmt.Sprint(gaps), unit(gaps, "gap", "gaps")
	}
	if gaps > 0 {
		cov.Sub, cov.Tone = plural(gaps, "fact", "facts")+" not visible: unknown, not absent", "unk"
	} else {
		cov.Sub = "every fact gop looked for was visible"
	}
	return append(out, cov)
}

func unit(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// nodeKind and nodeShort split a node ID ("repo:acme-app/web") for the hop
// chain: the kind is a small label, the name the chip text.
func nodeKind(id string) string {
	if i := strings.Index(id, ":"); i > 0 {
		return id[:i]
	}
	return ""
}

// nodeShort is the chip text: the name without its kind, with a full
// commit SHA after @ cut to 12 characters and a workflow's
// /.github/workflows/ shown as ›; the chip's title keeps the full ID.
func nodeShort(id string) string {
	name := id
	if i := strings.Index(id, ":"); i > 0 {
		name = id[i+1:]
	}
	name = strings.Replace(name, "/.github/workflows/", " › ", 1)
	if i := strings.LastIndex(name, "@"); i >= 0 && len(name)-i-1 == 40 && isHex(name[i+1:]) {
		name = name[:i+13] + "…"
	}
	return name
}

// nodeTitle is the full ID for a chip whose text nodeShort shortened, else "".
func nodeTitle(id string) string {
	name := id
	if i := strings.Index(id, ":"); i > 0 {
		name = id[i+1:]
	}
	if nodeShort(id) == name {
		return ""
	}
	return id
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
