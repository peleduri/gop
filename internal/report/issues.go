package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// The Issues view lists one row per actionable combination of facts gop
// already detects: an AI agent outsiders can start while it holds write,
// secrets or OIDC; a bot merge with no human review; an action with a known
// advisory that reaches secrets, self-hosted runners, OIDC or a cloud role;
// and a SHA-pinned action that still runs a mutable ref. Each row says how
// severe it is, which risk factors combine in it, whether its deciding facts
// were confirmed or only possible, where it is and how to fix it. Every
// field is computed from the graph; nothing is scored by hand.

// Issue kinds, also the data-k attribute of a row.
const (
	issueAgent    = "agent"
	issueBotMerge = "bot_merge"
	issueAdvisory = "advisory"
	issuePinned   = "pinned"
)

// Risk factor keys: the chips on a row and the values of the factor filter.
const (
	factorOutsiders = "outsiders"
	factorWrite     = "write"
	factorSecrets   = "secrets"
	factorOIDC      = "oidc"
	factorCloud     = "cloud"
	factorRunner    = "runner"
	factorDangerous = "dangerous"
	factorInjection = "injection"
	factorNoReview  = "no-review"
	factorMergeKey  = "merge-key"
	factorPolicy    = "policy"
	factorAdvisory  = "advisory"
	factorMutable   = "mutable"
)

// factorOrder is the order chips show in and the filter lists them in, with
// their labels.
var factorOrder = []struct{ Key, Label string }{
	{factorOutsiders, "Outsiders can start"},
	{factorNoReview, "No human review"},
	{factorAdvisory, "Known advisory"},
	{factorMutable, "Mutable ref"},
	{factorDangerous, "Dangerous mode"},
	{factorInjection, "Prompt injection"},
	{factorMergeKey, "AI holds merge key"},
	{factorPolicy, "Self-editable policy"},
	{factorWrite, "Write token"},
	{factorSecrets, "Secrets"},
	{factorOIDC, "OIDC"},
	{factorCloud, "Cloud role"},
	{factorRunner, "Self-hosted runner"},
}

// issueFactor is one risk-factor chip.
type issueFactor struct{ Key, Label string }

// issueRow is one row of the Issues view.
type issueRow struct {
	ID    string // dom id: is-1, is-2, ...
	Kind  string // issueAgent | issueBotMerge | issueAdvisory | issuePinned
	Sev   string // critical | high | medium
	Title string
	// Factors are the chips, in factorOrder; FactorKeys their keys joined by
	// spaces for the client-side filter.
	Factors    []issueFactor
	FactorKeys string
	// Confirmed is set when every deciding fact was read (live, inferred,
	// audit or supplied); a row with one not visible fact is possible.
	Confirmed bool
	// Where is the affected workflow, repo or action; Org its org; Used
	// says how many workflows use an action ("" for others).
	Where, WhereKind, Org, Used string
	Why                         string // one line: what an attacker gets
	Fixes                       []string
	Commands                    []string
	// Steps is an agent issue's hop-by-hop path (the Agent paths hops),
	// PathLink its diagram in Agent paths when it is listed there. Path is
	// the control-graph chain of an advisory or pinned issue.
	Steps    []pathHop
	PathLink string
	Path     *pathView
	// Facts are an issue's deciding facts as label/value pairs (bot merge).
	Facts [][2]string

	order int // kind order within a severity
}

// issueSummary counts the rows by severity and evidence for the cards on
// top of the view.
type issueSummary struct {
	Total, Critical, High, Medium int
	Confirmed, Possible           int
}

var issueSevRank = map[string]int{"critical": 0, "high": 1, "medium": 2}

// buildIssues returns every issue of the graph, most severe first,
// confirmed before possible, then by kind and place; the summary counts
// them all. agentPaths is the Agent paths section, so an agent issue can
// link to its diagram there.
func buildIssues(ix *graph.Index, bot []botMergeRow, agentPaths []agentPath) ([]issueRow, issueSummary) {
	var out []issueRow
	out = append(out, agentIssues(ix, agentPaths)...)
	out = append(out, botMergeIssues(bot)...)
	out = append(out, advisoryIssues(ix)...)
	out = append(out, pinnedIssues(ix)...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Sev != b.Sev {
			return issueSevRank[a.Sev] < issueSevRank[b.Sev]
		}
		if a.Confirmed != b.Confirmed {
			return a.Confirmed
		}
		if a.order != b.order {
			return a.order < b.order
		}
		return a.Where < b.Where
	})
	var s issueSummary
	for i := range out {
		out[i].ID = fmt.Sprintf("is-%d", i+1)
		keys := make([]string, len(out[i].Factors))
		for k, f := range out[i].Factors {
			keys[k] = f.Key
		}
		out[i].FactorKeys = strings.Join(keys, " ")
		s.Total++
		switch out[i].Sev {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		default:
			s.Medium++
		}
		if out[i].Confirmed {
			s.Confirmed++
		} else {
			s.Possible++
		}
	}
	return out, s
}

// factors orders a set of factor keys by factorOrder.
func factors(set map[string]bool) []issueFactor {
	var out []issueFactor
	for _, f := range factorOrder {
		if set[f.Key] {
			out = append(out, issueFactor{f.Key, f.Label})
		}
	}
	return out
}

// orgOf is the org of a "workflow:org/repo/...", "repo:org/repo" or
// "action:org/name@ref" id.
func orgOf(id string) string {
	if i := strings.Index(id, ":"); i >= 0 {
		id = id[i+1:]
	}
	if i := strings.IndexAny(id, "/@"); i >= 0 {
		return id[:i]
	}
	return id
}

// agentImpactFactors maps an agent job's AgentImpact to factor keys.
func agentImpactFactors(imp []string, set map[string]bool) {
	for _, p := range imp {
		switch p {
		case "secrets":
			set[factorSecrets] = true
		case "id-token:write":
			set[factorOIDC] = true
		default:
			set[factorWrite] = true
		}
	}
}

// agentIssues: one per AgentExposed workflow (a strong agent signal,
// outsiders can start it, and it holds write, secrets or OIDC). Critical
// when the agent also runs with its approvals or sandbox off.
func agentIssues(ix *graph.Index, paths []agentPath) []issueRow {
	link := map[string]string{}
	for _, p := range paths {
		link[p.Workflow] = "#" + p.ID
	}
	var out []issueRow
	for _, id := range ix.AgentWorkflows() {
		n, ok := ix.Node(id)
		if !ok || !graph.AgentExposed(n) {
			continue
		}
		wf := strings.TrimPrefix(id, "workflow:")
		set := map[string]bool{factorOutsiders: true}
		imp := graph.AgentImpact(n)
		agentImpactFactors(imp, set)
		mode := graph.AgentUnrestricted(n)
		if len(mode) > 0 {
			set[factorDangerous] = true
		}
		if n.Attrs[graph.AttrAgentPrompt] != "" {
			set[factorInjection] = true
		}
		// Confirmed only when someone gop names can start it by a verified
		// CAN_TRIGGER edge and the agent's own actor check is known.
		conf := false
		for _, e := range ix.In(id) {
			if e.Kind == graph.CanTrigger && graph.Verified(e.Evidence) {
				conf = true
			}
		}
		if n.Attrs[graph.AttrAgentGate] == graph.GateUnknown {
			conf = false
		}
		r := issueRow{Kind: issueAgent, Sev: "high", Confirmed: conf, Where: wf, WhereKind: "workflow", Org: orgOf(id),
			Title: "Outsiders can start an AI agent holding " + holdWords(set), PathLink: link[wf], order: 0}
		if len(mode) > 0 {
			r.Sev = "critical"
			r.Title += ", in dangerous mode"
		}
		r.Factors = factors(set)
		r.Why = "A prompt injection in text an outsider writes runs with the job's " + strings.TrimPrefix(holdWords(set), "a ") + " (" + strings.Join(imp, ", ") + ")."
		r.Fixes = graph.AgentFixes(n)
		if graph.AgentMemoryPoisoned(n) {
			r.Fixes = append(r.Fixes, graph.AgentMemoryFixes(n)...)
		}
		ap := agentPathFor(ix, n)
		r.Steps = ap.Present
		for _, f := range ap.Fixes {
			if f.Command != "" {
				r.Commands = append(r.Commands, f.Command)
			}
		}
		out = append(out, r)
	}
	return out
}

// botMergeIssues: one per repo with a bot approve + merge and no human
// review. Critical when an AI step holds the merge key.
func botMergeIssues(bot []botMergeRow) []issueRow {
	var out []issueRow
	for _, b := range bot {
		set := map[string]bool{factorNoReview: true}
		r := issueRow{Kind: issueBotMerge, Sev: "high", Confirmed: !b.Possible && b.Who != "" && !b.WhoPossible,
			Where: b.Repo, WhereKind: "repo", Org: orgOf(b.Repo), order: 1,
			Title: "Bot approval lands code on the default branch with no human review", Why: b.Note, Fixes: b.Fixes}
		if b.KeyHolders != "" {
			set[factorMergeKey] = true
			r.Sev = "critical"
			r.Title += "; an AI step holds the merge key"
			r.Facts = append(r.Facts, [2]string{"Merge key", "held by the AI step in " + b.KeyHolders})
		}
		if b.Policy != "" {
			set[factorPolicy] = true
			r.Facts = append(r.Facts, [2]string{"Self-editable policy", b.Policy})
		}
		if b.Who != "" {
			v := b.Who
			if b.WhoPossible {
				v = "possible: " + v
			}
			r.Facts = append([][2]string{{"Who can use it", v}}, r.Facts...)
		}
		if b.Reason != "" {
			r.Facts = append(r.Facts, [2]string{"Why no human review", b.Reason})
		}
		r.Factors = factors(set)
		out = append(out, r)
	}
	return out
}

// impactSet adds the factor keys of a reach's terminal targets.
func impactSet(rc graph.Reached, set map[string]bool) bool {
	hit := false
	for _, x := range []struct {
		n   int
		key string
	}{{len(rc.Secrets), factorSecrets}, {len(rc.Runners), factorRunner}, {len(rc.OIDC), factorOIDC}, {len(rc.CloudTargets), factorCloud}} {
		if x.n > 0 {
			set[x.key] = true
			hit = true
		}
	}
	return hit
}

// bestTarget is the most severe terminal of a reach (cloud, OIDC, secret,
// runner), "" when it has none.
func bestTarget(rc graph.Reached) string {
	for _, l := range [][]string{rc.CloudTargets, rc.OIDC, rc.Secrets, rc.Runners} {
		if len(l) > 0 {
			return l[0]
		}
	}
	return ""
}

// impactWords names the factors of an impact set in plain words.
func impactWords(set map[string]bool) string {
	var w []string
	for _, x := range []struct{ key, word string }{{factorCloud, "cloud roles"}, {factorOIDC, "OIDC"}, {factorSecrets, "secrets"}, {factorRunner, "self-hosted runners"}} {
		if set[x.key] {
			w = append(w, x.word)
		}
	}
	return joinAnd(w)
}

// usedBy counts the workflows that use an action directly.
func usedBy(ix *graph.Index, action string) int {
	n := 0
	for _, e := range ix.In(action) {
		if e.Kind == graph.Uses && ix.Kind(e.From) == graph.KindWorkflow {
			n++
		}
	}
	return n
}

// advisoryIssues: one per action with a known advisory whose reach takes
// in secrets, self-hosted runners, OIDC or a cloud role. Confirmed when a
// confirmed path does; critical for a critical advisory.
func advisoryIssues(ix *graph.Index) []issueRow {
	var out []issueRow
	for _, a := range ix.AdvisoryActions() {
		res := ix.Reach(a, graph.Options{})
		set := map[string]bool{factorAdvisory: true}
		conf := impactSet(res.Confirmed, set)
		if !conf && !impactSet(res.Possible, set) {
			continue
		}
		if ix.RefState(a) == graph.RefMutable {
			set[factorMutable] = true
		}
		label := advisoryLabel(ix, a)
		n, _ := ix.Node(a)
		r := issueRow{Kind: issueAdvisory, Sev: "high", Confirmed: conf, Where: strings.TrimPrefix(a, "action:"), WhereKind: "action",
			Org: orgOf(a), Used: plural(usedBy(ix, a), "workflow", "workflows"), order: 2,
			Title: "Action with a known advisory reaches " + impactWords(set), Why: label}
		if n.Attrs[graph.AttrAdvisorySeverity] == "critical" || strings.Contains(label, "severity critical") {
			r.Sev = "critical"
		}
		r.Factors = factors(set)
		r.Fixes = []string{"Move every workflow off " + r.Where + " to a fixed version and pin it to that commit SHA.",
			"Rotate the secrets its workflows hold if the affected version ran."}
		r.Commands = []string{"gop fix-plan --pin " + a}
		rc := res.Confirmed
		if !conf {
			rc = res.Possible
		}
		if p, ok := res.Paths[bestTarget(rc)]; ok {
			v := viewPath(ix, p)
			r.Path = &v
		}
		out = append(out, r)
	}
	return out
}

// pinnedIssues: one per SHA-pinned action that still runs a mutable ref
// someone can push to. High when the pinned action reaches secrets,
// runners, OIDC or a cloud role, medium otherwise; confirmed when the path
// to it is.
func pinnedIssues(ix *graph.Index) []issueRow {
	var out []issueRow
	for _, pe := range ix.PinnedExposures() {
		set := map[string]bool{factorMutable: true}
		res := ix.Reach(pe.Action, graph.Options{})
		impact := impactSet(res.Confirmed, set)
		via := strings.TrimPrefix(pe.Via, "action:")
		r := issueRow{Kind: issuePinned, Sev: "medium", Confirmed: !pe.Path.Unverified, Where: strings.TrimPrefix(pe.Action, "action:"),
			WhereKind: "action", Org: orgOf(pe.Action), Used: plural(pe.Consumers, "workflow", "workflows"), order: 3,
			Title: "SHA-pinned action still runs a mutable ref"}
		if impact {
			r.Sev = "high"
			r.Title += " and reaches " + impactWords(set)
		}
		r.Why = fmt.Sprintf("%s can change %s, which the pinned action runs, so the pin does not stop new code.", pe.Path.From, firstOr(via, "a nested ref"))
		if pe.ViaNote != "" {
			r.Why += " " + pe.ViaNote
		}
		r.Factors = factors(set)
		r.Fixes = []string{"Pin " + firstOr(via, "the nested ref") + " to a commit SHA inside " + r.Where + ", or replace the action.",
			"Add an actions.lock that locks every nested ref."}
		if pe.Via != "" {
			r.Commands = []string{"gop fix-plan --pin " + pe.Via}
		}
		v := viewPath(ix, pe.Path)
		r.Path = &v
		out = append(out, r)
	}
	return out
}

// holdWords names what an agent job holds: a write token, OIDC, secrets.
func holdWords(set map[string]bool) string {
	var w []string
	for _, x := range []struct{ key, word string }{{factorWrite, "a write token"}, {factorOIDC, "OIDC"}, {factorSecrets, "secrets"}} {
		if set[x.key] {
			w = append(w, x.word)
		}
	}
	return joinAnd(w)
}

// presentFactors lists the factors any row has, in factorOrder.
func presentFactors(rows []issueRow) []issueFactor {
	set := map[string]bool{}
	for _, r := range rows {
		for _, f := range r.Factors {
			set[f.Key] = true
		}
	}
	return factors(set)
}

// joinAnd is "a", "a and b", "a, b and c".
func joinAnd(w []string) string {
	switch len(w) {
	case 0:
		return "nothing"
	case 1:
		return w[0]
	}
	return strings.Join(w[:len(w)-1], ", ") + " and " + w[len(w)-1]
}

// issuesLine is the lede of the Issues view.
func issuesLine(s issueSummary) string {
	if s.Total == 0 {
		return ""
	}
	return fmt.Sprintf("%s where facts gop read combine into a path to act on: %d critical, %d high, %d medium. %d confirmed, %d possible; the two are never added up.",
		plural(s.Total, "issue", "issues"), s.Critical, s.High, s.Medium, s.Confirmed, s.Possible)
}
