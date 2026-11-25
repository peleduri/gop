package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Agent paths: one ordered chain per AI agent workflow, from who can start
// it to what its code reaches. Built from facts the graph already holds (the
// agent attrs of the workflow node and its CAN_TRIGGER, EXECUTES_WITH,
// DEFINED_IN, CAN_MERGE_VIA_BOT and CAN_ASSUME edges); nothing is collected.
//
//	slot:  who → input → workflow → agent → code → secrets → merge → oidc → role
//	zone:  outside   |   repo   |      runner        |  repo  |    cloud
//
// A slot the agent does not have is drawn dimmed ("not held"), never dropped,
// so the shape of every path is the same and an absent hop reads as absent.

// Hop slots, in path order.
const (
	hopWho = iota
	hopInput
	hopWorkflow
	hopAgent
	hopCode
	hopSecrets
	hopMerge
	hopOIDC
	hopRole
	hopCount
)

// hopLayout places each slot on the 1300x560 canvas and names its zone.
var hopLayout = [hopCount]struct{ X, Y int }{
	hopWho: {30, 90}, hopInput: {30, 250}, hopWorkflow: {240, 90}, hopMerge: {240, 370},
	hopAgent: {625, 90}, hopCode: {625, 250}, hopSecrets: {805, 250}, hopOIDC: {1015, 250}, hopRole: {1015, 370},
}

// pathZone is one dashed region of the canvas.
type pathZone struct {
	X, Y, W, H int
	Title, Sub string
	Danger     bool // the runner zone when the agent runs in dangerous mode
}

// pathHop is one step of an agent path.
type pathHop struct {
	N               int    // 1-based position among present hops; 0 when absent
	Slot            int    // hop slot
	Kind            string // e.g. "Agent · dangerous mode"
	Title, Detail   string
	Risk            string // one or two words for the hop card
	Ev, EvLabel     string // evidence class and label
	Present         bool
	Danger, Red     bool // dangerous-mode agent; attacker-controlled from here on
	X, Y, CX, CY    int  // node box and center
	Short, ShortSub string
}

// pathFix is a what-if toggle: Chain cuts its hop and everything after it;
// otherwise it removes only the listed hops.
type pathFix struct {
	ID, Label, Detail string
	Command           string // the gop fix-plan flag that models it, when one exists
	Chain             bool
	Cuts              []int // 1-based hop numbers
	CutsAttr          string
}

// pathEdge joins two present hops.
type pathEdge struct {
	D        string // SVG path data
	From, To int    // 1-based hop numbers
}

// agentPath is one agent workflow's chain.
type agentPath struct {
	ID       string // dom id suffix: ap-1, ap-2, ...
	Workflow string
	Agent    string
	Mode     string // dangerous-mode flags, comma separated; empty when none
	Banner   string
	Tone     string // crit | high | ok
	Outsider bool
	Hops     []pathHop // all slots, present or not
	Present  []pathHop // present hops in order
	Edges    []pathEdge
	Zones    []pathZone
	Fixes    []pathFix
	EvCount  string // "live 5, inferred 2, supplied 1"
	Reach    string // last present hop's title, for the one-line list
	rank     int
	redCount int
}

// agentPathsMax caps the section; the rest are in "AI agents in CI".
const agentPathsMax = 5

// buildAgentPaths returns the ranked agent paths: outsider-startable agents in
// dangerous mode first, then outsider-startable, then dangerous mode, then
// the rest; more attacker-controlled hops first within a rank.
func buildAgentPaths(ix *graph.Index) []agentPath {
	var out []agentPath
	for _, id := range ix.AgentWorkflows() {
		n, ok := ix.Node(id)
		if !ok || !graph.AgentConfirmed(n) {
			continue
		}
		out = append(out, agentPathFor(ix, n))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		if out[i].redCount != out[j].redCount {
			return out[i].redCount > out[j].redCount
		}
		return out[i].Workflow < out[j].Workflow
	})
	if len(out) > agentPathsMax {
		out = out[:agentPathsMax]
	}
	for i := range out {
		out[i].ID = "ap-" + strconv.Itoa(i+1)
	}
	return out
}

// bestEvidence is the strongest of the evidence levels, live first.
func bestEvidence(es []graph.Evidence) graph.Evidence {
	order := map[graph.Evidence]int{graph.Live: 0, graph.Audit: 1, graph.Supplied: 2, graph.Inferred: 3}
	best, bi := graph.NotVisible, 9
	for _, e := range es {
		if r, ok := order[e]; ok && r < bi {
			best, bi = e, r
		}
	}
	return best
}

func attrEv(n graph.Node, attr string) graph.Evidence {
	if e, ok := n.AttrEvidence[attr]; ok {
		return e
	}
	return n.Evidence
}

func agentPathFor(ix *graph.Index, n graph.Node) agentPath {
	a := n.Attrs
	wf := strings.TrimPrefix(n.ID, "workflow:")
	p := agentPath{Workflow: wf, Agent: a[graph.AttrAgent], Mode: strings.Join(graph.AgentUnrestricted(n), ", ")}
	exposure := a[graph.AttrAgentExposure]
	untrusted := exposure == graph.ExposureOutsiders || exposure == graph.ExposureListed
	p.Outsider = exposure == graph.ExposureOutsiders
	danger := p.Mode != ""

	hops := make([]pathHop, hopCount)
	for s := range hops {
		hops[s] = pathHop{Slot: s, Ev: "nv", EvLabel: "not visible"}
	}
	set := func(s int, h pathHop) {
		h.Slot, h.Present = s, true
		hops[s] = h
	}

	// who can start it
	var trig []graph.Evidence
	var who []string
	for _, e := range ix.In(n.ID) {
		if e.Kind == graph.CanTrigger {
			trig = append(trig, e.Evidence)
			who = append(who, e.From)
		}
	}
	sort.Strings(who)
	whoEv := bestEvidence(trig)
	if len(trig) == 0 {
		whoEv = attrEv(n, graph.AttrAgentExposure)
	}
	triggers := strings.ReplaceAll(a["risky_triggers"], ",", ", ")
	switch exposure {
	case graph.ExposureOutsiders:
		t := "People without push access"
		for _, w := range who {
			if w == "external:anyone" {
				t = "Anyone on GitHub"
			}
		}
		set(hopWho, pathHop{Kind: "Trigger · who", Title: t, Short: t, ShortSub: "no push access",
			Detail: "They can start the agent job" + onTriggers(triggers) + " with the base repo's token and secrets.", Risk: "Outsiders", Ev: evClass(whoEv), EvLabel: evLabel(whoEv)})
	case graph.ExposureListed:
		set(hopWho, pathHop{Kind: "Trigger · who", Title: "Named users without write access", Short: "Named users", ShortSub: "no write access",
			Detail: "The agent's allow list lets them start it" + onTriggers(triggers) + ".", Risk: "Listed users", Ev: evClass(whoEv), EvLabel: evLabel(whoEv)})
	case graph.ExposureForkRO:
		set(hopWho, pathHop{Kind: "Trigger · who", Title: "Anyone, from a fork", Short: "Fork pull request", ShortSub: "read-only token",
			Detail: "A fork's pull_request run gets a read-only token and no secrets.", Risk: "Read-only", Ev: evClass(whoEv), EvLabel: evLabel(whoEv)})
	default:
		set(hopWho, pathHop{Kind: "Trigger · who", Title: "Maintainers with write access", Short: "Maintainers", ShortSub: "write access",
			Detail: "Only people who can already push can start it.", Risk: "Insiders", Ev: evClass(n.Evidence), EvLabel: evLabel(n.Evidence)})
	}

	// untrusted input
	prompt := strings.ReplaceAll(a[graph.AttrAgentPrompt], ",", ", ")
	var reads []string
	if untrusted {
		for _, t := range strings.Split(a["risky_triggers"], ",") {
			if v := readsByTrigger[t]; v != "" {
				reads = append(reads, v)
			}
		}
	}
	if prompt != "" || len(reads) > 0 {
		d := ""
		if prompt != "" {
			d = prompt + " reaches the prompt or script."
		}
		if len(reads) > 0 {
			d = strings.TrimSpace(d + " The agent reads the triggering " + strings.Join(reads, ", ") + " text.")
		}
		ev := attrEv(n, graph.AttrAgentPrompt)
		set(hopInput, pathHop{Kind: "Trigger · input", Title: "Untrusted text reaches the agent", Short: "Untrusted input", ShortSub: firstOr(prompt, strings.Join(reads, ", ")),
			Detail: d, Risk: "Injection", Ev: evClass(ev), EvLabel: evLabel(ev)})
	}

	// workflow and token
	perms := strings.ReplaceAll(a[graph.AttrAgentPerms], ",", ", ")
	if perms == "" {
		perms = "read-only"
	}
	writes := 0
	for _, s := range strings.Split(a[graph.AttrAgentPerms], ",") {
		if strings.HasSuffix(s, ":write") || s == "write-all" || s == "default" {
			writes++
		}
	}
	risk := "Read-only token"
	if writes > 0 {
		risk = plural(writes, "write scope", "write scopes")
	}
	set(hopWorkflow, pathHop{Kind: "Workflow · token", Title: wf, Short: lastPart(wf), ShortSub: firstOr(triggers, "on: push"),
		Detail: "Agent job token: " + perms + "; runner: " + firstOr(a[graph.AttrAgentRunner], "unknown") + ".", Risk: risk, Ev: evClass(attrEv(n, graph.AttrAgentPerms)), EvLabel: evLabel(attrEv(n, graph.AttrAgentPerms))})

	// the agent
	agentKind := "Agent"
	agentRisk := "Approvals on"
	if danger {
		agentKind, agentRisk = "Agent · dangerous mode", "No approvals"
	}
	ref := a[graph.AttrAgentRefKind]
	ad := "Runs " + p.Agent
	if ref != "" {
		ad += ", pinned to a " + ref
	}
	if danger {
		ad += ", with " + p.Mode + ": the agent runs tools without its own approval prompts or sandbox."
	} else {
		ad += "."
	}
	set(hopAgent, pathHop{Kind: agentKind, Title: p.Agent, Short: firstPart(p.Agent), ShortSub: firstOr(p.Mode, "approvals on"),
		Detail: ad, Risk: agentRisk, Danger: danger, Ev: evClass(attrEv(n, graph.AttrAgentTools)), EvLabel: evLabel(attrEv(n, graph.AttrAgentTools))})

	// code runs
	if danger || untrusted {
		d := "Commands the agent runs are driven by "
		if untrusted {
			d += "text people without push access control."
		} else {
			d += "maintainers' input, with no approval step."
		}
		set(hopCode, pathHop{Kind: "Code runs", Title: "Commands on the runner", Short: "Code runs", ShortSub: map[bool]string{true: "attacker-driven", false: "no approval"}[untrusted],
			Detail: d, Risk: map[bool]string{true: "Attacker code", false: "Unreviewed code"}[untrusted], Ev: "inferred", EvLabel: "inferred"})
	}

	// secrets, oidc, cloud
	var secEv, oidcEv []graph.Evidence
	var roles []string
	var roleEv []graph.Evidence
	for _, e := range ix.Out(n.ID) {
		switch e.Kind {
		case graph.ExecutesWith:
			if t, ok := ix.Node(e.To); ok {
				switch t.Kind {
				case graph.KindSecret:
					secEv = append(secEv, e.Evidence)
				case graph.KindOIDC:
					oidcEv = append(oidcEv, e.Evidence)
				}
			}
		case graph.CanAssume:
			name := strings.TrimPrefix(e.To, "cloud:")
			if t, ok := ix.Node(e.To); ok && t.Name != "" {
				name = t.Name
			}
			roles = append(roles, name)
			roleEv = append(roleEv, e.Evidence)
		}
	}
	if s, _ := strconv.Atoi(a[graph.AttrAgentSecrets]); s > 0 {
		ev := bestEvidence(secEv)
		if len(secEv) == 0 {
			ev = attrEv(n, graph.AttrAgentSecrets)
		}
		set(hopSecrets, pathHop{Kind: "Secrets", Title: plural(s, "secret", "secrets") + " in the agent job", Short: "Secrets in env", ShortSub: plural(s, "secret", "secrets"),
			Detail: "Any command the agent runs can read them.", Risk: plural(s, "secret", "secrets"), Ev: evClass(ev), EvLabel: evLabel(ev)})
	}

	// write and merge
	repo := ""
	for _, e := range ix.Out(n.ID) {
		if e.Kind == graph.DefinedIn {
			repo = e.To
		}
	}
	var mergeEv []graph.Evidence
	if repo != "" {
		for _, e := range ix.In(repo) {
			if e.Kind == graph.CanMergeViaBot {
				mergeEv = append(mergeEv, e.Evidence)
			}
		}
	}
	contentsWrite := strings.Contains(a[graph.AttrAgentPerms], "contents:write") || strings.Contains(a[graph.AttrAgentPerms], "write-all")
	botMerge := len(mergeEv) > 0
	if botMerge || contentsWrite {
		r := strings.TrimPrefix(repo, "repo:")
		t, d, rk, ev := "Push to "+firstOr(r, "the repo"), "The token can push branches to the repo.", "Write", attrEv(n, graph.AttrAgentPerms)
		if botMerge {
			ev = bestEvidence(mergeEv)
			t, d, rk = "Merge to the default branch of "+firstOr(r, "the repo"), "A bot approves and merges pull requests with no human review (CAN_MERGE_VIA_BOT).", "No human"
		}
		set(hopMerge, pathHop{Kind: "Write · merge", Title: t, Short: firstOr(lastPart(r), "repo"), ShortSub: map[bool]string{true: "merge, no human", false: "push"}[botMerge],
			Detail: d, Risk: rk, Ev: evClass(ev), EvLabel: evLabel(ev)})
	}
	if strings.Contains(a[graph.AttrAgentPerms], "id-token:write") || len(oidcEv) > 0 {
		ev := bestEvidence(oidcEv)
		if len(oidcEv) == 0 {
			ev = attrEv(n, graph.AttrAgentPerms)
		}
		set(hopOIDC, pathHop{Kind: "Cloud identity", Title: "id-token: write", Short: "id-token: write", ShortSub: "OIDC token",
			Detail: "The job can request an OIDC token for a cloud provider.", Risk: "OIDC", Ev: evClass(ev), EvLabel: evLabel(ev)})
	}
	if len(roles) > 0 {
		sort.Strings(roles)
		ev := bestEvidence(roleEv)
		short := make([]string, len(roles))
		for i, r := range roles {
			short[i] = lastPart(r)
		}
		set(hopRole, pathHop{Kind: "Cloud reach", Title: "Assume " + strings.Join(short, ", "), Short: short[0], ShortSub: plural(len(roles), "cloud role", "cloud roles"),
			Detail: "A trust policy accepts this workflow's token: " + strings.Join(roles, ", ") + ".", Risk: "Cloud role", Ev: evClass(ev), EvLabel: evLabel(ev)})
	}

	// a fork's pull_request run gets none of the job's write scopes or secrets
	if exposure == graph.ExposureForkRO {
		for _, s := range []int{hopSecrets, hopMerge, hopOIDC, hopRole} {
			if hops[s].Present {
				hops[s] = pathHop{Slot: s, Ev: "nv", EvLabel: "not visible", ShortSub: "not given to forks"}
			}
		}
	}

	// number present hops, mark red, place nodes
	num, evc := 0, map[string]int{}
	for s := range hops {
		h := &hops[s]
		h.X, h.Y = hopLayout[s].X, hopLayout[s].Y
		h.CX, h.CY = h.X+80, h.Y+25
		if !h.Present {
			h.Short = slotName[s]
			h.ShortSub = firstOr(h.ShortSub, "not held")
			continue
		}
		h.Short, h.ShortSub = clip(h.Short, 20), clip(h.ShortSub, 24)
		num++
		h.N = num
		if untrusted && s > hopAgent {
			h.Red = true
			p.redCount++
		}
		evc[h.EvLabel]++
		p.Present = append(p.Present, *h)
	}
	p.Hops = hops
	for i := 1; i < len(p.Present); i++ {
		a, b := p.Present[i-1], p.Present[i]
		c := (a.CX + b.CX) / 2
		p.Edges = append(p.Edges, pathEdge{From: a.N, To: b.N, D: fmt.Sprintf("M%d,%d C%d,%d %d,%d %d,%d", a.CX, a.CY, c, a.CY, c, b.CY, b.CX, b.CY)})
	}
	var evs []string
	for _, k := range []string{"live", "audit", "inferred", "supplied file", "not visible"} {
		if evc[k] > 0 {
			evs = append(evs, fmt.Sprintf("%s %d", k, evc[k]))
			delete(evc, k)
		}
	}
	var rest []string
	for k := range evc {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		evs = append(evs, fmt.Sprintf("%s %d", k, evc[k]))
	}
	p.EvCount = strings.Join(evs, ", ")
	last := p.Present[len(p.Present)-1]
	p.Reach = last.Title

	p.Zones = []pathZone{
		{10, 20, 200, 470, "Who starts it", "outside or inside the org", false},
		{225, 20, 370, 470, "Repository", firstOr(strings.TrimPrefix(repo, "repo:"), "workflow repo"), false},
		{610, 20, 370, 330, "Actions runner", firstOr(a[graph.AttrAgentRunner], "runner") + " · agent job", danger},
		{995, 20, 200, 470, "Cloud", "supplied trust", false},
	}

	switch {
	case p.Outsider && danger:
		p.rank, p.Tone = 0, "crit"
	case p.Outsider:
		p.rank, p.Tone = 1, "crit"
	case untrusted && danger:
		p.rank, p.Tone = 2, "high"
	case danger:
		p.rank, p.Tone = 3, "high"
	case untrusted:
		p.rank, p.Tone = 4, "high"
	default:
		p.rank, p.Tone = 5, "ok"
	}
	whoT := hops[hopWho].Title
	mode := ""
	if danger {
		mode = " in dangerous mode"
	}
	p.Banner = fmt.Sprintf("%s can make an agent%s run code that reaches: %s.", whoT, mode, last.Title)
	if last.Slot <= hopAgent {
		p.Banner = fmt.Sprintf("%s can start an agent%s that holds a read-only token and no secrets.", whoT, mode)
	}

	// what-if fixes, mapped to hops
	hn := func(s int) int { return hops[s].N }
	addFix := func(f pathFix) {
		var cs []string
		for _, c := range f.Cuts {
			cs = append(cs, strconv.Itoa(c))
		}
		if len(cs) == 0 {
			return
		}
		f.CutsAttr = strings.Join(cs, " ")
		p.Fixes = append(p.Fixes, f)
	}
	if untrusted && hn(hopWho) > 0 {
		addFix(pathFix{ID: "trigger", Label: "Run it only for people with write access", Detail: "check the actor's permission before the agent runs, or require approval for outside contributors",
			Command: "gop fix-plan --harden-trigger " + n.ID, Chain: true, Cuts: []int{hn(hopWho)}})
	}
	if danger && hn(hopCode) > 0 {
		addFix(pathFix{ID: "mode", Label: "Drop " + p.Mode, Detail: "keep the agent's approval prompts and sandbox, and scope its allowed tools", Chain: true, Cuts: []int{hn(hopCode)}})
	}
	if writes > 0 {
		var cuts []int
		for _, s := range []int{hopMerge, hopOIDC, hopRole} {
			if hn(s) > 0 && (s != hopMerge || !botMerge) {
				cuts = append(cuts, hn(s))
			}
		}
		addFix(pathFix{ID: "token", Label: "Give the agent job a read-only token", Detail: "permissions: contents: read, no id-token; write in a separate job",
			Command: "gop fix-plan --restrict-token " + n.ID, Cuts: cuts})
	}
	if botMerge && hn(hopMerge) > 0 {
		addFix(pathFix{ID: "merge", Label: "Require a human approval after the last push", Detail: "remove the bot from the default branch's bypass list", Cuts: []int{hn(hopMerge)}})
	}
	if hn(hopSecrets) > 0 {
		addFix(pathFix{ID: "secrets", Label: "Keep secrets out of the agent job", Detail: "pass only what the agent step needs", Cuts: []int{hn(hopSecrets)}})
	}
	if hn(hopRole) > 0 {
		addFix(pathFix{ID: "trust", Label: "Pin the cloud trust to one workflow and branch", Detail: "match sub on the exact workflow ref, not a repo wildcard", Cuts: []int{hn(hopRole)}})
	}
	return p
}

var slotName = [hopCount]string{"Who", "Input", "Workflow", "Agent", "Code runs", "Secrets", "Write", "OIDC", "Cloud role"}

func onTriggers(t string) string {
	if t == "" {
		return ""
	}
	return " on " + t
}

// clip shortens a box label to n runes with an ellipsis: SVG text does not wrap.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func firstOr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func lastPart(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func firstPart(s string) string {
	if i := strings.Index(s, ","); i >= 0 {
		return s[:i]
	}
	return s
}

// agentPathsLine is the section's lede.
func agentPathsLine(ps []agentPath) string {
	dm, out := 0, 0
	for _, p := range ps {
		if p.Mode != "" {
			dm++
		}
		if p.Outsider {
			out++
		}
	}
	return fmt.Sprintf("%s; %d in dangerous mode, %d that people without push access can start.", plural(len(ps), "agent path", "agent paths"), dm, out)
}
