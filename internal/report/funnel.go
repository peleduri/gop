package report

import (
	"fmt"
	"strings"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// The funnel at the top of the report: how the AI agent workflows narrow
// down to the few to fix first, plus small stat widgets for the other
// headline questions. Every count is read from the graph; each stage is a
// subset of the stage before it, so the counts never grow down the funnel.

// Funnel stages, in order. A workflow's stage (agentRow.Stage) is the
// deepest one it reaches.
const (
	stageLooks     = 1 + iota // the agent attr is set, name-only matches included
	stageKnown                // a known agent action or CLI (graph.AgentConfirmed)
	stageOutsiders            // people without push access can start it (exposure outsiders)
	stageHolds                // and the agent job holds write, secrets or OIDC (graph.AgentExposed)
	stageEndToEnd             // and who can start it is confirmed, not possible only
	stageDanger               // and the agent runs with its approvals or sandbox off
	funnelStages   = stageDanger
)

// funnelDef is each stage's label and why workflows leave the funnel there.
var funnelDef = [funnelStages + 1]struct{ label, drop string }{
	stageLooks:     {"look like an AI agent (name-only matches included)", ""},
	stageKnown:     {"run a known agent action or CLI", "name-only matches: listed, never ranked"},
	stageOutsiders: {"can be started by people without push access", "need push access, an allow list, or run read-only from a fork"},
	stageHolds:     {"of those, the agent holds write, secrets or OIDC", "hold a read-only token and no secrets"},
	stageEndToEnd:  {"confirmed end-to-end agent paths", "possible only: who can start it is not visible"},
	stageDanger:    {"run in dangerous mode (approvals or sandbox off)", "keep the agent's approvals and sandbox on"},
}

// agentStage is the deepest funnel stage an agent row reaches.
func agentStage(r agentRow) int {
	switch {
	case r.NameOnly:
		return stageLooks
	case !r.Outsider:
		return stageKnown
	case !r.Exposed:
		return stageOutsiders
	case r.Possible:
		return stageHolds
	case r.Tools == "":
		return stageEndToEnd
	}
	return stageDanger
}

// funnelStage is one bar of the funnel.
type funnelStage struct {
	N, Count int
	Label    string
	// Drop is how many left since the previous stage and why, "" for the
	// first stage; DropPossible marks a drop of possible-only workflows.
	Drop         string
	DropPossible bool
	Width        string // bar width class, share of the first stage
	Tone         string // path | danger | ok (a stage that came to zero)
}

// funnel is the AI agents funnel; Empty says why there are no stages.
type funnel struct {
	Stages []funnelStage
	Line   string // the one-line summary, for the Markdown report too
	Empty  string
}

// buildFunnel turns the per-stage counts (counts[k] workflows reach stage
// k or deeper) into the funnel.
func buildFunnel(counts [funnelStages + 1]int) funnel {
	if counts[stageLooks] == 0 {
		return funnel{Empty: "No workflow in this graph looks like an AI agent (gop looks for known agent actions and CLIs, and for agent-like names), so there is no agent funnel to draw."}
	}
	var f funnel
	top := float64(counts[stageLooks])
	for k := stageLooks; k <= funnelStages; k++ {
		s := funnelStage{N: k, Count: counts[k], Label: funnelDef[k].label, Tone: "path", Width: "w0"}
		if k >= stageOutsiders {
			s.Tone = "danger"
		}
		if s.Count > 0 {
			s.Width = widthClass(max(float64(s.Count)/top, 0.08))
		} else if k > stageKnown {
			s.Tone = "ok"
		}
		if k > stageLooks {
			if d := counts[k-1] - counts[k]; d > 0 {
				s.Drop = fmt.Sprintf("−%s: %s", mcpserver.Num(d), funnelDef[k].drop)
				s.DropPossible = k == stageEndToEnd
			}
		}
		f.Stages = append(f.Stages, s)
	}
	last := counts[funnelStages]
	f.Line = fmt.Sprintf("From %s that %s like an AI agent to %s to fix first.", plural(counts[stageLooks], "workflow", "workflows"),
		map[bool]string{true: "looks", false: "look"}[counts[stageLooks] == 1], plural(last, "confirmed agent path in dangerous mode", "confirmed agent paths in dangerous mode"))
	return f
}

// statWidget is one small figure beside the funnel. Parts are shown apart,
// never added up: a confirmed and a possible count stay two numbers.
type statWidget struct {
	Label, Href, Sub, Tone string
	Parts                  []statPart
}

type statPart struct {
	Value, Unit string
	Kind        string // conf | poss | unk | "" (neutral)
}

// statWidgets are the bot merge, advisory and coverage figures.
func statWidgets(g *graph.Graph, ix *graph.Index, bot []botMergeRow) []statWidget {
	var out []statWidget

	conf, poss := 0, 0
	for _, r := range bot {
		if r.Possible {
			poss++
		} else {
			conf++
		}
	}
	bw := statWidget{Label: "Bots merge with no human", Sub: "repos where a bot approves and merges a pull request its author can steer",
		Parts: []statPart{{fmt.Sprint(conf), "confirmed", "conf"}, {fmt.Sprint(poss), "possible", "poss"}}}
	if len(bot) > 0 {
		bw.Href = "#ai-self-merge"
	}
	switch {
	case conf > 0:
		bw.Tone = "crit"
	case poss > 0:
		bw.Tone = "poss"
	default:
		bw.Tone = "ok"
	}
	out = append(out, bw)

	refs, unknown, skipped := 0, map[string]bool{}, false
	for _, n := range g.Nodes {
		if n.Kind == graph.KindActionRef {
			refs++
		}
	}
	for _, c := range g.Coverage {
		if c.Fact != graph.CoverageAdvisories {
			continue
		}
		if strings.HasPrefix(c.Scope, "enterprise:") {
			skipped = true
		} else {
			unknown[c.Scope] = true
		}
	}
	affected := len(ix.AdvisoryActions())
	aw := statWidget{Label: "Action refs with a known advisory", Href: "#top-risks",
		Sub: "unknown: gop could not place the ref, not safe"}
	switch {
	case skipped && affected == 0:
		aw.Parts, aw.Tone, aw.Href = []statPart{{"not checked", "", "unk"}}, "unk", "#coverage"
		aw.Sub = "no advisory data: unknown, not safe"
	default:
		aw.Parts = []statPart{{fmt.Sprint(affected), "affected", "conf"}, {fmt.Sprint(len(unknown)), "unknown", "unk"}, {fmt.Sprint(refs), "total", ""}}
		switch {
		case affected > 0:
			aw.Tone = "crit"
		case len(unknown) > 0:
			aw.Tone, aw.Href = "unk", "#coverage"
		}
	}
	out = append(out, aw)

	orgs, gaps := map[string]bool{}, map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindOrg {
			orgs[n.ID] = true
		}
	}
	for _, c := range g.Coverage {
		if o := graph.OrgOf(c.Scope); o != "" {
			orgs[o], gaps[o] = true, true
		}
	}
	cw := statWidget{Label: "Orgs gop could see", Href: "#coverage", Sub: "partly visible: some facts unknown, not absent",
		Parts: []statPart{{fmt.Sprint(len(orgs) - len(gaps)), "fully", "conf"}, {fmt.Sprint(len(gaps)), "partly", "unk"}}}
	cw.Tone = "ok"
	if len(gaps) > 0 {
		cw.Tone = "unk"
	}
	if len(orgs) == 0 {
		cw.Parts, cw.Sub = []statPart{{"0", "orgs", ""}}, "no orgs in this graph"
	}
	return append(out, cw)
}
