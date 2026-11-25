package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// agentRow is one workflow in the "AI agents in CI" section: who can start
// its agent, what the agent holds and reaches, the untrusted text it reads
// and the fixes (see docs/agents-in-ci.md).
type agentRow struct {
	Workflow   string // repo/path
	Kind       string // agent kinds, comma separated
	Confidence string // action | cli | name_only
	NameOnly   bool
	// Exposure is the label of who can start it; Tone crit | high | med | ok.
	Exposure, Tone string
	// Who names the principals that can start it without push access,
	// from its CAN_TRIGGER edges; Possible when none of them is verified.
	Who      string
	Possible bool
	Triggers string
	Holds    string // write scopes and secrets of the agent job, or "read-only token"
	Reach    string // confirmed terminal reach of the workflow
	Prompt   string // untrusted contexts interpolated into the agent steps
	Reads    string // event text the agent reads on its own (comments, issues, pull requests)
	Tools    string // approval or sandbox settings turned off
	// Memory is the cross-run agent memory line (graph.AgentMemoryNote),
	// MemoryPossible set when the match is not verified.
	Memory         string
	MemoryPossible bool
	Fixes          []string
	// Exposed: AgentExposed, the rank factor's workflow side.
	Exposed bool
}

// readsByTrigger is the event text an agent reads by itself on each trigger.
var readsByTrigger = map[string]string{
	"issue_comment": "comment", "issues": "issue", "pull_request_target": "pull request",
	"pull_request_review": "review", "pull_request_review_comment": "review comment",
	"discussion": "discussion", "discussion_comment": "discussion comment", "workflow_run": "upstream run",
}

// agentRows builds the AI agents section, exposed agents first.
func agentRows(ix *graph.Index) (rows []agentRow, line string) {
	ids := ix.AgentWorkflows()
	if len(ids) == 0 {
		return nil, ""
	}
	exposedN, outsiders := 0, 0
	for _, id := range ids {
		n, _ := ix.Node(id)
		r := agentRow{Workflow: strings.TrimPrefix(id, "workflow:"), Kind: n.Attrs[graph.AttrAgent],
			Confidence: n.Attrs[graph.AttrAgentConfidence], NameOnly: !graph.AgentConfirmed(n), Exposed: graph.AgentExposed(n)}
		if r.NameOnly {
			r.Kind = "unknown"
			r.Exposure, r.Tone = "name only: not counted as an agent", "unk"
			rows = append(rows, r)
			continue
		}
		var conf, poss []string
		for _, e := range ix.In(id) {
			if e.Kind != graph.CanTrigger {
				continue
			}
			if graph.Verified(e.Evidence) {
				conf = append(conf, e.From)
			} else {
				poss = append(poss, e.From)
			}
		}
		sort.Strings(conf)
		sort.Strings(poss)
		triggers := strings.Split(n.Attrs["risky_triggers"], ",")
		r.Triggers = strings.Join(triggers, ", ")
		switch n.Attrs[graph.AttrAgentExposure] {
		case graph.ExposureOutsiders:
			outsiders++
			r.Exposure, r.Tone = "outsiders: people without push access", "crit"
			switch {
			case len(conf) > 0:
				r.Who = whoList(conf)
			case len(poss) > 0:
				r.Who, r.Possible = whoList(poss), true
			default:
				r.Who = "nobody gop can name (see coverage)"
			}
			if n.Attrs[graph.AttrAgentGate] == graph.GateUnknown {
				r.Possible = true
			}
		case graph.ExposureListed:
			r.Exposure, r.Tone = "named users without write access", "high"
		case graph.ExposureForkRO:
			r.Exposure, r.Tone = "anyone, from a fork's pull_request (read-only token, no secrets)", "med"
			r.Triggers = "pull_request"
		default:
			r.Exposure, r.Tone = "maintainers: write access only", "ok"
			r.Triggers = ""
		}
		if !r.Exposed && r.Tone == "crit" {
			r.Tone = "high" // outsiders, but nothing to write or leak
		}
		if imp := graph.AgentImpact(n); len(imp) > 0 {
			r.Holds = strings.Join(imp, ", ")
			if n.Attrs[graph.AttrAgentExposure] == graph.ExposureForkRO {
				r.Holds += " (not given to a fork's pull_request run)"
			}
		} else {
			r.Holds = "read-only token, no secrets"
		}
		if r.Exposed {
			exposedN++
		}
		res := ix.Reach(id, graph.Options{})
		r.Reach = reachPhrase(res.Confirmed)
		r.Prompt = strings.ReplaceAll(n.Attrs[graph.AttrAgentPrompt], ",", ", ")
		if r.Tone == "crit" || r.Tone == "high" {
			var reads []string
			for _, t := range triggers {
				if v := readsByTrigger[t]; v != "" {
					reads = append(reads, v)
				}
			}
			if len(reads) > 0 {
				r.Reads = "the triggering " + strings.Join(reads, ", ") + " text"
			}
		}
		r.Tools = strings.Join(graph.AgentUnrestricted(n), ", ")
		r.Fixes = graph.AgentFixes(n)
		if graph.AgentMemoryPoisoned(n) {
			r.Memory, r.MemoryPossible = graph.AgentMemoryNote(n), !graph.AgentMemoryConfirmed(n)
			r.Fixes = append(r.Fixes, graph.AgentMemoryFixes(n)...)
		}
		rows = append(rows, r)
	}
	rank := func(r agentRow) int {
		switch {
		case r.NameOnly:
			return 5
		case r.Exposed && !r.Possible:
			return 0
		case r.Exposed:
			return 1
		}
		return map[string]int{"crit": 2, "high": 2, "med": 3, "ok": 4}[r.Tone]
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank(rows[i]) < rank(rows[j]) })
	verb := "run"
	if len(ids) == 1 {
		verb = "runs"
	}
	line = fmt.Sprintf("%s %s an AI coding agent; %d can be started by people without push access, %d of them while the agent holds write, secrets or OIDC.",
		plural(len(ids), "workflow", "workflows"), verb, outsiders, exposedN)
	return rows, line
}

// whoList names up to three principals, then a count.
func whoList(ps []string) string {
	names := make([]string, 0, 3)
	for i, p := range ps {
		if i == 3 {
			return strings.Join(names, ", ") + fmt.Sprintf(" and %d more", len(ps)-3)
		}
		if p == "external:anyone" {
			p = "anyone on the internet"
		}
		names = append(names, p)
	}
	return strings.Join(names, ", ")
}

// reachPhrase lists confirmed terminal reach: cloud roles, OIDC, secrets,
// runners and repos.
func reachPhrase(r graph.Reached) string {
	var parts []string
	for _, x := range []struct {
		n         int
		one, many string
	}{{len(r.CloudTargets), "cloud role", "cloud roles"}, {len(r.OIDC), "OIDC trust", "OIDC trusts"},
		{len(r.Secrets), "secret scope", "secret scopes"}, {len(r.Runners), "self-hosted runner pool", "self-hosted runner pools"},
		{len(r.Repos), "repo", "repos"}} {
		if x.n > 0 {
			parts = append(parts, plural(x.n, x.one, x.many))
		}
	}
	if len(parts) == 0 {
		return "nothing beyond the workflow"
	}
	return strings.Join(parts, ", ")
}
