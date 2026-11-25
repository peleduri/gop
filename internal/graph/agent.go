package graph

import (
	"sort"
	"strconv"
	"strings"
)

// IsAgent reports whether a workflow node runs an AI coding agent, by any
// signal, the weak name-only match included (attr agent, see
// docs/agents-in-ci.md).
func IsAgent(n Node) bool {
	return n.Kind == KindWorkflow && n.Attrs[AttrAgent] != ""
}

// AgentConfirmed reports whether a workflow runs an agent by a strong
// signal: a known agent action or CLI. A name-only match never is.
func AgentConfirmed(n Node) bool {
	return IsAgent(n) && n.Attrs[AttrAgentConfidence] != AgentNameOnly && n.Attrs[AttrAgentConfidence] != ""
}

// AgentImpact lists what an agent job holds that a prompt injection can
// use: write scopes of its token (contents, pull-requests, id-token, ...)
// and the secrets it references. Empty when it holds none of them; a token
// that takes the repo default is not counted (gop did not see it write).
func AgentImpact(n Node) []string {
	var out []string
	for _, p := range splitAttr(n.Attrs[AttrAgentPerms]) {
		if strings.HasSuffix(p, ":write") || p == "write-all" {
			out = append(out, p)
		}
	}
	if s, err := strconv.Atoi(n.Attrs[AttrAgentSecrets]); err == nil && s > 0 {
		out = append(out, "secrets")
	}
	return out
}

// AgentExposed reports whether a workflow is an agent workflow that people
// without push access can start with write, secrets or OIDC: a strong agent
// signal, exposure outsiders and a non-empty AgentImpact. This is the
// workflow side of the agent_exposed rank factor.
func AgentExposed(n Node) bool {
	return AgentConfirmed(n) && n.Attrs[AttrAgentExposure] == ExposureOutsiders && len(AgentImpact(n)) > 0
}

// AgentUnrestricted lists the agent_tools values that remove the agent's own
// approval or sandbox (every AgentToolFlags value but allowed_tools).
func AgentUnrestricted(n Node) []string {
	var out []string
	for _, f := range splitAttr(n.Attrs[AttrAgentTools]) {
		if f != "allowed_tools" {
			out = append(out, f)
		}
	}
	return out
}

// AgentFixes are the changes that shrink an agent workflow's exposure, most
// effective first, from its agent attrs. Empty for a name-only match.
func AgentFixes(n Node) []string {
	if !AgentConfirmed(n) {
		return nil
	}
	a := n.Attrs
	var out []string
	switch a[AttrAgentExposure] {
	case ExposureOutsiders, ExposureListed:
		off := "move it off " + orList(splitAttr(a["risky_triggers"]), "triggers outsiders can cause")
		switch a[AttrAgentGate] {
		case GateAnyone, GateListed:
			out = append(out, "Restrict who can start it: remove allowed_non_write_users / allow-users (or allowed_bots) so the action's write-access check applies, or "+
				off+", or require approval for outside contributors (an environment with required reviewers).")
		case GateNone:
			out = append(out, "Restrict who can start it: the agent has no actor check of its own, so "+off+
				", check the actor's repository permission in a step before the agent runs, or require approval for outside contributors (an environment with required reviewers).")
		default:
			out = append(out, "Restrict who can start it: confirm the action checks the actor's write access, or "+off+
				", or require approval for outside contributors (an environment with required reviewers).")
		}
	}
	perms := splitAttr(a[AttrAgentPerms])
	var writes []string
	for _, p := range perms {
		if strings.HasSuffix(p, ":write") || p == "write-all" || p == "default" {
			writes = append(writes, p)
		}
	}
	if len(writes) > 0 {
		out = append(out, "Give the agent job a read-only token (permissions: contents: read; it now has "+strings.Join(writes, ", ")+
			") and make changes in a separate job that takes the agent's output.")
	}
	switch a[AttrAgentRefKind] {
	case "tag", "branch":
		out = append(out, "Pin the agent action to a full commit SHA: a "+a[AttrAgentRefKind]+" can be moved to code that runs with this job's token and secrets.")
	}
	if u := AgentUnrestricted(n); len(u) > 0 {
		out = append(out, "Drop "+strings.Join(u, ", ")+": keep the agent's own approval prompts and sandbox.")
	}
	if !hasAttrValue(a[AttrAgentTools], "allowed_tools") && (a[AttrAgentExposure] == ExposureOutsiders || a[AttrAgentExposure] == ExposureListed || len(AgentUnrestricted(n)) > 0) {
		out = append(out, "Scope the allowed tools to what the job needs, for example --allowedTools \"Bash(gh pr comment:*)\".")
	}
	var ctxs []string
	prContent := false
	for _, p := range splitAttr(a[AttrAgentPrompt]) {
		if p == PromptPRContent {
			prContent = true
			continue
		}
		ctxs = append(ctxs, p)
	}
	if len(ctxs) > 0 {
		out = append(out, "Stop interpolating "+strings.Join(ctxs, ", ")+
			" into the prompt or script: pass it through env or a file, and treat what the agent reads as untrusted.")
	}
	if prContent {
		out = append(out, "The pull request's files, diff or text reach an AI step that holds secrets: keep secrets the step does not need out of its env, and treat the model's output as untrusted (never run it or pass it to a write step unchecked).")
	}
	return out
}

// AgentWorkflows lists the workflow nodes with any agent signal, sorted by ID.
func (ix *Index) AgentWorkflows() []string {
	var out []string
	for id, n := range ix.nodes {
		if IsAgent(n) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// agentExposedOn counts the confirmed-reached workflows of r that are
// AgentExposed and that r's principal starts through a CAN_TRIGGER edge
// into the workflow: it controls the agent without push access. A principal
// that can push to the workflow's repo by a confirmed path that does not go
// through the workflow already controls it, so the workflow is not counted
// for it.
func (ix *Index) agentExposedOn(r Result) int {
	if !ix.hasAgents() {
		return 0
	}
	n := 0
	for _, w := range r.Confirmed.Workflows {
		if !AgentExposed(ix.nodes[w]) {
			continue
		}
		p, ok := r.Paths[w]
		if !ok || p.Unverified || !hasHop(p, CanTrigger, w) {
			continue
		}
		if ix.pushesWithout(r, w) {
			continue
		}
		n++
	}
	return n
}

// pushesWithout reports whether r confirmed-reaches the repo workflow w is
// defined in by a path that does not pass through w.
func (ix *Index) pushesWithout(r Result, w string) bool {
	for _, e := range ix.out[w] {
		if e.Kind != DefinedIn {
			continue
		}
		rp, ok := r.Paths[e.To]
		if !ok || rp.Unverified {
			continue
		}
		through := false
		for _, h := range rp.Hops {
			if h.From == w || h.To == w {
				through = true
				break
			}
		}
		if !through {
			return true
		}
	}
	return false
}

func hasHop(p Path, kind EdgeKind, to string) bool {
	for _, h := range p.Hops {
		if h.Kind == kind && h.To == to {
			return true
		}
	}
	return false
}

// hasAgents reports whether any workflow node is AgentExposed (cached).
func (ix *Index) hasAgents() bool {
	ix.agentOnce.Do(func() {
		for _, n := range ix.nodes {
			if AgentExposed(n) {
				ix.agentAny = true
				return
			}
		}
	})
	return ix.agentAny
}

func splitAttr(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func hasAttrValue(list, v string) bool {
	for _, x := range splitAttr(list) {
		if x == v {
			return true
		}
	}
	return false
}

func orList(xs []string, empty string) string {
	switch len(xs) {
	case 0:
		return empty
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " or " + xs[len(xs)-1]
}

// AgentMemoryPoisoned reports whether a workflow runs an agent that
// outsiders can start and that saves state a privileged job restores on a
// later run (agent_memory_readers, see docs/agents-in-ci.md "Agent memory
// across runs").
func AgentMemoryPoisoned(n Node) bool {
	return AgentConfirmed(n) && n.Attrs[AttrAgentMemoryReaders] != ""
}

// AgentMemoryConfirmed reports whether the agent memory match is verified
// (live or inferred), not only possible.
func AgentMemoryConfirmed(n Node) bool {
	ev := n.Evidence
	if e, ok := n.AttrEvidence[AttrAgentMemoryReaders]; ok {
		ev = e
	}
	return Verified(ev)
}

// AgentMemoryReaders lists the workflows that restore the agent's saved
// state, sorted.
func AgentMemoryReaders(n Node) []string { return splitAttr(n.Attrs[AttrAgentMemoryReaders]) }

// AgentMemoryNote describes the cross-run path in one sentence.
func AgentMemoryNote(n Node) string {
	a := n.Attrs
	what := "the cache " + orList(splitAttr(a[AttrAgentMemoryPaths]), "entry")
	if d := splitAttr(a[AttrAgentMemoryDirs]); len(d) > 0 {
		what += " (agent memory: " + strings.Join(d, ", ") + ")"
	}
	var readers []string
	for _, r := range AgentMemoryReaders(n) {
		if r == n.ID {
			readers = append(readers, "later runs of the same workflow")
			continue
		}
		readers = append(readers, strings.TrimPrefix(r, "workflow:"))
	}
	verb := " restore it"
	if len(readers) <= 1 {
		verb = " restores it"
	}
	return "the agent job saves " + what + " on " + strings.ReplaceAll(a[AttrAgentMemoryTriggers], ",", ", ") +
		", and " + orList(readers, "a privileged job") + verb + " with secrets or a write token (" + a[AttrAgentMemoryMatch] + " key match)"
}

// AgentMemoryFixes are the changes that stop an outsider's run from
// planting state for later runs, most effective first.
func AgentMemoryFixes(n Node) []string {
	if !AgentMemoryPoisoned(n) {
		return nil
	}
	return []string{
		"Do not let the agent job save caches: drop cache-mode: write (or write-only) so " + strings.ReplaceAll(n.Attrs[AttrAgentMemoryTriggers], ",", ", ") +
			" keeps GitHub's read-only default, or replace actions/cache with actions/cache/restore in that job.",
		"Never restore the agent's cache in a job that holds secrets or a write token: give the privileged job its own key prefix and drop restore-keys that match the agent's key.",
		"Keep agent memory out of caches: rebuild it on each run from reviewed files on the default branch (CLAUDE.md, AGENTS.md), so changes to it go through code review.",
	}
}
