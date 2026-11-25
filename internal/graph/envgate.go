package graph

import "strings"

// Deployment environment protection rules as conditions on workflow
// -EXECUTES_WITH-> secret | oidc edges (see docs/schema.md "Environment
// protection"). A job that names an environment gets its secrets and its
// OIDC token only after the environment's protection rules pass. The
// collector sets these attrs only on edges where at least one job behind the
// edge names an environment; an edge without them has no environment.
const (
	// AttrEnvGate says whether the edge needs a human: required_reviewers
	// when every job behind it runs in an environment with required
	// reviewers, none when some job does not, unknown when no job is known
	// to be ungated but some environment's rules could not be read (or its
	// name is an expression). unknown is never treated as gated.
	AttrEnvGate = "env_gate"
	// AttrEnvGateReason says why env_gate is unknown.
	AttrEnvGateReason = "env_gate_reason"
	// AttrEnvProtection is a sorted comma list of <env>:<rule>+<rule> with
	// rules required_reviewers=N (reviewer entries), prevent_self_review,
	// wait_timer=N (minutes), branch_policy=protected|custom and
	// custom_rules=N (enabled custom deployment protection rules, or
	// unknown); <env>:none for an environment with no rule, <env>:absent for
	// one the repo does not have (GitHub creates it with no rules on the
	// first run) and <env>:unknown when gop could not read it.
	AttrEnvProtection = "env_protection"
	// AttrEnvBranches is a sorted comma list of <env>=<policy>: all (any
	// branch may deploy), protected (protected branches only), custom:<p>|<p>
	// (the custom branch and tag name patterns, tags as tag:<p>), or unknown.
	AttrEnvBranches = "env_branches"
	// AttrEnvDefaultBranch says whether a run on the repo's default branch
	// may use the edge's environments, which is where pull_request_target,
	// issue_comment and workflow_run runs execute: allowed (some job behind
	// the edge may), blocked (every job's environment refuses the default
	// branch) or unknown.
	AttrEnvDefaultBranch = "env_default_branch"
	// AttrEnvUngatedJobs is a sorted comma list of the jobs behind the edge
	// that reach it without a required-reviewer environment (set when
	// env_gate is none).
	AttrEnvUngatedJobs = "env_ungated_jobs"
	// FactEnvironments is the coverage fact of environments gop could not read.
	FactEnvironments = "environments"
)

// Values of env_gate.
const (
	EnvGateReviewers = "required_reviewers"
	EnvGateNone      = "none"
	EnvGateUnknown   = "unknown"
)

// Values of env_default_branch.
const (
	EnvBranchAllowed = "allowed"
	EnvBranchBlocked = "blocked"
	EnvBranchUnknown = "unknown"
)

// gatedFactor is the weight a gated terminal keeps in the score: it is still
// reached (a reviewer can approve the run), but a human must act first.
const gatedFactor = 0.5

// EnvGated reports whether an EXECUTES_WITH edge is gated by required
// reviewers on every job behind it.
func EnvGated(e Edge) bool {
	return e.Kind == ExecutesWith && e.Attrs[AttrEnvGate] == EnvGateReviewers
}

// envGateNote is the Hop.Gate text of a gated edge.
func envGateNote(e Edge) string {
	var envs []string
	for _, p := range strings.Split(e.Attrs[AttrEnvProtection], ",") {
		if name, rules, ok := strings.Cut(p, ":"); ok && strings.Contains(rules, EnvGateReviewers) {
			envs = append(envs, name)
		}
	}
	if len(envs) == 0 {
		return "environment needs a required reviewer to approve the run"
	}
	return "environment " + strings.Join(envs, ", ") + " needs a required reviewer to approve the run"
}

// oidcGates maps each workflow whose EXECUTES_WITH -> oidc edge is gated to
// its gate note: a CAN_ASSUME hop from that workflow needs the same approval,
// because the token is minted only inside the gated jobs.
func oidcGates(edges []Edge, kindOf func(string) NodeKind) map[string]string {
	var out map[string]string
	for _, e := range edges {
		if EnvGated(e) && kindOf(e.To) == KindOIDC {
			if out == nil {
				out = map[string]string{}
			}
			out[e.From] = envGateNote(e)
		}
	}
	return out
}

// hopGated reports whether any hop of a path carries a gate.
func hopsGated(hops []Hop) bool {
	for _, h := range hops {
		if h.Gate != "" {
			return true
		}
	}
	return false
}

// gatedCounts counts the terminals of set (secrets, oidc, cloud targets) that
// every reached workflow reaches only through a gated edge: each in-edge from
// a workflow in wfs is gated, and there is at least one. A terminal reached
// through any ungated edge is not counted.
func (ix *Index) gatedCounts(set Reached, wfs map[string]bool, oidc map[string]string) Counts {
	var c Counts
	gated := func(t string) bool {
		n := 0
		for _, e := range ix.in[t] {
			if !wfs[e.From] {
				continue
			}
			switch e.Kind {
			case ExecutesWith:
				if !EnvGated(e) {
					return false
				}
			case CanAssume:
				if oidc[e.From] == "" {
					return false
				}
			default:
				continue
			}
			n++
		}
		return n > 0
	}
	for _, t := range set.Secrets {
		if gated(t) {
			c.Secrets++
		}
	}
	for _, t := range set.OIDC {
		if gated(t) {
			c.OIDC++
		}
	}
	for _, t := range set.CloudTargets {
		if gated(t) {
			c.CloudTargets++
		}
	}
	return c
}

// envGatedOn returns the gated terminals of a reach result: confirmed ones
// judged over the confirmed workflows, possible ones over every reached
// workflow. Nothing is gated in a graph without a gated edge.
func (ix *Index) envGatedOn(r Result) (conf, poss Counts) {
	if !ix.anyEnvGate() {
		return conf, poss
	}
	wfs := map[string]bool{}
	for _, w := range r.Confirmed.Workflows {
		wfs[w] = true
	}
	conf = ix.gatedCounts(r.Confirmed, wfs, ix.oidcGate)
	for _, w := range r.Possible.Workflows {
		wfs[w] = true
	}
	poss = ix.gatedCounts(r.Possible, wfs, ix.oidcGate)
	return conf, poss
}

// anyEnvGate reports whether some EXECUTES_WITH edge is environment-gated.
func (ix *Index) anyEnvGate() bool {
	ix.envOnce.Do(func() {
		for _, e := range ix.g.Edges {
			if EnvGated(e) {
				ix.envAny = true
				return
			}
		}
	})
	return ix.envAny
}
