package fixplan

import (
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// envCaveats suggests required reviewers on the deployment environments of
// a workflow's secrets and OIDC edges that no reviewer gates (env_gate
// none, see docs/schema.md "Environment protection"): a defense in depth
// that makes a human approve the run before the job gets the secrets or
// the token. Only edges where some job names an environment carry the
// attrs, so a workflow with no environment gets no suggestion.
func envCaveats(ix *graph.Index, workflow string) []string {
	repo, _ := workflowLoc(ix, workflow)
	noReviewers, noEnv := map[string]bool{}, map[string]bool{}
	for _, e := range ix.Out(workflow) {
		if e.Kind != graph.ExecutesWith || e.Attrs[graph.AttrEnvGate] != graph.EnvGateNone {
			continue
		}
		for _, p := range splitList(e.Attrs[graph.AttrEnvProtection]) {
			name, rules, ok := strings.Cut(p, ":")
			if ok && !strings.Contains(rules, graph.EnvGateReviewers) && rules != "unknown" {
				noReviewers[name] = true
			}
		}
		for _, j := range splitList(e.Attrs[graph.AttrEnvUngatedJobs]) {
			noEnv[j] = true
		}
	}
	var out []string
	if len(noReviewers) > 0 {
		envs := keys(noReviewers)
		out = append(out, "defense in depth: add a required reviewer to environment "+strings.Join(envs, ", ")+" of "+repo+
			" (Settings > Environments > Required reviewers, with Prevent self-review) so a person approves each run before its jobs get the environment's secrets and OIDC token")
	}
	if len(noEnv) > 0 && len(noReviewers) == 0 {
		out = append(out, "defense in depth: run job "+strings.Join(keys(noEnv), ", ")+" of "+repo+
			" in a deployment environment with required reviewers so a person approves each run before it gets secrets or an OIDC token")
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
