package redact

import (
	"regexp"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Deployment environment conditions on EXECUTES_WITH edges (graph/envgate.go):
// environment names and branch patterns are renamed, rules are gop's
// vocabulary.
var envRulesRe = regexp.MustCompile(`^[a-z_]+(=[a-z0-9]+)?(\+[a-z_]+(=[a-z0-9]+)?)*$`)

func init() {
	for _, k := range []string{graph.AttrEnvGate, graph.AttrEnvGateReason, graph.AttrEnvProtection,
		graph.AttrEnvBranches, graph.AttrEnvDefaultBranch, graph.AttrEnvUngatedJobs} {
		DefaultAttrs[k] = true
	}
	policies[graph.AttrEnvGate] = enum(graph.EnvGateReviewers, graph.EnvGateNone, graph.EnvGateUnknown)
	policies[graph.AttrEnvDefaultBranch] = enum(graph.EnvBranchAllowed, graph.EnvBranchBlocked, graph.EnvBranchUnknown)
	policies[graph.AttrEnvGateReason] = text
	policies[graph.AttrEnvUngatedJobs] = list(func(r *redactor, s string) string { return r.job(s) })
	policies[graph.AttrEnvProtection] = envItems(":", func(r *redactor, rules string) (string, bool) {
		return rules, envRulesRe.MatchString(rules)
	})
	policies[graph.AttrEnvBranches] = envItems("=", envBranchPolicy)
}

// envItems maps a comma list of <env><sep><value>: the environment is
// renamed and value goes through f; an item f refuses drops the attr.
func envItems(sep string, f func(r *redactor, v string) (string, bool)) policy {
	return func(r *redactor, _ attrCtx, v string) (string, bool, bool) {
		items := strings.Split(v, ",")
		for i, it := range items {
			env, val, ok := strings.Cut(it, sep)
			if !ok {
				return "", false, false
			}
			out, ok := f(r, val)
			if !ok {
				return "", false, false
			}
			items[i] = r.environment(env) + sep + out
		}
		return strings.Join(items, ","), false, true
	}
}

// envBranchPolicy keeps all, protected and unknown, and renames each
// pattern of custom:<p>|<p> (tag patterns as tag:<p>).
func envBranchPolicy(r *redactor, v string) (string, bool) {
	switch v {
	case "all", "protected", "unknown":
		return v, true
	}
	rest, ok := strings.CutPrefix(v, "custom:")
	if !ok {
		return "", false
	}
	if rest == "" {
		return v, true
	}
	ps := strings.Split(rest, "|")
	for i, p := range ps {
		if t, ok := strings.CutPrefix(p, "tag:"); ok {
			ps[i] = "tag:" + r.ref(t)
		} else {
			ps[i] = r.ref(p)
		}
	}
	return "custom:" + strings.Join(ps, "|"), true
}
