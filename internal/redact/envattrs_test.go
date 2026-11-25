package redact

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestRedactEnvironmentConditions(t *testing.T) {
	g := load(t, acmePath)
	for i, e := range g.Edges {
		if e.Kind != graph.ExecutesWith {
			continue
		}
		attrs := map[string]string{}
		for k, v := range e.Attrs {
			attrs[k] = v
		}
		attrs[graph.AttrEnvGate] = graph.EnvGateNone
		attrs[graph.AttrEnvProtection] = "prodvault:required_reviewers=2+wait_timer=5,stagingvault:absent"
		attrs[graph.AttrEnvBranches] = "prodvault=protected,stagingvault=custom:releasetrain/*|tag:vtrain*"
		attrs[graph.AttrEnvDefaultBranch] = graph.EnvBranchAllowed
		attrs[graph.AttrEnvUngatedJobs] = "shipjob"
		g.Edges[i].Attrs = attrs
		break
	}
	b := string(marshal(t, redact(t, g, "salt").Graph))
	for _, name := range []string{"prodvault", "stagingvault", "releasetrain", "vtrain", "shipjob"} {
		if strings.Contains(b, name) {
			t.Errorf("redacted graph still names %q", name)
		}
	}
	for _, kept := range []string{`"env_gate": "none"`, "required_reviewers=2+wait_timer=5", ":absent", "=protected", `"env_default_branch": "allowed"`} {
		if !strings.Contains(b, kept) {
			t.Errorf("redacted graph lost %q", kept)
		}
	}
}
