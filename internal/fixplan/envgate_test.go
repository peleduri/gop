package fixplan

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestHardenPlanSuggestsEnvironmentReviewers(t *testing.T) {
	wf := "workflow:acme-app/web/.github/workflows/agent.yml"
	mk := func(attrs map[string]string) *graph.Index {
		return graph.NewIndex(&graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme",
			Nodes: []graph.Node{
				{ID: wf, Kind: graph.KindWorkflow, Name: "agent", Evidence: graph.Live,
					Attrs: map[string]string{"repo": "acme-app/web", "path": ".github/workflows/agent.yml"}},
				{ID: "secret:acme-app/web", Kind: graph.KindSecret, Name: "secrets", Evidence: graph.Live},
			},
			Edges: []graph.Edge{
				{From: "external:anyone", To: wf, Kind: graph.CanTrigger, Evidence: graph.Live, SourceAPI: "rest",
					Attrs: map[string]string{"trigger": "issue_comment", "exec": "agent", "job": "review"}},
				{From: wf, To: "secret:acme-app/web", Kind: graph.ExecutesWith, Evidence: graph.Live, SourceAPI: "rest", Attrs: attrs},
			}})
	}
	p := Build(mk(map[string]string{graph.AttrEnvGate: graph.EnvGateNone, graph.AttrEnvProtection: "ai-review:none",
		graph.AttrEnvUngatedJobs: "review"}), graph.HardenTrigger{Workflow: wf})
	if !strings.Contains(strings.Join(p.Caveats, "\n"), "add a required reviewer to environment ai-review of acme-app/web") {
		t.Errorf("caveats %q do not suggest a required reviewer", p.Caveats)
	}
	p = Build(mk(map[string]string{graph.AttrEnvGate: graph.EnvGateReviewers, graph.AttrEnvProtection: "ai-review:required_reviewers=1"}),
		graph.HardenTrigger{Workflow: wf})
	if strings.Contains(strings.Join(p.Caveats, "\n"), "required reviewer") {
		t.Errorf("gated environment still gets a suggestion: %q", p.Caveats)
	}
	p = Build(mk(nil), graph.HardenTrigger{Workflow: wf})
	if strings.Contains(strings.Join(p.Caveats, "\n"), "environment") {
		t.Errorf("workflow without environments gets a suggestion: %q", p.Caveats)
	}
}
