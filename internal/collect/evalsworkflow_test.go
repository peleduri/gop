package collect

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestEvalsWorkflowNotExposed runs gop's own workflow parser on the
// agent-behaviour eval workflow (.github/workflows/evals.yml, copied into
// testdata/evals). It holds a model API key, so gop must see it as a job only
// maintainers can start, with no agent_exposure=outsiders and no untrusted
// execution: gop's repo must not ship the pattern GOP004 warns about.
func TestEvalsWorkflowNotExposed(t *testing.T) {
	live, err := os.ReadFile("../../.github/workflows/evals.yml")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("testdata/evals/evals.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(live, src) {
		t.Fatal("testdata/evals/evals.yml differs from .github/workflows/evals.yml; copy the workflow into the fixture")
	}
	check := func(name string, src []byte) {
		t.Helper()
		f, err := ParseWorkflow(src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		f.File = ".github/workflows/evals.yml"
		for _, tr := range f.Triggers {
			if riskyTriggers[tr] {
				t.Errorf("%s: risky trigger %s", name, tr)
			}
		}
		if len(f.UntrustedExec) > 0 {
			t.Errorf("%s: untrusted execution %+v", name, f.UntrustedExec)
		}
		for _, a := range f.Agents {
			if a.Exposure != graph.ExposureMaintainer {
				t.Errorf("%s: agent job %s has exposure %s, want %s", name, a.Job, a.Exposure, graph.ExposureMaintainer)
			}
		}
		wn := &graph.Node{ID: "workflow:acme/gop/.github/workflows/evals.yml", Kind: graph.KindWorkflow}
		addAgentFacts(wn, f)
		if got := wn.Attrs[graph.AttrAgentExposure]; got == graph.ExposureOutsiders {
			t.Errorf("%s: agent_exposure=%s", name, got)
		}
	}
	f, err := ParseWorkflow(src)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"schedule", "workflow_dispatch"}; !slices.Equal(f.Triggers, want) {
		t.Errorf("triggers %v, want %v (only maintainers may start the eval)", f.Triggers, want)
	}
	check("evals.yml", src)
	// The key never sits next to attacker text: even on the riskiest
	// triggers, no step reads a pull request, issue or comment.
	for _, tr := range []string{"pull_request_target", "issue_comment"} {
		mutated := strings.Replace(string(src), "on:\n  workflow_dispatch:", "on:\n  "+tr+":\n  workflow_dispatch:", 1)
		f, err := ParseWorkflow([]byte(mutated))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(f.Triggers, tr) {
			t.Fatalf("mutation to %s did not apply", tr)
		}
		if len(f.UntrustedExec) > 0 {
			t.Errorf("on %s: untrusted execution %+v", tr, f.UntrustedExec)
		}
		for _, a := range f.Agents {
			if a.Exposure == graph.ExposureOutsiders {
				t.Errorf("on %s: agent job %s exposed to outsiders", tr, a.Job)
			}
		}
	}
}
