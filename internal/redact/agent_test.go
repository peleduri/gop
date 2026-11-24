package redact

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestRedactKeepsAgentAttrs: agent attrs are gop's vocabulary and survive
// redaction (job ids renamed), so the agent still ranks.
func TestRedactKeepsAgentAttrs(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/agents/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Redact(g, Options{Salt: []byte("test-salt")})
	if err != nil {
		t.Fatal(err)
	}
	exposed := 0
	for _, n := range res.Graph.Nodes {
		if !graph.AgentExposed(n) {
			continue
		}
		exposed++
		a := n.Attrs
		if a[graph.AttrAgentJobs] == "claude" || a[graph.AttrAgentJobs] == "review" {
			t.Errorf("job id kept: %v", a)
		}
		if a[graph.AttrAgentExposure] != graph.ExposureOutsiders || a[graph.AttrAgentSecrets] != "1" || a[graph.AttrAgentPerms] == "" {
			t.Errorf("redacted attrs %v", a)
		}
	}
	if exposed != 2 {
		t.Fatalf("exposed agent workflows after redaction = %d, want 2", exposed)
	}
	for _, n := range res.Graph.Nodes {
		if p := n.Attrs[graph.AttrAgentPrompt]; p != "" && !strings.HasPrefix(p, "github.") {
			t.Errorf("prompt contexts = %q", p)
		}
	}
	if top := graph.NewIndex(res.Graph).TopPaths(1); top[0].AgentExposed == 0 {
		t.Errorf("an agent-exposed principal must still rank first: %+v", top)
	}
}
