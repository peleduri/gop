package fixplan

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

const setupRef = "action:acme-actions/setup@main"

// linesWith loads the lines fixture with extra attrs on the given action nodes.
func linesWith(t *testing.T, attrs map[string]map[string]string) *graph.Index {
	t.Helper()
	g, err := graph.LoadFile(linesPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range g.Nodes {
		for k, v := range attrs[n.ID] {
			if g.Nodes[i].Attrs == nil {
				g.Nodes[i].Attrs = map[string]string{}
			}
			g.Nodes[i].Attrs[k] = v
		}
	}
	return graph.NewIndex(g)
}

var (
	immutableTag = map[string]string{graph.AttrRefKind: "tag", graph.AttrRefImmutable: "true", graph.AttrBypass: "none"}
	unknownTag   = map[string]string{graph.AttrRefKind: "tag", graph.AttrRefImmutable: "unknown"}
)

func TestNestedMutableFollowsRefGate(t *testing.T) {
	ids, _ := NestedMutable(linesWith(t, map[string]map[string]string{setupRef: immutableTag}), deployRef)
	if len(ids) != 0 {
		t.Errorf("immutable nested tag listed: %v", ids)
	}
	ids, labels := NestedMutable(linesWith(t, map[string]map[string]string{setupRef: unknownTag}), deployRef)
	if len(ids) != 1 || ids[0] != setupRef || !strings.Contains(labels[0], "[possibly mutable (immutability not visible)]") {
		t.Errorf("unknown nested tag: %v %v", ids, labels)
	}
}

func TestPinCaveatFollowsRefGate(t *testing.T) {
	p := Build(linesWith(t, map[string]map[string]string{deployRef: immutableTag, setupRef: immutableTag}), graph.PinRef{Action: deployRef})
	if !hasCaveat(p, "acme-actions/deploy@main is locked") || hasCaveat(p, "Pin those too") {
		t.Errorf("locked pin caveats: %v", p.Caveats)
	}
	p = Build(linesWith(t, map[string]map[string]string{deployRef: unknownTag}), graph.PinRef{Action: deployRef})
	if !hasCaveat(p, "acme-actions/deploy@main is possibly mutable (immutability not visible)") {
		t.Errorf("unknown pin caveats: %v", p.Caveats)
	}
	if hasCaveat(p, "already pinned") {
		t.Errorf("possibly mutable ref read as pinned: %v", p.Caveats)
	}
}
