package docs

import (
	"os"
	"strings"
	"testing"
)

// controlGraphComment returns the control-graph rules comment above
// controlGraph in internal/graph/reach.go, with the "//\t" prefix removed.
func controlGraphComment(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../internal/graph/reach.go")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	in := false
	for _, l := range strings.Split(string(src), "\n") {
		switch {
		case strings.HasPrefix(l, "// The control graph is directed"):
			in = true
		case in && strings.HasPrefix(l, "type controlGraph"):
			return strings.Join(lines, "\n")
		case in && strings.HasPrefix(l, "//\t"):
			lines = append(lines, strings.TrimRight(strings.TrimPrefix(l, "//\t"), " "))
		}
	}
	t.Fatal("control-graph rules comment not found in internal/graph/reach.go")
	return ""
}

// TestArchitectureControlGraphRules keeps the copy of the control-graph rules
// in docs/architecture.md identical to the comment in reach.go, the source of
// truth.
func TestArchitectureControlGraphRules(t *testing.T) {
	doc, err := os.ReadFile("architecture.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- control-graph-rules:begin -->\n```text\n", "\n```\n<!-- control-graph-rules:end -->"
	s := string(doc)
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatal("docs/architecture.md: control-graph-rules markers not found")
	}
	got := s[i+len(begin) : j]
	if want := controlGraphComment(t); got != want {
		t.Errorf("docs/architecture.md control-graph rules differ from internal/graph/reach.go; "+
			"paste the comment above controlGraph between the markers.\n--- reach.go\n%s\n--- architecture.md\n%s", want, got)
	}
}
