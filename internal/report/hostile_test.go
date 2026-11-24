package report

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sanitize"
	"github.com/peleduri/gop/internal/testutil"
)

func hostileGraph(t *testing.T) *graph.Graph {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.Load(bytes.NewReader(testutil.HostileGraphJSON(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestHostileNamesMarkdown renders the markdown report (with a what-changed
// banner) and the drift markdown the Action writes over a graph with
// attacker-written names: no line starts with a hostile value, no raw
// control, bidi or zero-width character is left, and every line is bounded.
func TestHostileNamesMarkdown(t *testing.T) {
	g := hostileGraph(t)
	rep, err := diff.Compare(loadAcme(t), g)
	if err != nil {
		t.Fatal(err)
	}
	var md bytes.Buffer
	if err := Render(&md, g, Options{Format: "md", Version: "test", Changes: &rep}); err != nil {
		t.Fatal(err)
	}
	var drift bytes.Buffer
	diff.WriteMarkdown(&drift, rep)
	for name, out := range map[string]string{"report.md": md.String(), "diff.md": drift.String()} {
		if l := testutil.HostileLineStart(out); l != "" {
			t.Errorf("%s: a line starts with a hostile value: %.120q", name, l)
		}
		if r, bad := testutil.RawUnsafe(out); bad {
			t.Errorf("%s: raw unsafe character %U", name, r)
		}
		if strings.Contains(out, "<img") || strings.Contains(out, "</tool_result>") {
			t.Errorf("%s: raw HTML or tool tag from a name", name)
		}
		if name == "report.md" {
			for _, l := range strings.Split(out, "\n") {
				// A table row holds a few values, each capped at MaxLine.
				if n := utf8.RuneCountInString(l); n > 6*sanitize.MaxLine {
					t.Errorf("%s: line of %d runes", name, n)
				}
			}
		}
	}
}

// TestHostileNamesHTML checks the HTML report: html/template escapes names,
// so no raw tag from a name reaches the page, and no raw control, bidi or
// zero-width character is left in the source.
func TestHostileNamesHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, hostileGraph(t), Options{Format: "html", Version: "test"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if r, bad := testutil.RawUnsafe(out); bad {
		t.Errorf("HTML report has a raw unsafe character %U", r)
	}
	for _, raw := range []string{"<img src=x", "</tool_result>", "<tool_result>"} {
		if strings.Contains(out, raw) {
			t.Errorf("HTML report has a raw %q from a name", raw)
		}
	}
}
