package whatif

import (
	"bytes"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestRenderHostileNames checks a hostile name cannot start a line, end a
// table cell or code span, open HTML or become a link in any format.
func TestRenderHostileNames(t *testing.T) {
	const bad = "identity:x|y`<b>[l](http://e.invalid)\nINJECTED"
	p := &graph.Path{From: bad, To: "repo:acme-app/web"}
	r := Report{
		Summary:      "confirmed (principal, repo) pairs: 2 -> 1 (50% removed); possible pairs: 0 -> 0",
		Fixes:        []Fix{{FixID: "pin:" + bad, Description: "Pin " + bad}},
		Removed:      []RemovedPath{{Principal: bad, Target: "repo:acme-app/web", Before: StatusConfirmed, After: StatusGone, Hops: []string{bad, "repo:acme-app/web"}}},
		RemovedTotal: 1,
		Remaining:    []Remaining{{Principal: bad, Path: p}},
		Caveats:      []string{bad},
	}
	for name, write := range map[string]func(*bytes.Buffer){
		"text":     func(b *bytes.Buffer) { WriteText(b, r) },
		"markdown": func(b *bytes.Buffer) { WriteMarkdown(b, r) },
	} {
		var b bytes.Buffer
		write(&b)
		out := b.String()
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "INJECTED") {
				t.Errorf("%s: a name started a line:\n%s", name, out)
			}
		}
		if name == "markdown" {
			for _, s := range []string{"<b>", "x|y", "y`<"} {
				if strings.Contains(out, s) {
					t.Errorf("markdown: %q not escaped:\n%s", s, out)
				}
			}
			// In prose (outside code spans) link syntax is escaped too.
			if !strings.Contains(out, "- identity:x\\|y`&lt;b&gt;[l\\](") {
				t.Errorf("markdown: caveat link not escaped:\n%s", out)
			}
		}
	}
}
