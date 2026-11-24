package fixplan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

// TestWriteMarkdownHostile checks the checklist escapes names itself, so the
// CLI (gop fix-plan --format markdown) and the fix_plan tool print the same
// safe text: no name starts a line, hides text, ends a code span or becomes
// a live link, while the plan value keeps the raw names.
func TestWriteMarkdownHostile(t *testing.T) {
	repo := "acme-app/" + testutil.HostileRepo[:80]
	link := "acme-app/web/.github/workflows/" + testutil.ImageFile
	p := Plan{
		Description: "Set permissions: contents: read on the GITHUB_TOKEN of " + link,
		Steps: []Step{{
			Kind: KindEditWorkflow, Repo: repo, File: ".github/workflows/" + testutil.HostileFile,
			Change: "edit " + testutil.LinkLogin, Note: testutil.HostileLogin,
			Diff: "-  uses: x```\n+  uses: y\n",
		}},
		Caveats: []string{"see " + testutil.LinkLogin},
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, p)
	out := buf.String()
	if l := testutil.HostileLineStart(out); l != "" {
		t.Errorf("a line starts with a hostile value: %.120q", l)
	}
	if r, bad := testutil.RawUnsafe(out); bad {
		t.Errorf("raw unsafe character %U", r)
	}
	if l := testutil.LiveLink(out); l != "" {
		t.Errorf("a name renders as a live link: %q", l)
	}
	if strings.Contains(out, "x```") {
		t.Error("a diff line can close the fence")
	}
	if p.Description != "Set permissions: contents: read on the GITHUB_TOKEN of "+link || p.Steps[0].Note != testutil.HostileLogin {
		t.Error("WriteMarkdown changed the plan it was given")
	}
}
