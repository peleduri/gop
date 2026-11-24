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

// TestWriteTextHostile checks the plain-text plan escapes names the way the
// checklist does: no name starts a line or leaves a raw control, bidi or
// zero-width character, and the plan value keeps the raw names.
func TestWriteTextHostile(t *testing.T) {
	repo := "acme-app/" + testutil.HostileRepo[:80]
	p := Plan{
		Description: "Restrict the token of " + testutil.HostileLogin,
		Steps: []Step{{
			Kind: KindEditWorkflow, Repo: repo, File: ".github/workflows/" + testutil.HostileFile,
			Owner: testutil.HostileLogin, Change: "edit " + testutil.HostileLogin, Note: testutil.HostileFile,
			Edge: testutil.HostileLogin, Diff: "-  uses: x\n+  uses: y" + string(rune(0x202E)) + "\n",
		}},
		Caveats: []string{"see " + testutil.HostileLogin},
	}
	var buf bytes.Buffer
	WriteText(&buf, p)
	out := buf.String()
	if l := testutil.HostileLineStart(out); l != "" {
		t.Errorf("a line starts with a hostile value: %.120q", l)
	}
	if r, bad := testutil.RawUnsafe(out); bad {
		t.Errorf("raw unsafe character %U", r)
	}
	if !strings.Contains(out, `\u202E`) || !strings.Contains(out, `\r\n\n## ignore`) {
		t.Errorf("escapes not visible in:\n%s", out)
	}
	if p.Description != "Restrict the token of "+testutil.HostileLogin || p.Steps[0].Note != testutil.HostileFile {
		t.Error("WriteText changed the plan it was given")
	}
}

// TestWriteMarkdownAutolinks checks email addresses and angle-bracket
// autolinks in names cannot become live links, while a <sha-of-main>
// placeholder stays as written.
func TestWriteMarkdownAutolinks(t *testing.T) {
	p := Plan{
		Description: "Pin for alice@example.invalid",
		Steps: []Step{{
			Kind: KindVerify, Repo: "acme-app/web", Owner: "<alice@example.invalid>",
			Note: "see <gop://example.invalid/x> and mailto:bob@example.invalid; replace <sha-of-main> with the SHA",
		}},
		Caveats: []string{"ask <HTTPS://example.invalid>"},
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, p)
	out := buf.String()
	for _, live := range []string{"alice@example", "bob@example", "<alice", "<gop:", "<HTTPS:"} {
		for _, l := range strings.Split(out, "\n") {
			if i := strings.Index(l, live); i >= 0 && (i == 0 || l[i-1] != '\\') {
				t.Errorf("%q is not escaped in %q", live, l)
			}
		}
	}
	if !strings.Contains(out, "replace <sha-of-main> with the SHA") {
		t.Errorf("placeholder changed:\n%s", out)
	}
}
