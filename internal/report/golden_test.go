package report

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

// externalRef matches a script, link or img (or any src/href) pointing at a
// remote URL, plus remote CSS url() and @import.
var externalRef = regexp.MustCompile(`(?i)(<(script|link|img)\b[^>]*(src|href)\s*=\s*["']?\s*(https?:)?//)|(url\(\s*["']?\s*(https?:)?//)|(@import\s+["']?\s*(url\()?\s*["']?(https?:)?//)`)

func TestGoldenReportHTML(t *testing.T) {
	const ver = "v9.9.9-golden"
	var buf bytes.Buffer
	if err := Render(&buf, loadAcme(t), Options{Format: "html", Version: ver}); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	assertSelfContained(t, out)
	testutil.Golden(t, "report.html", out, ver)
}

func TestGoldenReportMarkdown(t *testing.T) {
	const ver = "v9.9.9-golden"
	var buf bytes.Buffer
	if err := Render(&buf, loadAcme(t), Options{Format: "md", Version: ver}); err != nil {
		t.Fatal(err)
	}
	testutil.Golden(t, "report.md", buf.Bytes(), ver)
}

// assertSelfContained enforces the single-file rule: no script, style, font
// or image is loaded from a URL.
func assertSelfContained(t *testing.T, html []byte) {
	t.Helper()
	if m := externalRef.Find(html); m != nil {
		t.Errorf("report HTML references an external resource: %q", m)
	}
}

func TestAssertSelfContainedCatchesExternalRefs(t *testing.T) {
	for _, bad := range []string{
		`<script src="https://cdn.example.com/x.js"></script>`,
		`<link rel="stylesheet" href="http://example.com/a.css">`,
		`<img src="//example.com/logo.png">`,
		`<style>@font-face{src:url(https://example.com/f.woff2)}</style>`,
		`<style>@import "https://example.com/a.css";</style>`,
	} {
		if externalRef.FindString(bad) == "" {
			t.Errorf("not caught: %s", bad)
		}
	}
}
