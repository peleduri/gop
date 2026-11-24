package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

func loadHardening(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/hardening/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestOrgSettingsSection: one row per org with every setting; acme-legacy's
// IP allow list (token not an owner) reads unknown, linked to the coverage
// reason and fix, never off; the path context appears only for paths into
// weak or unknown orgs.
func TestOrgSettingsSection(t *testing.T) {
	g := loadHardening(t)
	out := render(t, g, "md")
	testutil.Golden(t, "hardening.md", []byte(out), "v0.0.0-test")
	for _, want := range []string{
		"| acme-app | enforced | required | on (2 active entries, installed apps on) | read | false | false | false | false | 50 |",
		"| acme-actions | configured | not\\_required | off (0 active entries, installed apps off) | write | true | true | true | true | 20 |",
		"| acme-legacy | none | not\\_required | [_unknown_](#why-unknown) | write | true | false | true | false | 5 |",
		"  - IP allow list: not visible: token is not an org owner. Access that fixes it: org owner on acme-legacy",
		"_Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off_",
		"_Context, not part of the score: target org acme-legacy: SSO not enforced (none), IP allow list unknown_",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if strings.Contains(out, "target org acme-app:") {
		t.Error("context shown for a path into a hardened org")
	}

	html := render(t, g, "html")
	for _, want := range []string{
		`<a class="badge nv" href="#why-acme-legacy"><span aria-hidden="true">?</span> unknown</a>`,
		`<li id="why-acme-legacy"><code>acme-legacy</code><ul><li><strong>IP allow list</strong>: not visible: token is not an org owner. Access that fixes it: org owner on acme-legacy</li></ul></li>`,
		`<span class="tip">not visible: token is not an org owner. Access that fixes it: org owner on acme-legacy</span>`,
		`<p class="ctx"><span aria-hidden="true">ⓘ</span> Context, not part of the score: target org acme-actions: SSO not enforced (configured), IP allow list off</p>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	if strings.Contains(html, "target org acme-app:") {
		t.Error("html: context shown for a path into a hardened org")
	}
}

// TestReportRanksUnchangedByHardening: the top risks table is identical with
// and without the IP allow list attributes.
func TestReportRanksUnchangedByHardening(t *testing.T) {
	g, bare := loadHardening(t), loadHardening(t)
	for i := range bare.Nodes {
		for _, k := range []string{graph.AttrIPAllowList, graph.AttrIPAllowEntries, graph.AttrIPAllowListEntries, graph.AttrIPAllowListApps} {
			delete(bare.Nodes[i].Attrs, k)
			delete(bare.Nodes[i].AttrEvidence, k)
		}
	}
	section := func(s string) string {
		_, after, _ := strings.Cut(s, "## Top risks")
		before, _, _ := strings.Cut(after, "## Top paths")
		return before
	}
	if a, b := section(render(t, g, "md")), section(render(t, bare, "md")); a != b {
		t.Errorf("top risks and fixes changed:\n%s\n---\n%s", a, b)
	}
}
