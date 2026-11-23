package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

const (
	dataOpen   = `<script type="application/json" id="gop-data">`
	scriptOpen = "<script>"
)

// block returns the text between open and the next </tag> after it.
func block(t *testing.T, html, open, tag string) string {
	t.Helper()
	i := strings.Index(html, open)
	if i < 0 {
		t.Fatalf("no %s in report", open)
	}
	rest := html[i+len(open):]
	j := strings.Index(rest, "</"+tag+">")
	if j < 0 {
		t.Fatalf("unterminated %s", open)
	}
	return rest[:j]
}

func embeddedJSON(t *testing.T, html string) string { return block(t, html, dataOpen, "script") }

// assertOnlyOwnScripts allows exactly the data block and the inline script.
func assertOnlyOwnScripts(t *testing.T, html string) {
	t.Helper()
	if n := strings.Count(strings.ToLower(html), "<script"); n != 2 {
		t.Errorf("want 2 script tags (data + inline), got %d", n)
	}
	if !strings.Contains(html, dataOpen) || !strings.Contains(html, scriptOpen+scriptJS+"</script>") {
		t.Error("script tags are not the report's own")
	}
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

var cspMeta = regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`)

// TestReportCSP recomputes the hashes from the served bytes: if html/template
// ever rewrote the style or script, the browser would block it.
func TestReportCSP(t *testing.T) {
	out := render(t, loadAcme(t), "html")
	m := cspMeta.FindStringSubmatch(out)
	if m == nil {
		t.Fatal("no CSP meta tag")
	}
	if i, j := strings.Index(out, m[0]), strings.Index(out, "<style>"); i > j {
		t.Error("CSP meta must come before the style block")
	}
	pol := m[1]
	style := block(t, out, "<style>", "style")
	script := block(t, out, scriptOpen, "script")
	if style != styleCSS || script != scriptJS {
		t.Error("served style or script differs from the hashed constant")
	}
	want := "default-src 'none'; script-src " + hashOf(script) + "; style-src " + hashOf(style) +
		"; base-uri 'none'; form-action 'none'"
	if pol != want {
		t.Errorf("CSP\n got %s\nwant %s", pol, want)
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http", "*"} {
		if strings.Contains(pol, bad) {
			t.Errorf("CSP allows %q", bad)
		}
	}
}

// TestInlineScriptRules keeps the script dependency-free and away from the
// APIs that turn data into code or markup.
func TestInlineScriptRules(t *testing.T) {
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
		"Function(", "setTimeout(\"", "import", "require(", "fetch(", "XMLHttpRequest", "src=", "http", "<!--", "</"} {
		if strings.Contains(scriptJS, bad) {
			t.Errorf("inline script contains %q", bad)
		}
	}
	if len(scriptJS) > 16<<10 {
		t.Errorf("inline script is %d bytes; keep it small", len(scriptJS))
	}
}

func TestEmbeddedData(t *testing.T) {
	var e embedded
	if err := json.Unmarshal([]byte(embeddedJSON(t, render(t, loadAcme(t), "html"))), &e); err != nil {
		t.Fatalf("embedded JSON does not parse: %v", err)
	}
	if e.V != dataVersion || len(e.Orgs) != 4 || len(e.Paths) == 0 || len(e.Fixes) == 0 || len(e.Coverage) != 2 {
		t.Fatalf("embedded data incomplete: v=%d orgs=%d paths=%d fixes=%d coverage=%d",
			e.V, len(e.Orgs), len(e.Paths), len(e.Fixes), len(e.Coverage))
	}
	if len(e.Truncated) != 0 {
		t.Errorf("acme paths truncated: %+v", e.Truncated)
	}
	for _, o := range e.Orgs {
		for _, a := range o.Settings {
			if !a.Known && a.Value != "unknown" {
				t.Errorf("%s %s: unseen setting reads %q, want unknown", o.Name, a.Key, a.Value)
			}
			if o.Name == "acme-legacy" && a.Key == graph.AttrIPAllowList &&
				(a.Value != "unknown" || a.Evidence != "not visible" || a.Known) {
				t.Errorf("acme-legacy ip_allow_list = %+v, want unknown / not visible", a)
			}
		}
	}
	kinds := map[string]bool{}
	for _, p := range e.Paths {
		kinds[p.ToKind] = true
		if p.Ev != "confirmed" && p.Ev != "possible" || len(p.Hops) == 0 || p.Hops[0].From != p.From {
			t.Errorf("bad path %+v", p)
		}
	}
	for _, k := range []string{"repo", "oidc", "secret", "runner"} {
		if !kinds[k] {
			t.Errorf("no embedded path ends at a %s", k)
		}
	}
	var pin embFix
	for _, f := range e.Fixes {
		if f.ID == "pin:action:acme-actions/deploy@main" {
			pin = f
		}
	}
	if !contains(pin.Orgs, "acme-actions") || !contains(pin.Orgs, "acme-app") {
		t.Errorf("pin fix orgs = %v, want the host and consumer orgs", pin.Orgs)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestStaticSectionWithoutJS checks what a reader sees with scripts off:
// everything outside the script blocks, with hidden sections removed.
func TestStaticSectionWithoutJS(t *testing.T) {
	out := render(t, loadAcme(t), "html")
	static := block(t, out, `<div id="gop-static">`, "footer")
	static = static[:strings.Index(static, `<section id="gop-explore" hidden>`)]
	for _, want := range []string{
		"Members of acme-actions can push code that runs in 12 repos", // headline
		"<h2>Top paths</h2>", "oidc:acme-app/web", // top paths
		"<h2>Suggested fixes</h2>", "Pin acme-actions/deploy@main to a commit SHA", // fixes
		"<h2>Coverage</h2>", "org owner on acme-legacy", // coverage
	} {
		if !strings.Contains(static, want) {
			t.Errorf("static section missing %q", want)
		}
	}
	if strings.Contains(static, " hidden") {
		t.Error("static section must not be hidden without JS")
	}
	for _, id := range []string{`<section id="gop-explore" hidden>`, `<section id="gop-orgview" hidden></section>`} {
		if !strings.Contains(out, id) {
			t.Errorf("JS-only section %q must start hidden", id)
		}
	}
}

func TestTruncatedPathsNote(t *testing.T) {
	g := loadAcme(t)
	ix := graph.NewIndex(g)
	e := buildEmbedded(ix, g, ix.Scores(), nil, 2)
	if len(e.Truncated) == 0 {
		t.Fatal("expected truncation at 2 paths per org")
	}
	per := map[string]int{}
	for _, p := range e.Paths {
		per[p.ToOrg]++
	}
	for o, n := range per {
		if n > 2 {
			t.Errorf("%s: %d paths embedded, cap is 2", o, n)
		}
	}
	d := build(g, Options{Top: 10, FixBudget: 5})
	if err := addEmbedded(&d, g); err != nil {
		t.Fatal(err)
	}
	if d.Truncated != "" {
		t.Errorf("acme should not be truncated at the default cap: %s", d.Truncated)
	}
}

func TestMediumDemoUnderBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("medium demo report in -short mode")
	}
	var buf bytes.Buffer
	if err := Render(&buf, demo.Generate(demo.Options{Seed: 1, Size: demo.SizeMedium}), Options{Version: "v0.0.0-test"}); err != nil {
		t.Fatal(err)
	}
	if n := buf.Len(); n >= 5<<20 {
		t.Errorf("medium demo report is %d bytes, budget 5 MB", n)
	}
	assertSelfContained(t, buf.Bytes())
	var e embedded
	if err := json.Unmarshal([]byte(embeddedJSON(t, buf.String())), &e); err != nil {
		t.Fatal(err)
	}
}

type harnessOut struct {
	InitialExploreHidden bool `json:"initialExploreHidden"`
	Org                  struct {
		StaticHidden, ExploreHidden, ViewHidden bool
		Headings                                []string
		Text                                    string
	} `json:"org"`
	Inbound    []string `json:"inbound"`
	LegacyText string   `json:"legacyText"`
	Filtered   struct {
		StaticHidden bool
		FormEv       string
		FormKind     string
		Count        string
		Summaries    []string
		Paths        [][4]string
	} `json:"filtered"`
	OrgFilter      [][2]json.RawMessage `json:"orgFilter"`
	OrgFixes       []string             `json:"orgFixes"`
	HashAfterInput string               `json:"hashAfterInput"`
	HashAfterReset string               `json:"hashAfterReset"`
	RoundTrip      string               `json:"roundTrip"`
	Junk           struct {
		Route string
		F     struct {
			Ev, Kind, Ref, Q string
			Orgs             []string
		}
	} `json:"junk"`
}

// TestInlineScriptInNode runs the served script under node with a fake DOM
// (testdata/jsharness). CI runners ship node; elsewhere it is skipped.
func TestInlineScriptInNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	g := loadAcme(t)
	out := render(t, g, "html")
	dir := t.TempDir()
	pre, err := os.ReadFile(filepath.Join("testdata", "jsharness", "prelude.js"))
	if err != nil {
		t.Fatal(err)
	}
	epi, err := os.ReadFile(filepath.Join("testdata", "jsharness", "epilogue.js"))
	if err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(dir, "harness.js")
	src := string(pre) + "\n" + block(t, out, scriptOpen, "script") + "\n" + string(epi)
	if err := os.WriteFile(prog, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	dataFile := filepath.Join(dir, "data.json")
	if err := os.WriteFile(dataFile, []byte(embeddedJSON(t, out)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, prog, dataFile) // #nosec G204 -- test-only, fixed program
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var h harnessOut
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("harness output: %v\n%s", err, raw)
	}

	if h.InitialExploreHidden {
		t.Error("explore section stays hidden with JS on")
	}
	// Per-org view: #/org/acme-app shows inbound reach from members:acme-actions.
	if !h.Org.StaticHidden || !h.Org.ExploreHidden || h.Org.ViewHidden {
		t.Errorf("org route visibility: %+v", h.Org)
	}
	if !contains(h.Inbound, "members:acme-actions") {
		t.Errorf("inbound reach of acme-app = %v, want members:acme-actions", h.Inbound)
	}
	shown := false
	for _, hd := range h.Org.Headings {
		shown = shown || strings.HasPrefix(hd, "members:acme-actions ")
	}
	if !shown {
		t.Errorf("org view inbound headings = %v, want members:acme-actions", h.Org.Headings)
	}
	for _, want := range []string{"Inbound reach", "Outbound reach", "Fixes that touch this org", "Coverage gaps",
		"Default permission", "pin:action:acme-actions/deploy@main"} {
		if !strings.Contains(h.Org.Text, want) {
			t.Errorf("org view missing %q", want)
		}
	}
	// acme-legacy: the unseen IP allow list reads unknown, never off.
	if !strings.Contains(h.LegacyText, "IP allow listunknownnot visible") || strings.Contains(h.LegacyText, "IP allow listoff") {
		t.Errorf("acme-legacy settings: %q", h.LegacyText)
	}
	if !strings.Contains(h.LegacyText, "org owner on acme-legacy") {
		t.Error("acme-legacy coverage gap missing from its org view")
	}

	// confirmed + oidc: exactly the confirmed OIDC reach, computed from the graph.
	ix := graph.NewIndex(g)
	var want [][4]string
	for _, p := range ix.ScoringPrincipals() {
		for _, o := range ix.Reach(p, graph.Options{}).Confirmed.OIDC {
			want = append(want, [4]string{p, o, "confirmed", "oidc"})
		}
	}
	got := append([][4]string{}, h.Filtered.Paths...)
	less := func(s [][4]string) func(i, j int) bool {
		return func(i, j int) bool { return s[i][0]+s[i][1] < s[j][0]+s[j][1] }
	}
	sort.Slice(want, less(want))
	sort.Slice(got, less(got))
	if len(want) == 0 || !reflect.DeepEqual(got, want) {
		t.Errorf("confirmed+oidc filter\n got %v\nwant %v", got, want)
	}
	if len(h.Filtered.Summaries) != len(want) || h.Filtered.FormEv != "confirmed" || h.Filtered.FormKind != "oidc" || h.Filtered.StaticHidden {
		t.Errorf("filtered view: %+v", h.Filtered)
	}
	for _, s := range h.Filtered.Summaries {
		if !strings.HasPrefix(s, "confirmed ") || !strings.HasSuffix(s, " oidc") {
			t.Errorf("filtered summary %q", s)
		}
	}
	if !strings.HasPrefix(h.Filtered.Count, plural(len(want), "path", "paths")+" match") {
		t.Errorf("count line %q", h.Filtered.Count)
	}
	for _, p := range h.OrgFilter {
		if !strings.Contains(string(p[0]), `"acme-legacy"`) && string(p[1]) != `"acme-legacy"` {
			t.Errorf("org filter kept a path that does not touch acme-legacy: %s", p)
		}
	}
	if len(h.OrgFilter) == 0 {
		t.Error("org filter matched nothing")
	}

	if h.HashAfterInput != "#org=acme-app&ev=possible" {
		t.Errorf("hash after input = %q", h.HashAfterInput)
	}
	if h.HashAfterReset != "" {
		t.Errorf("hash after reset = %q", h.HashAfterReset)
	}
	if h.RoundTrip != "org=acme-app&ev=confirmed&kind=oidc" {
		t.Errorf("hash round trip = %q", h.RoundTrip)
	}
	if j := h.Junk; j.Route != "" || j.F.Ev != "" || j.F.Kind != "" || j.F.Ref != "" || j.F.Q != "" ||
		!reflect.DeepEqual(j.F.Orgs, []string{"acme-app"}) {
		t.Errorf("junk hash parsed to %+v", j)
	}
}
