// Package site holds the checks for the GitHub Pages landing page in
// index.html. The page itself is static; site/build.sh adds the demo report.
package site

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/report"
)

const repoURL = "https://github.com/peleduri/gop"

// builtFiles are the paths site/build.sh writes next to index.html.
var builtFiles = map[string]bool{"favicon.svg": true, "demo/": true, "demo/report.md": true,
	"llms.txt": true, "llms-full.txt": true}

// pendingDocs are repo files the page links to that land in a parallel
// change. The link check skips them while they are missing; once they exist
// they are checked like every other link.
var pendingDocs = map[string]bool{"docs/compare.md": true, "docs/quickstart.md": true}

func loadPage(t *testing.T) (string, *html.Node) {
	t.Helper()
	b, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return string(b), doc
}

func walk(n *html.Node, f func(*html.Node)) {
	f(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, f)
	}
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func text(n *html.Node) string {
	var b strings.Builder
	walk(n, func(c *html.Node) {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	})
	return b.String()
}

// TestCSP keeps the page loadable under its own strict policy: one inline
// style block whose hash is in the policy, no scripts, and nothing loaded
// from another origin.
func TestCSP(t *testing.T) {
	src, doc := loadPage(t)
	var csp string
	var styles, scripts int
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		switch n.Data {
		case "meta":
			if v, _ := attr(n, "http-equiv"); strings.EqualFold(v, "Content-Security-Policy") {
				csp, _ = attr(n, "content")
			}
		case "style":
			styles++
		case "script":
			scripts++
		}
		if _, ok := attr(n, "style"); ok {
			t.Errorf("<%s> has a style attribute; the CSP blocks inline style attributes", n.Data)
		}
		for _, k := range []string{"src", "srcset", "data", "poster"} {
			if v, ok := attr(n, k); ok && isExternal(v) {
				t.Errorf("<%s %s=%q> loads from another origin", n.Data, k, v)
			}
		}
		if n.Data == "link" {
			if v, _ := attr(n, "href"); isExternal(v) {
				t.Errorf("<link href=%q> loads from another origin", v)
			}
		}
	})
	if styles != 1 || scripts != 0 {
		t.Fatalf("want 1 <style> and 0 <script>, got %d and %d", styles, scripts)
	}
	// Hash the raw bytes between the tags, as the browser does.
	i := strings.Index(src, "<style>")
	j := strings.Index(src, "</style>")
	if i < 0 || j < i {
		t.Fatal("<style> block not found")
	}
	sum := sha256.Sum256([]byte(src[i+len("<style>") : j]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	for _, d := range []string{"default-src 'none'", "style-src " + want, "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q lacks %q (update the style-src hash after editing the <style> block)", csp, d)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "script-src", "http:", "https:", "*"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP %q contains %q", csp, bad)
		}
	}
	css := src[i:j]
	if strings.Contains(css, "url(") || strings.Contains(css, "@import") || strings.Contains(css, "@font-face") {
		t.Error("the <style> block loads an external resource or web font")
	}
}

func isExternal(v string) bool {
	return strings.Contains(v, "://") || strings.HasPrefix(v, "//")
}

// TestLinks checks every link on the page: in-page anchors point at an id,
// relative links at a file build.sh writes, and repo links at a file in this
// repository.
func TestLinks(t *testing.T) {
	_, doc := loadPage(t)
	ids := map[string]bool{}
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if id, ok := attr(n, "id"); ok {
			if ids[id] {
				t.Errorf("duplicate id %q", id)
			}
			ids[id] = true
		}
	})
	var links int
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		var ref string
		switch n.Data {
		case "a", "link":
			ref, _ = attr(n, "href")
		case "iframe":
			ref, _ = attr(n, "src")
		default:
			return
		}
		links++
		if n.Data == "a" && strings.TrimSpace(text(n)) == "" {
			if _, ok := attr(n, "aria-label"); !ok {
				t.Errorf("link %q has no text", ref)
			}
		}
		switch {
		case strings.HasPrefix(ref, "#"):
			if !ids[ref[1:]] {
				t.Errorf("link %q: no element with that id", ref)
			}
		case ref == repoURL, ref == repoURL+"/releases":
		case strings.HasPrefix(ref, repoURL+"/blob/main/"):
			p := strings.TrimPrefix(ref, repoURL+"/blob/main/")
			if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(p))); err != nil {
				if pendingDocs[p] {
					t.Logf("link %q: %s does not exist yet (pending)", ref, p)
					return
				}
				t.Errorf("link %q: %s does not exist in the repo", ref, p)
			}
		case strings.HasPrefix(ref, cursorLink):
			checkCursorLink(t, ref)
		case isExternal(ref):
			t.Errorf("link %q: only links into %s are expected", ref, repoURL)
		default:
			if !builtFiles[ref] {
				t.Errorf("link %q: not a file site/build.sh writes", ref)
			}
		}
	})
	if links < 10 {
		t.Fatalf("found only %d links; is index.html parsed?", links)
	}
}

// demoNumbers renders the demo report as Markdown, exactly as
// `gop report --demo --format md` does, and pulls out the figures the page
// quotes.
func demoNumbers(t *testing.T) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	g := demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall})
	if err := report.Render(&buf, g, report.Options{Format: "md"}); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	got := map[string]string{}
	find := func(re string, keys ...string) {
		m := regexp.MustCompile(re).FindStringSubmatch(md)
		if m == nil {
			t.Fatalf("demo report no longer matches %q; update the test and the numbers in index.html", re)
		}
		for i, k := range keys {
			got[k] = m[i+1]
		}
	}
	find(`(?m)^\| members:acme-actions \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|`,
		"reach.repos", "reach.orgs", "reach.oidc", "reach.secrets", "reach.runners")
	find(`(?m)^\d+ workflows? runs? an AI coding agent; (\d+) can be started by people without push access`, "agents.exposed")
	find(`(?m)^\| 1 \| Remove standing org ownership from (\d+) accounts that own 5 or more orgs \(keep at least 2 owners per org\) \| \d+ \| (\d+)% \|`, "fix1.accounts", "fix1.pct")
	find(`(?m)^\| 2 \| [^|]+ \| \d+ \| (\d+)% \|`, "fix2.cum")
	find(`(?m)^\| 3 \| [^|]+ \| \d+ \| (\d+)% \|`, "fix3.cum")
	if !strings.Contains(md, "anyone on the internet on issue\\_comment") {
		t.Error("demo report no longer says the agent can be started by anyone on issue_comment; update the AI agents card in index.html")
	}
	return got
}

// TestDemoNumbers keeps every figure the page quotes (the elements with a
// data-n attribute) equal to what the current gop prints for the demo graph.
func TestDemoNumbers(t *testing.T) {
	want := demoNumbers(t)
	_, doc := loadPage(t)
	seen := map[string]bool{}
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		k, ok := attr(n, "data-n")
		if !ok {
			return
		}
		seen[k] = true
		w, known := want[k]
		switch {
		case !known:
			t.Errorf("data-n=%q is not a figure the test reads from the demo report", k)
		case strings.TrimSpace(text(n)) != w:
			t.Errorf("data-n=%q shows %q, gop report --demo says %q", k, text(n), w)
		}
	})
	for k := range want {
		if !seen[k] {
			t.Errorf("index.html does not show %s", k)
		}
	}
}
