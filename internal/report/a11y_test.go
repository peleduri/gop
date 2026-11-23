package report

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/net/html"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/diff"
)

// a11yPages are the reports the accessibility checks run on: the acme
// fixture, a report with the what-changed banner, and the demo graph
// (pinned exposures, cloud roles).
func a11yPages(t *testing.T) map[string]string {
	t.Helper()
	old, cur := loadPair(t, "lost-visibility")
	rep, err := diff.Compare(old, cur)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"acme":   render(t, loadAcme(t), "html"),
		"banner": renderWith(t, cur, "html", &rep),
		"demo":   render(t, demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}), "html"),
	}
}

var evidenceClasses = []string{"live", "inferred", "audit", "nv", "supplied"}

func TestA11yStructure(t *testing.T) {
	for name, page := range a11yPages(t) {
		t.Run(name, func(t *testing.T) {
			doc := parseHTML(t, page)
			if n := len(elements(doc, "h1")); n != 1 {
				t.Errorf("%d h1 elements, want 1", n)
			}
			for _, tag := range []string{"header", "nav", "main", "footer"} {
				if n := len(elements(doc, tag)); n != 1 {
					t.Errorf("%d <%s> landmarks, want 1", n, tag)
				}
			}
			if nav := elements(doc, "nav"); len(nav) == 1 {
				if l, _ := attr(nav[0], "aria-label"); l == "" {
					t.Error("nav has no aria-label")
				}
			}
			if h := elements(doc, "html"); len(h) != 1 || func() bool { l, _ := attr(h[0], "lang"); return l == "" }() {
				t.Error("html element has no lang")
			}

			// Headings in document order never skip a level going down.
			prev := 0
			walk(doc, func(n *html.Node) {
				if n.Type != html.ElementNode || len(n.Data) != 2 || n.Data[0] != 'h' || n.Data[1] < '1' || n.Data[1] > '6' {
					return
				}
				lvl := int(n.Data[1] - '0')
				if prev == 0 && lvl != 1 {
					t.Errorf("first heading is h%d, want h1", lvl)
				}
				if prev > 0 && lvl > prev+1 {
					t.Errorf("heading h%d %q follows h%d", lvl, text(n), prev)
				}
				prev = lvl
			})

			for _, tb := range elements(doc, "table") {
				caps := elements(tb, "caption")
				if len(caps) != 1 || strings.TrimSpace(text(caps[0])) == "" {
					t.Errorf("table without a caption: %.80q", text(tb))
				}
				ths := elements(tb, "th")
				if len(ths) == 0 {
					t.Errorf("table without th: %.80q", text(tb))
				}
				for _, th := range ths {
					if s, _ := attr(th, "scope"); s != "col" && s != "row" {
						t.Errorf("th %q has no scope", text(th))
					}
				}
			}

			labelFor := map[string]bool{}
			for _, l := range elements(doc, "label") {
				if f, ok := attr(l, "for"); ok {
					labelFor[f] = true
				}
			}
			for _, tag := range []string{"input", "select", "textarea"} {
				for _, c := range elements(doc, tag) {
					if !labelled(c, labelFor) {
						t.Errorf("<%s name=%q> has no label", tag, func() string { v, _ := attr(c, "name"); return v }())
					}
				}
			}
			for _, b := range elements(doc, "button") {
				if strings.TrimSpace(text(b)) == "" {
					t.Error("button without text")
				}
			}
			for _, a := range elements(doc, "a") {
				if strings.TrimSpace(text(a)) == "" {
					t.Error("link without text")
				}
				if h, _ := attr(a, "href"); strings.Contains(h, "ZgotmplZ") {
					t.Errorf("link %q was rejected by html/template", text(a))
				}
			}
			walk(doc, func(n *html.Node) {
				if v, ok := attr(n, "tabindex"); ok {
					if i, err := strconv.Atoi(v); err != nil || i > 0 {
						t.Errorf("tabindex %q: positive tabindex breaks keyboard order", v)
					}
				}
			})

			// Evidence is text plus an icon, never a CSS class alone.
			badges := 0
			walk(doc, func(n *html.Node) {
				if n.Type != html.ElementNode {
					return
				}
				for _, c := range evidenceClasses {
					if !hasClass(n, c) {
						continue
					}
					badges++
					if !hasWord(text(n)) {
						t.Errorf("evidence %q shown by class only: %q", c, text(n))
					}
					if ic := n.FirstChild; ic == nil || ic.Type != html.ElementNode || func() bool { v, _ := attr(ic, "aria-hidden"); return v != "true" }() {
						t.Errorf("evidence badge %q has no icon", text(n))
					}
				}
			})
			if badges == 0 {
				t.Error("no evidence badges found")
			}

			count := byID(doc, "gop-count")
			if count == nil {
				t.Fatal("no result count region")
			}
			if v, _ := attr(count, "aria-live"); v != "polite" {
				t.Errorf("result count region aria-live = %q, want polite", v)
			}
			if len(elements(doc, "svg")) > 0 {
				t.Error("report has an SVG: give it a text alternative listing the paths and update this check")
			}
		})
	}
}

// labelled reports whether a form control has an accessible name: a
// wrapping label, a label for its id, or aria-label.
func labelled(c *html.Node, labelFor map[string]bool) bool {
	if v, _ := attr(c, "aria-label"); strings.TrimSpace(v) != "" {
		return true
	}
	if id, ok := attr(c, "id"); ok && labelFor[id] {
		return true
	}
	for p := c.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && p.Data == "label" {
			return strings.TrimSpace(text(p)) != ""
		}
	}
	return false
}

func hasWord(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// TestScriptRendersAccessibleMarkup checks the inline script's own markup
// statically: every table it builds goes through one helper that adds a
// caption and scoped headers, every badge has an icon, and the result count
// is announced. TestInlineScriptInNode checks the rendered output.
func TestScriptRendersAccessibleMarkup(t *testing.T) {
	if n := strings.Count(scriptJS, `h("table"`); n != 1 {
		t.Errorf("script builds tables in %d places; route every table through table() so it gets a caption", n)
	}
	for _, want := range []string{`h("caption","vh",cap)`, `th.scope="col"`, `setAttribute("aria-hidden","true")`} {
		if !strings.Contains(scriptJS, want) {
			t.Errorf("script missing %q", want)
		}
	}
	if strings.Count(scriptJS, `h("span","badge`) != 1 {
		t.Error("script builds a badge without the icon helper")
	}
}

var (
	cssVar   = regexp.MustCompile(`--([a-z-]+):(#[0-9a-f]{3,6})`)
	darkPart = "@media (prefers-color-scheme: dark)"
)

func parseVars(s string) map[string]string {
	out := map[string]string{}
	for _, m := range cssVar.FindAllStringSubmatch(s, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func luminance(hex string) float64 {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) == 3 {
		hex = string([]byte{hex[0], hex[0], hex[1], hex[1], hex[2], hex[2]})
	}
	var c [3]float64
	for i := range c {
		v, _ := strconv.ParseUint(hex[2*i:2*i+2], 16, 8)
		x := float64(v) / 255
		if x <= 0.03928 {
			c[i] = x / 12.92
		} else {
			c[i] = math.Pow((x+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestContrastAA checks every text color on every background it is used on
// against WCAG AA (4.5:1 for normal text), in the light and dark themes.
func TestContrastAA(t *testing.T) {
	i := strings.Index(styleCSS, darkPart)
	if i < 0 {
		t.Fatal("no dark theme")
	}
	light := parseVars(styleCSS[:i])
	dark := map[string]string{}
	for k, v := range light {
		dark[k] = v
	}
	for k, v := range parseVars(styleCSS[i:]) {
		dark[k] = v
	}
	pairs := [][2]string{
		{"fg", "bg"}, {"fg", "card"}, {"muted", "bg"}, {"muted", "card"}, {"accent", "bg"}, {"accent", "card"},
		{"live", "live-bg"}, {"audit", "audit-bg"}, {"nv", "nv-bg"},
	}
	for theme, vars := range map[string]map[string]string{"light": light, "dark": dark} {
		for _, p := range pairs {
			fg, bg := vars[p[0]], vars[p[1]]
			if fg == "" || bg == "" {
				t.Fatalf("%s: missing --%s or --%s", theme, p[0], p[1])
			}
			if r := contrast(fg, bg); r < 4.5 {
				t.Errorf("%s: --%s on --%s is %.2f:1, want at least 4.5:1", theme, p[0], p[1], r)
			}
		}
	}
}
