package site

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/peleduri/gop/brand"
)

// siteColorFiles are the site's own files that carry colors, plus the social
// preview the page points og:image at.
var siteColorFiles = []string{"../docs/assets/architecture.svg", "index.html", "brand.css", "favicon.svg", "architecture.svg", "architecture-narrow.svg",
	filepath.Join("..", "brand", "social-preview.svg")}

var (
	hexColor = regexp.MustCompile(`#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b`)
	rgbColor = regexp.MustCompile(`rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)`)
)

// parseHex reads #rgb or #rrggbb.
func parseHex(t *testing.T, hex string) [3]uint8 {
	t.Helper()
	h := strings.TrimPrefix(hex, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	var c [3]uint8
	for i := range c {
		v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatalf("color %s: %v", hex, err)
		}
		c[i] = uint8(v)
	}
	return c
}

// TestNoYellow extends brand.TestNoYellow to the site: no color in the page's
// HTML and CSS, the favicon, the architecture diagrams or the social preview
// may be yellow, amber, gold or mustard.
func TestNoYellow(t *testing.T) {
	for _, f := range siteColorFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		var n int
		for _, hex := range hexColor.FindAllString(src, -1) {
			n++
			if c := parseHex(t, hex); brand.IsYellow(c[0], c[1], c[2]) {
				t.Errorf("%s uses yellow %s; the brand forbids yellow, amber, gold and mustard", f, hex)
			}
		}
		for _, m := range rgbColor.FindAllStringSubmatch(src, -1) {
			n++
			var c [3]uint8
			for i := range c {
				v, err := strconv.ParseUint(m[i+1], 10, 8)
				if err != nil {
					t.Fatalf("%s: %s: %v", f, m[0], err)
				}
				c[i] = uint8(v)
			}
			if brand.IsYellow(c[0], c[1], c[2]) {
				t.Errorf("%s uses yellow %s", f, m[0])
			}
		}
		for _, name := range []string{"yellow", "gold", "orange", "amber", "goldenrod", "khaki", "moccasin", "wheat"} {
			if regexp.MustCompile(`(?i)(?:fill|stroke|color|background)[=:]\s*"?` + name + `\b`).MatchString(src) {
				t.Errorf("%s uses the named color %s", f, name)
			}
		}
		if n == 0 {
			t.Errorf("%s: no colors found; is the check reading the right file?", f)
		}
	}
}

// tokenHexes is every color value in brand/tokens.json, both themes.
func tokenHexes(t *testing.T) map[string]bool {
	t.Helper()
	tk, err := brand.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, theme := range tk.Color {
		for _, v := range theme {
			m[strings.ToLower(v)] = true
		}
	}
	return m
}

// TestColorsFromTokens: every hex color the page and its SVGs use is a value
// from brand/tokens.json, so the site cannot drift from the palette.
func TestColorsFromTokens(t *testing.T) {
	tokens := tokenHexes(t)
	for _, f := range siteColorFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, hex := range hexColor.FindAllString(string(b), -1) {
			if len(hex) != 7 || !tokens[strings.ToLower(hex)] {
				t.Errorf("%s uses %s, which is not a color token in brand/tokens.json", f, hex)
			}
		}
	}
}

// TestBrandCSSInlined: the one <style> block starts with site/brand.css byte
// for byte, so the page uses the generated tokens and not a stale copy.
func TestBrandCSSInlined(t *testing.T) {
	src, _ := loadPage(t)
	css, err := os.ReadFile("brand.css")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(src, "<style>\n")
	if i < 0 || !strings.HasPrefix(src[i+len("<style>\n"):], string(css)) {
		t.Fatal("the <style> block must start with site/brand.css byte for byte (run go run ./brand/gen, then paste site/brand.css)")
	}
	rest := src[i+len("<style>\n")+len(css) : strings.Index(src, "</style>")]
	for _, primer := range []string{"#0969da", "#1a7f37", "#cf222e", "#0d1117", "#1f2328", "#f6f8fa"} {
		if strings.Contains(rest, primer) {
			t.Errorf("site CSS still uses the old GitHub Primer color %s; use a --gop-* token", primer)
		}
	}
}

// TestFavicon: the favicon is the brand mark, and the PNG fallbacks exist.
func TestFavicon(t *testing.T) {
	got, err := os.ReadFile("favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "brand", "logo", "gop-mark.svg"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("site/favicon.svg differs from brand/logo/gop-mark.svg; copy it over")
	}
	for _, f := range []string{"gop-mark-32.png", "gop-mark-180.png"} {
		if _, err := os.Stat(filepath.Join("..", "brand", "logo", "png", f)); err != nil {
			t.Errorf("build.sh copies brand/logo/png/%s: %v", f, err)
		}
	}
}

// TestBrandHead: the headline is the tagline, the description and og: tags use
// the brand description, and the social preview is wired up.
func TestBrandHead(t *testing.T) {
	tk, err := brand.Load()
	if err != nil {
		t.Fatal(err)
	}
	_, doc := loadPage(t)
	meta := map[string]string{}
	var h1, title string
	var images []string
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		switch n.Data {
		case "meta":
			k, ok := attr(n, "property")
			if !ok {
				k, _ = attr(n, "name")
			}
			v, _ := attr(n, "content")
			if k != "" && k != "theme-color" {
				meta[k] = v
			}
		case "h1":
			h1 = strings.Join(strings.Fields(text(n)), " ")
		case "title":
			title = text(n)
		case "img":
			v, _ := attr(n, "src")
			images = append(images, v)
		case "source":
			v, _ := attr(n, "srcset")
			images = append(images, v)
		}
	})
	if h1 != tk.Tagline {
		t.Errorf("h1 = %q, want the tagline %q", h1, tk.Tagline)
	}
	wantTitle := "gop: " + strings.ToLower(tk.Tagline[:1]) + strings.TrimSuffix(tk.Tagline[1:], ".")
	if title != wantTitle {
		t.Errorf("<title> = %q, want %q", title, wantTitle)
	}
	for k, want := range map[string]string{
		"description":     tk.Description,
		"og:description":  tk.Description,
		"og:title":        wantTitle,
		"og:site_name":    "gop",
		"og:type":         "website",
		"og:url":          siteURL,
		"og:image":        siteURL + "social-preview.png",
		"og:image:width":  "1280",
		"og:image:height": "640",
		"twitter:card":    "summary_large_image",
	} {
		if meta[k] != want {
			t.Errorf("meta %s = %q, want %q", k, meta[k], want)
		}
	}
	if meta["og:image:alt"] == "" {
		t.Error("og:image has no og:image:alt text")
	}
	png, err := os.ReadFile(filepath.Join("..", "brand", "social-preview.png"))
	if err != nil {
		t.Fatal(err)
	}
	// PNG IHDR: width and height are big-endian uint32 at bytes 16 and 20.
	if len(png) < 24 || string(png[1:4]) != "PNG" {
		t.Fatal("brand/social-preview.png is not a PNG")
	}
	w := int(png[16])<<24 | int(png[17])<<16 | int(png[18])<<8 | int(png[19])
	h := int(png[20])<<24 | int(png[21])<<16 | int(png[22])<<8 | int(png[23])
	if w != 1280 || h != 640 {
		t.Errorf("brand/social-preview.png is %dx%d, want 1280x640", w, h)
	}
	if len(images) == 0 {
		t.Error("the page shows no architecture diagram")
	}
	for _, src := range images {
		if !builtFiles[src] {
			t.Errorf("image %q is not a file site/build.sh writes", src)
		}
		if _, err := os.Stat(src); err != nil {
			t.Errorf("image %q: %v", src, err)
		}
	}
}

// TestNoEmDash: BRAND.md voice rules allow no em dash on any surface.
func TestNoEmDash(t *testing.T) {
	for _, f := range []string{"index.html", "architecture.svg", "architecture-narrow.svg"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "—") || strings.Contains(string(b), "&mdash;") {
			t.Errorf("%s has an em dash", f)
		}
	}
}
