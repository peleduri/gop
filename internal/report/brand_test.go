package report

import (
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/peleduri/gop/brand"
)

// TestReportUsesBrand: the style block starts with the brand tokens, the
// report's own rules take every color from them, and the header carries the
// mark and the tagline.
func TestReportUsesBrand(t *testing.T) {
	if !strings.HasPrefix(styleCSS, brand.CSS()) {
		t.Error("styleCSS does not start with brand.CSS()")
	}
	if tk := brand.MustLoad(); tagline != tk.Tagline {
		t.Errorf("tagline %q, brand/tokens.json says %q", tagline, tk.Tagline)
	}
	// every color in the report's own rules is a token: no literal hex,
	// rgb() or hsl() (color-mix of tokens is fine)
	if m := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(`).FindString(reportCSS); m != "" {
		t.Errorf("report CSS has a literal color %q; use a --gop-* token", m)
	}
	html := render(t, loadAcme(t), "html")
	for _, want := range []string{`<svg class="mark"`, `<p class="wm">gop <span>report</span></p>`, "<h1>" + tagline + "</h1>"} {
		if !strings.Contains(html, want) {
			t.Errorf("report header missing %q", want)
		}
	}
	md := render(t, loadAcme(t), "md")
	if !strings.HasPrefix(md, "# "+tagline+"\n") {
		t.Errorf("Markdown H1 is not the tagline: %q", strings.SplitN(md, "\n", 2)[0])
	}
	for name, out := range map[string]string{"html": html, "md": md} {
		if strings.Contains(out, "—") {
			t.Errorf("%s report has an em dash; BRAND.md forbids them", name)
		}
	}
}

// yellowNames are CSS color keywords in the forbidden hues.
var yellowNames = regexp.MustCompile(`(?i)\b(yellow|yellowgreen|greenyellow|gold|goldenrod|darkgoldenrod|palegoldenrod|lightgoldenrodyellow|khaki|darkkhaki|lightyellow|lemonchiffon|cornsilk|moccasin|wheat|orange|amber|mustard)\b`)

var (
	hexColor = regexp.MustCompile(`#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b`)
	rgbColor = regexp.MustCompile(`rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)`)
)

// TestReportNoYellow: like brand's TestNoYellow, for the report. No color in
// the style block, the inline script or the rendered pages (inline SVG
// included) is yellow by brand.IsYellow (HSL hue 30 to 70, saturation above 30%),
// and no CSS uses a yellow, gold, amber or orange keyword.
func TestReportNoYellow(t *testing.T) {
	sources := map[string]string{"style": styleCSS, "script": scriptJS}
	for name, page := range a11yPages(t) {
		sources["page "+name] = page
	}
	sources["markdown"] = render(t, loadAcme(t), "md")
	for name, src := range sources {
		for _, m := range hexColor.FindAllStringSubmatch(src, -1) {
			h := m[1]
			if len(h) == 3 {
				h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
			}
			r, _ := strconv.ParseUint(h[0:2], 16, 8)
			g, _ := strconv.ParseUint(h[2:4], 16, 8)
			b, _ := strconv.ParseUint(h[4:6], 16, 8)
			if yellow(float64(r), float64(g), float64(b)) {
				t.Errorf("%s uses yellow %s", name, m[0])
			}
		}
		for _, m := range rgbColor.FindAllStringSubmatch(src, -1) {
			r, _ := strconv.ParseFloat(m[1], 64)
			g, _ := strconv.ParseFloat(m[2], 64)
			b, _ := strconv.ParseFloat(m[3], 64)
			if yellow(r, g, b) {
				t.Errorf("%s uses yellow %s", name, m[0])
			}
		}
	}
	for name, css := range map[string]string{"style": styleCSS} {
		if m := yellowNames.FindString(css); m != "" {
			t.Errorf("%s uses the color keyword %q", name, m)
		}
	}
	// the emoji warning sign renders yellow on most systems
	for name, src := range sources {
		if strings.Contains(src, "⚠") {
			t.Errorf("%s uses ⚠, which renders as a yellow emoji; use the banner glyphs ▲ ? ⓘ", name)
		}
	}
}

// yellow is brand.IsYellow for float channels parsed from CSS.
func yellow(r, g, b float64) bool { return brand.IsYellow(uint8(r), uint8(g), uint8(b)) }

// TestNoHorizontalScroll390: at a 390px viewport the page must not be wider
// than the screen. Below 900px the navigation rail turns into a top menu
// with every group on one line, the widest row, so it scrolls inside itself
// and its intrinsic width must not reach the page; and no fixed width in the
// report's rules may exceed the 358px content column (390px less two 16px
// gutters).
func TestNoHorizontalScroll390(t *testing.T) {
	const narrow = "@media screen and (max-width:900px){"
	i := strings.Index(reportCSS, narrow)
	if i < 0 {
		t.Fatal("no narrow-screen block for the navigation rail")
	}
	block := reportCSS[i+len(narrow):]
	rule := func(css, sel string) string {
		j := strings.Index(css, "\n"+sel+"{")
		if j < 0 {
			t.Fatalf("no %s rule", sel)
		}
		r := css[j+1:]
		return r[:strings.Index(r, "}")]
	}
	menu := rule(block, ".rail-in")
	for _, want := range []string{"overflow-x:auto", "min-width:0", "max-width:100%", "contain:inline-size"} {
		if !strings.Contains(menu, want) {
			t.Errorf("narrow .rail-in rule lacks %s: %s", want, menu)
		}
	}
	if !strings.Contains(rule(reportCSS, ".rail"), "min-width:0") {
		t.Error(".rail must allow shrinking (min-width:0)")
	}
	if !strings.Contains(block, ".shell{display:block") {
		t.Error("the rail and content grid must stack below 900px")
	}
	screen := reportCSS[:strings.Index(reportCSS, "@media print")]
	for _, m := range regexp.MustCompile(`(?:^|[;{])((?:min-)?width):(\d+)px`).FindAllStringSubmatch(screen, -1) {
		if n, _ := strconv.Atoi(m[2]); n > 358 {
			t.Errorf("%s:%dpx is wider than the 358px content column at 390px", m[1], n)
		}
	}
	if !strings.Contains(render(t, loadAcme(t), "html"), `<meta name="viewport" content="width=device-width, initial-scale=1">`) {
		t.Error("no responsive viewport meta")
	}
}

// TestNoYellowPNG samples every pixel of the report screenshots that the
// README and docs/report.md show: none may be yellow by brand.IsYellow.
// Regenerate them from gop report --demo after a style change.
func TestNoYellowPNG(t *testing.T) {
	files, err := filepath.Glob("../../docs/assets/report-*.png")
	if err != nil || len(files) == 0 {
		t.Fatalf("no report screenshots: %v", err)
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		img, err := png.Decode(fh)
		_ = fh.Close()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		bd, n := img.Bounds(), 0
		for y := bd.Min.Y; y < bd.Max.Y; y++ {
			for x := bd.Min.X; x < bd.Max.X; x++ {
				r, g, b, a := img.At(x, y).RGBA()
				if a < 0x8000 {
					continue
				}
				if brand.IsYellow(uint8(r>>8), uint8(g>>8), uint8(b>>8)) {
					if n == 0 {
						t.Errorf("%s: yellow pixel #%02x%02x%02x at %d,%d", f, r>>8, g>>8, b>>8, x, y)
					}
					n++
				}
			}
		}
		if n > 0 {
			t.Errorf("%s: %d yellow pixels", f, n)
		}
	}
}
