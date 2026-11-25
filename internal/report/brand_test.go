package report

import (
	"math"
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
// included) has an HSL hue of 40 to 70 degrees with saturation above 30%,
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

func TestYellowCheck(t *testing.T) {
	for _, c := range []struct {
		r, g, b float64
		want    bool
	}{{255, 255, 0, true}, {212, 167, 44, true}, {210, 153, 34, true}, {242, 163, 58, false}, {58, 70, 201, false}, {128, 128, 100, false}} {
		if got := yellow(c.r, c.g, c.b); got != c.want {
			t.Errorf("yellow(%v,%v,%v) = %v, want %v", c.r, c.g, c.b, got, c.want)
		}
	}
}

// yellow reports an HSL hue of 40 to 70 degrees with saturation above 30%,
// the same rule as brand.TestNoYellow.
func yellow(r, g, b float64) bool {
	r, g, b = r/255, g/255, b/255
	mx, mn := math.Max(r, math.Max(g, b)), math.Min(r, math.Min(g, b))
	l, d := (mx+mn)/2, mx-mn
	if d == 0 {
		return false
	}
	s := d / (1 - math.Abs(2*l-1))
	var h float64
	switch mx {
	case r:
		h = math.Mod((g-b)/d, 6)
	case g:
		h = (b-r)/d + 2
	default:
		h = (r-g)/d + 4
	}
	h *= 60
	if h < 0 {
		h += 360
	}
	return h >= 40 && h <= 70 && s > 0.30
}

// TestNoHorizontalScroll390: at a 390px viewport the page must not be wider
// than the screen. The section nav is the widest row (every link on one
// line), so it scrolls inside itself and its intrinsic width must not reach
// the page; and no fixed width in the report's rules may exceed the 358px
// content column (390px less two 16px gutters).
func TestNoHorizontalScroll390(t *testing.T) {
	rule := func(sel string) string {
		i := strings.Index(reportCSS, "\n"+sel+"{")
		if i < 0 {
			t.Fatalf("no %s rule", sel)
		}
		r := reportCSS[i+1:]
		return r[:strings.Index(r, "}")]
	}
	ul := rule("nav ul")
	for _, want := range []string{"overflow-x:auto", "min-width:0", "max-width:100%", "contain:inline-size"} {
		if !strings.Contains(ul, want) {
			t.Errorf("nav ul rule lacks %s: %s", want, ul)
		}
	}
	if !strings.Contains(rule("nav .wrap"), "min-width:0") {
		t.Error("nav .wrap must allow shrinking (min-width:0)")
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
