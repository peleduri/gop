package brand

import (
	"image"
	"image/color"
	_ "image/png"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// TestThemesComplete: light and dark define the same tokens, all as
// lowercase #rrggbb.
func TestThemesComplete(t *testing.T) {
	tk := MustLoad()
	light, dark := tk.Color["light"], tk.Color["dark"]
	if len(light) == 0 || len(dark) == 0 || len(tk.Color) != 2 {
		t.Fatalf("want exactly the light and dark themes, got %d themes", len(tk.Color))
	}
	for k, v := range light {
		if _, ok := dark[k]; !ok {
			t.Errorf("token %q is in light but not dark", k)
		}
		if !hexColor.MatchString(v) {
			t.Errorf("light %s = %q, want lowercase #rrggbb", k, v)
		}
	}
	for k, v := range dark {
		if _, ok := light[k]; !ok {
			t.Errorf("token %q is in dark but not light", k)
		}
		if !hexColor.MatchString(v) {
			t.Errorf("dark %s = %q, want lowercase #rrggbb", k, v)
		}
	}
}

// TestContrast checks every declared pair against WCAG 2 AA in both themes:
// 4.5:1 for text, 3:1 for strokes and UI boundaries.
func TestContrast(t *testing.T) {
	tk := MustLoad()
	if len(tk.Contrast) == 0 {
		t.Fatal("no contrast pairs declared")
	}
	for theme, c := range tk.Color {
		for _, p := range tk.Contrast {
			if p.Min < 3 {
				t.Errorf("pair %s on %s: min %.1f is below WCAG AA for graphics (3)", p.FG, p.BG, p.Min)
			}
			fg, ok1 := c[p.FG]
			bg, ok2 := c[p.BG]
			if !ok1 || !ok2 {
				t.Errorf("%s: pair %s on %s names an unknown token", theme, p.FG, p.BG)
				continue
			}
			r, err := Contrast(fg, bg)
			if err != nil {
				t.Fatal(err)
			}
			if r < p.Min {
				t.Errorf("%s: %s (%s) on %s (%s) = %.2f:1, want >= %.1f:1", theme, p.FG, fg, p.BG, bg, r, p.Min)
			}
		}
	}
}

// TestEverySemanticColorChecked: each foreground role used for evidence,
// reach or nodes appears in at least one contrast pair against surface.
func TestEverySemanticColorChecked(t *testing.T) {
	tk := MustLoad()
	onSurface := map[string]bool{}
	for _, p := range tk.Contrast {
		if p.BG == "surface" {
			onSurface[p.FG] = true
		}
	}
	var roles []string
	for _, s := range tk.Evidence {
		roles = append(roles, s.Color)
	}
	for _, s := range tk.Reach {
		roles = append(roles, s.Color)
	}
	for _, n := range tk.Nodes {
		roles = append(roles, n.Color)
	}
	for _, r := range roles {
		if !onSurface[r] {
			t.Errorf("color token %q is used in the graph language but has no contrast pair on surface", r)
		}
	}
}

// TestNotColorAlone: the evidence levels and reach states differ by line
// style and glyph, not only by color, so they survive grayscale and red/green
// color blindness. Node kinds differ by shape.
func TestNotColorAlone(t *testing.T) {
	tk := MustLoad()
	for _, ev := range []string{"live", "inferred", "audit", "supplied", "not_visible"} {
		if _, ok := tk.Evidence[ev]; !ok {
			t.Errorf("evidence level %q has no style", ev)
		}
	}
	unique := func(what string, vals map[string]string) {
		seen := map[string]string{}
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := vals[k]
			if v == "" {
				t.Errorf("%s %q is empty", what, k)
			}
			if o, ok := seen[v]; ok {
				t.Errorf("%s %q repeats %q from %q", what, v, k, o)
			}
			seen[v] = k
		}
	}
	dash, glyph := map[string]string{}, map[string]string{}
	for k, s := range tk.Evidence {
		dash[k], glyph[k] = s.Dash, s.Glyph
	}
	unique("evidence dash", dash)
	unique("evidence glyph", glyph)
	rglyph, rstyle := map[string]string{}, map[string]string{}
	for k, s := range tk.Reach {
		rglyph[k], rstyle[k] = s.Glyph, s.Dash+"/"+s.Width
	}
	unique("reach glyph", rglyph)
	unique("reach dash/width", rstyle)
	shape := map[string]string{}
	for k, n := range tk.Nodes {
		shape[k] = n.Shape
	}
	unique("node shape", shape)
	for _, k := range []string{"enterprise", "org", "org_members", "identity", "external", "repo", "workflow",
		"action_ref", "secret", "oidc", "runner", "cloud_target", "agent"} {
		if _, ok := tk.Nodes[k]; !ok {
			t.Errorf("node kind %q has no shape", k)
		}
	}
}

// TestCopiesMatch: the generated CSS files equal TokensCSS and SiteCSS. Run
// go run ./brand/gen after editing tokens.json.
func TestCopiesMatch(t *testing.T) {
	for p, want := range map[string]string{"tokens.css": TokensCSS(), "../site/brand.css": SiteCSS()} {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s is stale; run go run ./brand/gen from the repository root", p)
		}
	}
}

// fontURL matches every url() in the generated CSS.
var fontURL = regexp.MustCompile(`url\(([^)]*)\)`)

// TestCSSSafeForReport: the CSS has no comments (html/template strips them,
// breaking the report's CSP hash) and loads nothing (the report works
// offline): its only url()s are the embedded fonts as data: URLs.
func TestCSSSafeForReport(t *testing.T) {
	css := CSS()
	for _, bad := range []string{"/*", "@import", "</"} {
		if strings.Contains(css, bad) {
			t.Errorf("CSS contains %q", bad)
		}
	}
	urls := fontURL.FindAllStringSubmatch(css, -1)
	for _, m := range urls {
		if !strings.HasPrefix(m[1], `"data:font/woff2;base64,`) {
			t.Errorf("CSS loads %.60s; the report may only embed fonts as data: URLs", m[1])
		}
	}
	var want int
	for _, f := range MustLoad().Faces {
		if f.Report {
			want++
		}
	}
	if len(urls) != want || strings.Count(css, "@font-face{") != want {
		t.Errorf("CSS has %d font URLs, want one per report face (%d)", len(urls), want)
	}
	if !strings.Contains(css, "--gop-accent:") || !strings.Contains(css, "--gop-dash-ev-not-visible:2 4;") {
		t.Errorf("CSS lacks expected tokens:\n%s", css)
	}
	if tc := TokensCSS(); strings.Contains(tc, "url(") || strings.Contains(tc, "@font-face") || !strings.HasSuffix(css, tc) {
		t.Error("TokensCSS must be the custom properties only, and CSS must end with it")
	}
}

// reportFontBudget caps the bytes the embedded faces add to every HTML
// report (base64 included).
const reportFontBudget = 150 << 10

// TestFaces: every face names a vendored woff2 file, the files ship with the
// OFL, the embedded faces stay within budget, and the font stacks start with
// the vendored families and keep the system stack as the fallback.
func TestFaces(t *testing.T) {
	tk := MustLoad()
	if len(tk.Faces) == 0 || tk.FaceRange == "" {
		t.Fatal("tokens.json has no faces or no face_unicode_range")
	}
	families := map[string]bool{}
	for _, f := range tk.Faces {
		b, err := FontFile(f.File)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < 4 || string(b[:4]) != "wOF2" {
			t.Errorf("%s is not a woff2 file", f.File)
		}
		families[f.Family] = true
	}
	if lic, err := os.ReadFile("fonts/OFL.txt"); err != nil || !strings.Contains(string(lic), "SIL OPEN FONT LICENSE Version 1.1") {
		t.Errorf("brand/fonts/OFL.txt must hold the SIL Open Font License next to the fonts (err %v)", err)
	}
	for k, fallback := range map[string]string{"sans": "system-ui,", "mono": "ui-monospace,"} {
		stack := tk.Font[k]
		fam := strings.Trim(strings.SplitN(stack, ",", 2)[0], `"`)
		if !families[fam] {
			t.Errorf("font.%s starts with %q, which is not a vendored face", k, fam)
		}
		if !strings.Contains(stack, fallback) {
			t.Errorf("font.%s lost its system fallback %q", k, fallback)
		}
	}
	if n := len(CSS()) - len(TokensCSS()); n > reportFontBudget {
		t.Errorf("embedded faces add %d bytes to the report, budget %d", n, reportFontBudget)
	}
}

// TestDocMatchesTokens: BRAND.md lists every color token with its light and
// dark values, so the doc cannot drift from tokens.json.
func TestDocMatchesTokens(t *testing.T) {
	doc, err := os.ReadFile("../BRAND.md")
	if err != nil {
		t.Fatal(err)
	}
	tk := MustLoad()
	for k, light := range tk.Color["light"] {
		row := "| `" + k + "` | `" + light + "` | `" + tk.Color["dark"][k] + "` |"
		if !strings.Contains(string(doc), row) {
			t.Errorf("BRAND.md lacks the row %s", row)
		}
	}
	if !strings.Contains(string(doc), tk.Tagline) {
		t.Errorf("BRAND.md lacks the tagline %q", tk.Tagline)
	}
	if !strings.Contains(string(doc), tk.Description) {
		t.Errorf("BRAND.md lacks the description %q", tk.Description)
	}
	if n := len(strings.Fields(tk.Description)); n != 25 {
		t.Errorf("description has %d words, want 25", n)
	}
	if strings.ContainsRune(string(doc), '\u2014') {
		t.Error("BRAND.md uses an em dash; the voice rules forbid it")
	}
}

func TestContrastKnownValues(t *testing.T) {
	r, err := Contrast("#000000", "#ffffff")
	if err != nil || r < 20.99 || r > 21.01 {
		t.Errorf("black on white = %v, %v; want 21", r, err)
	}
	if _, err := Contrast("#fff", "#000000"); err == nil {
		t.Error("short hex accepted")
	}
}

// TestNoYellow: the brand has no yellow, amber, gold or mustard. Any color
// token or brand SVG color that IsYellow reports (HSL hue 30 to 70 degrees,
// saturation above 30%) fails. site/site_test.go applies the same check to
// the site's HTML, CSS and SVG.
func TestNoYellow(t *testing.T) {
	tk := MustLoad()
	for theme, c := range tk.Color {
		for tok, hex := range c {
			if yellowHex(t, hex) {
				h, sat := hsl(t, hex)
				t.Errorf("%s: %s %s is yellow (hue %.0f, saturation %.0f%%); the brand forbids yellow", theme, tok, hex, h, sat*100)
			}
		}
	}
	for _, f := range []string{"graph-language.svg", "logo/gop-mark.svg", "logo/gop-mark-color.svg", "logo/gop-mark-mono.svg", "logo/gop-logo.svg", "social-preview.svg"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, hex := range regexp.MustCompile(`#[0-9a-fA-F]{6}\b`).FindAllString(string(b), -1) {
			if yellowHex(t, strings.ToLower(hex)) {
				t.Errorf("%s uses yellow %s", f, hex)
			}
		}
	}
}

// TestNoYellowPNG samples every pixel of the logo PNGs and of the plugin
// icons copied from them: none may be yellow by the rule above. Pixels that
// are almost transparent are skipped (their color is anti-aliasing noise).
func TestNoYellowPNG(t *testing.T) {
	files, err := filepath.Glob("logo/png/*.png")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "../.claude-plugin/icon.png", "../.cursor-plugin/logo.png", "social-preview.png")
	for _, f := range files {
		r, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		img, _, err := image.Decode(r)
		_ = r.Close()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		b, yellow := img.Bounds(), 0
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
				if c.A < 64 {
					continue
				}
				if IsYellow(c.R, c.G, c.B) {
					yellow++
				}
			}
		}
		if yellow > 0 {
			t.Errorf("%s has %d yellow pixels; the brand forbids yellow", f, yellow)
		}
	}
}

// TestIsYellow keeps the exported check in step with the token test above.
func TestIsYellow(t *testing.T) {
	for c, want := range map[[3]uint8]bool{{255, 255, 0}: true, {0xf2, 0xa3, 0x3a}: true, {0xe1, 0x6f, 0x24}: false, {0xd4, 0xa0, 0x17}: true, {0xc9, 0xa2, 0x27}: true, {0x3a, 0x46, 0xc9}: false, {0x80, 0x80, 0x80}: false, {0xee, 0xee, 0xe0}: false} {
		if got := IsYellow(c[0], c[1], c[2]); got != want {
			t.Errorf("IsYellow(%v) = %v, want %v", c, got, want)
		}
	}
}

func yellowHex(t *testing.T, hex string) bool {
	t.Helper()
	var c [3]uint8
	for i := range c {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		c[i] = uint8(v)
	}
	return IsYellow(c[0], c[1], c[2])
}

func TestHSL(t *testing.T) {
	for hex, want := range map[string]float64{"#ffff00": 60, "#ff0000": 0, "#0000ff": 240, "#f2a33a": 34} {
		if h, _ := hsl(t, hex); math.Abs(h-want) > 1 {
			t.Errorf("hue(%s) = %.1f, want %.0f", hex, h, want)
		}
	}
}

// hsl returns the HSL hue in degrees and the saturation (0 to 1).
func hsl(t *testing.T, hex string) (float64, float64) {
	t.Helper()
	var rgb [3]float64
	for i := range rgb {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		rgb[i] = float64(v) / 255
	}
	return hslRGB(rgb[0], rgb[1], rgb[2])
}

// hslRGB returns the HSL hue in degrees and the saturation (0 to 1) of an
// RGB color with channels from 0 to 1.
func hslRGB(r, g, b float64) (float64, float64) {
	mx, mn := math.Max(r, math.Max(g, b)), math.Min(r, math.Min(g, b))
	if mx == mn {
		return 0, 0
	}
	d, l := mx-mn, (mx+mn)/2
	sat := d / (1 - math.Abs(2*l-1))
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
	return h, sat
}
