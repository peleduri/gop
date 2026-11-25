// Package brand holds gop's design tokens: the single source of truth for
// color, type, spacing, radius, evidence styles and graph node shapes that
// every surface (HTML report, site, social preview, icons) follows.
//
// tokens.json is the source. CSS renders it as CSS custom properties
// (--gop-*); brand/gen writes that CSS to brand/tokens.css and site/brand.css,
// and the HTML report reads it from this package. BRAND.md at the repository
// root explains how to use each token.
package brand

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

//go:embed tokens.json
var tokensJSON []byte

// TokensJSON returns the raw tokens.json bytes.
func TokensJSON() []byte { return append([]byte(nil), tokensJSON...) }

// Tokens is the parsed tokens.json.
type Tokens struct {
	Name        string                       `json:"name"`
	Tagline     string                       `json:"tagline"`
	Description string                       `json:"description"`
	Color       map[string]map[string]string `json:"color"` // theme (light, dark) -> token -> #rrggbb
	Contrast    []Pair                       `json:"contrast"`
	Font        map[string]string            `json:"font"`
	Text        map[string]string            `json:"text"`
	Space       map[string]string            `json:"space"`
	Radius      map[string]string            `json:"radius"`
	Evidence    map[string]Stroke            `json:"evidence"` // graph.Evidence value -> style
	Reach       map[string]Stroke            `json:"reach"`    // confirmed, possible, danger, cut
	Nodes       map[string]Node              `json:"nodes"`    // node kind (plus "agent") -> style
}

// Pair is a foreground and background color token that must meet a minimum
// WCAG 2 contrast ratio in every theme.
type Pair struct {
	FG  string  `json:"fg"`
	BG  string  `json:"bg"`
	Min float64 `json:"min"`
}

// Stroke is how an edge or path is drawn: a color token, an SVG dash array
// ("none" for solid), an optional width, and the glyph shown next to its
// label so the style never depends on color alone.
type Stroke struct {
	Color string `json:"color"`
	Dash  string `json:"dash"`
	Width string `json:"width,omitempty"`
	Glyph string `json:"glyph"`
	Label string `json:"label,omitempty"`
}

// Node is how a graph node kind is drawn.
type Node struct {
	Shape string `json:"shape"`
	Color string `json:"color"`
}

// Load parses the embedded tokens.json.
func Load() (Tokens, error) {
	var t Tokens
	if err := json.Unmarshal(tokensJSON, &t); err != nil {
		return t, fmt.Errorf("brand: tokens.json: %w", err)
	}
	return t, nil
}

// MustLoad is Load that panics on a malformed tokens.json (a test guards it).
func MustLoad() Tokens {
	t, err := Load()
	if err != nil {
		panic(err)
	}
	return t
}

// CSS returns the tokens as CSS custom properties: light values on :root,
// dark values under prefers-color-scheme: dark (screen only, so print stays
// light). The output has no comments: html/template strips CSS comments,
// which would change the bytes a CSP hash covers.
func CSS() string {
	t := MustLoad()
	var b strings.Builder
	b.WriteString(":root{")
	decl(&b, "", t.Color["light"])
	decl(&b, "font-", t.Font)
	decl(&b, "text-", t.Text)
	decl(&b, "space-", t.Space)
	decl(&b, "radius-", t.Radius)
	dashes := map[string]string{}
	for k, s := range t.Evidence {
		dashes["ev-"+strings.ReplaceAll(k, "_", "-")] = s.Dash
	}
	for k, s := range t.Reach {
		dashes["reach-"+k] = s.Dash
	}
	decl(&b, "dash-", dashes)
	b.WriteString("}\n@media screen and (prefers-color-scheme: dark){:root{")
	decl(&b, "", t.Color["dark"])
	b.WriteString("}}\n")
	return b.String()
}

func decl(b *strings.Builder, prefix string, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "--gop-%s%s:%s;", prefix, k, m[k])
	}
}

// Contrast returns the WCAG 2 contrast ratio of two #rrggbb colors.
func Contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), nil
}

func luminance(hex string) (float64, error) {
	if len(hex) != 7 || hex[0] != '#' {
		return 0, fmt.Errorf("brand: color %q is not #rrggbb", hex)
	}
	var c [3]float64
	for i := range c {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("brand: color %q: %w", hex, err)
		}
		s := float64(v) / 255
		if s <= 0.04045 {
			c[i] = s / 12.92
		} else {
			c[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2], nil
}

// IsYellow reports whether an sRGB color (0 to 255 per channel) is yellow,
// amber, gold or mustard, which the brand forbids everywhere: an HSL hue of
// 30 to 70 degrees with saturation above 30%. The range starts at 30, not 40,
// so amber such as #f2a33a (hue 34) counts too.
func IsYellow(r, g, b uint8) bool {
	rf, gf, bf := float64(r)/255, float64(g)/255, float64(b)/255
	mx, mn := math.Max(rf, math.Max(gf, bf)), math.Min(rf, math.Min(gf, bf))
	if mx == mn {
		return false
	}
	d, l := mx-mn, (mx+mn)/2
	sat := d / (1 - math.Abs(2*l-1))
	var h float64
	switch mx {
	case rf:
		h = math.Mod((gf-bf)/d, 6)
	case gf:
		h = (bf-rf)/d + 2
	default:
		h = (rf-gf)/d + 4
	}
	h *= 60
	if h < 0 {
		h += 360
	}
	return h >= 30 && h <= 70 && sat > 0.30
}
