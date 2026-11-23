package report

import (
	"bytes"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
)

var diffCases = []string{"default-perm-raised", "identical", "lost-visibility", "org-added", "ref-unpinned"}

func loadPair(t *testing.T, name string) (old, cur *graph.Graph) {
	t.Helper()
	dir := filepath.Join("..", "diff", "testdata", name)
	old, err := graph.LoadFile(filepath.Join(dir, "old.json"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err = graph.LoadFile(filepath.Join(dir, "new.json"))
	if err != nil {
		t.Fatal(err)
	}
	return old, cur
}

func renderWith(t *testing.T, g *graph.Graph, format string, ch *diff.Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, g, Options{Format: format, Version: "v0.0.0-test", Changes: ch}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// wantCounts counts what gop diff reports, per banner group, straight from
// the diff report (independently of buildBanner).
func wantCounts(r diff.Report) map[string]int {
	settings, lostSettings := 0, 0
	for _, c := range r.Settings {
		switch c.Status {
		case diff.Changed, diff.GainedVisibility:
			settings++
		case diff.LostVisibility:
			lostSettings++
		}
	}
	return map[string]int{
		"new-confirmed": r.Paths.Count(diff.Added, true) + r.Paths.Count(diff.Upgraded, false),
		"removed":       r.Paths.Count(diff.Removed, false),
		"new-possible":  r.Paths.Count(diff.Added, false),
		"settings":      settings,
		"lost-visibility": r.Paths.Count(diff.LostVisibility, false) + r.Paths.Count(diff.Downgraded, false) +
			lostSettings + len(r.Coverage.Opened),
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

func hasClass(n *html.Node, c string) bool {
	v, _ := attr(n, "class")
	for _, f := range strings.Fields(v) {
		if f == c {
			return true
		}
	}
	return false
}

func walk(n *html.Node, f func(*html.Node)) {
	f(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, f)
	}
}

func elements(root *html.Node, tag string) []*html.Node {
	var out []*html.Node
	walk(root, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tag {
			out = append(out, n)
		}
	})
	return out
}

func byID(root *html.Node, id string) *html.Node {
	var found *html.Node
	walk(root, func(n *html.Node) {
		if v, ok := attr(n, "id"); ok && v == id && found == nil {
			found = n
		}
	})
	return found
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

func parseHTML(t *testing.T, s string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestBannerMatchesDiff: with --previous, every banner group counts exactly
// what gop diff reports, and the banner leads with gop diff's own headline.
func TestBannerMatchesDiff(t *testing.T) {
	nonzero := map[string]bool{}
	for _, name := range diffCases {
		t.Run(name, func(t *testing.T) {
			old, cur := loadPair(t, name)
			rep, err := diff.Compare(old, cur)
			if err != nil {
				t.Fatal(err)
			}
			doc := parseHTML(t, renderWith(t, cur, "html", &rep))
			ban := byID(doc, "changes")
			if ban == nil {
				t.Fatal("no banner with --previous")
			}
			if got := text(ban); !strings.Contains(got, rep.Headline()) {
				t.Errorf("banner does not lead with gop diff's headline %q:\n%s", rep.Headline(), got)
			}
			want := wantCounts(rep)
			seen := 0
			for _, g := range elements(ban, "div") {
				if !hasClass(g, "group") {
					continue
				}
				seen++
				id, _ := attr(g, "id")
				key := strings.TrimPrefix(id, "changes-")
				dc, _ := attr(g, "data-count")
				n, err := strconv.Atoi(dc)
				if err != nil {
					t.Fatalf("%s: data-count %q", id, dc)
				}
				w, ok := want[key]
				if !ok {
					t.Errorf("unexpected group %s", id)
					continue
				}
				if n != w {
					t.Errorf("%s: banner counts %d, gop diff reports %d", key, n, w)
				}
				if n > 0 {
					nonzero[key] = true
				}
				items := len(elements(g, "li"))
				wantItems := min(w, maxBannerItems)
				if w > maxBannerItems {
					wantItems++ // "and N more"
				}
				if items != wantItems {
					t.Errorf("%s: %d list items, want %d", key, items, wantItems)
				}
				for _, a := range elements(g, "a") {
					if h, _ := attr(a, "href"); !strings.HasPrefix(h, "#") {
						t.Errorf("%s: link %q is not a view in this file", key, h)
					}
				}
			}
			if seen != len(want) {
				t.Errorf("%d groups, want %d", seen, len(want))
			}
		})
	}
	for _, k := range []string{"new-confirmed", "settings", "lost-visibility"} {
		if !nonzero[k] {
			t.Errorf("no fixture exercises a non-empty %s group", k)
		}
	}
}

func TestBannerLinks(t *testing.T) {
	old, cur := loadPair(t, "ref-unpinned")
	rep, err := diff.Compare(old, cur)
	if err != nil {
		t.Fatal(err)
	}
	b := buildBanner(&rep, nil)
	if len(b.Groups[0].Items) == 0 {
		t.Fatal("ref-unpinned: no new confirmed path")
	}
	it := b.Groups[0].Items[0]
	s := parseFilterHash(it.Href)
	q, err := url.QueryUnescape(s["q"])
	if err != nil || it.Ev != "confirmed" || s["ev"] != "confirmed" || q == "" || !strings.HasPrefix(it.Text, q+" → ") {
		t.Errorf("new confirmed item %+v links to %v", it, s)
	}
	old, cur = loadPair(t, "default-perm-raised")
	if rep, err = diff.Compare(old, cur); err != nil {
		t.Fatal(err)
	}
	b = buildBanner(&rep, nil)
	if len(b.Groups[3].Items) == 0 || !strings.HasPrefix(b.Groups[3].Items[0].Href, "#/org/") {
		t.Errorf("setting change does not link to its org view: %+v", b.Groups[3])
	}
}

// parseFilterHash reads a filter hash the way the report's script does (key=value
// pairs after "#"), enough to check the banner's links.
func parseFilterHash(h string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(strings.TrimPrefix(h, "#"), "&") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

func TestNoBannerWithoutPrevious(t *testing.T) {
	_, cur := loadPair(t, "ref-unpinned")
	out := renderWith(t, cur, "html", nil)
	for _, bad := range []string{`id="changes"`, "What changed", `href="#changes"`, `class="banner"`} {
		if strings.Contains(out, bad) {
			t.Errorf("report without --previous has banner markup %q", bad)
		}
	}
	if md := renderWith(t, cur, "md", nil); strings.Contains(md, "What changed") {
		t.Error("markdown report without --previous has a what-changed section")
	}
}

func TestBannerMarkdown(t *testing.T) {
	old, cur := loadPair(t, "ref-unpinned")
	rep, err := diff.Compare(old, cur)
	if err != nil {
		t.Fatal(err)
	}
	md := renderWith(t, cur, "md", &rep)
	want := wantCounts(rep)
	for _, w := range []string{"## What changed\n\nPrevious snapshot 2026-11-13 → this snapshot 2026-11-20.", "- New confirmed paths: " + strconv.Itoa(want["new-confirmed"]),
		"- Removed paths: " + strconv.Itoa(want["removed"])} {
		if !strings.Contains(md, w) {
			t.Errorf("markdown banner missing %q", w)
		}
	}
}
