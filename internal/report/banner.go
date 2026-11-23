package report

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
)

// maxBannerItems caps the items listed per banner group; the count stays
// exact and the rest is summarized as "and N more".
const maxBannerItems = 10

// banner is the "what changed" block at the top of the report, built from
// diff.Compare(previous, current). It lists what gop diff reports: its
// headline sentence verbatim, then the path and setting changes per group.
type banner struct {
	Since, Until string
	Summary      string
	Groups       []bannerGroup
	Score        bannerItem
}

type bannerGroup struct {
	ID, Title string
	Note      string
	Count     int
	Items     []bannerItem
	More      int
}

type bannerItem struct {
	Text string
	// Ev is "confirmed" or "possible" when the item is a path; it is shown
	// as text plus an icon, never as color alone.
	Ev string
	// Href is the filtered view (a hash the report's script reads) or the
	// org view that shows the item; "" when no view shows it.
	Href string
}

func (g *bannerGroup) add(it bannerItem) {
	g.Count++
	if len(g.Items) < maxBannerItems {
		g.Items = append(g.Items, it)
	} else {
		g.More++
	}
}

func snapDate(t time.Time, zero string) string {
	if t.IsZero() {
		return zero
	}
	return t.UTC().Format("2006-01-02")
}

// filterHref is the hash URL of the explore view filtered to one principal,
// with an optional evidence and terminal kind; the script parses it.
func filterHref(principal, ev, kind string) string {
	h := "#"
	if ev != "" {
		h += "ev=" + ev + "&"
	}
	if kind != "" {
		h += "kind=" + kind + "&"
	}
	// QueryEscape also escapes ":", which html/template would otherwise
	// read as a URL scheme and reject; the script decodes it.
	return h + "q=" + strings.ReplaceAll(url.QueryEscape(principal), "+", "%20")
}

// orgHref is the hash URL of the org view of the org that owns id, or "".
func orgHref(id string) string {
	if o := orgName(graph.OrgOf(id)); o != "" {
		return "#/org/" + url.PathEscape(o)
	}
	return ""
}

func pathText(c diff.PathChange) string {
	return c.Principal + " → " + c.Target
}

// buildBanner turns a diff report into banner groups. top is the score of
// the principal the current report's headline names (nil when none).
func buildBanner(r *diff.Report, top *graph.Score) *banner {
	b := &banner{
		Since:   snapDate(r.Old.CollectedAt, "the previous snapshot"),
		Until:   snapDate(r.New.CollectedAt, "this snapshot"),
		Summary: r.Summary,
	}
	if b.Summary == "" {
		b.Summary = r.Headline()
	}
	newConf := bannerGroup{ID: "new-confirmed", Title: "New confirmed paths"}
	removed := bannerGroup{ID: "removed", Title: "Removed paths"}
	newPoss := bannerGroup{ID: "new-possible", Title: "New possible paths", Note: "A hop is not visible to the token: unknown, not absent."}
	settings := bannerGroup{ID: "settings", Title: "Setting changes"}
	lost := bannerGroup{ID: "lost-visibility", Title: "Lost visibility", Note: "The newer snapshot cannot see something the older one could: unknown, not fixed."}
	for _, c := range r.Paths {
		kind := targetKind(c.TargetKind)
		switch c.Status {
		case diff.Added:
			if c.New != nil && !c.New.Unverified {
				newConf.add(bannerItem{Text: pathText(c), Ev: "confirmed", Href: filterHref(c.Principal, "confirmed", kind)})
			} else {
				newPoss.add(bannerItem{Text: pathText(c), Ev: "possible", Href: filterHref(c.Principal, "possible", kind)})
			}
		case diff.Upgraded:
			newConf.add(bannerItem{Text: pathText(c) + " (was possible)", Ev: "confirmed", Href: filterHref(c.Principal, "confirmed", kind)})
		case diff.Removed:
			was := "possible"
			if c.Old != nil && !c.Old.Unverified {
				was = "confirmed"
			}
			removed.add(bannerItem{Text: pathText(c) + " (was " + was + ")", Href: filterHref(c.Principal, "", "")})
		case diff.Downgraded:
			lost.add(bannerItem{Text: pathText(c) + ": confirmed → possible, a hop is no longer visible", Ev: "possible",
				Href: filterHref(c.Principal, "possible", kind)})
		case diff.LostVisibility:
			lost.add(bannerItem{Text: pathText(c) + ": part of the path is no longer visible", Href: filterHref(c.Principal, "", "")})
		}
	}
	for _, c := range r.Settings {
		switch c.Status {
		case diff.Changed, diff.GainedVisibility:
			settings.add(bannerItem{Text: c.Phrase(), Href: orgHref(c.Node)})
		case diff.LostVisibility:
			lost.add(bannerItem{Text: c.Phrase(), Href: orgHref(c.Node)})
		}
	}
	for _, c := range r.Coverage.Opened {
		lost.add(bannerItem{Text: fmt.Sprintf("%s: %s not visible (%s)", c.Scope, c.Fact, c.Reason), Href: orgHref(c.Scope)})
	}
	b.Groups = []bannerGroup{newConf, removed, newPoss, settings, lost}
	if top != nil {
		b.Score = bannerItem{Text: scoreText(r, *top), Href: filterHref(top.Principal, "", "")}
	}
	return b
}

// scoreText is the top principal's score delta; a principal missing from
// the diff's score list did not change.
func scoreText(r *diff.Report, top graph.Score) string {
	for _, s := range r.Scores {
		if s.Principal == top.Principal {
			return fmt.Sprintf("%s: score %.1f → %.1f (%+.1f confirmed)", top.Principal, s.Old.Score, s.New.Score, s.DeltaConfirmed)
		}
	}
	return fmt.Sprintf("%s: score %.1f, unchanged", top.Principal, top.Score)
}
