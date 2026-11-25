package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

func decorated(t *testing.T, g *graph.Graph) data {
	t.Helper()
	d := build(g, Options{Top: 10, FixBudget: 5})
	if err := addEmbedded(&d, g); err != nil {
		t.Fatal(err)
	}
	decorate(&d, g)
	return d
}

func kpiByLabel(d data, label string) kpi {
	for _, k := range d.KPIs {
		if k.Label == label {
			return k
		}
	}
	return kpi{}
}

// TestVerdictHero: the hero leads with the headline principal's confirmed
// figures; possible figures are separate strings, never added in.
func TestVerdictHero(t *testing.T) {
	d := decorated(t, loadAcme(t))
	if d.Verdict != "critical" || d.VerdictLabel != "Critical exposure" {
		t.Errorf("verdict = %q %q, want critical", d.Verdict, d.VerdictLabel)
	}
	if n := len(d.KPIs); n < 4 || n > 6 {
		t.Errorf("%d KPI tiles, want 4 to 6", n)
	}
	top, who := widest(&d)
	if who != "members of acme-actions" || top == nil || top.Principal != "members:acme-actions" {
		t.Fatalf("widest reach = %+v, want members:acme-actions", top)
	}
	c := top.Confirmed
	reach := kpiByLabel(d, "Confirmed reach")
	if reach.Value != "12" || reach.Sub != "across 2 orgs" || reach.Value != itoa(c.Repos) {
		t.Errorf("confirmed reach tile = %+v", reach)
	}
	cov := kpiByLabel(d, "Coverage")
	if cov.Value != "3/4" || cov.Tone != "unk" || !strings.Contains(cov.Sub, "2 facts not visible") {
		t.Errorf("coverage tile = %+v, want 3/4 orgs with the gaps marked unknown", cov)
	}
	for _, k := range d.KPIs {
		if k.Possible != "" && !strings.HasSuffix(k.Possible, " possible") {
			t.Errorf("%s: possible figure %q is not labelled possible", k.Label, k.Possible)
		}
	}
	// A principal with possible reach only: its tile shows the possible
	// figure apart from the confirmed one.
	got := kpis(&d, &graph.Score{Confirmed: graph.Counts{Repos: 2, Orgs: 1}, Possible: graph.Counts{Repos: 3}}, 4, 1, 2)[0]
	if got.Value != "2" || got.Possible != "+3 repos possible" {
		t.Errorf("tile with possible reach = %+v, want 2 confirmed and +3 possible apart", got)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestVerdictNeverSafeWhenUnseen: with no confirmed reach the verdict reads
// safe only when gop saw everything and found no possible reach either.
// TestHeroGroups: a group row is named by its label and counted as all its
// members.
func TestHeroGroups(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/owners/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	d := decorated(t, g)
	if d.PickWho != "14 principals (org owners of acme-security)" {
		t.Errorf("widest reach named %q, want the group", d.PickWho)
	}
	if k := kpiByLabel(d, "Top risks"); k.Value != "17" || !strings.HasPrefix(k.Sub, "14 critical") {
		t.Errorf("top risks tile = %+v, want 17 principals, 14 critical", k)
	}
}

func TestVerdictNeverSafeWhenUnseen(t *testing.T) {
	d := data{Risks: []riskRow{{Sev: "low"}}}
	if tone, _ := verdict(&d, 2); tone != "unk" {
		t.Errorf("no reach with coverage gaps reads %q, want unk", tone)
	}
	d.Risks = []riskRow{{Sev: "unknown", PossibleRepos: 1}}
	if tone, _ := verdict(&d, 0); tone != "unk" {
		t.Errorf("possible reach only reads %q, want unk", tone)
	}
	d.Risks = []riskRow{{Sev: "low"}}
	if tone, _ := verdict(&d, 0); tone != "ok" {
		t.Errorf("nothing reached, nothing unseen reads %q, want ok", tone)
	}
}

func TestRiskSeverityAndBars(t *testing.T) {
	d := decorated(t, loadAcme(t))
	sev := map[string]string{}
	for _, r := range d.Risks {
		sev[r.Principal] = r.Sev
	}
	for p, want := range map[string]string{
		"members:acme-actions": "critical", // OIDC
		"identity:alice":       "medium",   // repo CI only
		"members:acme-legacy":  "unknown",  // possible reach only: never low
	} {
		if sev[p] != want {
			t.Errorf("%s severity = %q, want %q", p, sev[p], want)
		}
	}
	for _, r := range d.Risks {
		if r.Principal != "members:acme-actions" {
			continue
		}
		if len(r.Bar) != 3 || r.Bar[0].Kind != "oidc" || r.Bar[0].Label != "OIDC trust" || r.Bar[0].Width == "w0" {
			t.Errorf("acme-actions impact bar = %+v", r.Bar)
		}
	}
	for share, want := range map[float64]string{0: "w0", 0.001: "w4", 0.5: "w52", 1: "w100", 2: "w100"} {
		if got := widthClass(share); got != want && !(share == 0.5 && got == "w48") {
			t.Errorf("widthClass(%v) = %s, want %s", share, got, want)
		}
	}
	for i := 0; i <= 100; i += 4 {
		if !strings.Contains(styleCSS, ".w"+itoa(i)+"{width:"+itoa(i)+"%}") {
			t.Errorf("no CSS for width class w%d", i)
		}
	}
}

// TestFixCards: each card's share is its own removed pairs over the
// baseline, and the shares add up to the cumulative figure.
func TestFixCards(t *testing.T) {
	d := decorated(t, loadAcme(t))
	if len(d.Fixes) == 0 {
		t.Fatal("no fixes")
	}
	sum := 0
	for i, f := range d.Fixes {
		s := d.sugg[i]
		base := s.CumulativeRemoved + s.Remaining
		sum += s.Removed
		if f.Pct == "" || f.Why == "" || f.Width == "" {
			t.Errorf("fix %d card incomplete: %+v", i+1, f)
		}
		if sum != s.CumulativeRemoved || base == 0 {
			t.Errorf("fix %d: removed pairs do not add up to the cumulative count", i+1)
		}
	}
	if d.Fixes[0].PrevWidth != "w0" {
		t.Errorf("first fix has an earlier-fixes segment %q", d.Fixes[0].PrevWidth)
	}
	if !strings.Contains(d.Fixes[0].Why, "acme-actions/deploy") {
		t.Errorf("pin fix why = %q", d.Fixes[0].Why)
	}
}

func TestCoverageGroups(t *testing.T) {
	got := coverageGroups([]graph.Coverage{
		{Scope: "org:acme-legacy", Fact: "repositories", NeedsFix: "org owner on acme-legacy (SAML enforced: join through the IdP first)"},
		{Scope: "org:acme-legacy", Fact: "ip_allow_list", NeedsFix: "org owner on acme-legacy"},
		{Scope: "org:acme-x", Fact: "ip_allow_list", NeedsFix: "org owner on acme-x"},
		{Scope: "repo:acme-app/web", Fact: "environments", NeedsFix: "repo admin on acme-app/web"},
	})
	if len(got) != 2 || got[0].Title != "Org owner needed on 2 orgs" || got[0].Facts != 3 ||
		got[1].Title != "Repo admin needed on 1 scope" {
		t.Errorf("coverage groups = %+v", got)
	}
}

// TestOrgGrid: a setting gop could not see is its own tone with the
// coverage reason, never strong or weak.
func TestOrgGrid(t *testing.T) {
	d := decorated(t, loadAcme(t))
	for _, o := range d.Orgs {
		for j, c := range o.Cells {
			if c.NV && (c.Tone != "unk" || c.Reason == "") {
				t.Errorf("%s %s: unseen cell tone %q reason %q", o.Org, settingCols[j].Key, c.Tone, c.Reason)
			}
			if o.Org == "acme-legacy" && settingCols[j].Key == graph.AttrIPAllowList && !strings.HasPrefix(c.Reason, "not visible: token is not an org owner") {
				t.Errorf("acme-legacy ip_allow_list reason = %q, want the coverage reason", c.Reason)
			}
			if o.Org == "acme-actions" && settingCols[j].Key == graph.AttrDefaultPerm && c.Tone != "weak" {
				t.Errorf("acme-actions default write reads %q, want weak", c.Tone)
			}
			if c.NV && c.Ref == "" {
				t.Errorf("%s %s: unknown cell links nowhere", o.Org, settingCols[j].Key)
			}
		}
	}
}

func TestSettingTones(t *testing.T) {
	for _, tc := range []struct {
		key, v, want string
	}{
		{graph.AttrIPAllowList, "on (4 active entries, installed apps on)", "good"},
		{graph.AttrIPAllowList, "off", "weak"},
		{graph.AttrMembersCreate, "true", "weak"},
		{graph.AttrPrivateForks, "false", "good"},
		{graph.AttrMembers, "40", ""},
	} {
		if got := settingTone(tc.key, &cell{Value: tc.v}); got != tc.want {
			t.Errorf("%s=%q tone %q, want %q", tc.key, tc.v, got, tc.want)
		}
	}
	if got := settingTone(graph.AttrSSO, &cell{Value: "unknown", NV: true}); got != "unk" {
		t.Errorf("unknown setting tone %q, want unk", got)
	}
}

func TestNodeChips(t *testing.T) {
	sha := "action:acme-actions/release@9b8a7c6d5e4f30211a2b3c4d5e6f708192a3b4c5"
	for id, want := range map[string][3]string{
		"repo:acme-app/web":  {"repo", "acme-app/web", ""},
		sha:                  {"action", "acme-actions/release@9b8a7c6d5e4f…", sha},
		"action:acme/a@main": {"action", "acme/a@main", ""},
		"workflow:acme-app/web/.github/workflows/ci.yml": {"workflow", "acme-app/web › ci.yml", "workflow:acme-app/web/.github/workflows/ci.yml"},
	} {
		if k, s, ti := nodeKind(id), nodeShort(id), nodeTitle(id); k != want[0] || s != want[1] || ti != want[2] {
			t.Errorf("%s: got %q %q %q, want %v", id, k, s, ti, want)
		}
	}
}

// TestHopChainEvidence: every hop of a server-rendered path carries an
// evidence badge and its source API, and paths start collapsed.
func TestHopChainEvidence(t *testing.T) {
	out := render(t, loadAcme(t), "html")
	doc := parseHTML(t, out)
	chains := 0
	walk(doc, func(n *html.Node) {
		if !hasClass(n, "chain") {
			return
		}
		chains++
		hops := 0
		walk(n, func(h *html.Node) {
			if !hasClass(h, "hop") {
				return
			}
			hops++
			badge, tip := false, false
			for _, c := range []string{"live", "inferred", "audit", "supplied", "nv"} {
				walk(h, func(b *html.Node) { badge = badge || hasClass(b, c) })
			}
			walk(h, func(b *html.Node) {
				tip = tip || (hasClass(b, "tip") && strings.HasPrefix(text(b), "source "))
			})
			if !badge || !tip {
				t.Errorf("hop %q has no evidence badge or source", text(h))
			}
		})
		if hops == 0 {
			t.Error("chain without hops")
		}
	})
	if chains == 0 {
		t.Fatal("no hop chains")
	}
	for _, d := range elements(doc, "details") {
		if _, open := attr(d, "open"); open {
			t.Error("a path is expanded by default")
		}
	}
}

// demoBaselineBytes is the size of gop report --demo without the Graph tab's
// embedded graph data. It was 129483 before the redesign (budget 1.5x); it
// was measured again when the demo graph gained the multi-org owners, the AI
// approve + self-merge chain and the branch protection notes, which add
// reach, and so embedded paths, rather than markup. The budget is 1.2x.
const demoBaselineBytes = 452657

func TestDemoSizeBudget(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}), Options{Version: "v0.0.0-test"}); err != nil {
		t.Fatal(err)
	}
	var e embedded
	if err := json.Unmarshal([]byte(embeddedJSON(t, buf.String())), &e); err != nil {
		t.Fatal(err)
	}
	gj, err := json.Marshal(e.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if n := buf.Len() - len(gj); n > demoBaselineBytes*6/5 {
		t.Errorf("demo report without graph data is %d bytes, budget %d (1.2x the baseline)", n, demoBaselineBytes*6/5)
	}
}
