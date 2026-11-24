package mcpserver

import (
	"reflect"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

func loadHardening(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/hardening/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestHardeningContextOnPaths: paths into a weak or unknown target org carry
// target_org_hardening, paths into acme-app (SSO enforced, IP allow list on)
// do not, and unknown stays unknown.
func TestHardeningContextOnPaths(t *testing.T) {
	e := NewEngine(loadHardening(t))
	who, err := e.WhoCanReach(WhoCanReachInput{Target: "repo:acme-app/web"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(who.Confirmed, who.Possible...) {
		if p.TargetOrgHardening != nil {
			t.Errorf("%s -> acme-app/web: context %+v for a hardened org", p.From, *p.TargetOrgHardening)
		}
	}
	paths, err := e.Paths(PathsInput{From: "identity:alice"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*graph.OrgHardening{}
	for _, p := range append(paths.Confirmed, paths.Possible...) {
		got[p.To] = p.TargetOrgHardening
	}
	if h := got["repo:acme-app/web"]; h != nil {
		t.Errorf("acme-app/web: context %+v", *h)
	}
	if h := got["repo:acme-actions/deploy"]; h == nil || h.SSO != "configured" || h.IPAllowList != "off" {
		t.Errorf("acme-actions/deploy: context %+v, want configured/off", h)
	}
	if h := got["repo:acme-legacy/old-api"]; h == nil || h.SSO != "none" || h.IPAllowList != "unknown" {
		t.Errorf("acme-legacy/old-api: context %+v, want none/unknown", h)
	}
	one, err := e.Paths(PathsInput{From: "identity:alice", To: "repo:acme-legacy/old-api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Possible) != 1 || one.Possible[0].TargetOrgHardening == nil {
		t.Errorf("paths to: %+v, want one possible path with context", one)
	}
	ex, err := e.Explain(ExplainInput{From: "identity:bob", To: "repo:acme-actions/deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.TargetOrgHardening == nil || ex.TargetOrgHardening.Org != "org:acme-actions" {
		t.Errorf("explain context = %+v, want org:acme-actions", ex.TargetOrgHardening)
	}
	ex, err = e.Explain(ExplainInput{From: "identity:carol", To: "repo:acme-app/web"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.TargetOrgHardening != nil {
		t.Errorf("explain context for a hardened org: %+v", *ex.TargetOrgHardening)
	}
}

// TestTopRisksUnchangedByHardening: the ranked risks are identical with and
// without the IP allow list attributes; only target_org_hardening differs.
func TestTopRisksUnchangedByHardening(t *testing.T) {
	g, bare := loadHardening(t), loadHardening(t)
	for i := range bare.Nodes {
		for _, k := range []string{graph.AttrIPAllowList, graph.AttrIPAllowEntries, graph.AttrIPAllowListEntries, graph.AttrIPAllowListApps} {
			delete(bare.Nodes[i].Attrs, k)
			delete(bare.Nodes[i].AttrEvidence, k)
		}
	}
	with, err := NewEngine(g).TopRisks(TopRisksInput{N: 10})
	if err != nil {
		t.Fatal(err)
	}
	without, err := NewEngine(bare).TopRisks(TopRisksInput{N: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(with.Risks, without.Risks) || with.Summary != without.Summary {
		t.Errorf("risks changed with hardening attrs:\n with %+v\n without %+v", with.Risks, without.Risks)
	}
	var orgs []string
	for _, h := range with.TargetOrgHardening {
		orgs = append(orgs, h.Org)
	}
	if !reflect.DeepEqual(orgs, []string{"org:acme-actions", "org:acme-legacy"}) {
		t.Errorf("top_risks target_org_hardening orgs = %v", orgs)
	}
}

// TestSummaryOrgSettings: the summary resource carries the same per-org
// settings as the report table; a setting the token could not read is
// not_visible, never off.
func TestSummaryOrgSettings(t *testing.T) {
	s := NewEngine(loadHardening(t)).Summary(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC))
	by := map[string]OrgSummary{}
	for _, o := range s.Orgs {
		by[o.ID] = o
	}
	app, legacy := by["org:acme-app"], by["org:acme-legacy"]
	if app.IPAllowList != "on" || app.IPAllowListEntries != "2" || app.IPAllowListApps != "on" || app.MembersCreate != "false" ||
		app.ChangeVisibility != "false" || app.DeleteRepos != "false" || app.PrivateForks != "false" {
		t.Errorf("acme-app summary = %+v", app)
	}
	if legacy.IPAllowList != "not_visible" || legacy.IPAllowListEntries != "not_visible" || legacy.IPAllowListApps != "not_visible" {
		t.Errorf("acme-legacy summary = %+v, want not_visible IP allow list facts", legacy)
	}
}
