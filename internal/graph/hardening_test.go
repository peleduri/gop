package graph

import (
	"reflect"
	"testing"
)

func loadHardening(t *testing.T) *Graph {
	t.Helper()
	g, err := LoadFile("../../testdata/hardening/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestOrgHardeningCombinations covers the fixture's three orgs: enforced plus
// on (strong, no context), configured plus off, and none plus unknown for an
// org the token does not own (unknown stays unknown, never off).
func TestOrgHardeningCombinations(t *testing.T) {
	ix := NewIndex(loadHardening(t))
	for _, tc := range []struct {
		org, sso, ip string
		weak         bool
		line         string
	}{
		{"org:acme-app", "enforced", "on", false, "target org acme-app: SSO enforced, IP allow list on"},
		{"org:acme-actions", "configured", "off", true, "target org acme-actions: SSO not enforced (configured), IP allow list off"},
		{"org:acme-legacy", "none", "unknown", true, "target org acme-legacy: SSO not enforced (none), IP allow list unknown"},
	} {
		h, ok := ix.OrgHardening(tc.org)
		if !ok {
			t.Fatalf("%s: no org", tc.org)
		}
		if h.SSO != tc.sso || h.IPAllowList != tc.ip || h.Weak() != tc.weak || h.Line() != tc.line {
			t.Errorf("%s = %+v weak=%t line=%q, want %s/%s weak=%t %q", tc.org, h, h.Weak(), h.Line(), tc.sso, tc.ip, tc.weak, tc.line)
		}
	}
	if _, ok := ix.OrgHardening("org:nope"); ok {
		t.Error("an org missing from the graph has hardening")
	}
}

func TestOrgSettingUnknown(t *testing.T) {
	n := Node{Kind: KindOrg, Evidence: Live,
		Attrs:        map[string]string{AttrSSO: "enforced", AttrIPAllowList: "off", AttrTwoFactor: "unknown"},
		AttrEvidence: map[string]Evidence{AttrIPAllowList: NotVisible}}
	for key, want := range map[string]string{
		AttrSSO:         "enforced",
		AttrIPAllowList: "unknown", // not_visible evidence wins over the value
		AttrTwoFactor:   "unknown",
		AttrDefaultPerm: "unknown", // not collected
	} {
		if got := OrgSetting(n, key); got != want {
			t.Errorf("OrgSetting(%s) = %q, want %q", key, got, want)
		}
	}
}

func TestTargetRepo(t *testing.T) {
	for _, tc := range []struct {
		p    Path
		want string
	}{
		{Path{To: "repo:acme-app/web"}, "repo:acme-app/web"},
		{Path{To: "workflow:acme-app/web/.github/workflows/ci.yml"}, "repo:acme-app/web"},
		{Path{To: "oidc:acme-app/web"}, "repo:acme-app/web"},
		{Path{To: "cloud:aws:arn:aws:iam::111111111111:role/deploy", Hops: []Hop{
			{From: "identity:bob", To: "repo:acme-actions/deploy"},
			{From: "workflow:acme-app/web/.github/workflows/ci.yml", To: "oidc:acme-app/web"},
			{From: "oidc:acme-app/web", To: "cloud:aws:arn:aws:iam::111111111111:role/deploy"},
		}}, "repo:acme-app/web"},
		{Path{To: "action:acme-actions/deploy@main"}, ""},
		{Path{To: "members:acme-app"}, ""},
	} {
		if got := TargetRepo(tc.p); got != tc.want {
			t.Errorf("TargetRepo(%s) = %q, want %q", tc.p.To, got, tc.want)
		}
	}
}

// TestTargetOrgHardeningOnlyWeak: paths into acme-app (enforced, on) carry
// no context; paths into the other two orgs do.
func TestTargetOrgHardeningOnlyWeak(t *testing.T) {
	ix := NewIndex(loadHardening(t))
	for _, pr := range ix.Principals() {
		for to, p := range ix.Reach(pr, Options{}).Paths {
			h := ix.TargetOrgHardening(p)
			switch OrgOf(TargetRepo(p)) {
			case "org:acme-app":
				if h != nil {
					t.Errorf("%s -> %s: context %+v for a hardened org", pr, to, *h)
				}
			case "org:acme-actions", "org:acme-legacy":
				if h == nil {
					t.Errorf("%s -> %s: no context for a weak or unknown org", pr, to)
				}
			}
		}
	}
}

// TestHardeningDoesNotChangeScores: removing the IP allow list attributes,
// or turning every org's IP allow list on, leaves scores, counts and rank
// order identical: target org hardening is context only. (SSO and 2FA of the
// principal's own org already weight its score, see rawScore; that is
// unchanged and unrelated to the target org.)
func TestHardeningDoesNotChangeScores(t *testing.T) {
	g := loadHardening(t)
	stripped := loadHardening(t)
	hardened := loadHardening(t)
	for i := range stripped.Nodes {
		if stripped.Nodes[i].Kind != KindOrg {
			continue
		}
		for _, k := range []string{AttrIPAllowList, AttrIPAllowEntries, AttrIPAllowListEntries, AttrIPAllowListApps} {
			delete(stripped.Nodes[i].Attrs, k)
			delete(stripped.Nodes[i].AttrEvidence, k)
			delete(hardened.Nodes[i].AttrEvidence, k)
		}
		hardened.Nodes[i].Attrs[AttrIPAllowList] = "on"
		hardened.Nodes[i].Attrs[AttrIPAllowListApps] = "on"
	}
	want := NewIndex(g).TopPaths(0)
	if len(want) == 0 {
		t.Fatal("fixture has no scored principals")
	}
	for name, other := range map[string]*Graph{"stripped": stripped, "hardened": hardened} {
		if got := NewIndex(other).TopPaths(0); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: scores differ:\n got %+v\nwant %+v", name, got, want)
		}
	}
}
