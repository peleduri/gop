package graph

import (
	"reflect"
	"testing"
)

func TestCoverageSummary(t *testing.T) {
	g, err := LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	got := CoverageSummary(g)
	if !reflect.DeepEqual(got, CoverageSummary(g)) {
		t.Fatal("CoverageSummary is not deterministic")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Org >= got[i].Org {
			t.Fatalf("not sorted by org: %q before %q", got[i-1].Org, got[i].Org)
		}
	}
	var legacy *OrgCoverage
	for i := range got {
		if got[i].Org == "org:acme-legacy" {
			legacy = &got[i]
		}
	}
	if legacy == nil {
		t.Fatalf("no org:acme-legacy entry in %+v", got)
	}
	want := OrgCoverage{Org: "org:acme-legacy", NotVisibleNodes: 1, NotVisibleEdges: 1, Entries: 2,
		Facts: map[string]int{"repositories": 1, "ip_allow_list": 1}}
	if !reflect.DeepEqual(*legacy, want) {
		t.Errorf("acme-legacy = %+v, want %+v", *legacy, want)
	}
	for _, c := range got {
		if c.Org != "org:acme-legacy" && (c.NotVisibleNodes+c.NotVisibleEdges+c.NotVisibleAttrs+c.Entries) != 0 {
			t.Errorf("%s should be fully visible: %+v", c.Org, c)
		}
	}
}

func TestCoverageSummaryAttribution(t *testing.T) {
	g := &Graph{
		Enterprise: "acme",
		Nodes: []Node{
			{ID: "enterprise:acme", Kind: KindEnterprise, Evidence: Live, AttrEvidence: map[string]Evidence{"orgs": NotVisible}},
			{ID: "org:acme-app", Kind: KindOrg, Evidence: Live},
			{ID: "identity:alice", Kind: KindIdentity, Evidence: Live},
			{ID: "repo:acme-app/web", Kind: KindRepo, Evidence: Live, AttrEvidence: map[string]Evidence{"workflows": NotVisible, "org": Live}},
			{ID: "repo:acme-actions/deploy", Kind: KindRepo, Evidence: NotVisible},
			{ID: "cloud:aws:arn:aws:iam::111111111111:role/deploy", Kind: KindCloudTarget, Evidence: Supplied},
		},
		Edges: []Edge{
			{From: "identity:alice", To: "repo:acme-app/web", Kind: CanPush, Evidence: NotVisible},
			{From: "members:acme-actions", To: "repo:acme-actions/deploy", Kind: CanPush, Evidence: NotVisible},
			{From: "identity:alice", To: "org:acme-app", Kind: MemberOf, Evidence: Live},
			// supplied is verified (read from a trust file), never not_visible.
			{From: "workflow:acme-app/web/.github/workflows/ci.yml", To: "cloud:aws:arn:aws:iam::111111111111:role/deploy", Kind: CanAssume, Evidence: Supplied},
		},
		Coverage: []Coverage{
			{Scope: "enterprise:acme", Fact: "members"},
			{Scope: "repo:acme-app/web", Fact: "workflows"},
			{Scope: "workflow:acme-app/web/.github/workflows/ci.yml", Fact: "runner_labels"},
			{Scope: "repo:acme-actions/deploy", Fact: "can_push"},
		},
	}
	want := []OrgCoverage{
		{Org: "enterprise:acme", NotVisibleAttrs: 1, Entries: 1, Facts: map[string]int{"members": 1}},
		{Org: "org:acme-actions", NotVisibleNodes: 1, NotVisibleEdges: 1, Entries: 1, Facts: map[string]int{"can_push": 1}},
		{Org: "org:acme-app", NotVisibleEdges: 1, NotVisibleAttrs: 1, Entries: 2, Facts: map[string]int{"workflows": 1, "runner_labels": 1}},
	}
	if got := CoverageSummary(g); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if got := CoverageSummary(nil); got == nil || len(got) != 0 {
		t.Errorf("nil graph = %#v", got)
	}
}

func TestFixCaveatNestedUnknown(t *testing.T) {
	g, err := LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	picks := SuggestFixes(g, 3)
	var pin *PinRef
	for _, p := range picks {
		if p.Caveat != "" {
			t.Errorf("%s has a caveat on a fully visible graph: %q", p.FixID, p.Caveat)
		}
		if pr, ok := p.Fix.(PinRef); ok && pin == nil {
			pin = &pr
		}
	}
	if pin == nil {
		t.Fatalf("no PinRef among %+v", picks)
	}
	for i := range g.Nodes {
		if g.Nodes[i].ID == pin.Action {
			g.Nodes[i].Attrs["nested"] = "unknown"
			g.Nodes[i].AttrEvidence = map[string]Evidence{"nested": NotVisible}
		}
	}
	found := false
	for _, p := range SuggestFixes(g, 3) {
		switch {
		case p.FixID == pin.ID():
			found = true
			if p.Caveat != "nested references not visible: the pin may not close every path" {
				t.Errorf("caveat = %q", p.Caveat)
			}
		case p.Caveat != "":
			t.Errorf("%s: unexpected caveat %q", p.FixID, p.Caveat)
		}
	}
	if !found {
		t.Fatalf("%s no longer picked", pin.ID())
	}
	d := WhatIf(g, []Fix{*pin, LowerDefaultPerm{Org: "org:acme-actions", To: "read"}})
	if want := []string{pin.ID() + ": nested references not visible: the pin may not close every path"}; !reflect.DeepEqual(d.Caveats, want) {
		t.Errorf("WhatIf caveats = %q, want %q", d.Caveats, want)
	}
}
