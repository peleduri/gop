package collect

import (
	"bytes"
	"slices"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestEndToEndAcme runs the whole pipeline on the synthetic acme enterprise:
// fake GitHub API -> Collect -> graph.json round-trip -> reachability engine.
func TestEndToEndAcme(t *testing.T) {
	_, ix := collectAcme(t)

	var buf bytes.Buffer
	if err := WriteGraph(&buf, ix.g); err != nil {
		t.Fatalf("WriteGraph: %v", err)
	}
	g, err := graph.Load(&buf)
	if err != nil {
		t.Fatalf("graph.Load of collected graph: %v", err)
	}
	eng := graph.NewIndex(g)

	res := eng.Reach("members:acme-actions", graph.Options{})
	repos := res.Confirmed.Repos
	t.Logf("members:acme-actions confirmed repos: %v", repos)
	t.Logf("possible repos: %v", res.Possible.Repos)

	// Branch and tag consumers of acme-actions/deploy are reachable.
	for _, want := range []string{"repo:acme-app/web", "repo:acme-app/billing", "repo:acme-app/worker"} {
		if !slices.Contains(repos, want) {
			t.Errorf("expected %s in confirmed reach", want)
		}
	}
	// acme-app/api pins deploy by SHA, but that composite action itself uses
	// acme-actions/setup@main, so the path stays open through the nested ref.
	if !slices.Contains(repos, "repo:acme-app/api") {
		t.Errorf("SHA-pinned composite with a mutable nested ref must stay reachable")
	}
	// acme-secure never runs acme-actions code on a mutable ref at top level and
	// its default permission is read: members of acme-secure reach nothing outside.
	sec := eng.Reach("members:acme-secure", graph.Options{})
	for _, r := range sec.Confirmed.Repos {
		if graph.OrgOf(r) != "org:acme-secure" {
			t.Errorf("acme-secure members should not reach %s", r)
		}
	}

	// Pinning deploy@main alone removes nothing: the deploy action itself calls
	// acme-actions/setup@main, so whoever controls setup still controls every
	// deploy@main consumer. This is the nested-reference trap gop exists to show.
	pinDeploy := graph.PinRef{Action: "action:acme-actions/deploy@main"}
	d := eng.WhatIf([]graph.Fix{pinDeploy})
	if d.After.ConfirmedPairs != d.Before.ConfirmedPairs {
		t.Errorf("pinning only deploy@main should not change reach (nested setup@main): before %d after %d", d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
	}
	after := eng.Reach("members:acme-actions", graph.Options{Fixes: []graph.Fix{pinDeploy}})
	if !slices.Contains(after.Confirmed.Repos, "repo:acme-app/api") {
		t.Errorf("api stays reachable through setup@main after pinning deploy@main")
	}
	// Pinning both mutable refs does cut reach.
	both := eng.WhatIf([]graph.Fix{pinDeploy, graph.PinRef{Action: "action:acme-actions/setup@main"}})
	if both.After.ConfirmedPairs >= both.Before.ConfirmedPairs {
		t.Errorf("pinning deploy@main and setup@main should lower reach: before %d after %d", both.Before.ConfirmedPairs, both.After.ConfirmedPairs)
	}

	// The greedy fix list goes for the root cause: acme-actions' Write default.
	sug := eng.SuggestFixes(3)
	if len(sug) == 0 {
		t.Fatalf("expected fix suggestions")
	}
	if sug[0].FixID != "default_perm:org:acme-actions->read" {
		t.Errorf("first fix = %s, want lowering acme-actions default permission", sug[0].FixID)
	}
	for _, s := range sug {
		t.Logf("fix %s removes %d (cumulative %.0f%%)", s.FixID, s.Removed, s.CumulativePct)
	}

	// Every edge the engine walks came from the collector with evidence attached,
	// and anything the token could not see shows up in coverage, never as "off".
	if len(g.Coverage) == 0 {
		t.Errorf("expected coverage entries for acme-legacy")
	}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindOrg && n.AttrEvidence[graph.AttrIPAllowList] == graph.NotVisible && n.Attrs[graph.AttrIPAllowList] == "off" {
			t.Errorf("%s: not visible IP allow list rendered as off", n.ID)
		}
	}
}
