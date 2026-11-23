package demo

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

func serialize(t *testing.T, g *graph.Graph) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := collect.WriteGraph(&b, g); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func small(t *testing.T) *graph.Graph {
	t.Helper()
	return Generate(Options{Seed: 1, Size: SizeSmall})
}

func TestDeterministic(t *testing.T) {
	for _, size := range []string{SizeSmall, SizeMedium} {
		a := serialize(t, Generate(Options{Seed: 1, Size: size}))
		b := serialize(t, Generate(Options{Seed: 1, Size: size}))
		if !bytes.Equal(a, b) {
			t.Fatalf("%s: two runs with the same seed differ", size)
		}
	}
	if bytes.Equal(serialize(t, Generate(Options{Seed: 1})), serialize(t, Generate(Options{Seed: 2}))) {
		t.Error("different seeds gave the same graph")
	}
}

func TestLoadsAndMarksDemo(t *testing.T) {
	g, err := graph.Load(bytes.NewReader(serialize(t, small(t))))
	if err != nil {
		t.Fatal(err)
	}
	if !graph.IsDemo(g) {
		t.Fatal("enterprise node lacks demo=true")
	}
	if !g.CollectedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("collected_at = %v", g.CollectedAt)
	}
	for _, e := range g.Edges {
		if !strings.HasPrefix(e.SourceAPI, "demo:") || e.Evidence == "" {
			t.Errorf("edge %s %s %s: source_api %q evidence %q", e.From, e.Kind, e.To, e.SourceAPI, e.Evidence)
		}
	}
	for _, n := range g.Nodes {
		if !strings.HasPrefix(n.Attrs["source_api"], "demo:") || n.Evidence == "" {
			t.Errorf("node %s: source_api %q evidence %q", n.ID, n.Attrs["source_api"], n.Evidence)
		}
	}
}

func TestPlantedCrossOrgPath(t *testing.T) {
	ix := graph.NewIndex(small(t))
	var found bool
	for _, p := range ix.WhoCanReach("repo:acme-app/web") {
		if p.From != ActionsMembers {
			continue
		}
		found = true
		if p.Unverified {
			t.Fatalf("members:acme-actions -> acme-app/web is not confirmed: %+v", p)
		}
		if !hasHop(p, DeployMain) {
			t.Errorf("path does not go through %s: %+v", DeployMain, p.Hops)
		}
	}
	if !found {
		t.Fatal("members:acme-actions cannot reach repo:acme-app/web")
	}
}

func hasHop(p graph.Path, id string) bool {
	for _, h := range p.Hops {
		if h.From == id || h.To == id {
			return true
		}
	}
	return false
}

func confirmed(ix *graph.Index, from, to string, fixes ...graph.Fix) bool {
	p, ok := ix.Reach(from, graph.Options{Fixes: fixes}).Paths[to]
	return ok && !p.Unverified
}

func TestPinnedConsumers(t *testing.T) {
	ix := graph.NewIndex(small(t))
	// (2) SHA-pinned consumer of deploy with no nested mutable ref: unreachable.
	for _, p := range ix.Principals() {
		if _, ok := ix.Reach(p, graph.Options{}).Paths["oidc:acme-secure/vault"]; ok {
			t.Errorf("%s reaches oidc:acme-secure/vault through a SHA pin", p)
		}
	}
	// (3) SHA-pinned release still runs setup@main: reachable, before and after pinning deploy@main.
	pin := graph.PinRef{Action: DeployMain}
	for _, target := range []string{"oidc:acme-secure/signer", "repo:acme-app/payments"} {
		if !confirmed(ix, ActionsMembers, target) || !confirmed(ix, ActionsMembers, target, pin) {
			t.Errorf("nested-action path to %s missing (before or after pinning deploy@main)", target)
		}
	}
	p := ix.Reach(ActionsMembers, graph.Options{Fixes: []graph.Fix{pin}}).Paths["oidc:acme-secure/signer"]
	if !hasHop(p, SetupMain) || !hasHop(p, ReleaseSHA) {
		t.Errorf("signer path is not through the nested action: %+v", p.Hops)
	}
	// Pinning deploy@main still cuts the direct path and lowers confirmed reach.
	if confirmed(ix, ActionsMembers, "oidc:acme-app/web", pin) {
		t.Error("pinning deploy@main left members:acme-actions -> oidc:acme-app/web")
	}
	d := ix.WhatIf([]graph.Fix{pin})
	if d.After.ConfirmedPairs >= d.Before.ConfirmedPairs {
		t.Errorf("pinning deploy@main did not lower confirmed pairs: %d -> %d", d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
	}
	// Totals count ScoringPrincipals only: filler users whose only edge is an
	// org membership add no pairs of their own.
	if sp := ix.ScoringPrincipals(); d.Before.Principals != len(sp) || len(sp) >= len(ix.Principals()) {
		t.Errorf("totals over %d principals, ScoringPrincipals %d, Principals %d", d.Before.Principals, len(sp), len(ix.Principals()))
	}
	// The report helper names the trap.
	ex := ix.PinnedExposures()
	if len(ex) != 1 || ex[0].Action != ReleaseSHA || ex[0].Via != SetupMain || ex[0].Path.Unverified {
		t.Errorf("PinnedExposures = %+v", ex)
	}
}

func TestPossibleAndCoverage(t *testing.T) {
	g := small(t)
	ix := graph.NewIndex(g)
	p, ok := ix.Reach(LegacyMembers, graph.Options{}).Paths["secret:acme-legacy/old-api"]
	if !ok || !p.Unverified {
		t.Fatalf("want a possible (unverified) path to the legacy secret, got %+v ok=%v", p, ok)
	}
	var cov bool
	for _, c := range g.Coverage {
		cov = cov || (c.Scope == "org:acme-legacy" && c.Fact == "repositories")
	}
	if !cov {
		t.Error("coverage does not list the acme-legacy repositories gap")
	}
}

func TestRunnerPlanted(t *testing.T) {
	if !confirmed(graph.NewIndex(small(t)), ActionsMembers, "runner:acme-app/worker") {
		t.Error("self-hosted runner not reachable")
	}
}

var (
	orgRe  = regexp.MustCompile(`^acme(-[a-z0-9-]+)?$`)
	userRe = regexp.MustCompile(`^(alice|bob|user-\d{3})$`)
)

func TestSyntheticNames(t *testing.T) {
	for _, size := range []string{SizeSmall, SizeMedium} {
		g := Generate(Options{Seed: 7, Size: size})
		for _, n := range g.Nodes {
			id := n.ID
			if o := graph.OrgOf(id); o != "" && !orgRe.MatchString(strings.TrimPrefix(o, "org:")) {
				t.Errorf("%s: org name in %s", size, id)
			}
			if n.Kind == graph.KindIdentity && !userRe.MatchString(strings.TrimPrefix(id, "identity:")) {
				t.Errorf("%s: user name %s", size, id)
			}
		}
		if g.Enterprise != "acme" {
			t.Errorf("enterprise %q", g.Enterprise)
		}
	}
}

func countKind(g *graph.Graph, k graph.NodeKind) (n int) {
	for _, nd := range g.Nodes {
		if nd.Kind == k {
			n++
		}
	}
	return n
}

func TestSizes(t *testing.T) {
	for _, tc := range []struct {
		size           string
		orgs, min, max int
	}{
		{SizeSmall, 5, 50, 75},
		{SizeMedium, 20, 900, 1100},
	} {
		g := Generate(Options{Seed: 1, Size: tc.size})
		if n := countKind(g, graph.KindOrg); n != tc.orgs {
			t.Errorf("%s: %d orgs, want %d", tc.size, n, tc.orgs)
		}
		if n := countKind(g, graph.KindRepo); n < tc.min || n > tc.max {
			t.Errorf("%s: %d repos, want %d..%d", tc.size, n, tc.min, tc.max)
		}
	}
	g := Generate(Options{Seed: 1, Orgs: 2, ReposPerOrg: 3})
	if n := countKind(g, graph.KindOrg); n != 4 {
		t.Errorf("Orgs below the planted four: got %d orgs, want 4", n)
	}
}

func TestLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("large demo graph")
	}
	start := time.Now()
	g := Generate(Options{Seed: 1, Size: SizeLarge})
	b := serialize(t, g)
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("large took %v, want < 5s", el)
	}
	lg, err := graph.Load(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if n := countKind(lg, graph.KindRepo); n < 9000 || n > 11000 {
		t.Errorf("large: %d repos", n)
	}
}

func TestValidatesClean(t *testing.T) {
	for _, size := range []string{SizeSmall, SizeMedium} {
		r, err := schema.Validate(serialize(t, Generate(Options{Seed: 1, Size: size})))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Valid || len(r.Errors) != 0 || len(r.Warnings) != 0 {
			t.Errorf("%s: valid=%v errors=%v warnings=%v", size, r.Valid, r.Errors, r.Warnings)
		}
	}
}
