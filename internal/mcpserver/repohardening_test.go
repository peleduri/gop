package mcpserver

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
)

func acmeEngine(t *testing.T) *Engine {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(g)
}

// Advisory hardening fixes plan a setting change, remove no reach, and are
// accepted by what_if as a no-op.
func TestAdvisoryFixPlan(t *testing.T) {
	e := acmeEngine(t)
	for _, f := range []FixSpec{{Type: "require_reviews", Repo: "repo:acme-actions/setup"}, {Type: "enable_push_protection", Repo: "repo:acme-app/web"}} {
		out, err := e.FixPlan(FixPlanInput{Fix: &f})
		if err != nil {
			t.Fatal(err)
		}
		p := out.Plan
		if len(p.Steps) != 1 || p.Steps[0].Kind != fixplan.KindChangeSetting || p.Steps[0].API == "" {
			t.Errorf("%s: steps %+v", f.Type, p.Steps)
		}
		if p.Removes.Before != p.Removes.After || len(p.Caveats) == 0 || p.Caveats[0] != fixplan.HardeningCaveat {
			t.Errorf("%s: removes %+v caveats %v", f.Type, p.Removes, p.Caveats)
		}
		w, err := e.WhatIf(WhatIfInput{Fixes: []FixSpec{f}})
		if err != nil {
			t.Fatal(err)
		}
		if w.Delta.Before != w.Delta.After {
			t.Errorf("%s: what_if changed reach", f.Type)
		}
	}
	if _, err := e.FixPlan(FixPlanInput{Fix: &FixSpec{Type: "require_reviews", Repo: "org:acme-app"}}); err == nil ||
		!strings.Contains(err.Error(), "is not a repo") {
		t.Errorf("non-repo accepted: %v", err)
	}
}

// Paths carry hop notes; suggest_fixes lists hardening apart from fixes.
func TestPathNotesAndHardening(t *testing.T) {
	e := acmeEngine(t)
	out, err := e.Paths(PathsInput{From: "identity:bob", To: "oidc:acme-app/web"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Confirmed) != 1 || out.Confirmed[0].Hops[0].Note != "push needs 1 approval to reach `main` + CODEOWNERS on workflows" {
		t.Fatalf("paths %+v", out.Confirmed)
	}
	s, err := e.SuggestFixes(SuggestFixesInput{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range s.Fixes {
		if strings.HasPrefix(f.FixID, "require_reviews:") || strings.HasPrefix(f.FixID, "push_protection:") {
			t.Errorf("advisory fix %s counted as a fix", f.FixID)
		}
	}
	if len(s.Hardening) == 0 || s.Hardening[0].FixID != "require_reviews:repo:acme-actions/setup" {
		t.Errorf("hardening %+v", s.Hardening)
	}
}
