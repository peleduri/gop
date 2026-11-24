package sarif

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
)

func TestAdvisoryRuleRanksFirst(t *testing.T) {
	l := build(t, demo.Generate(demo.Options{Seed: 1}), Options{})
	rs := results(l)
	adv := byRule(l, RuleAdvisory)
	if len(adv) != 1 || rs[0].RuleID != RuleAdvisory {
		t.Fatalf("want one GOP003 result, first: %d results, first %s", len(adv), rs[0].RuleID)
	}
	r := adv[0]
	if r.Properties.Severity != SeverityCritical || r.Level != "error" || r.Properties.Repository != "acme-app/docs" ||
		r.Properties.Terminals.Secrets != 1 || len(r.Properties.Advisories) != 1 || r.Properties.Advisories[0] != demo.DemoAdvisory {
		t.Errorf("result %+v", r.Properties)
	}
	if !strings.Contains(r.Message.Text, "Move to v2.4.1") || r.Properties.Fix.Action != demo.CheckoutIsh {
		t.Errorf("message %q fix %+v", r.Message.Text, r.Properties.Fix)
	}
	if top := build(t, demo.Generate(demo.Options{Seed: 1}), Options{Top: 1}); results(top)[0].RuleID != RuleAdvisory {
		t.Error("--top 1 must keep the advisory result")
	}
}
