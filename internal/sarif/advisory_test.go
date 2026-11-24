package sarif

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/advisory"
	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
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

// lockedCheckoutIsh is the demo graph with every use of checkout-ish@v2
// pinned by an actions.lock to sha, annotated against a synthetic advisory
// that lists the commit 0a0a... as affected, 1b1b... as fixed, and tags
// v3.0.0 up to v3.1.0 (so the v2 tag itself is not affected).
func lockedCheckoutIsh(t *testing.T, sha string) (*graph.Graph, advisory.Stats) {
	t.Helper()
	dir := t.TempDir()
	rec := `{"id": "GHSA-acme-lock-0001", "modified": "2026-01-01T00:00:00Z",
  "summary": "Synthetic: a compromised commit of acme-oss/checkout-ish",
  "affected": [{"package": {"ecosystem": "GitHub Actions", "name": "acme-oss/checkout-ish"},
    "ranges": [
      {"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}]},
      {"type": "GIT", "repo": "https://github.com/acme-oss/checkout-ish", "events": [
        {"introduced": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}, {"fixed": "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"}]}]}],
  "database_specific": {"severity": "CRITICAL"}}`
	if err := os.WriteFile(filepath.Join(dir, "GHSA-acme-lock-0001.json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := advisory.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := demo.Generate(demo.Options{Seed: 1})
	for i := range g.Edges {
		if e := &g.Edges[i]; e.Kind == graph.Uses && e.To == demo.CheckoutIsh {
			e.Attrs[graph.AttrActionsLock] = graph.LockLocked
			e.Attrs[graph.AttrLockedSHA] = sha
			e.Attrs[graph.AttrLine] = "12"
		}
	}
	return g, advisory.Annotate(g, db)
}

func TestLockedAffectedCommit(t *testing.T) {
	g, st := lockedCheckoutIsh(t, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")
	if st.LockAffected != 1 || st.Affected != 1 {
		t.Fatalf("stats %+v", st)
	}
	ix := graph.NewIndex(g)
	if top := ix.TopPaths(1); len(top) != 1 || top[0].Principal != demo.CheckoutIsh {
		t.Errorf("top path %+v, want the locked affected action first", top)
	}
	adv := byRule(build(t, g, Options{}), RuleAdvisory)
	if len(adv) != 1 || adv[0].Properties.Repository != "acme-app/docs" || adv[0].Properties.Severity != SeverityCritical ||
		!strings.Contains(adv[0].Message.Text, "actions.lock pins to 0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a") ||
		!strings.Contains(adv[0].Message.Text, "Rerun gh actions-lock after moving to v3.1.0") {
		t.Fatalf("GOP003 results %+v", adv)
	}
	p := fixplan.Build(ix, graph.PinRef{Action: demo.CheckoutIsh})
	if !strings.Contains(strings.Join(p.Caveats, "\n"), "actions.lock pins an affected commit: rerun gh actions-lock after moving to v3.1.0") {
		t.Errorf("fix-plan caveats %v", p.Caveats)
	}
}

func TestLockedUnlistedCommitIsUnknown(t *testing.T) {
	g, st := lockedCheckoutIsh(t, "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d")
	if st.LockAffected != 0 || st.Affected != 0 || st.Unknown != 1 {
		t.Fatalf("stats %+v", st)
	}
	n, _ := graph.NewIndex(g).Node(demo.CheckoutIsh)
	if graph.HasAdvisory(n) {
		t.Error("an unlisted locked commit must not be affected")
	}
	var cov []graph.Coverage
	for _, c := range g.Coverage {
		if c.Fact == graph.CoverageAdvisories {
			cov = append(cov, c)
		}
	}
	if len(cov) != 1 || cov[0].Scope != demo.CheckoutIsh || !strings.Contains(cov[0].Reason, "unknown, not safe: actions.lock pins it to 3d3d") {
		t.Errorf("coverage %+v", cov)
	}
	if adv := byRule(build(t, g, Options{}), RuleAdvisory); len(adv) != 0 {
		t.Errorf("GOP003 results %+v", adv)
	}
}

func TestLockedFixedCommitIsNotAffected(t *testing.T) {
	g, st := lockedCheckoutIsh(t, "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b")
	if st != (advisory.Stats{Actions: st.Actions}) {
		t.Fatalf("stats %+v", st)
	}
	for _, e := range g.Edges {
		if e.Attrs[graph.AttrLockAdvisories] != "" {
			t.Errorf("edge %s %s has lock_advisories", e.From, e.To)
		}
	}
	for _, c := range g.Coverage {
		if c.Fact == graph.CoverageAdvisories {
			t.Errorf("coverage %+v", c)
		}
	}
}
