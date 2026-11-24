package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

const poutineFixture = "../../testdata/poutine/report.json"

func TestEnrichPoutine(t *testing.T) {
	out := filepath.Join(t.TempDir(), "enriched.json")
	r := runApp(t, nil, nil, "enrich", "--graph", fixture, "--poutine", poutineFixture, "--out", out)
	if r.code != exitOK {
		t.Fatalf("enrich: %+v", r)
	}
	if !strings.Contains(r.stderr, "7 findings: 3 matched 2 workflows (1 with an injection finding), 4 unmatched (listed in coverage)") {
		t.Errorf("stderr = %q", r.stderr)
	}
	if strings.Count(r.stderr, "matches no workflow") != 4 {
		t.Errorf("want 4 unmatched warnings, stderr = %q", r.stderr)
	}
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := graph.LoadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Edges) != len(orig.Edges) {
		t.Errorf("poutine changed edges: %d -> %d", len(orig.Edges), len(g.Edges))
	}
	n := 0
	for _, c := range g.Coverage {
		if c.Fact == graph.FactPoutine {
			n++
		}
	}
	if n != 4 {
		t.Errorf("poutine coverage entries = %d", n)
	}
	if v := runApp(t, nil, nil, "validate", "--graph", out); v.code != exitOK {
		t.Errorf("validate: %+v", v)
	}

	// Redaction keeps the poutine attrs and passes its self-check.
	red := filepath.Join(t.TempDir(), "redacted.json")
	if rr := runApp(t, nil, nil, "redact", "--graph", out, "--out", red); rr.code != exitOK {
		t.Fatalf("redact: %+v", rr)
	}
	rg, err := graph.LoadFile(red)
	if err != nil {
		t.Fatal(err)
	}
	if top := graph.TopPaths(rg, 1); len(top) != 1 || top[0].PoutineInjectable != 1 {
		t.Errorf("redacted top = %+v", top)
	}

	// The report ranks the principal reaching the injectable workflow first.
	rep := runApp(t, nil, nil, "report", "--graph", out, "--format", "md", "--out", "-")
	if rep.code != exitOK {
		t.Fatalf("report: %+v", rep)
	}
	alice, bob := strings.Index(rep.stdout, "| identity:alice |"), strings.Index(rep.stdout, "| identity:bob |")
	if alice < 0 || bob < 0 || alice > bob {
		t.Errorf("alice at %d, bob at %d in report:\n%s", alice, bob, rep.stdout)
	}
	base := runApp(t, nil, nil, "report", "--graph", fixture, "--format", "md", "--out", "-")
	if a, b := strings.Index(base.stdout, "| identity:alice |"), strings.Index(base.stdout, "| identity:bob |"); a < b {
		t.Errorf("without poutine alice should rank below bob")
	}
}

func TestEnrichPoutineErrors(t *testing.T) {
	r := runApp(t, nil, nil, "enrich", "--graph", fixture, "--poutine", "does-not-exist.json", "--out", "-")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "--poutine") {
		t.Errorf("missing report: %+v", r)
	}
	dir := t.TempDir()
	for name, data := range map[string]string{
		"bad.json":   `{"findings": [`,
		"sarif.json": `{"version": "2.1.0", "runs": []}`,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		r = runApp(t, nil, nil, "enrich", "--graph", fixture, "--poutine", p, "--out", "-")
		if r.code != exitRuntime || !strings.Contains(r.stderr, "not a poutine JSON report") || !strings.Contains(r.stderr, "--format json") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}
