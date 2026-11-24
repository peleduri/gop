package poutine

import (
	"errors"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

const fixture = "../../testdata/poutine/report.json"

func loadAcme(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func node(t *testing.T, g *graph.Graph, id string) graph.Node {
	t.Helper()
	for _, n := range g.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("no node %s", id)
	return graph.Node{}
}

func TestParseFixture(t *testing.T) {
	r, err := ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 7 || r.Rules != 4 || len(r.Warnings) != 0 {
		t.Fatalf("findings %d rules %d warnings %v", len(r.Findings), r.Rules, r.Warnings)
	}
	f := r.Findings[0]
	if f.RuleID != "injection" || f.Repo != "acme-app/infra" || f.Path != ".github/workflows/ci.yml" ||
		f.Job != "lint" || f.Line != 21 || f.Level != LevelWarning || f.Problem != "" {
		t.Errorf("finding 0 = %+v", f)
	}
	if p := r.Findings[5].Problem; !strings.Contains(p, "not a GitHub repository") {
		t.Errorf("gitlab finding problem = %q", p)
	}
	if p := r.Findings[6].Problem; !strings.Contains(p, "no file path") {
		t.Errorf("blobsha finding problem = %q", p)
	}
}

func TestAnnotate(t *testing.T) {
	r, err := ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	g := loadAcme(t)
	edges := append([]graph.Edge(nil), g.Edges...)
	st := Annotate(g, r)
	if st.Findings != 7 || st.Matched != 3 || st.Workflows != 2 || st.Injectable != 1 || len(st.Unmatched) != 4 {
		t.Fatalf("stats = %+v", st)
	}
	infra := node(t, g, "workflow:acme-app/infra/.github/workflows/ci.yml")
	want := map[string]string{
		graph.AttrPoutineRules:    "injection,pr_runs_on_self_hosted",
		graph.AttrPoutineSeverity: "warning",
		graph.AttrPoutineJobs:     "build,lint",
		graph.AttrPoutineFile:     "../../testdata/poutine/report.json",
	}
	for k, v := range want {
		if infra.Attrs[k] != v {
			t.Errorf("infra %s = %q, want %q", k, infra.Attrs[k], v)
		}
	}
	if !graph.PoutineInjectable(infra) {
		t.Error("infra ci.yml is not injectable")
	}
	nightly := node(t, g, "workflow:acme-app/web/.github/workflows/nightly.yml")
	if nightly.Attrs[graph.AttrPoutineRules] != "debug_enabled" || nightly.Attrs[graph.AttrPoutineSeverity] != "note" ||
		nightly.Attrs[graph.AttrPoutineJobs] != "" || nightly.Attrs["token_write"] != "false" {
		t.Errorf("nightly attrs = %v", nightly.Attrs)
	}
	if graph.PoutineInjectable(nightly) {
		t.Error("debug_enabled counted as injection")
	}
	// Edges and evidence are untouched.
	if len(edges) != len(g.Edges) {
		t.Fatalf("edges %d -> %d", len(edges), len(g.Edges))
	}
	for i := range edges {
		if edges[i].Evidence != g.Edges[i].Evidence || edges[i].From != g.Edges[i].From || edges[i].To != g.Edges[i].To {
			t.Fatalf("edge %d changed", i)
		}
	}

	// Unmatched findings are listed in coverage.
	var cov []graph.Coverage
	for _, c := range g.Coverage {
		if c.Fact == graph.FactPoutine {
			cov = append(cov, c)
		}
	}
	if len(cov) != 4 {
		t.Fatalf("poutine coverage = %+v", cov)
	}
	for i, want := range []struct{ scope, reason string }{
		{"workflow:acme-app/ghost/.github/workflows/pr.yml", "rule untrusted_checkout_exec (error) at line 30 matches no workflow node: the graph has no such workflow"},
		{"workflow:acme-actions/deploy/action.yml", "composite action"},
		{"poutine:../../testdata/poutine/report.json", "not a GitHub repository"},
		{"repo:acme-app/web", "no file path"},
	} {
		if cov[i].Scope != want.scope || !strings.Contains(cov[i].Reason, want.reason) || cov[i].NeedsFix == "" {
			t.Errorf("coverage %d = %+v, want scope %s reason containing %q", i, cov[i], want.scope, want.reason)
		}
	}

	// A second run with an empty report clears the earlier attrs and coverage.
	st = Annotate(g, &Result{File: "empty.json"})
	if st.Workflows != 0 || len(st.Unmatched) != 0 {
		t.Errorf("rerun stats = %+v", st)
	}
	if v := node(t, g, "workflow:acme-app/infra/.github/workflows/ci.yml").Attrs[graph.AttrPoutineRules]; v != "" {
		t.Errorf("stale poutine_rules = %q", v)
	}
	for _, c := range g.Coverage {
		if c.Fact == graph.FactPoutine {
			t.Errorf("stale coverage %+v", c)
		}
	}
}

func TestAnnotateCaseInsensitiveRepo(t *testing.T) {
	r, err := Parse("r.json", []byte(`{"findings":[{"rule_id":"untrusted_checkout_exec","purl":"pkg:github/ACME-App/Infra@main","meta":{"path":"./.github/workflows/ci.yml"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g := loadAcme(t)
	st := Annotate(g, r)
	if st.Matched != 1 || st.Injectable != 1 {
		t.Fatalf("stats = %+v", st)
	}
	n := node(t, g, "workflow:acme-app/infra/.github/workflows/ci.yml")
	if _, ok := n.Attrs[graph.AttrPoutineSeverity]; ok {
		t.Errorf("severity set without a rules map: %v", n.Attrs)
	}
}

func TestParseMalformed(t *testing.T) {
	for _, tc := range []struct{ name, data, want string }{
		{"truncated", `{"findings": [`, "--format json"},
		{"not json", `poutine found 3 findings`, "--format json"},
		{"array", `[]`, "--format json"},
		{"no findings", `{"rules": {}}`, `no "findings" key`},
		{"sarif", `{"version":"2.1.0","runs":[]}`, "this is SARIF"},
		{"findings not array", `{"findings": {}}`, "not an array"},
		{"rules not object", `{"findings": [], "rules": []}`, `"rules" is not an object`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("bad.json", []byte(tc.data))
			if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "bad.json") {
				t.Errorf("err = %v, want ErrFormat containing %q", err, tc.want)
			}
		})
	}
}

func TestParseBadFindingsWarn(t *testing.T) {
	r, err := Parse("r.json", []byte(`{"findings":[42,{"purl":"pkg:github/acme/x"},{"rule_id":"injection","purl":"pkg:github/acme/x@v1","meta":{"path":"a.yml","line":"x","job":7}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 2 || len(r.Findings) != 1 {
		t.Fatalf("warnings %v findings %+v", r.Warnings, r.Findings)
	}
	if f := r.Findings[0]; f.Index != 2 || f.Job != "7" || f.Line != 0 || f.Repo != "acme/x" {
		t.Errorf("finding = %+v", f)
	}
}

func TestRepoOf(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:github/acme-app/web":                                       "acme-app/web",
		"pkg:github/acme-app/web@main":                                  "acme-app/web",
		"pkg:github/acme-app/web@v1?repository_url=github.acme.example": "acme-app/web",
		"pkg:GitHub/acme-app/web#sub/dir":                               "acme-app/web",
		"pkg:github/acme%2Dapp/web@refs%2Fheads%2Fmain":                 "acme-app/web",
		"pkg:generic/github-actions-workflow":                           "",
		"pkg:github/acme-app":                                           "",
		"pkg:github/acme/web/extra":                                     "",
		"":                                                              "",
		"github.com/acme/web":                                           "",
	} {
		got, problem := repoOf(purl)
		if got != want || (want == "") == (problem == "") {
			t.Errorf("repoOf(%q) = %q, %q; want %q", purl, got, problem, want)
		}
	}
}
