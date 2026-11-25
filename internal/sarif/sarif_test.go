package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

const fixture = "../../testdata/acme/graph.json"

const deployMain = "action:acme-actions/deploy@main"

func load(t *testing.T) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// edit changes the USES edge from workflow into deploy@main.
func edit(t *testing.T, g *graph.Graph, workflow string, f func(*graph.Edge)) {
	t.Helper()
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind == graph.Uses && e.From == workflow && e.To == deployMain {
			f(e)
			return
		}
	}
	t.Fatalf("no USES edge %s -> %s", workflow, deployMain)
}

func build(t *testing.T, g *graph.Graph, opts Options) *Log {
	t.Helper()
	l, err := Build(g, opts)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func encode(t *testing.T, l *Log) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, l); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func validate(t *testing.T, d *draft4, data []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if probs := d.Validate(v); len(probs) > 0 {
		t.Fatalf("SARIF does not validate against the 2.1.0 schema:\n%s", strings.Join(probs, "\n"))
	}
}

func results(l *Log) []Result { return l.Runs[0].Results }

func byRule(l *Log, rule string) []Result {
	var out []Result
	for _, r := range results(l) {
		if r.RuleID == rule {
			out = append(out, r)
		}
	}
	return out
}

func withLines(t *testing.T) *graph.Graph {
	g := load(t)
	edit(t, g, "workflow:acme-app/web/.github/workflows/release.yml", func(e *graph.Edge) {
		e.Attrs = map[string]string{graph.AttrRefKind: "branch", graph.AttrLine: "42", graph.AttrCol: "15", graph.AttrFileRef: "main"}
	})
	return g
}

func TestGolden(t *testing.T) {
	data := encode(t, build(t, load(t), Options{Version: testutil.TestVersion}))
	validate(t, loadSARIFSchema(t), data)
	testutil.Golden(t, "acme.sarif", data)
}

func TestSchemaValid(t *testing.T) {
	d := loadSARIFSchema(t)
	g := withLines(t)
	edit(t, g, "workflow:acme-app/docs/.github/workflows/ci.yml", func(e *graph.Edge) { e.Evidence = graph.NotVisible })
	for _, opts := range []Options{
		{},
		{Version: "v1.2.3", IncludePossible: true},
		{MinSeverity: SeverityCritical},
		{Top: 1},
	} {
		l := build(t, g, opts)
		validate(t, d, encode(t, l))
		for key, sub := range Split(l) {
			t.Run(key, func(t *testing.T) { validate(t, d, encode(t, sub)) })
		}
	}
	// An empty log validates too.
	validate(t, d, encode(t, build(t, &graph.Graph{Schema: graph.SchemaVersion}, Options{})))
}

func TestDriver(t *testing.T) {
	l := build(t, load(t), Options{Version: "v9.9.9"})
	if l.Version != "2.1.0" || len(l.Runs) != 1 {
		t.Fatalf("log: %+v", l)
	}
	d := l.Runs[0].Tool.Driver
	if d.Name != "gop" || d.Version != "v9.9.9" || d.InformationURI != InformationURI {
		t.Errorf("driver: %+v", d)
	}
	if len(d.Rules) != 6 || d.Rules[0].ID != RuleMutableRef || d.Rules[0].Name != "mutable-action-ref-reachable" ||
		d.Rules[1].ID != RuleDefaultPerm || d.Rules[1].Name != "default-permission-grants-push" {
		t.Fatalf("rules: %+v", d.Rules)
	}
	for _, r := range d.Rules {
		if r.ShortDescription.Text == "" || !strings.Contains(r.Help.Markdown, "## Fix") {
			t.Errorf("%s: short description or help markdown missing", r.ID)
		}
	}
	for _, r := range results(l) {
		if d.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %s has ruleIndex %d", r.RuleID, r.RuleIndex)
		}
	}
}

// One GOP001 result per consuming workflow USES edge of deploy@main.
func TestMutableRefCounts(t *testing.T) {
	g := withLines(t)
	want := map[string]bool{}
	for _, e := range g.Edges {
		if e.Kind == graph.Uses && e.To == deployMain {
			want[e.From] = true
		}
	}
	if len(want) != 10 {
		t.Fatalf("fixture has %d USES edges into deploy@main, want 10", len(want))
	}
	l := build(t, g, Options{})
	got := map[string]Result{}
	for _, r := range byRule(l, RuleMutableRef) {
		if r.Properties.Fix.Action != deployMain {
			continue
		}
		from, _, _ := strings.Cut(r.Properties.Edge, " USES ")
		if _, dup := got[from]; dup {
			t.Errorf("two results for %s", from)
		}
		got[from] = r
	}
	if len(got) != len(want) {
		t.Fatalf("%d GOP001 results for deploy@main, want %d", len(got), len(want))
	}
	for from := range want {
		r, ok := got[from]
		if !ok {
			t.Errorf("no result for %s", from)
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(from, "workflow:"), "/", 3)
		pl := r.Locations[0].PhysicalLocation
		if r.Properties.Repository != parts[0]+"/"+parts[1] || pl == nil || pl.ArtifactLocation.URI != parts[2] {
			t.Errorf("%s: repository %q location %+v", from, r.Properties.Repository, pl)
		}
		if r.Properties.Fix.Type != "pin_ref" || r.Properties.Possible || r.Level == "note" {
			t.Errorf("%s: %+v", from, r.Properties)
		}
		if len(r.Properties.ConfirmedPrincipals) == 0 || r.Properties.ConfirmedPrincipals[len(r.Properties.ConfirmedPrincipals)-1] != "members:acme-actions" {
			t.Errorf("%s: confirmed principals %v", from, r.Properties.ConfirmedPrincipals)
		}
		if r.Properties.ReachRemovedPct <= 0 || r.Properties.ReachRemovedPct > 100 {
			t.Errorf("%s: reach_removed_pct %v", from, r.Properties.ReachRemovedPct)
		}
		region := pl.Region
		if strings.HasSuffix(from, "acme-app/web/.github/workflows/release.yml") {
			if region == nil || region.StartLine != 42 || region.StartColumn != 15 {
				t.Errorf("release.yml: region %+v, want line 42 col 15", region)
			}
		} else if region != nil {
			t.Errorf("%s: region %+v, want none (no line attribute)", from, region)
		}
	}
	// The setup@main consumer lives in acme-actions itself: its only
	// controllers are inside that org, so it is not a GOP001 result.
	for _, r := range byRule(l, RuleMutableRef) {
		if r.Properties.Fix.Action == "action:acme-actions/setup@main" {
			t.Errorf("unexpected result for setup@main: %+v", r.Properties)
		}
	}
}

func TestDefaultPermResult(t *testing.T) {
	rs := byRule(build(t, load(t), Options{}), RuleDefaultPerm)
	if len(rs) != 1 {
		t.Fatalf("%d GOP002 results, want 1 (acme-actions)", len(rs))
	}
	r := rs[0]
	if r.Properties.Org != "acme-actions" || r.Properties.Repository != "" || r.Properties.Fix.Type != "lower_default_perm" || r.Properties.Fix.Org != "org:acme-actions" {
		t.Fatalf("GOP002: %+v", r.Properties)
	}
	loc := r.Locations[0]
	if loc.PhysicalLocation != nil || len(loc.LogicalLocations) != 1 || loc.LogicalLocations[0].FullyQualifiedName != "org:acme-actions" {
		t.Errorf("GOP002 location: %+v", loc)
	}
	// acme-legacy's default-perm edge is not_visible: never a candidate.
	for _, r := range rs {
		if r.Properties.Org == "acme-legacy" {
			t.Errorf("acme-legacy reported: %+v", r.Properties)
		}
	}
}

func TestFingerprintsStable(t *testing.T) {
	a := encode(t, build(t, withLines(t), Options{}))
	b := encode(t, build(t, withLines(t), Options{}))
	if !bytes.Equal(a, b) {
		t.Fatal("two runs on the same graph differ")
	}
	l := build(t, withLines(t), Options{})
	seen := map[string]string{}
	for _, r := range results(l) {
		fp := r.PartialFingerprints[FingerprintKey]
		if len(fp) != 64 {
			t.Errorf("fingerprint %q", fp)
		}
		if prev, ok := seen[fp]; ok {
			t.Errorf("fingerprint shared by %s and %s", prev, r.Properties.Edge)
		}
		seen[fp] = r.Properties.Edge
	}
	// The fingerprint ignores the line: moving the uses: line keeps it.
	g := withLines(t)
	edit(t, g, "workflow:acme-app/web/.github/workflows/release.yml", func(e *graph.Edge) { e.Attrs[graph.AttrLine] = "50" })
	moved := build(t, g, Options{})
	for i, r := range results(moved) {
		if r.PartialFingerprints[FingerprintKey] != results(l)[i].PartialFingerprints[FingerprintKey] {
			t.Errorf("fingerprint of %s changed when its line moved", r.Properties.Edge)
		}
	}
}

func TestPossibleExcludedByDefault(t *testing.T) {
	g := load(t)
	docs := "workflow:acme-app/docs/.github/workflows/ci.yml"
	edit(t, g, docs, func(e *graph.Edge) { e.Evidence = graph.NotVisible })
	find := func(l *Log) *Result {
		for _, r := range byRule(l, RuleMutableRef) {
			if strings.HasPrefix(r.Properties.Edge, docs+" ") {
				return &r
			}
		}
		return nil
	}
	if r := find(build(t, g, Options{})); r != nil {
		t.Fatalf("possible-only result included by default: %+v", r.Properties)
	}
	r := find(build(t, g, Options{IncludePossible: true}))
	if r == nil {
		t.Fatal("--include-possible dropped the result")
	}
	if r.Level != "note" || !r.Properties.Possible || len(r.Properties.ConfirmedPrincipals) != 0 ||
		len(r.Properties.PossiblePrincipals) == 0 || r.Properties.Evidence != graph.NotVisible {
		t.Errorf("possible result: level %s %+v", r.Level, r.Properties)
	}
	// Possible results sort after confirmed ones.
	rs := results(build(t, g, Options{IncludePossible: true}))
	if !rs[len(rs)-1].Properties.Possible {
		t.Error("possible result not last")
	}
}

func TestSeverity(t *testing.T) {
	for _, tc := range []struct {
		t    Terminals
		want string
	}{
		{Terminals{}, SeverityLow},
		{Terminals{Repos: 1}, SeverityMedium},
		{Terminals{Repos: 1, Secrets: 2}, SeverityHigh},
		{Terminals{Repos: 1, Runners: 1}, SeverityHigh},
		{Terminals{Repos: 1, OIDC: 1, Secrets: 1}, SeverityCritical},
		{Terminals{CloudTargets: 1}, SeverityCritical},
	} {
		if got := severityOf(tc.t); got != tc.want {
			t.Errorf("severityOf(%+v) = %s, want %s", tc.t, got, tc.want)
		}
	}
	for _, tc := range []struct {
		sev      string
		possible bool
		want     string
	}{
		{SeverityCritical, false, "error"}, {SeverityHigh, false, "error"}, {SeverityMedium, false, "warning"},
		{SeverityLow, false, "note"}, {SeverityCritical, true, "note"},
	} {
		if got := level(tc.sev, tc.possible); got != tc.want {
			t.Errorf("level(%s, %v) = %s, want %s", tc.sev, tc.possible, got, tc.want)
		}
	}

	// On the fixture: web (OIDC) is critical, billing (secrets) and worker
	// (self-hosted runner) high, the other consumers repo CI only.
	want := map[string]string{
		"acme-app/web": SeverityCritical, "acme-app/billing": SeverityHigh, "acme-app/worker": SeverityHigh,
		"acme-app/admin": SeverityMedium, "acme-app/docs": SeverityMedium,
	}
	for _, r := range byRule(build(t, load(t), Options{}), RuleMutableRef) {
		if w, ok := want[r.Properties.Repository]; ok && r.Properties.Fix.Action == deployMain && r.Properties.Severity != w {
			t.Errorf("%s: severity %s, want %s", r.Properties.Edge, r.Properties.Severity, w)
		}
	}
}

func TestFilters(t *testing.T) {
	g := load(t)
	all := results(build(t, g, Options{}))
	crit := results(build(t, g, Options{MinSeverity: "critical"}))
	if len(crit) == 0 || len(crit) >= len(all) {
		t.Fatalf("critical: %d of %d", len(crit), len(all))
	}
	for _, r := range crit {
		if r.Properties.Severity != SeverityCritical {
			t.Errorf("min-severity critical kept %s", r.Properties.Severity)
		}
	}
	top := results(build(t, g, Options{Top: 2}))
	if len(top) != 2 || top[0].Properties.Edge != all[0].Properties.Edge || top[1].Properties.Edge != all[1].Properties.Edge {
		t.Errorf("top 2: %+v", top)
	}
	for i := 1; i < len(all); i++ {
		if severityRank(all[i].Properties.Severity) > severityRank(all[i-1].Properties.Severity) {
			t.Errorf("result %d is more severe than result %d", i, i-1)
		}
	}
	if _, err := Build(g, Options{MinSeverity: "urgent"}); err == nil {
		t.Error("bad severity accepted")
	}
	if _, err := Build(g, Options{Top: -1}); err == nil {
		t.Error("negative top accepted")
	}
	for _, s := range []string{"", "LOW", " high "} {
		if _, err := ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q): %v", s, err)
		}
	}
}

func TestSplit(t *testing.T) {
	l := build(t, withLines(t), Options{})
	parts := Split(l)
	total := 0
	for key, sub := range parts {
		rs := results(sub)
		total += len(rs)
		if len(rs) == 0 {
			t.Errorf("%s: empty log", key)
		}
		if len(sub.Runs[0].Tool.Driver.Rules) != len(Rules()) {
			t.Errorf("%s: rules missing", key)
		}
		for _, r := range rs {
			got := r.Properties.Repository
			if got == "" {
				got = "org:" + r.Properties.Org
			}
			if got != key {
				t.Errorf("%s holds a result for %s", key, got)
			}
		}
	}
	if total != len(results(l)) {
		t.Errorf("split holds %d results, want %d", total, len(results(l)))
	}
	if web := parts["acme-app/web"]; web == nil || len(results(web)) != 2 {
		t.Errorf("acme-app/web: want 2 results (ci.yml and release.yml)")
	}
	if parts["org:acme-actions"] == nil {
		t.Error("org:acme-actions missing")
	}
	if len(Split(&Log{})) != 0 {
		t.Error("split of an empty log")
	}
}
