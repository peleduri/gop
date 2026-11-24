// Package ossie_test checks the Apache Ossie semantic model in this
// directory (gop.ossie.yaml) against the published Ossie JSON Schema, against
// the tables of gop export --format sql plus views.sql, and against the
// numbers gop's own engine computes for the demo graph.
package ossie_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sqlexport"
	"github.com/peleduri/gop/internal/testutil"
)

const (
	modelFile  = "gop.ossie.yaml"
	viewsFile  = "views.sql"
	schemaFile = "testdata/ossie-schema-0.3.0.dev0.json"
	// ossieVersion is the Ossie core spec version the model targets.
	ossieVersion = "0.3.0.dev0"
	// sourcePrefix is how datasets name a table: database gop (the file
	// gop.db), schema main.
	sourcePrefix = "gop.main."
)

type model struct {
	Version       string         `yaml:"version"`
	Name          string         `yaml:"name"`
	Datasets      []dataset      `yaml:"datasets"`
	Relationships []relationship `yaml:"relationships"`
	Metrics       []metric       `yaml:"metrics"`
}

type expression struct {
	SQL string `yaml:"sql"`
}

type aiContext struct {
	Synonyms []string `yaml:"synonyms"`
}

type field struct {
	Name       string     `yaml:"name"`
	Expression expression `yaml:"expression"`
}

type dataset struct {
	Name        string    `yaml:"name"`
	Source      string    `yaml:"source"`
	Description string    `yaml:"description"`
	PrimaryKey  []string  `yaml:"primary_key"`
	AIContext   aiContext `yaml:"ai_context"`
	Fields      []field   `yaml:"fields"`
}

func (d dataset) table() string { return strings.TrimPrefix(d.Source, sourcePrefix) }

func (d dataset) hasField(name string) bool {
	return slices.ContainsFunc(d.Fields, func(f field) bool { return f.Name == name })
}

type relationship struct {
	Name        string   `yaml:"name"`
	From        string   `yaml:"from"`
	To          string   `yaml:"to"`
	FromColumns []string `yaml:"from_columns"`
	ToColumns   []string `yaml:"to_columns"`
}

type metric struct {
	Name        string     `yaml:"name"`
	Expression  expression `yaml:"expression"`
	Description string     `yaml:"description"`
}

func loadModel(t *testing.T) model {
	t.Helper()
	data, err := os.ReadFile(modelFile)
	if err != nil {
		t.Fatal(err)
	}
	var m model
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m model) dataset(name string) (dataset, bool) {
	for _, d := range m.Datasets {
		if d.Name == name {
			return d, true
		}
	}
	return dataset{}, false
}

// sqlite3 returns the path of the sqlite3 shell. Tests that need it skip
// without it locally and fail without it in CI, as in internal/sqlexport.
func sqlite3(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sqlite3")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("sqlite3 not on PATH; the Ossie model tests need it in CI")
		}
		t.Skip("sqlite3 not on PATH")
	}
	return p
}

// run feeds script to sqlite3 on db.
func run(t *testing.T, db string, script []byte) {
	t.Helper()
	cmd := exec.Command(sqlite3(t), "-bail", db)
	cmd.Stdin = bytes.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil || len(out) > 0 {
		t.Fatalf("sqlite3: %v\n%s", err, out)
	}
}

// query runs q and returns the rows as JSON objects.
func query(t *testing.T, db, q string) []map[string]any {
	t.Helper()
	out, err := exec.Command(sqlite3(t), "-bail", "-json", db, q).CombinedOutput()
	if err != nil {
		t.Fatalf("sqlite3 %q: %v\n%s", q, err, out)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("sqlite3 %q: %v\n%s", q, err, out)
	}
	return rows
}

// loadDB exports graphs with gop export --format sql, loads the script and
// views.sql into a new SQLite database, and returns its path.
func loadDB(t *testing.T, graphs ...*graph.Graph) string {
	t.Helper()
	var buf bytes.Buffer
	if err := sqlexport.Write(&buf, graphs); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "gop.db")
	run(t, db, buf.Bytes())
	views, err := os.ReadFile(viewsFile)
	if err != nil {
		t.Fatal(err)
	}
	run(t, db, views)
	run(t, db, views) // reloading the views is safe
	return db
}

// demoGraph is the graph `gop export --format sql --demo` exports.
func demoGraph() *graph.Graph { return demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}) }

// laterRun is the demo a week later with acme-actions' default permission
// lowered: its via=default_perm CAN_PUSH edges are gone, so reach drops.
func laterRun() *graph.Graph {
	g := demoGraph()
	g.CollectedAt = g.CollectedAt.Add(7 * 24 * time.Hour)
	var es []graph.Edge
	for _, e := range g.Edges {
		if e.Kind == graph.CanPush && e.From == "members:acme-actions" && e.Attrs[graph.AttrVia] == graph.ViaDefaultPerm {
			continue
		}
		es = append(es, e)
	}
	g.Edges = es
	for i, n := range g.Nodes {
		if n.ID == "org:acme-actions" {
			attrs := map[string]string{}
			for k, v := range n.Attrs {
				attrs[k] = v
			}
			attrs[graph.AttrDefaultPerm] = "read"
			g.Nodes[i].Attrs = attrs
		}
	}
	return g
}

// TestSchema validates the model against the published Ossie JSON Schema
// (core-spec/ossie-schema.json of apache/ossie, version 0.3.0.dev0, copied
// into testdata), and checks the validator rejects a broken model.
func TestSchema(t *testing.T) {
	raw, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := modelJSON(t)
	if err := rs.Validate(doc); err != nil {
		t.Fatalf("%s does not validate against %s: %v", modelFile, schemaFile, err)
	}

	broken := modelJSON(t)
	broken["datasets"].([]any)[0].(map[string]any)["filter"] = "kind = 'repo'"
	if rs.Validate(broken) == nil {
		t.Error("the schema accepted an unknown dataset key; the validator is not checking the model")
	}
	broken = modelJSON(t)
	broken["version"] = "0.2.0"
	if rs.Validate(broken) == nil {
		t.Error("the schema accepted another spec version")
	}
}

// modelJSON is the model as JSON values (what the schema validates).
func modelJSON(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(modelFile)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := yaml.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s is not JSON-representable: %v", modelFile, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestTerms checks the business terms the model promises are there, each
// with a description and synonyms.
func TestTerms(t *testing.T) {
	m := loadModel(t)
	if m.Version != ossieVersion {
		t.Errorf("version = %q, want %q", m.Version, ossieVersion)
	}
	for _, name := range []string{"organization", "repository", "workflow", "action", "identity", "principal",
		"cloud_role", "secret", "runner", "finding", "run", "reach"} {
		d, ok := m.dataset(name)
		switch {
		case !ok:
			t.Errorf("term %s: no dataset", name)
		case d.Description == "":
			t.Errorf("term %s: no description", name)
		case len(d.AIContext.Synonyms) == 0:
			t.Errorf("term %s: no synonyms", name)
		}
	}
	id, _ := m.dataset("identity")
	if !slices.Contains(id.AIContext.Synonyms, "outside collaborator") {
		t.Error("identity: missing the synonym outside collaborator")
	}
	for _, name := range []string{"confirmed_reach_count", "possible_reach_count", "unpinned_reachable_actions",
		"orgs_default_write", "finding_count", "confirmed_reach_delta"} {
		if !slices.ContainsFunc(m.Metrics, func(x metric) bool { return x.Name == name }) {
			t.Errorf("metric %s missing", name)
		}
	}
	for _, x := range m.Metrics {
		if x.Name == "possible_reach_count" && !strings.Contains(x.Description, "never summed with confirmed") {
			t.Error("possible_reach_count: the description must say it is never summed with confirmed reach")
		}
	}
}

// TestColumns checks every column the model references exists in the export
// schema plus views.sql, and every column of those tables is in the model,
// so a change to the export schema fails here until the model follows.
func TestColumns(t *testing.T) {
	m := loadModel(t)
	db := loadDB(t, demoGraph())
	names := map[string]bool{}
	for _, d := range m.Datasets {
		if names[d.Name] {
			t.Errorf("dataset %s declared twice", d.Name)
		}
		names[d.Name] = true
		if !strings.HasPrefix(d.Source, sourcePrefix) {
			t.Errorf("dataset %s: source %q must be %s<table>", d.Name, d.Source, sourcePrefix)
			continue
		}
		var cols []string
		for _, r := range query(t, db, fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", d.table())) {
			cols = append(cols, r["name"].(string))
		}
		if len(cols) == 0 {
			t.Errorf("dataset %s: table %s does not exist", d.Name, d.table())
			continue
		}
		seen := map[string]bool{}
		for _, f := range d.Fields {
			if seen[f.Name] {
				t.Errorf("%s.%s declared twice", d.Name, f.Name)
			}
			seen[f.Name] = true
			if f.Expression.SQL != f.Name {
				t.Errorf("%s.%s: expression %q must be the column of the same name", d.Name, f.Name, f.Expression.SQL)
			}
			if !slices.Contains(cols, f.Expression.SQL) {
				t.Errorf("%s.%s: column %s.%s does not exist", d.Name, f.Name, d.table(), f.Expression.SQL)
			}
		}
		for _, c := range cols {
			if !seen[c] {
				t.Errorf("dataset %s: column %s.%s is not in the model", d.Name, d.table(), c)
			}
		}
		if !slices.Contains(d.PrimaryKey, "run_id") {
			t.Errorf("dataset %s: primary key must include run_id", d.Name)
		}
		for _, k := range d.PrimaryKey {
			if !d.hasField(k) {
				t.Errorf("dataset %s: primary key %s is not a field", d.Name, k)
			}
		}
		// The primary key holds in the demo.
		pk := strings.Join(d.PrimaryKey, ", ")
		if dup := query(t, db, fmt.Sprintf("SELECT %s, COUNT(*) AS n FROM %s GROUP BY %s HAVING COUNT(*) > 1 LIMIT 1", pk, d.table(), pk)); len(dup) > 0 {
			t.Errorf("dataset %s: primary key (%s) is not unique: %v", d.Name, pk, dup[0])
		}
	}

	rels := map[string]bool{}
	for _, r := range m.Relationships {
		if rels[r.Name] {
			t.Errorf("relationship %s declared twice", r.Name)
		}
		rels[r.Name] = true
		from, ok1 := m.dataset(r.From)
		to, ok2 := m.dataset(r.To)
		if !ok1 || !ok2 {
			t.Errorf("relationship %s: unknown dataset %s or %s", r.Name, r.From, r.To)
			continue
		}
		if len(r.FromColumns) != len(r.ToColumns) || r.FromColumns[0] != "run_id" || r.ToColumns[0] != "run_id" {
			t.Errorf("relationship %s: columns must pair up and start with run_id", r.Name)
		}
		for _, c := range r.FromColumns {
			if !from.hasField(c) {
				t.Errorf("relationship %s: %s.%s is not a field", r.Name, r.From, c)
			}
		}
		for _, c := range r.ToColumns {
			if !to.hasField(c) {
				t.Errorf("relationship %s: %s.%s is not a field", r.Name, r.To, c)
			}
		}
		if !slices.Equal(r.ToColumns, to.PrimaryKey) {
			t.Errorf("relationship %s: to_columns %v must be the primary key of %s %v", r.Name, r.ToColumns, r.To, to.PrimaryKey)
		}
	}
	for _, label := range []string{"push_grant", "action_use", "action_host", "workflow_definition", "workflow_capability",
		"membership", "trigger_grant", "role_assumption"} {
		if _, ok := m.dataset(label); !ok {
			t.Errorf("edge dataset %s missing", label)
		}
	}

	for _, x := range m.Metrics {
		if _, err := metricDataset(m, x); err != nil {
			t.Errorf("metric %s: %v", x.Name, err)
		}
	}
}

var (
	stringLit = regexp.MustCompile(`'(?:[^']|'')*'`)
	qualified = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\b`)
)

// metricDataset returns the one dataset a metric reads, checking every
// dataset.field reference exists.
func metricDataset(m model, x metric) (dataset, error) {
	expr := stringLit.ReplaceAllString(x.Expression.SQL, "''")
	refs := qualified.FindAllStringSubmatch(expr, -1)
	if len(refs) == 0 {
		return dataset{}, fmt.Errorf("references no dataset.field")
	}
	var ds string
	for _, r := range refs {
		d, ok := m.dataset(r[1])
		if !ok {
			return dataset{}, fmt.Errorf("unknown dataset %s", r[1])
		}
		if !d.hasField(r[2]) {
			return dataset{}, fmt.Errorf("%s.%s is not a field", r[1], r[2])
		}
		if ds != "" && ds != r[1] {
			return dataset{}, fmt.Errorf("reads %s and %s; keep each metric on one dataset", ds, r[1])
		}
		ds = r[1]
	}
	d, _ := m.dataset(ds)
	return d, nil
}

// metricValues runs every metric once per run, as
// SELECT <expression> FROM <source> AS <dataset> WHERE run_id = <run>, and
// returns name -> values in collected_at order (nil for NULL).
func metricValues(t *testing.T, m model, db string) map[string][]any {
	t.Helper()
	out := map[string][]any{}
	for _, x := range m.Metrics {
		d, err := metricDataset(m, x)
		if err != nil {
			t.Fatalf("metric %s: %v", x.Name, err)
		}
		q := fmt.Sprintf("SELECT r.run_id, (SELECT %s FROM %s AS %s WHERE %s.run_id = r.run_id) AS value FROM runs r ORDER BY r.collected_at, r.run_id",
			x.Expression.SQL, d.table(), d.Name, d.Name)
		for _, row := range query(t, db, q) {
			out[x.Name] = append(out[x.Name], row["value"])
		}
	}
	return out
}

// expected computes each metric for one graph with gop's engine, not SQL.
func expected(g *graph.Graph) map[string]float64 {
	ix := graph.NewIndex(g)
	before := ix.WhatIf(nil).Before
	refKind := map[string]string{}
	orgsWrite := 0
	for _, n := range g.Nodes {
		switch n.Kind {
		case graph.KindActionRef:
			refKind[n.ID] = n.Attrs[graph.AttrRefKind]
		case graph.KindOrg:
			if p := n.Attrs[graph.AttrDefaultPerm]; p == "write" || p == "admin" {
				orgsWrite++
			}
		}
	}
	unpinned := map[string]bool{}
	for _, p := range ix.ScoringPrincipals() {
		for _, a := range ix.Reach(p, graph.Options{}).Confirmed.Actions {
			if k := refKind[a]; k == "tag" || k == "branch" {
				unpinned[a] = true
			}
		}
	}
	findings, maxSev := 0, 0.0
	for _, s := range ix.TopPaths(0) {
		if s.Score == 0 && s.PossibleScore == 0 {
			continue
		}
		findings++
		maxSev = max(maxSev, s.Score)
	}
	for _, f := range ix.Candidates() {
		d := ix.WhatIf([]graph.Fix{f})
		findings++
		maxSev = max(maxSev, float64(d.Before.ConfirmedPairs-d.After.ConfirmedPairs))
	}
	return map[string]float64{
		"confirmed_reach_count":      float64(before.ConfirmedPairs),
		"possible_reach_count":       float64(before.PossiblePairs),
		"unpinned_reachable_actions": float64(len(unpinned)),
		"orgs_default_write":         float64(orgsWrite),
		"finding_count":              float64(findings),
		"max_finding_severity":       maxSev,
	}
}

// TestMetrics runs every metric's SQL on the demo export (two runs) and
// compares it with what gop's engine computes, and with a golden file.
func TestMetrics(t *testing.T) {
	m := loadModel(t)
	runs := []*graph.Graph{demoGraph(), laterRun()}
	db := loadDB(t, runs...)
	got := metricValues(t, m, db)

	var want []map[string]float64
	for _, g := range runs {
		want = append(want, expected(g))
	}
	num := func(v any) (float64, bool) { f, ok := v.(float64); return f, ok }
	for name := range want[0] {
		vals := got[name]
		if len(vals) != len(runs) {
			t.Fatalf("%s: %d values, want one per run (%d)", name, len(vals), len(runs))
		}
		for i := range runs {
			if f, ok := num(vals[i]); !ok || f != want[i][name] {
				t.Errorf("%s run %d: SQL gives %v, engine gives %v", name, i+1, vals[i], want[i][name])
			}
		}
	}
	for _, d := range []struct{ metric, base string }{
		{"confirmed_reach_delta", "confirmed_reach_count"},
		{"possible_reach_delta", "possible_reach_count"},
	} {
		vals := got[d.metric]
		if len(vals) != 2 || vals[0] != nil {
			t.Errorf("%s: %v, want NULL for the first run", d.metric, vals)
			continue
		}
		if f, ok := num(vals[1]); !ok || f != want[1][d.base]-want[0][d.base] {
			t.Errorf("%s run 2: %v, want %v", d.metric, vals[1], want[1][d.base]-want[0][d.base])
		}
	}
	if w := want[0]; w["confirmed_reach_count"] == 0 || w["possible_reach_count"] == 0 || w["unpinned_reachable_actions"] == 0 ||
		w["orgs_default_write"] == 0 || want[1]["confirmed_reach_count"] == w["confirmed_reach_count"] {
		t.Errorf("the demo no longer exercises every metric: %v %v", want[0], want[1])
	}

	var b strings.Builder
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "%s:", n)
		for _, v := range got[n] {
			if v == nil {
				b.WriteString(" NULL")
			} else {
				fmt.Fprintf(&b, " %v", v)
			}
		}
		b.WriteString("\n")
	}
	testutil.Golden(t, "metrics.txt", []byte(b.String()))
}

// TestScoringPrincipals: the principals view marks exactly gop's scoring
// principals, the ones the reach table and the reach metrics count.
func TestScoringPrincipals(t *testing.T) {
	g := demoGraph()
	db := loadDB(t, g)
	var got []string
	for _, r := range query(t, db, "SELECT principal_id FROM principals WHERE is_scoring = 1 ORDER BY principal_id") {
		got = append(got, r["principal_id"].(string))
	}
	want := graph.NewIndex(g).ScoringPrincipals()
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("scoring principals:\n got %v\nwant %v", got, want)
	}
}

// TestIdentities checks the outside collaborator and membership flags and the
// edge views on a small graph with a member, an outside collaborator and a
// team.
func TestIdentities(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	edge := func(from, to string, kind graph.EdgeKind, attrs map[string]string) graph.Edge {
		return graph.Edge{From: from, To: to, Kind: kind, Evidence: graph.Live, SourceAPI: "test", ObservedAt: at, Attrs: attrs}
	}
	g := &graph.Graph{
		Schema: graph.SchemaVersion, CollectedAt: at, Enterprise: "acme",
		Nodes: []graph.Node{
			{ID: "org:acme", Kind: graph.KindOrg, Name: "acme", Evidence: graph.Live, Attrs: map[string]string{graph.AttrDefaultPerm: "read"}},
			{ID: "repo:acme/web", Kind: graph.KindRepo, Name: "acme/web", Evidence: graph.Live},
			{ID: "identity:alice", Kind: graph.KindIdentity, Name: "alice", Evidence: graph.Live},
			{ID: "identity:bob", Kind: graph.KindIdentity, Name: "bob", Evidence: graph.Live},
			{ID: "team:acme/platform", Kind: graph.KindIdentity, Name: "acme/platform", Evidence: graph.Live},
		},
		Edges: []graph.Edge{
			edge("identity:alice", "org:acme", graph.MemberOf, map[string]string{"role": "member"}),
			edge("identity:alice", "team:acme/platform", graph.MemberOf, nil),
			edge("team:acme/platform", "repo:acme/web", graph.CanPush, map[string]string{graph.AttrVia: graph.ViaTeam}),
			edge("identity:bob", "repo:acme/web", graph.CanPush, map[string]string{graph.AttrVia: graph.ViaOutsideCollaborator, "permission": "write"}),
		},
	}
	db := loadDB(t, g)
	rows := query(t, db, "SELECT identity_id || ' ' || identity_type || ' ' || COALESCE(CAST(is_org_member AS TEXT), 'NULL') || ' ' || is_outside_collaborator AS r FROM identities ORDER BY identity_id")
	var got []string
	for _, r := range rows {
		got = append(got, r["r"].(string))
	}
	want := []string{"identity:alice user 1 0", "identity:bob user 0 1", "team:acme/platform team NULL 0"}
	if !slices.Equal(got, want) {
		t.Errorf("identities:\n got %v\nwant %v", got, want)
	}
	got = nil
	for _, r := range query(t, db, "SELECT member_id || ' ' || group_kind || ' ' || COALESCE(role_name, '-') AS r FROM memberships ORDER BY member_id, group_id") {
		got = append(got, r["r"].(string))
	}
	want = []string{"identity:alice org member", "identity:alice team -"}
	if !slices.Equal(got, want) {
		t.Errorf("memberships:\n got %v\nwant %v", got, want)
	}
	got = nil
	for _, r := range query(t, db, "SELECT grantee_id || ' ' || via || ' ' || confirmed AS r FROM push_grants ORDER BY grantee_id") {
		got = append(got, r["r"].(string))
	}
	want = []string{"identity:bob outside_collaborator 1", "team:acme/platform team 1"}
	if !slices.Equal(got, want) {
		t.Errorf("push_grants:\n got %v\nwant %v", got, want)
	}
}
