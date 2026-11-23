package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/oidc"
	"github.com/peleduri/gop/internal/schema"
	pub "github.com/peleduri/gop/schema"
)

const acmePath = "../../testdata/acme/graph.json"

func load(t *testing.T, path string) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func redact(t *testing.T, g *graph.Graph, salt string, keep ...string) *Result {
	t.Helper()
	res, err := Redact(g, Options{Salt: []byte(salt), KeepAttrs: keep})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func marshal(t *testing.T, g *graph.Graph) []byte {
	t.Helper()
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// enrichedAcme is testdata/acme with its trust files applied (cloud targets,
// supplied evidence).
func enrichedAcme(t *testing.T) *graph.Graph {
	t.Helper()
	g := load(t, acmePath)
	dir := filepath.Join("..", "..", "testdata", "acme", "trust")
	files, err := oidc.TrustFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := oidc.Parse(oidc.Options{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	oidc.Enrich(g, res.Trusts, files, res.Warnings)
	return g
}

// testGraphs are the graphs the invariants run on.
func testGraphs(t *testing.T) map[string]*graph.Graph {
	t.Helper()
	gs := map[string]*graph.Graph{
		"acme":          load(t, acmePath),
		"acme-enriched": enrichedAcme(t),
		"demo-small":    demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}),
		"demo-medium":   demo.Generate(demo.Options{Seed: 7, Size: demo.SizeMedium}),
	}
	files, err := filepath.Glob(filepath.Join("..", "schema", "testdata", "valid", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("schema fixtures: %v", err)
	}
	for _, f := range files {
		gs["schema/"+filepath.Base(f)] = load(t, f)
	}
	return gs
}

// reachSignature is every scoring principal's counts and scores, without
// its name, sorted: equal signatures mean equal reach results.
func reachSignature(g *graph.Graph) []string {
	ix := graph.NewIndex(g)
	var out []string
	for _, s := range ix.TopPaths(0) {
		out = append(out, fmt.Sprintf("%+v %+v x%.2f %.2f %.2f", s.Confirmed, s.Possible, s.Multiplier, s.Score, s.PossibleScore))
	}
	sort.Strings(out)
	return out
}

func pairTotals(g *graph.Graph) (confirmed, possible int, top float64) {
	ix := graph.NewIndex(g)
	scores := ix.TopPaths(0)
	for _, s := range scores {
		confirmed += s.Confirmed.Repos
		possible += s.Possible.Repos
	}
	if len(scores) > 0 {
		top = scores[0].Score
	}
	return confirmed, possible, top
}

func TestReachUnchanged(t *testing.T) {
	for name, g := range testGraphs(t) {
		t.Run(name, func(t *testing.T) {
			res := redact(t, g, "salt-one")
			out := res.Graph
			if len(out.Nodes) != len(g.Nodes) || len(out.Edges) != len(g.Edges) || len(out.Coverage) != len(g.Coverage) {
				t.Fatalf("shape changed: %d/%d/%d nodes/edges/coverage, want %d/%d/%d",
					len(out.Nodes), len(out.Edges), len(out.Coverage), len(g.Nodes), len(g.Edges), len(g.Coverage))
			}
			ids := map[string]bool{}
			for _, n := range out.Nodes {
				if ids[n.ID] {
					t.Fatalf("two nodes redact to %s", n.ID)
				}
				ids[n.ID] = true
			}
			c1, p1, top1 := pairTotals(g)
			c2, p2, top2 := pairTotals(out)
			if c1 != c2 || p1 != p2 || top1 != top2 {
				t.Errorf("pairs/top score = %d/%d/%.2f, want %d/%d/%.2f", c2, p2, top2, c1, p1, top1)
			}
			want, got := reachSignature(g), reachSignature(out)
			if strings.Join(want, "\n") != strings.Join(got, "\n") {
				t.Errorf("reach signature changed:\n got %v\nwant %v", got, want)
			}
			if len(graph.NewIndex(out).PinnedExposures()) != len(graph.NewIndex(g).PinnedExposures()) {
				t.Error("pinned exposures changed")
			}
			v, err := schema.Validate(marshal(t, out))
			if err != nil {
				t.Fatal(err)
			}
			if !v.Valid {
				t.Errorf("redacted graph does not validate: %v", v.Errors)
			}
			orig, err := schema.Validate(marshal(t, g))
			if err != nil {
				t.Fatal(err)
			}
			if len(v.Warnings) != len(orig.Warnings) {
				t.Errorf("validate warnings = %d, want %d: %v", len(v.Warnings), len(orig.Warnings), v.Warnings)
			}
		})
	}
}

func TestNoOriginalNames(t *testing.T) {
	g := enrichedAcme(t)
	res := redact(t, g, "salt-one")
	out := strings.ToLower(string(marshal(t, res.Graph)))
	for _, name := range []string{"acme-actions", "acme-app", "acme-secure", "acme-legacy", "alice", "bob",
		"old-api", "billing", "gateway", "release.yml", "nightly.yml", "ci.yml", "\"prod\"", "111111111111", "trust/aws"} {
		if strings.Contains(out, name) {
			t.Errorf("redacted graph contains %q", name)
		}
	}
	if res.Graph.Enterprise != "acme-enterprise" {
		t.Errorf("enterprise = %q", res.Graph.Enterprise)
	}
	if res.Mapping[CatOrg]["acme-app"] == "" || res.Mapping[CatUser]["alice"] == "" {
		t.Errorf("mapping misses names: %v", res.Mapping)
	}
}

func TestDeterministic(t *testing.T) {
	g := load(t, acmePath)
	a := marshal(t, redact(t, g, "salt-one").Graph)
	b := marshal(t, redact(t, g, "salt-one").Graph)
	if !bytes.Equal(a, b) {
		t.Fatal("same salt gave different output")
	}
	c := redact(t, g, "salt-two")
	if bytes.Equal(a, marshal(t, c.Graph)) {
		t.Fatal("different salt gave the same output")
	}
	m1, m2 := redact(t, g, "salt-one").Mapping, c.Mapping
	same := 0
	for real, fake := range m1[CatRepo] {
		if m2[CatRepo][real] == fake {
			same++
		}
	}
	if same == len(m1[CatRepo]) {
		t.Error("different salt gave the same repo names")
	}
}

func TestTimesShifted(t *testing.T) {
	g := load(t, acmePath)
	out := redact(t, g, "salt-one").Graph
	if out.CollectedAt.Equal(g.CollectedAt) {
		t.Error("collected_at not shifted")
	}
	d := g.CollectedAt.Sub(out.CollectedAt)
	if d < 24*time.Hour || d > 367*24*time.Hour {
		t.Errorf("offset = %v", d)
	}
	// One offset for every timestamp: relative times are kept.
	byKey := map[string]time.Time{}
	for _, e := range g.Edges {
		byKey[e.SourceAPI] = e.ObservedAt
	}
	for _, e := range out.Edges {
		if orig, ok := byKey[e.SourceAPI]; ok && !orig.IsZero() && orig.Sub(e.ObservedAt) != d {
			t.Fatalf("observed_at offset %v, want %v", orig.Sub(e.ObservedAt), d)
		}
	}
}

func TestSelfCheckFailsOnLeak(t *testing.T) {
	g := load(t, acmePath)
	for i := range g.Nodes {
		if g.Nodes[i].ID == "repo:acme-app/web" {
			g.Nodes[i].Attrs = map[string]string{"visibility": "private", "note": "ask alice_x about it"}
		}
	}
	// Unknown attrs are dropped by default, so nothing leaks.
	res := redact(t, g, "salt-one")
	if res.Dropped["note"] != 1 {
		t.Errorf("dropped = %v", res.Dropped)
	}
	// Kept with --keep-attr: the name glued to other text is not rewritten
	// and the self-check must catch it.
	_, err := Redact(g, Options{Salt: []byte("salt-one"), KeepAttrs: []string{"note"}})
	var leak *LeakError
	if !errors.As(err, &leak) {
		t.Fatalf("err = %v, want a leak", err)
	}
	if leak.Count != 1 || len(leak.Locations) != 1 || !strings.HasSuffix(leak.Locations[0], ".attrs.note") {
		t.Errorf("leak = %+v", leak)
	}
	if strings.Contains(strings.ToLower(err.Error()), "alice") {
		t.Errorf("error names the leaked name: %v", err)
	}
	// A plain word is rewritten, so the same attr passes.
	g2 := load(t, acmePath)
	for i := range g2.Nodes {
		if g2.Nodes[i].ID == "repo:acme-app/web" {
			g2.Nodes[i].Attrs = map[string]string{"note": "ask alice about acme-app/web."}
		}
	}
	res2 := redact(t, g2, "salt-one", "note")
	for _, n := range res2.Graph.Nodes {
		if v := n.Attrs["note"]; v != "" {
			want := "ask " + res2.Mapping[CatUser]["alice"] + " about " + res2.Mapping[CatRepo]["acme-app/web"] + "."
			if v != want {
				t.Errorf("note = %q, want %q", v, want)
			}
		}
	}
}

func TestCoverageRewritten(t *testing.T) {
	g := load(t, filepath.Join("..", "schema", "testdata", "valid", "teams.json"))
	res := redact(t, g, "salt-one")
	for _, c := range res.Graph.Coverage {
		s := strings.ToLower(c.Scope + c.Fact + c.Reason + c.NeedsFix)
		if strings.Contains(s, "platform") || strings.Contains(s, "acme-actions") {
			t.Errorf("coverage = %+v", c)
		}
	}
}

func TestCaseVariants(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme", CollectedAt: ts,
		Nodes: []graph.Node{
			{ID: "repo:acme-actions/deploy", Kind: graph.KindRepo, Name: "deploy", Evidence: graph.Live},
			{ID: "action:acme-actions/deploy@main", Kind: graph.KindActionRef, Evidence: graph.Live},
			{ID: "action:Acme-Actions/Deploy@main", Kind: graph.KindActionRef, Evidence: graph.Live},
		},
		Edges: []graph.Edge{{From: "action:Acme-Actions/Deploy@main", To: "repo:acme-actions/deploy", Kind: graph.ResolvesTo,
			Evidence: graph.Live, SourceAPI: "rest:repos.get", ObservedAt: ts}},
	}
	out := redact(t, g, "salt-one").Graph
	var actions []string
	for _, n := range out.Nodes {
		if n.Kind == graph.KindActionRef {
			actions = append(actions, n.ID)
		}
	}
	if len(actions) != 2 || actions[0] == actions[1] || !strings.EqualFold(actions[0], actions[1]) {
		t.Errorf("case variants = %v, want distinct and equal ignoring case", actions)
	}
}

func TestCartographyAttrs(t *testing.T) {
	g := enrichedAcme(t)
	var orig string
	for i, e := range g.Edges {
		if e.Kind == graph.CanAssume {
			g.Edges[i].Attrs[graph.AttrSource] = graph.SourceCartography
			g.Edges[i].Attrs[graph.AttrObservedUse] = "true"
			g.Edges[i].Attrs[graph.AttrTimesUsed] = "42"
			g.Edges[i].Attrs[graph.AttrLastUsed] = "2026-11-20T08:00:00Z"
			orig = g.Edges[i].Attrs[graph.AttrLastUsed]
			break
		}
	}
	res := redact(t, g, "salt-one")
	want := mustTime(t, orig).Add(redactOffset(t, g, res)).Format(time.RFC3339)
	found := false
	for _, e := range res.Graph.Edges {
		if e.Attrs[graph.AttrObservedUse] != "true" {
			continue
		}
		found = true
		if e.Attrs[graph.AttrSource] != graph.SourceCartography || e.Attrs[graph.AttrTimesUsed] != "20" || e.Attrs[graph.AttrLastUsed] != want {
			t.Errorf("attrs = %v, want last_used %s", e.Attrs, want)
		}
	}
	if !found {
		t.Fatal("observed_use edge missing")
	}
	if v, err := schema.Validate(marshal(t, res.Graph)); err != nil || !v.Valid {
		t.Errorf("validate: %v %+v", err, v)
	}
	for _, in := range []string{"1700000000", "1700000000000", "2026-11-20"} {
		if _, _, ok := timeAttr(&redactor{offset: -time.Hour * 48}, attrCtx{}, in); !ok {
			t.Errorf("timeAttr(%s) dropped", in)
		}
	}
	if _, _, ok := timeAttr(&redactor{}, attrCtx{}, "last tuesday"); ok {
		t.Error("timeAttr kept an unparsed value")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// redactOffset is the shift applied to collected_at.
func redactOffset(t *testing.T, g *graph.Graph, res *Result) time.Duration {
	t.Helper()
	return res.Graph.CollectedAt.Sub(g.CollectedAt)
}

func TestBucket(t *testing.T) {
	for in, want := range map[string]string{"0": "0", "1": "1", "3": "2", "7": "5", "12": "10", "40": "20", "120": "100",
		"75": "50", "999": "500", "1000": "1000", "unknown": "unknown"} {
		if got, _, ok := bucket(nil, attrCtx{}, in); !ok || got != want {
			t.Errorf("bucket(%s) = %q, want %q", in, got, want)
		}
	}
	if _, _, ok := bucket(nil, attrCtx{}, "many"); ok {
		t.Error("bucket accepted a non-number")
	}
}

func TestRefsKeepKind(t *testing.T) {
	g := load(t, acmePath)
	out := redact(t, g, "salt-one").Graph
	seen := map[string]bool{}
	for _, n := range out.Nodes {
		if n.Kind != graph.KindActionRef {
			continue
		}
		ref := refOf(n.ID)
		switch n.Attrs[graph.AttrRefKind] {
		case "sha":
			if len(ref) != 40 || !hexRe.MatchString(ref) {
				t.Errorf("sha ref %q", ref)
			}
		case "tag":
			if !strings.HasPrefix(ref, "v1.") {
				t.Errorf("tag ref %q", ref)
			}
		case "branch":
			if !strings.HasPrefix(ref, "branch-") {
				t.Errorf("branch ref %q", ref)
			}
		}
		seen[n.Attrs[graph.AttrRefKind]] = true
	}
	if len(seen) != 3 {
		t.Errorf("ref kinds = %v", seen)
	}
}

// TestDefaultAttrsInSync fails when types.go or the JSON Schema gains an attr
// key the redaction does not keep, or a kept key has no policy.
func TestDefaultAttrsInSync(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "graph", "types.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, id := range vs.Names {
			if !strings.HasPrefix(id.Name, "Attr") || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			k, _ := strconv.Unquote(lit.Value)
			if !DefaultAttrs[k] {
				t.Errorf("types.go %s = %q is not in DefaultAttrs", id.Name, k)
			}
		}
		return true
	})
	var doc struct {
		Defs map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(pub.GraphV1, &doc); err != nil {
		t.Fatal(err)
	}
	for _, def := range []string{"NodeAttrs", "EdgeAttrs"} {
		for k := range doc.Defs[def].Properties {
			if !DefaultAttrs[k] {
				t.Errorf("schema %s.%s is not in DefaultAttrs", def, k)
			}
		}
	}
	for k := range DefaultAttrs {
		if policies[k] == nil {
			t.Errorf("default attr %q has no policy", k)
		}
	}
}

func TestErrors(t *testing.T) {
	if _, err := Redact(nil, Options{Salt: []byte("x")}); err == nil {
		t.Error("nil graph accepted")
	}
	if _, err := Redact(&graph.Graph{}, Options{}); err == nil {
		t.Error("empty salt accepted")
	}
}
