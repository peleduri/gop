package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

func load(t *testing.T, name string) (*graph.Graph, *graph.Graph) {
	t.Helper()
	o, err := graph.LoadFile(filepath.Join("testdata", name, "old.json"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := graph.LoadFile(filepath.Join("testdata", name, "new.json"))
	if err != nil {
		t.Fatal(err)
	}
	return o, n
}

func compare(t *testing.T, o, n *graph.Graph) Report {
	t.Helper()
	r, err := Compare(o, n)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type pc struct{ status, principal, target string }

func pathSummary(r Report) []pc {
	out := []pc{}
	for _, c := range r.Paths {
		out = append(out, pc{c.Status, c.Principal, c.Target})
	}
	return out
}

func TestCases(t *testing.T) {
	for _, tc := range []struct {
		name         string
		paths        []pc
		settings     []string // "node key status"
		confirmedOld int
		confirmedNew int
	}{
		{name: "identical", paths: []pc{}, settings: []string{}, confirmedOld: 3, confirmedNew: 3},
		{
			name: "ref-unpinned",
			paths: []pc{
				{Added, "identity:bob", "oidc:acme-app/web"},
				{Added, "identity:bob", "repo:acme-app/web"},
			},
			settings:     []string{"action:acme-actions/deploy@main ref_kind node_added"},
			confirmedOld: 3, confirmedNew: 4,
		},
		{
			name: "default-perm-raised",
			paths: []pc{
				{Added, "members:acme-actions", "secret:acme-app/api"},
				{Added, "members:acme-actions", "repo:acme-actions/deploy"},
				{Added, "members:acme-actions", "repo:acme-app/api"},
			},
			settings:     []string{"org:acme-actions default_perm changed"},
			confirmedOld: 3, confirmedNew: 5,
		},
		{
			name: "lost-visibility",
			paths: []pc{
				{LostVisibility, "identity:bob", "secret:acme-app/api"},
				{LostVisibility, "identity:bob", "repo:acme-actions/deploy"},
				{LostVisibility, "identity:bob", "repo:acme-app/api"},
			},
			settings:     []string{"org:acme-actions two_factor lost_visibility"},
			confirmedOld: 3, confirmedNew: 1,
		},
		{
			name: "org-added",
			paths: []pc{
				{Added, "members:acme-legacy", "runner:acme-legacy/old-api"},
				{Added, "members:acme-legacy", "repo:acme-legacy/old-api"},
			},
			settings: []string{
				"org:acme-legacy default_perm node_added",
				"org:acme-legacy sso node_added",
				"org:acme-legacy two_factor node_added",
				"repo:acme-legacy/old-api visibility node_added",
			},
			confirmedOld: 3, confirmedNew: 4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, n := load(t, tc.name)
			r := compare(t, o, n)
			if got := pathSummary(r); !reflect.DeepEqual(got, tc.paths) {
				t.Errorf("paths:\n got %v\nwant %v", got, tc.paths)
			}
			settings := []string{}
			for _, s := range r.Settings {
				settings = append(settings, s.Node+" "+s.Key+" "+s.Status)
			}
			if !reflect.DeepEqual(settings, tc.settings) {
				t.Errorf("settings:\n got %v\nwant %v", settings, tc.settings)
			}
			if r.Totals.Old.ConfirmedPairs != tc.confirmedOld || r.Totals.New.ConfirmedPairs != tc.confirmedNew {
				t.Errorf("confirmed pairs %d -> %d, want %d -> %d", r.Totals.Old.ConfirmedPairs, r.Totals.New.ConfirmedPairs, tc.confirmedOld, tc.confirmedNew)
			}
			for _, c := range r.Paths {
				if c.Status == Removed {
					t.Errorf("%s: unexpected removed path %s -> %s", tc.name, c.Principal, c.Target)
				}
			}
		})
	}
}

func TestIdenticalIsEmpty(t *testing.T) {
	o, _ := load(t, "identical")
	r := compare(t, o, o)
	if !r.Empty() {
		t.Fatalf("self diff not empty: %+v", r)
	}
	if h := r.Headline(); h != "Since 2026-11-13: no posture changes." {
		t.Errorf("headline = %q", h)
	}
}

func TestFixtureAgainstItself(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if r := compare(t, g, g); !r.Empty() {
		t.Fatalf("acme self diff not empty: %+v", r)
	}
}

// TestUsesRefKindFlip changes one USES edge ref_kind from sha to branch in place.
func TestUsesRefKindFlip(t *testing.T) {
	o, _ := load(t, "identical")
	n := clone(t, o)
	const sha = "action:acme-actions/deploy@3f2c9a8e1b7d4c6f0a5e9d8c7b6a5f4e3d2c1b0a"
	for i := range n.Nodes {
		if n.Nodes[i].ID == sha {
			delete(n.Nodes[i].Attrs, graph.AttrRefKind) // the edge attr decides
		}
	}
	for i, e := range n.Edges {
		if e.Kind == graph.Uses && e.To == sha {
			n.Edges[i].Attrs = map[string]string{graph.AttrRefKind: "branch"}
		}
	}
	r := compare(t, o, n)
	want := []pc{{Added, "identity:bob", "oidc:acme-app/web"}, {Added, "identity:bob", "repo:acme-app/web"}}
	if got := pathSummary(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for _, c := range r.Paths {
		if c.New == nil || c.New.Unverified {
			t.Errorf("%v: want a confirmed new path", c)
		}
	}
	if len(r.Edges.Changed) != 1 || r.Edges.Changed[0].Old.Attrs[graph.AttrRefKind] != "sha" || r.Edges.Changed[0].New.Attrs[graph.AttrRefKind] != "branch" {
		t.Errorf("edge change = %+v", r.Edges.Changed)
	}
}

func clone(t *testing.T, g *graph.Graph) *graph.Graph {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var out graph.Graph
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestRemovedAndDowngraded(t *testing.T) {
	o, _ := load(t, "identical")

	// Bob loses push and the new snapshot sees everything: a real removal.
	n := clone(t, o)
	var kept []graph.Edge
	for _, e := range n.Edges {
		if e.From == "identity:bob" && e.Kind == graph.CanPush {
			continue
		}
		kept = append(kept, e)
	}
	n.Edges = kept
	r := compare(t, o, n)
	if len(r.Paths) != 3 || r.Paths.Count(Removed, false) != 3 {
		t.Fatalf("want 3 removed paths, got %v", pathSummary(r))
	}
	if len(r.Edges.Removed) != 1 || len(r.Edges.LostVisibility) != 0 {
		t.Errorf("edges = %+v", r.Edges)
	}

	// Bob's push edge becomes not_visible: confirmed -> possible, not a fix.
	n = clone(t, o)
	for i, e := range n.Edges {
		if e.From == "identity:bob" && e.Kind == graph.CanPush {
			n.Edges[i].Evidence = graph.NotVisible
		}
	}
	r = compare(t, o, n)
	if len(r.Paths) != 3 || r.Paths.Count(Downgraded, false) != 3 {
		t.Fatalf("want 3 downgraded paths, got %v", pathSummary(r))
	}
	if len(r.Edges.LostVisibility) != 1 || r.Edges.LostVisibility[0].Status != LostVisibility {
		t.Errorf("edge lost visibility = %+v", r.Edges)
	}
	if !strings.Contains(r.Headline(), "3 downgraded to possible") {
		t.Errorf("headline = %q", r.Headline())
	}

	// And back: possible -> confirmed.
	r = compare(t, n, o)
	if r.Paths.Count(Upgraded, false) != 3 {
		t.Fatalf("want 3 upgraded paths, got %v", pathSummary(r))
	}
	if !strings.Contains(r.Headline(), "Since 2026-11-13: 3 new confirmed paths.") {
		t.Errorf("headline = %q", r.Headline())
	}
}

func TestLostVisibilityNeverOff(t *testing.T) {
	o, n := load(t, "lost-visibility")
	r := compare(t, o, n)
	var s *SettingChange
	for i := range r.Settings {
		if r.Settings[i].Key == graph.AttrTwoFactor {
			s = &r.Settings[i]
		}
	}
	if s == nil || s.Status != LostVisibility || s.Old != "required" || s.OldEvidence != graph.Live || s.NewEvidence != graph.NotVisible {
		t.Fatalf("two_factor change = %+v", s)
	}
	var buf bytes.Buffer
	WriteText(&buf, r)
	out := buf.String()
	for _, want := range []string{"two_factor required → not visible (lost visibility)", "evidence live → not visible", "3 lost visibility"} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{" off", "removed", "turned off"} {
		if strings.Contains(out, bad) {
			t.Errorf("text contains %q:\n%s", bad, out)
		}
	}

	// A value of not_visible on a node that is otherwise live is also lost visibility.
	n2 := clone(t, o)
	for i := range n2.Nodes {
		if n2.Nodes[i].ID == "org:acme-app" {
			n2.Nodes[i].Attrs[graph.AttrSSO] = string(graph.NotVisible)
		}
	}
	r = compare(t, o, n2)
	if len(r.Settings) != 1 || r.Settings[0].Status != LostVisibility || r.Settings[0].Key != graph.AttrSSO {
		t.Fatalf("settings = %+v", r.Settings)
	}
	// And the reverse is gained visibility, not a change.
	r = compare(t, n2, o)
	if len(r.Settings) != 1 || r.Settings[0].Status != GainedVisibility {
		t.Fatalf("settings = %+v", r.Settings)
	}
}

func TestRefusesDifferentEnterprise(t *testing.T) {
	o, _ := load(t, "identical")
	n := clone(t, o)
	n.Enterprise = "acme-other"
	_, err := Compare(o, n)
	if !errors.Is(err, ErrEnterpriseMismatch) || !strings.Contains(err.Error(), `"acme" vs "acme-other"`) || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v", err)
	}
	if _, err := CompareWith(o, n, Options{Force: true}); err != nil {
		t.Fatalf("forced: %v", err)
	}
	n = clone(t, o)
	n.Schema = "gop.graph/v3"
	if _, err := Compare(o, n); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("schema err = %v", err)
	}
	n.Schema = graph.SchemaVersion + ".3"
	if _, err := Compare(o, n); err != nil {
		t.Fatalf("minor schema bump refused: %v", err)
	}
	if _, err := Compare(nil, o); err == nil {
		t.Fatal("nil graph accepted")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	for _, name := range []string{"identical", "ref-unpinned", "default-perm-raised", "lost-visibility", "org-added"} {
		o, n := load(t, name)
		r := compare(t, o, n)
		var buf bytes.Buffer
		if err := WriteJSON(&buf, r); err != nil {
			t.Fatal(err)
		}
		var back Report
		if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(r, back) {
			t.Errorf("%s: round trip differs", name)
		}
	}
}

func TestDeterministic(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	// Reverse slices: ordering must not depend on input position.
	n := clone(t, g)
	for i, j := 0, len(n.Nodes)-1; i < j; i, j = i+1, j-1 {
		n.Nodes[i], n.Nodes[j] = n.Nodes[j], n.Nodes[i]
	}
	for i, j := 0, len(n.Edges)-1; i < j; i, j = i+1, j-1 {
		n.Edges[i], n.Edges[j] = n.Edges[j], n.Edges[i]
	}
	empty := clone(t, g)
	empty.Nodes, empty.Edges = nil, nil
	var first string
	for i := 0; i < 5; i++ {
		for _, pair := range [][2]*graph.Graph{{empty, g}, {empty, n}} {
			r := compare(t, pair[0], pair[1])
			var buf bytes.Buffer
			WriteText(&buf, r)
			if first == "" {
				first = buf.String()
			} else if buf.String() != first {
				t.Fatal("output differs between runs or input orderings")
			}
		}
	}
	// Status, then severity (oidc > secret > runner > repo), then IDs.
	r := compare(t, empty, g)
	for i := 1; i < len(r.Paths); i++ {
		a, b := r.Paths[i-1], r.Paths[i]
		if pathStatusOrder[a.Status] == pathStatusOrder[b.Status] && severity(a.TargetKind) > severity(b.TargetKind) {
			t.Fatalf("order: %v before %v", a, b)
		}
	}
	if r.Paths[0].TargetKind != graph.KindOIDC {
		t.Errorf("first change targets %s, want oidc", r.Paths[0].TargetKind)
	}
}

func TestOnlyAndMarkdown(t *testing.T) {
	o, n := load(t, "default-perm-raised")
	r := compare(t, o, n).Only([]string{SectionSettings})
	if len(r.Paths) != 0 || len(r.Scores) != 0 || len(r.Settings) != 1 || len(r.Edges.Added) != 0 {
		t.Fatalf("only settings: %+v", r)
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, compare(t, o, n))
	md := buf.String()
	for _, want := range []string{"# gop posture drift", "acme-actions default_perm read → write", "| Confirmed (principal, repo) pairs | 3 | 5 | +2 |", "## Paths", "## Scores"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

// TestFixturesValidate keeps the hand-built snapshots valid against the published JSON Schema.
func TestFixturesValidate(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		res, err := schema.Validate(b)
		if err != nil || !res.Valid || len(res.Warnings) > 0 {
			t.Errorf("%s: err %v, result %+v", f, err, res)
		}
	}
}
