package mcpserver

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

var diffCases = []string{"default-perm-raised", "identical", "lost-visibility", "org-added", "ref-unpinned"}

// loadPair loads internal/diff/testdata/<name>/{old,new}.json.
func loadPair(t *testing.T, name string) (old, cur *graph.Graph) {
	t.Helper()
	dir := filepath.Join("..", "diff", "testdata", name)
	old, err := graph.LoadFile(filepath.Join(dir, "old.json"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err = graph.LoadFile(filepath.Join(dir, "new.json"))
	if err != nil {
		t.Fatal(err)
	}
	return old, cur
}

func connectDiff(t *testing.T, name string) *mcp.ClientSession {
	t.Helper()
	old, cur := loadPair(t, name)
	return connectServer(t, NewServerWith(cur, "test", ServerOptions{Baseline: old}))
}

func reportJSON(t *testing.T, r diff.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := diff.WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestDiffMatchesCLI checks that the tool returns the same report as
// gop diff OLD NEW --format json (diff.Compare rendered by diff.WriteJSON).
func TestDiffMatchesCLI(t *testing.T) {
	for _, name := range diffCases {
		t.Run(name, func(t *testing.T) {
			old, cur := loadPair(t, name)
			want, err := diff.Compare(old, cur)
			if err != nil {
				t.Fatal(err)
			}
			var out DiffOutput
			res := call(t, connectDiff(t, name), "diff", map[string]any{"limit": 1000}, &out)
			if got, w := reportJSON(t, out.Report), reportJSON(t, want); got != w {
				t.Errorf("report differs from gop diff --format json:\n%s", testutil.UnifiedDiff(w, got))
			}
			if out.Truncated {
				t.Error("truncated with a limit above every list length")
			}
			if out.Summary != want.Headline() || !strings.HasPrefix(text(res), want.Headline()+"\n") {
				t.Errorf("summary %q, want the CLI lead line %q", out.Summary, want.Headline())
			}
			if !out.BaselineCollectedAt.Equal(old.CollectedAt) || !out.CurrentCollectedAt.Equal(cur.CollectedAt) {
				t.Errorf("collected_at %v → %v, want %v → %v", out.BaselineCollectedAt, out.CurrentCollectedAt, old.CollectedAt, cur.CollectedAt)
			}
		})
	}
}

func TestDiffFilters(t *testing.T) {
	cs := connectDiff(t, "ref-unpinned")
	var all DiffOutput
	call(t, cs, "diff", map[string]any{}, &all)
	if len(all.Report.Paths) < 2 {
		t.Fatalf("fixture has %d path changes, want at least 2", len(all.Report.Paths))
	}

	var oidc DiffOutput
	call(t, cs, "diff", map[string]any{"target_kind": "oidc"}, &oidc)
	if len(oidc.Report.Paths) == 0 {
		t.Fatal("target_kind=oidc kept no paths")
	}
	for _, c := range oidc.Report.Paths {
		if c.TargetKind != graph.KindOIDC {
			t.Errorf("target_kind=oidc kept %s -> %s (%s)", c.Principal, c.Target, c.TargetKind)
		}
	}
	if oidc.Summary != all.Summary {
		t.Errorf("filtered summary %q, want the full lead line %q", oidc.Summary, all.Summary)
	}

	var bob DiffOutput
	call(t, cs, "diff", map[string]any{"principal": "identity:bob"}, &bob)
	if len(bob.Report.Paths) == 0 {
		t.Fatal("principal=identity:bob kept no paths")
	}
	for _, c := range bob.Report.Paths {
		if c.Principal != "identity:bob" {
			t.Errorf("principal filter kept %s", c.Principal)
		}
	}
	for _, s := range bob.Report.Scores {
		if s.Principal != "identity:bob" {
			t.Errorf("principal filter kept score of %s", s.Principal)
		}
	}
	for _, e := range append(bob.Report.Edges.Added, bob.Report.Edges.Removed...) {
		if e.From != "identity:bob" && e.To != "identity:bob" {
			t.Errorf("principal filter kept edge %s -> %s", e.From, e.To)
		}
	}

	var none DiffOutput
	call(t, cs, "diff", map[string]any{"principal": "members:acme-legacy"}, &none)
	if len(none.Report.Paths) != 0 || len(none.Report.Scores) != 0 {
		t.Errorf("principal with no changes kept %d paths, %d scores", len(none.Report.Paths), len(none.Report.Scores))
	}

	var only DiffOutput
	call(t, cs, "diff", map[string]any{"only": []string{"scores"}}, &only)
	if len(only.Report.Paths) != 0 || len(only.Report.Scores) != len(all.Report.Scores) {
		t.Errorf("only=scores kept %d paths and %d/%d scores", len(only.Report.Paths), len(only.Report.Scores), len(all.Report.Scores))
	}
}

func TestDiffLimitTruncates(t *testing.T) {
	cs := connectDiff(t, "default-perm-raised")
	var all DiffOutput
	call(t, cs, "diff", map[string]any{}, &all)
	if all.Truncated || len(all.Report.Paths) < 2 {
		t.Fatalf("default limit: truncated=%v with %d paths", all.Truncated, len(all.Report.Paths))
	}
	var one DiffOutput
	call(t, cs, "diff", map[string]any{"limit": 1}, &one)
	if !one.Truncated {
		t.Error("limit 1 did not set truncated")
	}
	if len(one.Report.Paths) != 1 || one.Report.Paths[0].Target != all.Report.Paths[0].Target {
		t.Errorf("limit 1 kept %d paths, want the first of %d", len(one.Report.Paths), len(all.Report.Paths))
	}
	for name, n := range map[string]int{"settings": len(one.Report.Settings), "scores": len(one.Report.Scores),
		"edges.added": len(one.Report.Edges.Added), "coverage.opened": len(one.Report.Coverage.Opened)} {
		if n > 1 {
			t.Errorf("limit 1 kept %d %s", n, name)
		}
	}
}

func TestDiffErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		cs   func(t *testing.T) *mcp.ClientSession
		args map[string]any
		want string
	}{
		{"no baseline", connect, map[string]any{}, "--baseline"},
		{"bad section", func(t *testing.T) *mcp.ClientSession { return connectDiff(t, "identical") },
			map[string]any{"only": []string{"nodes"}}, `unknown section "nodes"`},
		{"bad target kind", func(t *testing.T) *mcp.ClientSession { return connectDiff(t, "identical") },
			map[string]any{"target_kind": "workflow"}, "target_kind must be"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.cs(t).CallTool(context.Background(), &mcp.CallToolParams{Name: "diff", Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if !res.IsError || !strings.Contains(text(res), tc.want) {
				t.Fatalf("want tool error containing %q, got error=%v %q", tc.want, res.IsError, text(res))
			}
		})
	}
	// Snapshots of different enterprises are refused, as gop diff does without --force.
	old, cur := loadPair(t, "identical")
	other := *old
	other.Enterprise = "acme-other"
	cs := connectServer(t, NewServerWith(cur, "test", ServerOptions{Baseline: &other}))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "diff", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "different enterprises") {
		t.Fatalf("want enterprise mismatch error, got %q", text(res))
	}
}

// TestGoldenDiffText goldens the full TextContent of the diff tool.
func TestGoldenDiffText(t *testing.T) {
	for _, tc := range []struct {
		golden, pair string
		args         map[string]any
	}{
		{"diff.txt", "default-perm-raised", map[string]any{}},
		{"diff_filtered.txt", "ref-unpinned", map[string]any{"principal": "identity:bob", "target_kind": "oidc", "only": []string{"paths", "scores"}}},
		{"diff_lost_visibility.txt", "lost-visibility", map[string]any{"limit": 1}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			res, err := connectDiff(t, tc.pair).CallTool(context.Background(), &mcp.CallToolParams{Name: "diff", Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("tool error: %s", text(res))
			}
			testutil.Golden(t, tc.golden, []byte(text(res)))
		})
	}
}
