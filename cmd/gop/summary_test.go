package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/schema"
	"github.com/peleduri/gop/internal/testutil"
)

// TestGoldenSummary goldens gop summary --demo with and without --names and
// checks both match the published schema.
func TestGoldenSummary(t *testing.T) {
	for golden, args := range map[string][]string{
		"summary_demo.json":       {"summary", "--demo", "--out", "-"},
		"summary_demo_names.json": {"summary", "--demo", "--names", "--out", "-"},
	} {
		t.Run(golden, func(t *testing.T) {
			r := runApp(t, nil, nil, args...)
			if r.code != exitOK || !strings.HasPrefix(r.stderr, "gop summary: ") {
				t.Fatalf("%v: %+v", args, r)
			}
			ps, err := schema.ValidateSummary([]byte(r.stdout))
			if err != nil || len(ps) > 0 {
				t.Fatalf("schema: %v %v", err, ps)
			}
			testutil.Golden(t, golden, []byte(r.stdout))
		})
	}
}

func TestSummaryFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "summary.json")
	r := runApp(t, nil, nil, "summary", "--graph", fixture, "--top", "2", "--out", out)
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	if !strings.Contains(r.stderr, "2 top findings, hash IDs only") {
		t.Errorf("stderr %q", r.stderr)
	}
}

func TestSummaryUsage(t *testing.T) {
	for _, args := range [][]string{
		{"summary", "--demo"},
		{"summary", "--out", "-"},
		{"summary", "--demo", "--graph", fixture, "--out", "-"},
		{"summary", "--demo", "--top", "0", "--out", "-"},
		{"summary", "--demo", "--top", "501", "--out", "-"},
		{"summary", "--demo", "--out", "-", "extra"},
	} {
		if r := runApp(t, nil, nil, args...); r.code != exitUsage {
			t.Errorf("%v: %+v", args, r)
		}
	}
}
