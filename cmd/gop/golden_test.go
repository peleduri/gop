package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

// TestGoldenCLIText goldens the text output of gop who, gop paths and gop validate.
func TestGoldenCLIText(t *testing.T) {
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"who.txt", []string{"who", "--graph", fixture, "--target", "repo:acme-app/web"}},
		{"paths.txt", []string{"paths", "--graph", fixture, "--from", "members:acme-actions"}},
		{"paths_to.txt", []string{"paths", "--graph", fixture, "--from", "members:acme-actions", "--to", "oidc:acme-app/web"}},
		{"paths_possible.txt", []string{"paths", "--graph", fixture, "--from", "members:acme-legacy"}},
		{"validate.txt", []string{"validate", "--graph", fixture}},
		{"validate_warnings.txt", []string{"validate", "--graph", "../../internal/schema/testdata/valid/uncovered.json"}},
		{"validate_warnings.json", []string{"validate", "--graph", "../../internal/schema/testdata/valid/uncovered.json", "--format", "json"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			r := runApp(t, nil, nil, tc.args...)
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%v: %+v", tc.args, r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

// TestGoldenDemo goldens gop demo --size small and gop report --demo --format md,
// and checks the demo graph passes gop validate with no warnings.
func TestGoldenDemo(t *testing.T) {
	d := runApp(t, nil, nil, "demo", "--size", "small", "--seed", "1")
	if d.code != exitOK {
		t.Fatalf("demo: %+v", d)
	}
	testutil.Golden(t, "demo_small.json", []byte(d.stdout))
	r := runApp(t, nil, nil, "report", "--demo", "--format", "md", "--out", "-")
	if r.code != exitOK || r.stderr != "" {
		t.Fatalf("report --demo: %+v", r)
	}
	testutil.Golden(t, "report_demo.md", []byte(r.stdout))

	path := filepath.Join(t.TempDir(), "demo.json")
	if err := os.WriteFile(path, []byte(d.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	v := runApp(t, nil, nil, "validate", "--graph", path)
	if v.code != exitOK || !strings.Contains(v.stdout, ": valid (gop.graph/v1, 0 errors, 0 warnings)") {
		t.Fatalf("validate demo: %+v", v)
	}
}
