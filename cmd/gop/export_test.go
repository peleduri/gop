package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

const cloudFixture = "../../internal/schema/testdata/valid/cloud-target.json"

func TestGoldenExportCypher(t *testing.T) {
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"export_demo.cypher", []string{"export", "--format", "cypher", "--demo"}},
		{"export_cloud.cypher", []string{"export", "--format", "cypher", cloudFixture}},
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

func TestExportCypherForms(t *testing.T) {
	want := runApp(t, nil, nil, "export", fixture).stdout
	if !strings.Contains(want, "MERGE (n:GopNode") {
		t.Fatalf("export: %q", want)
	}
	if got := runApp(t, nil, nil, "export", "--graph", fixture, "--format", "CYPHER").stdout; got != want {
		t.Errorf("--graph form differs from the positional form")
	}
	out := filepath.Join(t.TempDir(), "gop.cypher")
	if r := runApp(t, nil, nil, "export", fixture, "--out", out); r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	data, err := os.ReadFile(out)
	if err != nil || string(data) != want {
		t.Errorf("--out file differs: %v", err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("--out mode: %v %v", fi, err)
	}
	ghe := runApp(t, nil, nil, "export", fixture, "--github-url", "https://ghe.acme.example").stdout
	if !strings.Contains(ghe, "target: 'https://ghe.acme.example/acme-app/web'") {
		t.Errorf("--github-url not used")
	}
}

func TestExportErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"export"}, exitUsage, "--graph is required"},
		{[]string{"export", "--format", "csv", fixture}, exitUsage, "--format must be cypher"},
		{[]string{"export", fixture, fixture}, exitUsage, "want one graph file"},
		{[]string{"export", "--graph", fixture, fixture}, exitUsage, "not both"},
		{[]string{"export", "--demo", fixture}, exitUsage, "use --graph or --demo"},
		{[]string{"export", fixture, "--github-url", "ftp://x"}, exitUsage, "--github-url"},
		{[]string{"export", fixture, "--out", ""}, exitUsage, "--out is required"},
		{[]string{"export", "nope.json"}, exitRuntime, "nope.json"},
	} {
		r := runApp(t, nil, nil, tc.args...)
		if r.code != tc.code || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v: code %d stderr %q, want %d and %q", tc.args, r.code, r.stderr, tc.code, tc.want)
		}
	}
}
