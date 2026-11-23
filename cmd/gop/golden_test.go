package main

import (
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
