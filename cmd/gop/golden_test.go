package main

import (
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

// TestGoldenCLIText goldens the text output of gop who and gop paths.
func TestGoldenCLIText(t *testing.T) {
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"who.txt", []string{"who", "--graph", fixture, "--target", "repo:acme-app/web"}},
		{"paths.txt", []string{"paths", "--graph", fixture, "--from", "members:acme-actions"}},
		{"paths_to.txt", []string{"paths", "--graph", fixture, "--from", "members:acme-actions", "--to", "oidc:acme-app/web"}},
		{"paths_possible.txt", []string{"paths", "--graph", fixture, "--from", "members:acme-legacy"}},
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
