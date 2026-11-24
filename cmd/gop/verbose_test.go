package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
)

func TestCollectVerbose(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		flag bool
		want bool
	}{
		{"default", "", false, false},
		{"flag", "", true, true},
		{"env 1", "1", false, true},
		{"env true", "TRUE", false, true},
		{"env 0", "0", false, false},
		{"env junk", "yes please", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got collect.Config
			fake := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
				got = cfg
				return graph.LoadFile(fixture)
			}
			args := []string{"collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json")}
			if tc.flag {
				args = append(args, "--verbose")
			}
			env := map[string]string{"GITHUB_TOKEN": "test-token-value-123", "GOP_VERBOSE": tc.env}
			if r := runApp(t, env, fake, args...); r.code != 0 {
				t.Fatalf("collect: %+v", r)
			}
			if got.Verbose != tc.want {
				t.Errorf("Verbose = %v, want %v", got.Verbose, tc.want)
			}
		})
	}
}
