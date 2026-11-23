package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/testutil"
)

const (
	awsDeploy = "cloud:aws:arn:aws:iam::111111111111:role/deploy"
	azureWeb  = "cloud:azure:app:11111111-1111-1111-1111-111111111111"
)

// enrichAcme runs gop enrich on testdata/acme with testdata/acme/trust from
// the repo root (so graph.json records repo-relative trust file paths) and
// returns the output path.
func enrichAcme(t *testing.T, in string) (out string, r result) {
	t.Helper()
	out = filepath.Join(t.TempDir(), "enriched.json")
	t.Run("enrich", func(t *testing.T) {
		t.Chdir(filepath.Join("..", ".."))
		r = runApp(t, nil, nil, "enrich", "--graph", in, "--oidc-trust", "testdata/acme/trust", "--out", out)
	})
	if r.code != exitOK {
		t.Fatalf("enrich: %+v", r)
	}
	return out, r
}

func TestEnrichEndToEnd(t *testing.T) {
	out, r := enrichAcme(t, "testdata/acme/graph.json")
	if !strings.Contains(r.stderr, "1 confirmed and 5 possible paths into 4 cloud targets") ||
		!strings.Contains(r.stderr, "not from the cloud") {
		t.Errorf("stderr = %q", r.stderr)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// Same inputs again: byte-identical.
	out2, _ := enrichAcme(t, "testdata/acme/graph.json")
	second, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("gop enrich twice on the same inputs differs")
	}
	// Enriching the enriched graph with the same files replaces its edges.
	out3, _ := enrichAcme(t, out)
	third, err := os.ReadFile(out3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Error("re-enriching an enriched graph with the same files changed it")
	}

	v := runApp(t, nil, nil, "validate", "--graph", out)
	if v.code != exitOK || !strings.Contains(v.stdout, "valid (gop.graph/v1, 0 errors, 0 warnings)") {
		t.Errorf("validate: %+v", v)
	}

	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"enrich_who_aws.txt", []string{"who", "--graph", out, "--target", awsDeploy}},
		{"enrich_paths_azure.txt", []string{"paths", "--graph", out, "--from", "members:acme-actions", "--to", azureWeb}},
		{"enrich_report.md", []string{"report", "--graph", out, "--format", "md", "--out", "-", "--top", "3"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			r := runApp(t, nil, nil, tc.args...)
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%v: %+v", tc.args, r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout), version)
		})
	}

	// MCP: blast_radius and who_can_reach show cloud reach, confirmed and
	// possible apart, with the supplied-file caveat.
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	e := mcpserver.NewEngine(g)
	br, err := e.BlastRadius(mcpserver.BlastRadiusInput{Principal: "members:acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	if br.Score.Confirmed.CloudTargets != 1 || len(br.Possible.CloudTargets) != 3 ||
		!strings.Contains(br.Summary, "1 cloud role") ||
		!strings.Contains(br.Summary, "cloud hop from supplied trust file testdata/acme/trust/aws/deploy.json") {
		t.Errorf("blast_radius = %q confirmed %+v possible %v", br.Summary, br.Score.Confirmed, br.Possible.CloudTargets)
	}
	who, err := e.WhoCanReach(mcpserver.WhoCanReachInput{Target: awsDeploy})
	if err != nil {
		t.Fatal(err)
	}
	if len(who.Confirmed) != 2 || len(who.Possible) != 0 || !strings.Contains(who.Summary, "not read from the cloud") {
		t.Errorf("who_can_reach = %+v", who)
	}
	az, err := e.WhoCanReach(mcpserver.WhoCanReachInput{Target: azureWeb})
	if err != nil {
		t.Fatal(err)
	}
	if len(az.Confirmed) != 0 || len(az.Possible) == 0 {
		t.Errorf("azure who_can_reach must be possible only: %+v", az)
	}
}

func TestEnrichUsage(t *testing.T) {
	for _, args := range [][]string{
		{"enrich", "--graph", fixture, "--out", "-"},                               // no --oidc-trust
		{"enrich", "--graph", fixture, "--oidc-trust", "x"},                        // no --out
		{"enrich", "--oidc-trust", "x", "--out", "-"},                              // no --graph
		{"enrich", "--graph", fixture, "--oidc-trust", "x", "--out", "-", "extra"}, // positional
	} {
		if r := runApp(t, nil, nil, args...); r.code != exitUsage {
			t.Errorf("%v: code %d, want 2 (stderr %q)", args, r.code, r.stderr)
		}
	}
	r := runApp(t, nil, nil, "enrich", "--graph", fixture, "--oidc-trust", "does-not-exist", "--out", "-")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "--oidc-trust") {
		t.Errorf("missing trust path: %+v", r)
	}
}

func TestCollectWithOIDCTrust(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "test-token"}
	fake := func(context.Context, collect.Config) (*graph.Graph, error) { return graph.LoadFile(fixture) }
	out := filepath.Join(t.TempDir(), "g.json")
	r := runApp(t, env, fake, "collect", "--enterprise", "acme", "--out", out, "--oidc-trust", "../../testdata/acme/trust/aws")
	if r.code != exitOK {
		t.Fatalf("collect: %+v", r)
	}
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume && e.To == awsDeploy && e.Evidence == graph.Supplied {
			found = true
		}
	}
	if !found {
		t.Error("collect --oidc-trust did not add the CAN_ASSUME edge")
	}

	// An unreadable trust path fails before collection starts.
	r = runApp(t, env, nil, "collect", "--enterprise", "acme", "--out", out, "--oidc-trust", "does-not-exist")
	if r.code != exitUsage {
		t.Errorf("bad trust path: %+v", r)
	}
}

// TestCollectAppModeWithOIDCTrust: GitHub App mode and --oidc-trust work together.
func TestCollectAppModeWithOIDCTrust(t *testing.T) {
	keyFile := writeKey(t, 0o600)
	var got collect.Config
	fake := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		return graph.LoadFile(fixture)
	}
	out := filepath.Join(t.TempDir(), "g.json")
	r := runApp(t, nil, fake, "collect", "--enterprise", "acme", "--out", out,
		"--app-id", "4242", "--app-key-file", keyFile, "--oidc-trust", "../../testdata/acme/trust/aws")
	if r.code != exitOK {
		t.Fatalf("collect: %+v", r)
	}
	if got.AppID != 4242 || len(got.AppPrivateKeyPEM) == 0 || got.Token != "" {
		t.Errorf("config: app id %d, key set %v, token set %v", got.AppID, len(got.AppPrivateKeyPEM) > 0, got.Token != "")
	}
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume && e.To == awsDeploy && e.Evidence == graph.Supplied {
			return
		}
	}
	t.Error("collect in App mode with --oidc-trust did not add the CAN_ASSUME edge")
}
