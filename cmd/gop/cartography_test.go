package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// enrichRepoRoot runs gop enrich from the repo root, so graph.json records
// repo-relative input paths, and returns the output path and the result.
func enrichRepoRoot(t *testing.T, args ...string) (string, result) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "enriched.json")
	var r result
	t.Run("enrich", func(t *testing.T) {
		t.Chdir(filepath.Join("..", ".."))
		r = runApp(t, nil, nil, append([]string{"enrich", "--graph", "testdata/acme/graph.json", "--out", out}, args...)...)
	})
	if r.code != exitOK {
		t.Fatalf("enrich %v: %+v", args, r)
	}
	return out, r
}

// withoutSource clears what necessarily differs between enriching from a
// trust file and from a Cartography export: the input file and pointer, the
// source_api naming the file, and the source attr.
func withoutSource(t *testing.T, path string) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind == graph.CanAssume {
			for _, k := range []string{graph.AttrFile, graph.AttrPointer, graph.AttrSource} {
				delete(e.Attrs, k)
			}
			e.SourceAPI = ""
		}
	}
	for i := range g.Nodes {
		delete(g.Nodes[i].Attrs, graph.AttrSource)
	}
	return g
}

// TestEnrichCartographyEqualsTrustFile: a Cartography export of the deploy
// role's trust gives the same graph as its trust policy file.
func TestEnrichCartographyEqualsTrustFile(t *testing.T) {
	viaFile, _ := enrichRepoRoot(t, "--oidc-trust", "testdata/acme/trust/aws/deploy.json")
	viaExport, r := enrichRepoRoot(t, "--cartography", "testdata/cartography/deploy-only.json")
	if strings.Contains(r.stderr, "warning") {
		t.Errorf("stderr = %q", r.stderr)
	}
	a, b := withoutSource(t, viaFile), withoutSource(t, viaExport)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("enrich via the Cartography export differs from enrich via the trust file\nfile:   %+v\nexport: %+v", a.Edges[len(a.Edges)-1], b.Edges[len(b.Edges)-1])
	}
	g, err := graph.LoadFile(viaExport)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume {
			n++
			if e.Attrs[graph.AttrSource] != graph.SourceCartography || e.Attrs[graph.AttrFile] != "testdata/cartography/deploy-only.json" ||
				e.SourceAPI != "supplied:testdata/cartography/deploy-only.json" || e.Evidence != graph.Supplied {
				t.Errorf("edge %+v", e)
			}
		}
	}
	if n == 0 {
		t.Error("no CAN_ASSUME edge from the export")
	}
}

func TestEnrichCartography(t *testing.T) {
	out, r := enrichRepoRoot(t, "--cartography", "testdata/cartography/oidc-trusts.json")
	testutil.Golden(t, "enrich_cartography_stderr.txt", []byte(r.stderr), version)
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := enrichRepoRoot(t, "--cartography", "testdata/cartography/oidc-trusts.json")
	second, err := os.ReadFile(again)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("gop enrich --cartography twice on the same inputs differs")
	}
	v := runApp(t, nil, nil, "validate", "--graph", out)
	if v.code != exitOK || !strings.Contains(v.stdout, "0 errors") {
		t.Errorf("validate: %+v", v)
	}
	w := runApp(t, nil, nil, "who", "--graph", out, "--target", awsDeploy)
	if w.code != exitOK {
		t.Fatalf("who: %+v", w)
	}
	testutil.Golden(t, "enrich_cartography_who_aws.txt", []byte(w.stdout), version)

	// Trust files and an export together: one Enrich, both sources kept apart.
	both, r := enrichRepoRoot(t, "--oidc-trust", "testdata/acme/trust", "--cartography", "testdata/cartography/oidc-trusts.json")
	if !strings.Contains(r.stderr, "from 5 files") {
		t.Errorf("stderr = %q", r.stderr)
	}
	g, err := graph.LoadFile(both)
	if err != nil {
		t.Fatal(err)
	}
	var fromFile, observed int
	for _, e := range g.Edges {
		if e.Kind != graph.CanAssume {
			continue
		}
		if e.Attrs[graph.AttrSource] == "" {
			fromFile++
		}
		if e.Attrs[graph.AttrObservedUse] == "true" {
			observed++ // the deploy edge from the trust file and from the export
		}
	}
	if fromFile == 0 || observed != 2 {
		t.Errorf("trust-file edges %d, observed edges %d", fromFile, observed)
	}
}

func TestEnrichCartographyUsage(t *testing.T) {
	r := runApp(t, nil, nil, "enrich", "--graph", fixture, "--out", "-")
	if r.code != exitUsage || !strings.Contains(r.stderr, "--oidc-trust or --cartography") {
		t.Errorf("no input: %+v", r)
	}
	r = runApp(t, nil, nil, "enrich", "--graph", fixture, "--cartography", "does-not-exist.json", "--out", "-")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "--cartography") {
		t.Errorf("missing export: %+v", r)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = runApp(t, nil, nil, "enrich", "--graph", fixture, "--cartography", bad, "--out", "-")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "unrecognized export format") {
		t.Errorf("malformed export: %+v", r)
	}
}
