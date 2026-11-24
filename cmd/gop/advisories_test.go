package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
)

const osvFixture = "../../testdata/advisories/osv"

func advisoryGraph() *graph.Graph {
	return &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme", Nodes: []graph.Node{
		{ID: "enterprise:acme", Kind: graph.KindEnterprise, Name: "acme", Evidence: graph.Live},
		{ID: "action:acme-actions/checkout-ish@v2.3.0", Kind: graph.KindActionRef, Name: "acme-actions/checkout-ish@v2.3.0", Evidence: graph.Live},
	}}
}

func advisoryApp(t *testing.T, cachePath string) (*app, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, getenv: func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "test-token"
		}
		return ""
	},
		collect: func(context.Context, collect.Config) (*graph.Graph, error) { return advisoryGraph(), nil }}
	if cachePath != "" {
		a.advisoryPath = func() (string, error) { return cachePath, nil }
	}
	return a, &out, &errb
}

func loadOut(t *testing.T, p string) *graph.Graph {
	t.Helper()
	g, err := graph.LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func affected(g *graph.Graph) string {
	for _, n := range g.Nodes {
		if n.Kind == graph.KindActionRef {
			return n.Attrs[graph.AttrAdvisories]
		}
	}
	return ""
}

func TestCollectAdvisoriesSkippedWithoutData(t *testing.T) {
	a, _, errb := advisoryApp(t, filepath.Join(t.TempDir(), "missing.zip"))
	out := filepath.Join(t.TempDir(), "g.json")
	if code := a.run([]string{"collect", "--enterprise", "acme", "--out", out}); code != 0 {
		t.Fatalf("collect must not fail without advisory data: %d %s", code, errb)
	}
	g := loadOut(t, out)
	var skipped bool
	for _, c := range g.Coverage {
		if c.Fact == graph.CoverageAdvisories && strings.Contains(c.Reason, "skipped") {
			skipped = true
		}
	}
	if !skipped || affected(g) != "" || !strings.Contains(errb.String(), "advisories: skipped") {
		t.Errorf("coverage %+v stderr %s", g.Coverage, errb)
	}
}

func TestCollectAdvisoriesFromPathAndCache(t *testing.T) {
	a, _, errb := advisoryApp(t, "")
	out := filepath.Join(t.TempDir(), "g.json")
	if code := a.run([]string{"collect", "--enterprise", "acme", "--out", out, "--advisories", osvFixture}); code != 0 {
		t.Fatalf("collect: %d %s", code, errb)
	}
	if got := affected(loadOut(t, out)); got != "GHSA-acme-test-0001" {
		t.Errorf("advisories %q", got)
	}
	if code := a.run([]string{"collect", "--enterprise", "acme", "--out", out, "--advisories", osvFixture, "--advisories-live"}); code != exitUsage {
		t.Errorf("both sources: exit %d", code)
	}
}

func TestEnrichAdvisoriesLive(t *testing.T) {
	recs, err := os.ReadFile(filepath.Join(osvFixture, "GHSA-acme-test-0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-acme-test-0001"}]}]}`))
		case "/v1/vulns/GHSA-acme-test-0001":
			_, _ = w.Write(recs)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.json"), filepath.Join(dir, "out.json")
	f, err := os.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := collect.WriteGraph(f, advisoryGraph()); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	a, _, errb := advisoryApp(t, "")
	a.osvAPIURL = srv.URL
	if code := a.run([]string{"enrich", "--graph", in, "--advisories-live", "--out", out}); code != 0 {
		t.Fatalf("enrich: %d %s", code, errb)
	}
	if got := affected(loadOut(t, out)); got != "GHSA-acme-test-0001" {
		t.Errorf("advisories %q (stderr %s)", got, errb)
	}
}

func TestAdvisoriesUpdate(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	b, err := os.ReadFile(filepath.Join(osvFixture, "GHSA-acme-test-0002.json"))
	if err != nil {
		t.Fatal(err)
	}
	w, _ := zw.Create("GHSA-acme-test-0002.json")
	_, _ = w.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(zb.Bytes()) }))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "gop", "osv.zip")
	a, _, errb := advisoryApp(t, dest)
	a.osvZipURL = srv.URL + "/all.zip"
	if code := a.run([]string{"advisories", "update"}); code != 0 {
		t.Fatalf("update: %d %s", code, errb)
	}
	if _, err := os.Stat(dest); err != nil || !strings.Contains(errb.String(), "wrote 1 GitHub Actions advisories") {
		t.Errorf("stat %v stderr %s", err, errb)
	}
	if code := a.run([]string{"advisories"}); code != exitUsage {
		t.Errorf("no subcommand: exit %d", code)
	}
}
