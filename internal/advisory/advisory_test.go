package advisory

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// fixtureDir holds synthetic OSV records (acme-actions/checkout-ish and
// acme-actions/lint-ish, made-up GHSA IDs).
var fixtureDir = filepath.Join("..", "..", "testdata", "advisories", "osv")

func loadFixture(t *testing.T) *DB {
	t.Helper()
	db, err := Load(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// fixtureZip writes the fixture records into a zip shaped like all.zip.
func fixtureZip(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "all.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	ents, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(fixtureDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.Create(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDropsWithdrawnAndOtherEcosystems(t *testing.T) {
	for name, path := range map[string]string{"dir": fixtureDir, "zip": fixtureZip(t)} {
		db, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if db.Records != 2 {
			t.Errorf("%s: %d records, want 2 (withdrawn and PyPI dropped)", name, db.Records)
		}
	}
	if _, err := Load(filepath.Join(fixtureDir, "GHSA-acme-test-0001.json")); err == nil {
		t.Error("a single JSON file is not a zip: want an error")
	}
}

func TestMatch(t *testing.T) {
	db := loadFixture(t)
	const ghsa1, ghsa2 = "GHSA-acme-test-0001", "GHSA-acme-test-0002"
	for _, tc := range []struct {
		repo, path, ref string
		affected        []string
		unknown         []string
		sev, fixed      string
	}{
		{repo: "checkout-ish", ref: "v2.3.0", affected: []string{ghsa1}, sev: "critical", fixed: "2.4.1"}, // affected tag (range)
		{repo: "checkout-ish", ref: "v2.4.0", affected: []string{ghsa1}, sev: "critical", fixed: "2.4.1"}, // affected tag (listed)
		{repo: "checkout-ish", ref: "v2.4.1"},                       // fixed tag
		{repo: "checkout-ish", ref: "v3"},                           // after the fix
		{repo: "checkout-ish", ref: "v1"},                           // before the range
		{repo: "checkout-ish", ref: "v2", unknown: []string{ghsa1}}, // moving tag across the fix
		{repo: "checkout-ish", ref: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", affected: []string{ghsa1}, sev: "critical", fixed: "2.4.1"}, // introduced commit
		{repo: "checkout-ish", ref: "2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c", affected: []string{ghsa1}, sev: "critical", fixed: "2.4.1"}, // listed commit
		{repo: "checkout-ish", ref: "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"},                                                             // fixed commit
		{repo: "checkout-ish", ref: "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d", unknown: []string{ghsa1}},                                   // unlisted commit
		{repo: "checkout-ish", ref: "main", unknown: []string{ghsa1}},                                                                       // branch
		{repo: "lint-ish", ref: "v1.1.0", affected: []string{ghsa2}, sev: "medium", fixed: "1.2.0"},
		{repo: "lint-ish", ref: "v1.2.0"}, // the withdrawn advisory would say affected
		{repo: "lint-ish", path: "sub", ref: "v1.0.0", affected: []string{ghsa2}, sev: "medium", fixed: "1.2.0"},
		{repo: "other", ref: "v1"},
	} {
		m := db.Match("acme-actions", tc.repo, tc.path, tc.ref)
		if !reflect.DeepEqual(m.Affected, tc.affected) || !reflect.DeepEqual(m.Unknown, tc.unknown) || m.Severity != tc.sev || m.Fixed != tc.fixed {
			t.Errorf("%s/%s@%s: got %+v", tc.repo, tc.path, tc.ref, m)
		}
		if len(tc.unknown) > 0 && m.Why == "" {
			t.Errorf("%s@%s: unknown without a reason", tc.repo, tc.ref)
		}
	}
}

func TestVersionIntervals(t *testing.T) {
	ivs, ok := intervals([]Event{{Fixed: "1.0.0"}, {Introduced: "0"}, {Introduced: "2.0.0"}, {LastAffected: "2.1.0"}})
	if !ok || len(ivs) != 2 {
		t.Fatalf("intervals: %+v %v", ivs, ok)
	}
	in := func(s string) bool {
		v, _ := parseVersion(s)
		return ivs[0].contains(v) || ivs[1].contains(v)
	}
	for s, want := range map[string]bool{"0.9": true, "1.0.0": false, "1.5": false, "2.0.0": true, "2.1.0": true, "2.1.1": false, "1.0.0-rc1": true} {
		if in(s) != want {
			t.Errorf("%s: got %v", s, !want)
		}
	}
	if _, ok := intervals([]Event{{Introduced: "not-a-version"}}); ok {
		t.Error("an unparsed event must make the range unusable")
	}
}

func actionGraph() *graph.Graph {
	return &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme", Nodes: []graph.Node{
		{ID: "action:acme-actions/checkout-ish@v2.3.0", Kind: graph.KindActionRef, Evidence: graph.Live},
		{ID: "action:acme-actions/checkout-ish@main", Kind: graph.KindActionRef, Evidence: graph.Live},
		{ID: "action:acme-actions/checkout-ish@v2.4.1", Kind: graph.KindActionRef, Evidence: graph.Live,
			Attrs: map[string]string{graph.AttrAdvisories: "GHSA-stale"}},
		{ID: "repo:acme-app/web", Kind: graph.KindRepo, Evidence: graph.Live},
	}}
}

func TestAnnotate(t *testing.T) {
	g := actionGraph()
	st := Annotate(g, loadFixture(t))
	if st != (Stats{Actions: 3, Affected: 1, Unknown: 1}) {
		t.Errorf("stats %+v", st)
	}
	a := g.Nodes[0].Attrs
	if a[graph.AttrAdvisories] != "GHSA-acme-test-0001" || a[graph.AttrAdvisorySeverity] != "critical" || a[graph.AttrAdvisoryFixed] != "2.4.1" {
		t.Errorf("affected attrs %v", a)
	}
	if _, ok := g.Nodes[2].Attrs[graph.AttrAdvisories]; ok {
		t.Error("a stale advisories attr on a fixed ref must be removed")
	}
	if len(g.Coverage) != 1 || g.Coverage[0].Scope != "action:acme-actions/checkout-ish@main" ||
		g.Coverage[0].Fact != graph.CoverageAdvisories || !strings.Contains(g.Coverage[0].Reason, "unknown, not safe") {
		t.Errorf("coverage %+v", g.Coverage)
	}
	again := Annotate(g, loadFixture(t))
	if again != st || len(g.Coverage) != 1 {
		t.Errorf("annotating twice must not add entries: %+v %+v", again, g.Coverage)
	}
}

func TestSkipNoData(t *testing.T) {
	g := actionGraph()
	Skip(g, "no advisory data")
	if len(g.Coverage) != 1 || g.Coverage[0].Scope != "enterprise:acme" || g.Coverage[0].Fact != graph.CoverageAdvisories ||
		!strings.Contains(g.Coverage[0].Reason, "skipped") {
		t.Errorf("coverage %+v", g.Coverage)
	}
	if _, ok := g.Nodes[2].Attrs[graph.AttrAdvisories]; ok {
		t.Error("skip must drop advisory attrs gop can no longer vouch for")
	}
	_, err := Resolve(context.Background(), g, filepath.Join(t.TempDir(), "missing.zip"), false, nil, "", time.Time{})
	if err == nil {
		t.Error("a missing --advisories path must be an error the caller turns into a skip")
	}
}

// fakeOSV serves the fixture through the querybatch and vulns endpoints.
func fakeOSV(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	recs := map[string][]byte{}
	byPkg := map[string][]string{}
	ents, _ := os.ReadDir(fixtureDir)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(fixtureDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		recs[r.ID] = b
		for _, a := range r.Affected {
			if a.Package.Ecosystem == Ecosystem {
				byPkg[a.Package.Name] = append(byPkg[a.Package.Name], r.ID)
			}
		}
	}
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var q struct {
				Queries []struct {
					Package Package `json:"package"`
					Version string  `json:"version"`
				} `json:"queries"`
			}
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &q); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			type vuln struct {
				ID string `json:"id"`
			}
			out := struct {
				Results []struct {
					Vulns []vuln `json:"vulns,omitempty"`
				} `json:"results"`
			}{}
			for _, qq := range q.Queries {
				if qq.Package.Ecosystem != Ecosystem || qq.Version != "" {
					http.Error(w, "unexpected query", http.StatusBadRequest)
					return
				}
				asked = append(asked, qq.Package.Name)
				var res struct {
					Vulns []vuln `json:"vulns,omitempty"`
				}
				for _, id := range byPkg[qq.Package.Name] {
					res.Vulns = append(res.Vulns, vuln{id})
				}
				out.Results = append(out.Results, res)
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			b, ok := recs[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &asked
}

func TestLive(t *testing.T) {
	srv, asked := fakeOSV(t)
	g := actionGraph()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	db, err := Resolve(context.Background(), g, "", true, srv.Client(), srv.URL, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*asked, []string{"acme-actions/checkout-ish"}) {
		t.Errorf("queried %v: only package names, once each", *asked)
	}
	// The live API returns the withdrawn record too; it is dropped.
	if db.Records != 1 || !db.AsOf.Equal(now) || db.Source != srv.URL {
		t.Errorf("db %+v", db)
	}
	if st := Annotate(g, db); st.Affected != 1 || st.Unknown != 1 {
		t.Errorf("live stats %+v", st)
	}
}

func TestLiveHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := Live(context.Background(), srv.Client(), srv.URL, []string{"acme-actions/checkout-ish"}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "503") {
		t.Errorf("err %v", err)
	}
}

func TestDownload(t *testing.T) {
	zipPath := fixtureZip(t)
	body, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad.zip" {
			_, _ = w.Write([]byte("not a zip"))
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "cache", CacheFile)
	n, err := Download(context.Background(), srv.Client(), srv.URL+"/all.zip", dest)
	if err != nil || n != 2 {
		t.Fatalf("download: %d %v", n, err)
	}
	if _, err := Load(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := Download(context.Background(), srv.Client(), srv.URL+"/bad.zip", dest); err == nil {
		t.Error("a body that is not a zip must be refused")
	}
	if db, err := Load(dest); err != nil || db.Records != 2 {
		t.Errorf("a refused download must keep the old copy: %v", err)
	}
}

func TestPackages(t *testing.T) {
	g := &graph.Graph{Nodes: []graph.Node{
		{ID: "action:acme-actions/lint-ish/sub@v1", Kind: graph.KindActionRef},
		{ID: "action:acme-actions/lint-ish@v1", Kind: graph.KindActionRef},
		{ID: "action:bad", Kind: graph.KindActionRef},
	}}
	if got := Packages(g); !reflect.DeepEqual(got, []string{"acme-actions/lint-ish", "acme-actions/lint-ish/sub"}) {
		t.Errorf("packages %v", got)
	}
}
