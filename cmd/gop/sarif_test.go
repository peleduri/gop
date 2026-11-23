package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/sarif"
)

func readSARIF(t *testing.T, path string) sarif.Log {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var l sarif.Log
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestSARIFUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"sarif", "--graph", fixture},
		{"sarif", "--graph", fixture, "--out", "-", "--split-by-repo", t.TempDir()},
		{"sarif", "--graph", fixture, "--out", "-", "--top", "-1"},
		{"sarif", "--graph", fixture, "--out", "-", "--min-severity", "urgent"},
		{"sarif", "--out", "-"},
		{"sarif", "--graph", fixture, "--demo", "--out", "-"},
		{"sarif", "--graph", fixture, "--out", "-", "extra"},
	} {
		if r := runApp(t, nil, nil, args...); r.code != exitUsage {
			t.Errorf("%v: code %d, want 2 (stderr %q)", args, r.code, r.stderr)
		}
	}
}

func TestSARIFOut(t *testing.T) {
	r := runApp(t, nil, nil, "sarif", "--graph", fixture, "--out", "-", "--min-severity", "high")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.stderr, "code scanning") || !strings.Contains(r.stderr, "docs/sarif.md") {
		t.Errorf("no upload warning on stderr: %q", r.stderr)
	}
	var l sarif.Log
	if err := json.Unmarshal([]byte(r.stdout), &l); err != nil {
		t.Fatal(err)
	}
	if l.Version != "2.1.0" || len(l.Runs[0].Results) == 0 {
		t.Fatalf("log: %+v", l)
	}
	for _, res := range l.Runs[0].Results {
		if s := res.Properties.Severity; s != sarif.SeverityHigh && s != sarif.SeverityCritical {
			t.Errorf("--min-severity high kept %s", s)
		}
	}

	path := filepath.Join(t.TempDir(), "gop.sarif")
	if r := runApp(t, nil, nil, "sarif", "--demo", "--out", path, "--top", "3"); r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if n := len(readSARIF(t, path).Runs[0].Results); n != 3 {
		t.Errorf("--top 3 wrote %d results", n)
	}
}

func TestSARIFSplitByRepo(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sarif")
	r := runApp(t, nil, nil, "sarif", "--graph", fixture, "--split-by-repo", dir)
	if r.code != exitOK || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	want := []string{
		"acme-actions.org.sarif",
		"acme-app/admin.sarif", "acme-app/api.sarif", "acme-app/auth.sarif", "acme-app/billing.sarif", "acme-app/docs.sarif",
		"acme-app/gateway.sarif", "acme-app/mobile.sarif", "acme-app/search.sarif", "acme-app/web.sarif", "acme-app/worker.sarif",
	}
	if strings.Join(files, "\n") != strings.Join(want, "\n") {
		t.Fatalf("files:\n%s\nwant:\n%s", strings.Join(files, "\n"), strings.Join(want, "\n"))
	}
	for _, f := range files {
		l := readSARIF(t, filepath.Join(dir, f))
		key := "org:acme-actions"
		if f != "acme-actions.org.sarif" {
			key = strings.TrimSuffix(f, ".sarif")
		}
		for _, res := range l.Runs[0].Results {
			got := res.Properties.Repository
			if got == "" {
				got = "org:" + res.Properties.Org
			}
			if got != key {
				t.Errorf("%s holds a result for %s", f, got)
			}
		}
	}
	if n := len(readSARIF(t, filepath.Join(dir, "acme-app/web.sarif")).Runs[0].Results); n != 2 {
		t.Errorf("acme-app/web.sarif: %d results, want 2", n)
	}
	if fi, err := os.Stat(filepath.Join(dir, "acme-app")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("acme-app dir: %v %v", fi, err)
	}
}

func TestSafeName(t *testing.T) {
	for s, want := range map[string]bool{
		"acme-app": true, "web": true, "my.repo": true, ".github": true,
		"": false, ".": false, "..": false, "...": false, "a/b": false, `a\b`: false, "a\x00": false,
	} {
		if got := safeName(s); got != want {
			t.Errorf("safeName(%q) = %v, want %v", s, got, want)
		}
	}
}
