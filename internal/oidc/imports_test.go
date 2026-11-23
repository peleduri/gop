package oidc_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoNetworkImports: the package parses local files only.
func TestNoNetworkImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := map[string]bool{"net": true, "net/http": true, "net/rpc": true, "os/exec": true, "net/http/httptest": true}
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if banned[p] {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if len(files) < 5 {
		t.Fatalf("only %d files checked", len(files))
	}
}

// TestNoNetworkImportsTransitive: neither the package nor any gop package it
// imports (internal/graph, for Enrich) imports a network package, so
// matching and enrichment cannot call a cloud API.
func TestNoNetworkImportsTransitive(t *testing.T) {
	const module = "github.com/peleduri/gop/"
	banned := map[string]bool{"net": true, "net/http": true, "net/rpc": true, "os/exec": true}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var walk func(dir, name string)
	walk = func(dir, name string) {
		if seen[dir] {
			return
		}
		seen[dir] = true
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if banned[p] {
					t.Errorf("%s (imported by %s) imports %s", f, name, p)
				}
				if rest, ok := strings.CutPrefix(p, module); ok {
					walk(filepath.Join("..", "..", filepath.FromSlash(rest)), p)
				}
			}
		}
	}
	walk(".", "internal/oidc")
	if !seen[filepath.Join("..", "..", "internal", "graph")] {
		t.Fatalf("internal/graph not reached: %v", seen)
	}
}
