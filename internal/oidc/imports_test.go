package oidc_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
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
