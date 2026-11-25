// Package testutil holds test helpers shared across gop packages.
package testutil

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// update rewrites golden files instead of comparing: go test ./... -update
var update = flag.Bool("update", false, "rewrite golden files under testdata/golden")

// TestVersion replaces the gop version in golden output.
const TestVersion = "vTEST"

// Golden compares got with testdata/golden/<name> (relative to the package
// under test) and fails with a unified diff when they differ. With -update it
// rewrites the file instead. got is normalized first: CRLF becomes LF,
// every non-empty string in versions is replaced with TestVersion and every
// embedded woff2 font with FontPlaceholder.
func Golden(t *testing.T, name string, got []byte, versions ...string) {
	t.Helper()
	got = Normalize(got, versions...)
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v (run go test ./... -update to create it)", path, err)
	}
	want = Normalize(want)
	if !bytes.Equal(want, got) {
		t.Errorf("golden %s differs (-want +got); if the change is intended, run go test ./... -update\n%s",
			path, UnifiedDiff(string(want), string(got)))
	}
}

// FontPlaceholder stands in for the base64 of each embedded brand font in
// golden files: the fonts are tested in package brand, and a golden would
// otherwise carry tens of kilobytes of base64 per face.
const FontPlaceholder = "data:font/woff2;base64,@@font@@"

var embeddedFont = regexp.MustCompile(`data:font/woff2;base64,[A-Za-z0-9+/=]+`)

// Normalize converts line endings to LF, replaces each version with
// TestVersion and each embedded woff2 font with FontPlaceholder.
func Normalize(b []byte, versions ...string) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = embeddedFont.ReplaceAll(b, []byte(FontPlaceholder))
	for _, v := range versions {
		if v != "" && v != TestVersion {
			b = bytes.ReplaceAll(b, []byte(v), []byte(TestVersion))
		}
	}
	return b
}

// UnifiedDiff returns a line-based unified diff of a and b with 3 lines of context.
func UnifiedDiff(a, b string) string {
	x, y := splitLines(a), splitLines(b)
	ops := diffOps(x, y)
	const ctx = 3
	var sb strings.Builder
	sb.WriteString("--- want\n+++ got\n")
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// Hunk: extend from i while changes are within 2*ctx lines of each other.
		start := max(i-ctx, 0)
		end := i
		for j := i; j < len(ops); j++ {
			if ops[j].kind != ' ' {
				end = j
			} else if j-end > 2*ctx {
				break
			}
		}
		end = min(end+ctx+1, len(ops))
		ax, ay := ops[start].ai, ops[start].bi
		var na, nb int
		var body strings.Builder
		for _, op := range ops[start:end] {
			switch op.kind {
			case ' ':
				na++
				nb++
				body.WriteString(" " + x[op.ai] + "\n")
			case '-':
				na++
				body.WriteString("-" + x[op.ai] + "\n")
			case '+':
				nb++
				body.WriteString("+" + y[op.bi] + "\n")
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", ax+1, na, ay+1, nb)
		sb.WriteString(body.String())
		i = end
	}
	if sb.Len() == len("--- want\n+++ got\n") {
		sb.WriteString("(lines are equal; the difference is a trailing newline)\n")
	}
	return sb.String()
}

type diffOp struct {
	kind   byte // ' ', '-', '+'
	ai, bi int  // line index in a and b at this op
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// diffOps computes an edit script by longest common subsequence.
func diffOps(x, y []string) []diffOp {
	n, m := len(x), len(y)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, diffOp{' ', i, j})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, diffOp{'-', i, j})
			i++
		default:
			ops = append(ops, diffOp{'+', i, j})
			j++
		}
	}
	return ops
}
