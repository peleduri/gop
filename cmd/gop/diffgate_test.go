package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestActionDiffGate runs the Action's reach-increase gate script
// (action/diff-gate.sh) against a freshly built gop and the diff fixtures.
func TestActionDiffGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		// "bash" may resolve to WSL here; CI's action-smoke job runs the
		// script in Git Bash on a Windows runner instead.
		t.Skip("the gate is tested on Windows by the action-smoke workflow")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if testing.Short() {
		t.Skip("builds the gop binary")
	}
	bin := filepath.Join(t.TempDir(), "gop")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "action", "diff-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, oldGraph, newGraph string
		wantCode                 int
		wantResult               string
		wantDiff                 bool
	}{
		{"identical", "", "", 0, "clean", true},
		{"lost-visibility", "", "", 0, "clean", true},
		{"ref-unpinned", "", "", 1, "increase", true},
		{"default-perm-raised", "", "", 1, "increase", true},
		{"broken-baseline", broken, fixture, 2, "error", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, n := tc.oldGraph, tc.newGraph
			if o == "" {
				o, n = diffCase(tc.name)
			}
			out := filepath.Join(t.TempDir(), "gop-out")
			cmd := exec.Command(bash, script, o, n, out)
			cmd.Env = append(os.Environ(), "GOP_BIN="+bin)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.wantCode || stdout.String() != tc.wantResult+"\n" {
				t.Fatalf("code %d stdout %q, want %d %q (stderr %q)", code, stdout.String(), tc.wantCode, tc.wantResult, stderr.String())
			}
			// The log must never name nodes: everything the script prints
			// is the result word.
			if stderr.Len() != 0 {
				t.Errorf("stderr must be empty, got %q", stderr.String())
			}
			if !tc.wantDiff {
				b, err := os.ReadFile(filepath.Join(out, "diff-stderr.txt"))
				if err != nil || len(b) == 0 {
					t.Errorf("error case must keep gop's stderr in the artifact: %v", err)
				}
				return
			}
			errb, err := os.ReadFile(filepath.Join(out, "diff-stderr.txt"))
			switch {
			case tc.wantResult == "clean" && !os.IsNotExist(err):
				t.Errorf("diff-stderr.txt should be removed when empty: %v %q", err, errb)
			case tc.wantResult == "increase" && !strings.Contains(string(errb), "--fail-on matched: confirmed-increase"):
				t.Errorf("diff-stderr.txt should keep the --fail-on message: %v %q", err, errb)
			}
			md, err := os.ReadFile(filepath.Join(out, "diff.md"))
			if err != nil || len(md) == 0 {
				t.Fatalf("diff.md: %v", err)
			}
			js, err := os.ReadFile(filepath.Join(out, "diff.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(js) {
				t.Errorf("diff.json is not valid JSON")
			}
			if tc.wantResult == "increase" && !strings.Contains(string(md), "repo:") {
				t.Errorf("diff.md should name the changed nodes:\n%s", md)
			}
		})
	}
}
