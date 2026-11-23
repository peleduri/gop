package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/testutil"
)

func diffCase(name string) (string, string) {
	d := filepath.Join("..", "..", "internal", "diff", "testdata", name)
	return filepath.Join(d, "old.json"), filepath.Join(d, "new.json")
}

func TestDiffSelfExitsZero(t *testing.T) {
	r := runApp(t, nil, nil, "diff", fixture, fixture, "--fail-on", "confirmed-increase,any-new-path")
	if r.code != exitOK || r.stderr != "" {
		t.Fatalf("self diff: %+v", r)
	}
	testutil.Golden(t, "diff_self.txt", []byte(r.stdout))
}

func TestDiffFailOn(t *testing.T) {
	for _, tc := range []struct {
		name, failOn string
		want         int
	}{
		{"identical", "confirmed-increase", exitOK},
		{"ref-unpinned", "confirmed-increase", exitRuntime},
		{"ref-unpinned", "any-new-path", exitRuntime},
		{"ref-unpinned", "", exitOK},
		{"default-perm-raised", "confirmed-increase", exitRuntime},
		{"org-added", "confirmed-increase", exitRuntime},
		// Lost visibility shrinks confirmed pairs and adds no path: never a failure.
		{"lost-visibility", "confirmed-increase", exitOK},
		{"lost-visibility", "any-new-path", exitOK},
	} {
		o, n := diffCase(tc.name)
		args := []string{"diff", o, n}
		if tc.failOn != "" {
			args = append(args, "--fail-on", tc.failOn)
		}
		r := runApp(t, nil, nil, args...)
		if r.code != tc.want {
			t.Errorf("%s --fail-on %q: code %d, want %d (stderr %q)", tc.name, tc.failOn, r.code, tc.want, r.stderr)
		}
		if tc.want == exitRuntime && !strings.Contains(r.stderr, "--fail-on matched: "+tc.failOn) {
			t.Errorf("%s: stderr %q", tc.name, r.stderr)
		}
	}
	// A possible-only new path trips any-new-path but not confirmed-increase.
	dir := t.TempDir()
	o, _ := diffCase("identical")
	b, err := os.ReadFile(o)
	if err != nil {
		t.Fatal(err)
	}
	poss := strings.Replace(string(b), `"from": "identity:bob",
      "to": "repo:acme-actions/deploy",
      "kind": "CAN_PUSH",
      "evidence": "live"`, `"from": "identity:bob",
      "to": "repo:acme-actions/deploy",
      "kind": "CAN_PUSH",
      "evidence": "not_visible"`, 1)
	if poss == string(b) {
		t.Fatal("fixture edit did not apply")
	}
	pf := filepath.Join(dir, "possible.json")
	if err := os.WriteFile(pf, []byte(poss), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runApp(t, nil, nil, "diff", pf, o, "--fail-on", "confirmed-increase"); r.code != exitRuntime {
		t.Errorf("upgrade should grow confirmed pairs: %+v", r)
	}
	if r := runApp(t, nil, nil, "diff", o, pf, "--fail-on", "confirmed-increase,any-new-path"); r.code != exitOK {
		t.Errorf("downgrade must not fail: %+v", r)
	}
}

// TestDiffGolden goldens the three formats and --only over the demo snapshot pairs.
func TestDiffGolden(t *testing.T) {
	for _, tc := range []struct {
		golden, name string
		extra        []string
	}{
		{"diff_ref_unpinned.txt", "ref-unpinned", nil},
		{"diff_default_perm_raised.txt", "default-perm-raised", nil},
		{"diff_default_perm_raised.md", "default-perm-raised", []string{"--format", "markdown"}},
		{"diff_default_perm_raised.json", "default-perm-raised", []string{"--format", "json"}},
		{"diff_default_perm_raised_scores.txt", "default-perm-raised", []string{"--only", "scores"}},
		{"diff_lost_visibility.txt", "lost-visibility", nil},
		{"diff_lost_visibility.md", "lost-visibility", []string{"--format", "md"}},
		{"diff_org_added.txt", "org-added", nil},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			o, n := diffCase(tc.name)
			// Flags after the positionals work too.
			r := runApp(t, nil, nil, append([]string{"diff", o, n}, tc.extra...)...)
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%s: %+v", tc.golden, r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

func TestDiffJSONDecodes(t *testing.T) {
	o, n := diffCase("default-perm-raised")
	r := runApp(t, nil, nil, "diff", "--format", "json", o, n)
	var rep diff.Report
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("json does not decode into diff.Report: %v", err)
	}
	if rep.Old.Enterprise != "acme" || len(rep.Paths) != 3 || rep.Totals.New.ConfirmedPairs != 5 {
		t.Errorf("decoded = %+v", rep)
	}
	r = runApp(t, nil, nil, "diff", o, n, "--format", "json", "--only", "settings")
	rep = diff.Report{}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || len(rep.Paths) != 0 || len(rep.Settings) != 1 {
		t.Fatalf("--only settings: %v %+v", err, rep)
	}
}

func TestDiffLostVisibilityWording(t *testing.T) {
	o, n := diffCase("lost-visibility")
	r := runApp(t, nil, nil, "diff", o, n)
	if !strings.Contains(r.stdout, "two_factor required → not visible (lost visibility)") || strings.Contains(r.stdout, "removed") || strings.Contains(r.stdout, " off") {
		t.Fatalf("lost visibility: %+v", r)
	}
}

func TestDiffErrors(t *testing.T) {
	o, n := diffCase("identical")
	dir := t.TempDir()
	b, err := os.ReadFile(n)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.json")
	if err := os.WriteFile(other, []byte(strings.Replace(string(b), `"enterprise": "acme"`, `"enterprise": "acme-other"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"diff"},
		{"diff", o},
		{"diff", o, n, n},
		{"diff", o, n, "--format", "pdf"},
		{"diff", o, n, "--only", "everything"},
		{"diff", o, n, "--fail-on", "sometimes"},
		{"diff", o, filepath.Join(dir, "missing.json")},
		{"diff", bad, n},
		{"diff", o, other},
	} {
		if r := runApp(t, nil, nil, args...); r.code != exitUsage {
			t.Errorf("%v: code %d, want 2 (stderr %q)", args, r.code, r.stderr)
		}
	}
	r := runApp(t, nil, nil, "diff", o, other)
	if !strings.Contains(r.stderr, "different enterprises") || !strings.Contains(r.stderr, `"acme" vs "acme-other"`) {
		t.Errorf("enterprise mismatch message: %q", r.stderr)
	}
	if r := runApp(t, nil, nil, "diff", "--force", o, other); r.code != exitOK {
		t.Errorf("--force: %+v", r)
	}
}
