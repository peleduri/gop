package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

const linesFixture = "../../internal/fixplan/testdata/lines.json"

func TestGoldenFixPlanCLI(t *testing.T) {
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"fixplan_pin.txt", []string{"fix-plan", "--graph", linesFixture, "--pin", "action:acme-actions/deploy@main"}},
		{"fixplan_pin.md", []string{"fix-plan", "--graph", linesFixture, "--pin", "action:acme-actions/deploy@main", "--format", "markdown"}},
		{"fixplan_lower.txt", []string{"fix-plan", "--graph", fixture, "--lower-default-perm", "org:acme-actions", "--to", "read"}},
		{"fixplan_restrict.txt", []string{"fix-plan", "--graph", fixture, "--restrict-token", "workflow:acme-app/web/.github/workflows/ci.yml"}},
		{"fixplan_owners.md", []string{"fix-plan", "--graph", "../../testdata/causes/graph.json", "--reduce-owners", "19", "--format", "markdown"}},
		{"fixplan_harden.md", []string{"fix-plan", "--graph", "../../internal/fixplan/testdata/triggers.json", "--harden-trigger", "workflow:acme-app/docs/.github/workflows/preview.yml", "--format", "markdown"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			r := runApp(t, nil, nil, tc.args...)
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%v: %+v", tc.args, r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

func TestFixPlanCLIJSON(t *testing.T) {
	r := runApp(t, nil, nil, "fix-plan", "--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--format", "json")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	var out struct {
		Summary string `json:"summary"`
		Plan    struct {
			FixID string `json:"fix_id"`
			Steps []struct {
				Kind string `json:"kind"`
			} `json:"steps"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Plan.FixID != "pin:action:acme-actions/deploy@main" || len(out.Plan.Steps) == 0 || out.Summary == "" {
		t.Errorf("%+v", out)
	}
}

func TestFixPlanCLIErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"fix-plan", "--graph", fixture, "--reduce-owners", "-1"}, exitUsage, "--reduce-owners must be positive"},
		{[]string{"fix-plan", "--graph", fixture}, exitUsage, "one of --pin, --lower-default-perm, --restrict-token, --harden-trigger or --reduce-owners is required"},
		{[]string{"fix-plan", "--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--lower-default-perm", "org:acme-actions"}, exitUsage, "use only one of"},
		{[]string{"fix-plan", "--graph", fixture, "--restrict-token", "workflow:acme-app/web/.github/workflows/ci.yml", "--harden-trigger", "workflow:acme-app/web/.github/workflows/ci.yml"}, exitUsage, "use only one of"},
		{[]string{"fix-plan", "--graph", fixture, "--restrict-token", "repo:acme-app/web"}, exitRuntime, "not a workflow"},
		{[]string{"fix-plan", "--graph", fixture, "--harden-trigger", "workflow:acme-app/web/.github/workflows/nope.yml"}, exitRuntime, "unknown fix.workflow"},
		{[]string{"fix-plan", "--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--format", "html"}, exitUsage, "--format"},
		{[]string{"fix-plan", "--pin", "action:acme-actions/deploy@main"}, exitUsage, "--graph is required"},
		{[]string{"fix-plan", "--graph", fixture, "--pin", "repo:acme-app/web"}, exitRuntime, "not an action ref"},
		{[]string{"fix-plan", "--graph", fixture, "--lower-default-perm", "org:acme-actions", "--to", "write"}, exitRuntime, "fix.to"},
	} {
		r := runApp(t, nil, nil, tc.args...)
		if r.code != tc.code || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v: code %d stderr %q, want %d and %q", tc.args, r.code, r.stderr, tc.code, tc.want)
		}
	}
}
