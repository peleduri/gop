package collect

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// fakeEnvs is the deployment environments the fake serves.
type fakeEnvs struct {
	list     map[string][]map[string]any // "o/r" -> environments
	custom   map[string][]map[string]any // "o/r/env" -> custom deployment protection rules
	branches map[string][]map[string]any // "o/r/env" -> deployment branch policies
	forbid   map[string]bool             // "o/r" -> the list answers 403
}

var envPathRe = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/environments(?:/([^/]+)/(deployment_protection_rules|deployment-branch-policies))?$`)

// serveEnvironments answers the environments endpoints; false for other paths.
func (f *fakeGitHub) serveEnvironments(w http.ResponseWriter, p string) bool {
	m := envPathRe.FindStringSubmatch(p)
	if m == nil {
		return false
	}
	full := m[1] + "/" + m[2]
	e := f.envs
	if e == nil {
		e = &fakeEnvs{}
	}
	switch {
	case e.forbid[full]:
		writeJSON(w, 403, map[string]string{"message": "Resource not accessible by personal access token"})
	case m[4] == "deployment_protection_rules":
		rules := e.custom[full+"/"+m[3]]
		writeJSON(w, 200, map[string]any{"total_count": len(rules), "custom_deployment_protection_rules": orEmpty(rules)})
	case m[4] == "deployment-branch-policies":
		ps := e.branches[full+"/"+m[3]]
		writeJSON(w, 200, map[string]any{"total_count": len(ps), "branch_policies": orEmpty(ps)})
	default:
		envs := e.list[full]
		writeJSON(w, 200, map[string]any{"total_count": len(envs), "environments": orEmpty(envs)})
	}
	return true
}

func orEmpty(xs []map[string]any) []map[string]any {
	if xs == nil {
		return []map[string]any{}
	}
	return xs
}

const envDeployWF = `on: push
permissions:
  contents: read
jobs:
  deploy:
    environment: production
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh "${{ secrets.DEPLOY_KEY }}"
  staging:
    environment:
      name: staging
      url: https://staging.example.test
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh "${{ secrets.STAGING_KEY }}"
  qa:
    environment: qa
    runs-on: ubuntu-latest
    steps:
      - run: ./qa.sh "${{ secrets.QA_KEY }}"
`

const envDynamicWF = `on:
  workflow_dispatch:
    inputs:
      env:
        type: string
jobs:
  ship:
    environment: ${{ inputs.env }}
    runs-on: ubuntu-latest
    steps:
      - run: ./ship.sh "${{ secrets.SHIP_KEY }}"
`

const envForbiddenWF = `on: push
jobs:
  release:
    environment: production
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: ./release.sh
`

func envFixture(f *fakeGitHub) {
	f.extraWorkflows["acme-app/billing/deploy.yml"] = envDeployWF
	f.extraWorkflows["acme-app/mobile/ship.yml"] = envDynamicWF
	f.extraWorkflows["acme-app/worker/release.yml"] = envForbiddenWF
	f.envs = &fakeEnvs{
		list: map[string][]map[string]any{
			"acme-app/billing": {
				{"name": "Production", "protection_rules": []map[string]any{
					{"type": "required_reviewers", "prevent_self_review": true, "reviewers": []map[string]any{
						{"type": "User", "reviewer": map[string]any{"login": "alice"}},
						{"type": "Team", "reviewer": map[string]any{"slug": "release"}},
					}},
					{"type": "wait_timer", "wait_timer": 30},
					{"type": "branch_policy"},
				}, "deployment_branch_policy": map[string]any{"protected_branches": true, "custom_branch_policies": false}},
				{"name": "staging", "protection_rules": []map[string]any{{"type": "branch_policy"}},
					"deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true}},
			},
		},
		custom: map[string][]map[string]any{
			"acme-app/billing/production": {{"id": 1, "enabled": true, "app": map[string]any{"id": 7, "slug": "acme-deploy-gate"}}},
		},
		branches: map[string][]map[string]any{
			"acme-app/billing/staging": {{"name": "release/*", "type": "branch"}, {"name": "v*", "type": "tag"}},
		},
		forbid: map[string]bool{"acme-app/worker": true},
	}
}

func TestEnvironmentConditions(t *testing.T) {
	f := newFakeGitHub(t)
	envFixture(f)
	ix := collectFake(t, f)
	wf := "workflow:acme-app/billing/.github/workflows/deploy.yml"

	oidc := ix.mustEdge(t, wf, "oidc:acme-app/billing", graph.ExecutesWith)
	if got := oidc.Attrs[graph.AttrEnvGate]; got != graph.EnvGateReviewers {
		t.Errorf("oidc env_gate = %q, want required_reviewers (attrs %v)", got, oidc.Attrs)
	}
	if got, want := oidc.Attrs[graph.AttrEnvProtection], "production:required_reviewers=2+prevent_self_review+wait_timer=30+branch_policy=protected+custom_rules=1"; got != want {
		t.Errorf("oidc env_protection = %q, want %q", got, want)
	}
	if got := oidc.Attrs[graph.AttrEnvBranches]; got != "production=protected" {
		t.Errorf("oidc env_branches = %q", got)
	}
	// The default branch may deploy to production only when it is protected.
	want := graph.EnvBranchUnknown
	switch ix.node(t, "repo:acme-app/billing").Attrs[graph.AttrBranchProtected] {
	case "true":
		want = graph.EnvBranchAllowed
	case "false":
		want = graph.EnvBranchBlocked
	}
	if got := oidc.Attrs[graph.AttrEnvDefaultBranch]; got != want {
		t.Errorf("oidc env_default_branch = %q, want %q", got, want)
	}

	sec := ix.mustEdge(t, wf, "secret:acme-app/billing", graph.ExecutesWith)
	if got := sec.Attrs[graph.AttrEnvGate]; got != graph.EnvGateNone {
		t.Errorf("secret env_gate = %q, want none", got)
	}
	if got := sec.Attrs[graph.AttrEnvUngatedJobs]; got != "qa,staging" {
		t.Errorf("secret env_ungated_jobs = %q, want qa,staging", got)
	}
	if got := sec.Attrs[graph.AttrEnvProtection]; !strings.Contains(got, "qa:absent") || !strings.Contains(got, "staging:branch_policy=custom") {
		t.Errorf("secret env_protection = %q", got)
	}
	if got := sec.Attrs[graph.AttrEnvBranches]; !strings.Contains(got, "staging=custom:release/*|tag:v*") {
		t.Errorf("secret env_branches = %q", got)
	}
	// qa is absent (GitHub creates it with no rules): the default branch may deploy.
	if got := sec.Attrs[graph.AttrEnvDefaultBranch]; got != graph.EnvBranchAllowed {
		t.Errorf("secret env_default_branch = %q, want allowed", got)
	}

	dyn := ix.mustEdge(t, "workflow:acme-app/mobile/.github/workflows/ship.yml", "secret:acme-app/mobile", graph.ExecutesWith)
	if dyn.Attrs[graph.AttrEnvGate] != graph.EnvGateUnknown || !strings.Contains(dyn.Attrs[graph.AttrEnvGateReason], "expression") {
		t.Errorf("dynamic environment: attrs %v, want env_gate unknown with an expression reason", dyn.Attrs)
	}

	hidden := ix.mustEdge(t, "workflow:acme-app/worker/.github/workflows/release.yml", "oidc:acme-app/worker", graph.ExecutesWith)
	if hidden.Attrs[graph.AttrEnvGate] != graph.EnvGateUnknown || hidden.Attrs[graph.AttrEnvProtection] != "production:unknown" {
		t.Errorf("unreadable environments: attrs %v, want env_gate unknown", hidden.Attrs)
	}
	if !strings.Contains(hidden.Attrs[graph.AttrEnvGateReason], "could not read the environments") {
		t.Errorf("env_gate_reason = %q", hidden.Attrs[graph.AttrEnvGateReason])
	}
	found := false
	for _, c := range ix.g.Coverage {
		if c.Scope == "repo:acme-app/worker" && c.Fact == graph.FactEnvironments {
			found = true
		}
	}
	if !found {
		t.Error("no environments coverage entry for acme-app/worker")
	}

	// Environments are read only for repos with an edge behind one.
	if n := f.hitCount("/repos/acme-app/web/environments?per_page=100"); n != 0 {
		t.Errorf("read the environments of acme-app/web %d times, want 0", n)
	}
	if n := f.hitCount("/repos/acme-app/billing/environments/production/deployment-branch-policies?per_page=100"); n != 0 {
		t.Errorf("read branch policies of a protected-branches environment %d times, want 0", n)
	}

	// The engine: the OIDC hop is gated, the secret hop is not.
	gix := graph.NewIndex(ix.g)
	var gated bool
	for _, p := range gix.WhoCanReach("oidc:acme-app/billing") {
		gated = gated || p.Gated
	}
	if !gated {
		t.Error("no gated path into oidc:acme-app/billing")
	}
}

func TestEnvironmentsNotReadWithoutEnvironments(t *testing.T) {
	f := newFakeGitHub(t)
	ix := collectFake(t, f)
	for k := range f.hits {
		if strings.Contains(k, "/environments") {
			t.Errorf("read %s with no job that names an environment", k)
		}
	}
	for _, e := range ix.g.Edges {
		if _, ok := e.Attrs[graph.AttrEnvGate]; ok {
			t.Errorf("edge %s -> %s has env_gate without an environment", e.From, e.To)
		}
	}
}

func TestSecretJobs(t *testing.T) {
	cases := []struct {
		name, wf string
		want     string
	}{
		{"per job", `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps: [{run: "echo ${{ secrets.A }}"}]
  b:
    runs-on: ubuntu-latest
    steps: [{run: echo}]
`, "a"},
		{"workflow env reaches every job", `on: push
env:
  K: ${{ secrets.K }}
jobs:
  a:
    runs-on: ubuntu-latest
    steps: [{run: echo}]
  b:
    runs-on: ubuntu-latest
    steps: [{run: echo}]
`, "a,b"},
		{"inherit", `on: push
jobs:
  call:
    uses: acme-actions/deploy/.github/workflows/d.yml@main
    secrets: inherit
  b:
    runs-on: ubuntu-latest
    steps: [{run: echo}]
`, "call"},
		{"alias", `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps: &s [{run: "echo ${{ secrets.A }}"}]
  b:
    runs-on: ubuntu-latest
    steps: *s
`, "a,b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(c.wf))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(f.SecretJobs, ","); got != c.want {
				t.Errorf("SecretJobs = %q, want %q", got, c.want)
			}
		})
	}
}

func TestFnmatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"main", "main", true},
		{"main", "mainline", false},
		{"release/*", "release/1.0", true},
		{"release/*", "release/1.0/hotfix", false},
		{"release/*/*", "release/1.0/hotfix", true},
		{"release/**/*", "release/a/b/c", true},
		{"release/**/*", "release/a", true},
		{"v?", "v1", true},
		{"v?", "v10", false},
		{"[mr]ain", "rain", true},
		{"[!m]ain", "main", false},
		{"feat.x", "featyx", false},
		{"[bad", "b", false},
	}
	for _, c := range cases {
		if got := fnmatch(c.pattern, c.name); got != c.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
