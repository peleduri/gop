package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestRefKind(t *testing.T) {
	cases := map[string]string{
		testSHA:      "sha",
		"v1":         "tag",
		"v4.1.0":     "tag",
		"1.2.3":      "tag",
		"2.0":        "tag",
		"main":       "branch",
		"release/v1": "branch",
		"version":    "branch",
		"0123abc":    "branch",
	}
	for ref, want := range cases {
		if got := RefKind(ref); got != want {
			t.Errorf("RefKind(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestParseUses(t *testing.T) {
	u, ok := ParseUses("acme-actions/setup/.github/workflows/build.yml@main")
	if !ok || u.Owner != "acme-actions" || u.Repo != "setup" || u.Path != ".github/workflows/build.yml" ||
		u.Ref != "main" || !u.IsReusableWorkflow() {
		t.Errorf("got %+v ok=%v", u, ok)
	}
	for _, bad := range []string{"./local", "docker://alpine:3", "noref", "acme-actions@main", "acme/x@", ""} {
		if _, ok := ParseUses(bad); ok {
			t.Errorf("ParseUses(%q) should be skipped", bad)
		}
	}
}

func TestParseWorkflow(t *testing.T) {
	src := []byte(`
on: push
permissions: write-all
jobs:
  a:
    runs-on: {group: build, labels: [self-hosted, gpu]}
    steps:
      - uses: acme-actions/deploy@v1
      - run: echo ${{ secrets.API_KEY }} ${{ secrets.GITHUB_TOKEN }} ${{ secrets[matrix.name] }}
  b:
    uses: acme-actions/setup/.github/workflows/build.yml@main
    secrets: inherit
`)
	f, err := ParseWorkflow(src)
	if err != nil {
		t.Fatal(err)
	}
	if !f.IDTokenWrite || !f.SelfHosted || !f.InheritsSecrets {
		t.Errorf("facts = %+v", f)
	}
	if !reflect.DeepEqual(f.Secrets, []string{"*", "API_KEY"}) {
		t.Errorf("secrets = %v", f.Secrets)
	}
	if len(f.Uses) != 2 || f.Uses[0].Level != LevelStep || f.Uses[1].Level != LevelJob {
		t.Errorf("uses = %+v", f.Uses)
	}
	if _, err := ParseWorkflow([]byte("jobs: [unclosed")); err == nil {
		t.Error("expected parse error")
	}
}

func TestParseCompositeAction(t *testing.T) {
	uses, using, err := ParseCompositeAction([]byte("runs:\n  using: node20\n  main: index.js\n"))
	if err != nil || using != "node20" || len(uses) != 0 {
		t.Errorf("node action: %v %q %v", uses, using, err)
	}
}

func TestParseWorkflowPositions(t *testing.T) {
	type pos struct {
		raw       string
		line, col int
	}
	cases := []struct {
		name       string
		src        string
		uses       []pos
		idToken    map[string]int
		runsOnLine int
	}{
		{
			name: "block style step and job",
			src: `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: acme-actions/deploy@main
      - run: echo hi
      -   uses: "acme-actions/setup@v1"
  b:
    uses: acme-actions/setup/.github/workflows/build.yml@main
`,
			uses: []pos{
				{"acme-actions/deploy@main", 9, 15},
				{"acme-actions/setup@v1", 11, 17},
				{"acme-actions/setup/.github/workflows/build.yml@main", 13, 11},
			},
			idToken: map[string]int{"a": 7},
		},
		{
			name: "flow style",
			src: `on: push
permissions: write-all
jobs:
  a: {runs-on: [self-hosted, linux], steps: [{uses: acme-actions/deploy@main}, {run: x}]}
  b:
    runs-on:
      - self-hosted
    steps: [{uses: acme-actions/setup@main}]
`,
			uses: []pos{
				{"acme-actions/deploy@main", 4, 53},
				{"acme-actions/setup@main", 8, 20},
			},
			idToken:    map[string]int{"workflow": 2},
			runsOnLine: 4,
		},
		{
			name: "multi-document: first document only, lines from file start",
			src: `---
on: push
jobs:
  a:
    runs-on:
      - self-hosted
    steps:
      - uses: acme-actions/deploy@main
---
jobs:
  z:
    steps:
      - uses: acme-actions/other@main
`,
			uses:       []pos{{"acme-actions/deploy@main", 8, 15}},
			idToken:    map[string]int{},
			runsOnLine: 5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			var got []pos
			for _, u := range f.Uses {
				got = append(got, pos{u.Raw, u.Line, u.Column})
			}
			if !reflect.DeepEqual(got, tc.uses) {
				t.Errorf("uses = %+v, want %+v", got, tc.uses)
			}
			if !reflect.DeepEqual(f.IDTokenLines, tc.idToken) {
				t.Errorf("id-token lines = %v, want %v", f.IDTokenLines, tc.idToken)
			}
			if f.RunsOnLine != tc.runsOnLine {
				t.Errorf("runs-on line = %d, want %d", f.RunsOnLine, tc.runsOnLine)
			}
		})
	}
}

func TestCompositeActionPositions(t *testing.T) {
	uses, _, err := ParseCompositeAction([]byte("runs:\n  using: composite\n  steps:\n    - uses: acme-actions/setup@main\n"))
	if err != nil || len(uses) != 1 || uses[0].Line != 4 || uses[0].Column != 13 {
		t.Errorf("composite uses = %+v err=%v", uses, err)
	}
}

func TestParseWorkflowTokenPermissions(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		want   string
		write  []string
		deflt  []string
		scopes []string
	}{
		{
			name:  "no permissions takes the default",
			src:   "on: push\njobs:\n  a:\n    runs-on: x\n  b:\n    runs-on: x\n",
			want:  TokenDefault,
			deflt: []string{"a", "b"},
		},
		{
			name:  "workflow contents write",
			src:   "permissions:\n  contents: write\njobs:\n  a:\n    runs-on: x\n",
			want:  TokenWrite,
			write: []string{"a"},
		},
		{
			name: "workflow write-all replaced by job contents read on every job",
			src: "permissions: write-all\njobs:\n  a:\n    permissions: {contents: read}\n" +
				"  b:\n    permissions:\n      contents: read\n",
			want: TokenRead,
		},
		{
			name:  "job {} plus a job with no key and no workflow key",
			src:   "jobs:\n  a:\n    permissions: {}\n  b:\n    runs-on: x\n",
			want:  TokenDefault,
			deflt: []string{"b"},
		},
		{
			name: "read-all",
			src:  "permissions: read-all\njobs:\n  a:\n    runs-on: x\n",
			want: TokenRead,
		},
		{
			name:   "id-token only: contents omitted means none",
			src:    "permissions: {id-token: write}\njobs:\n  a:\n    runs-on: x\n",
			want:   TokenRead,
			scopes: []string{"id-token"},
		},
		{
			name:   "write-all on one job, read on another",
			src:    "permissions: {contents: read}\njobs:\n  a:\n    runs-on: x\n  b:\n    permissions: write-all\n",
			want:   TokenWrite,
			write:  []string{"b"},
			scopes: []string{"write-all"},
		},
		{
			name:   "write beats default; other write scopes recorded",
			src:    "jobs:\n  a:\n    runs-on: x\n  b:\n    permissions: {contents: write, packages: write, pull-requests: read}\n",
			want:   TokenWrite,
			write:  []string{"b"},
			deflt:  []string{"a"},
			scopes: []string{"packages"},
		},
		{
			name: "null permissions is none",
			src:  "permissions:\njobs:\n  a:\n    runs-on: x\n",
			want: TokenRead,
		},
		{
			name: "no jobs",
			src:  "on: push\n",
			want: TokenRead,
		},
		{
			name:  "aliased permissions",
			src:   "x: &w {contents: write}\npermissions: *w\njobs:\n  a:\n    runs-on: x\n",
			want:  TokenWrite,
			write: []string{"a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if f.TokenContentsWrite != tc.want {
				t.Errorf("token contents = %q, want %q", f.TokenContentsWrite, tc.want)
			}
			if !reflect.DeepEqual(f.TokenWriteJobs, tc.write) {
				t.Errorf("write jobs = %v, want %v", f.TokenWriteJobs, tc.write)
			}
			if !reflect.DeepEqual(f.TokenDefaultJobs, tc.deflt) {
				t.Errorf("default jobs = %v, want %v", f.TokenDefaultJobs, tc.deflt)
			}
			if !reflect.DeepEqual(f.TokenScopes, tc.scopes) {
				t.Errorf("scopes = %v, want %v", f.TokenScopes, tc.scopes)
			}
		})
	}
}

func TestParseWorkflowIDTokenJobs(t *testing.T) {
	fixture := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("testdata", "oidc", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cases := []struct {
		name   string
		src    string
		jobs   []IDTokenJob
		scopes []string
		lines  map[string]int
		envs   []string
	}{
		{
			name:  "workflow write-all overridden by the only job",
			src:   fixture("override.yml"),
			lines: map[string]int{},
		},
		{
			name: "workflow write-all overridden by one job of two",
			src: `permissions: write-all
jobs:
  a:
    runs-on: x
    permissions:
      contents: read
  b:
    runs-on: x
`,
			jobs:   []IDTokenJob{{Job: "b", Line: 1}},
			scopes: []string{"workflow"},
			lines:  map[string]int{"workflow": 1},
		},
		{
			name: "workflow id-token with no job overrides",
			src: `permissions:
  id-token: write
jobs:
  a:
    runs-on: x
  b:
    runs-on: x
`,
			jobs:   []IDTokenJob{{Job: "a", Line: 2}, {Job: "b", Line: 2}},
			scopes: []string{"workflow"},
			lines:  map[string]int{"workflow": 2},
		},
		{
			name: "workflow id-token with no jobs",
			src: `permissions:
  id-token: write
jobs: {}
`,
			lines: map[string]int{},
		},
		{
			name: "empty job permissions remove a workflow grant",
			src: `permissions:
  id-token: write
jobs:
  a:
    runs-on: x
    permissions: {}
`,
			lines: map[string]int{},
		},
		{
			name: "job-level grant next to a workflow-level one",
			src: `permissions:
  id-token: write
jobs:
  a:
    runs-on: x
  b:
    runs-on: x
    permissions:
      id-token: write
  c:
    runs-on: x
    permissions: read-all
`,
			jobs:   []IDTokenJob{{Job: "a", Line: 2}, {Job: "b", Line: 9}},
			scopes: []string{"workflow", "b"},
			lines:  map[string]int{"workflow": 2, "b": 9},
		},
		{
			name:   "environment on the id-token job only",
			src:    fixture("environments.yml"),
			jobs:   []IDTokenJob{{Job: "deploy", Environment: "prod", Line: 13}},
			scopes: []string{"deploy"},
			lines:  map[string]int{"deploy": 13},
			envs:   []string{"prod"},
		},
		{
			name: "environment mapping form, and an environment without id-token",
			src: `jobs:
  a:
    runs-on: x
    environment: {name: staging, url: https://acme.example}
    permissions: {id-token: write}
  b:
    runs-on: x
    environment: prod
`,
			jobs:   []IDTokenJob{{Job: "a", Environment: "staging", Line: 5}},
			scopes: []string{"a"},
			lines:  map[string]int{"a": 5},
			envs:   []string{"staging"},
		},
		{
			name:   "environment expression is dynamic",
			src:    fixture("dynamic.yml"),
			jobs:   []IDTokenJob{{Job: "promote", Environment: "${{ inputs.target }}", EnvironmentDynamic: true, Line: 8}},
			scopes: []string{"workflow"},
			lines:  map[string]int{"workflow": 8},
			envs:   []string{graph.EnvDynamic},
		},
		{
			name: "environment through an alias",
			src: `x: &env {name: prod}
jobs:
  a:
    runs-on: x
    environment: *env
    permissions: write-all
`,
			jobs:   []IDTokenJob{{Job: "a", Environment: "prod", Line: 6}},
			scopes: []string{"a"},
			lines:  map[string]int{"a": 6},
			envs:   []string{"prod"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if f.IDTokenWrite != (len(tc.jobs) > 0) {
				t.Errorf("IDTokenWrite = %v, want %v", f.IDTokenWrite, len(tc.jobs) > 0)
			}
			if !reflect.DeepEqual(f.IDTokenJobs, tc.jobs) {
				t.Errorf("IDTokenJobs = %+v, want %+v", f.IDTokenJobs, tc.jobs)
			}
			if !reflect.DeepEqual(f.IDTokenScopes, tc.scopes) {
				t.Errorf("IDTokenScopes = %q, want %q", f.IDTokenScopes, tc.scopes)
			}
			if !reflect.DeepEqual(f.IDTokenLines, tc.lines) {
				t.Errorf("IDTokenLines = %v, want %v", f.IDTokenLines, tc.lines)
			}
			if got := f.IDTokenEnvironments(); !reflect.DeepEqual(got, tc.envs) {
				t.Errorf("IDTokenEnvironments = %q, want %q", got, tc.envs)
			}
		})
	}
}

func TestClaimRef(t *testing.T) {
	cases := map[[2]string]string{
		{"main", "branch"}:            "refs/heads/main",
		{"v1", "tag"}:                 "refs/tags/v1",
		{testSHA, "sha"}:              testSHA,
		{"refs/heads/main", "branch"}: "refs/heads/main",
	}
	for in, want := range cases {
		if got := claimRef(in[0], in[1]); got != want {
			t.Errorf("claimRef(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
