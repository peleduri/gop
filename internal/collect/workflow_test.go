package collect

import (
	"reflect"
	"testing"
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
