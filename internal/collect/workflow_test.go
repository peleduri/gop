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
