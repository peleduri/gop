package fixplan

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

const (
	acmePath  = "../../testdata/acme/graph.json"
	linesPath = "testdata/lines.json"
	deployRef = "action:acme-actions/deploy@main"
)

func index(t *testing.T, path string) *graph.Index {
	t.Helper()
	g, err := graph.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return graph.NewIndex(g)
}

func edits(p Plan) []Step {
	var out []Step
	for _, s := range p.Steps {
		if s.Kind == KindEditWorkflow {
			out = append(out, s)
		}
	}
	return out
}

func TestPinAcmeListsEveryConsumerSorted(t *testing.T) {
	ix := index(t, acmePath)
	p := Build(ix, graph.PinRef{Action: deployRef})
	var want []string
	for _, e := range ix.In(deployRef) {
		if e.Kind == graph.Uses {
			want = append(want, e.From)
		}
	}
	got := edits(p)
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("got %d edit steps, want %d", len(got), len(want))
	}
	for i, s := range got {
		if i > 0 {
			prev := got[i-1]
			if prev.Repo > s.Repo || (prev.Repo == s.Repo && prev.File > s.File) {
				t.Errorf("steps not sorted by repo then file: %s %s before %s %s", prev.Repo, prev.File, s.Repo, s.File)
			}
		}
		okFile := s.File == ".github/workflows/ci.yml" || (s.Repo == "acme-app/web" && s.File == ".github/workflows/release.yml")
		if !okFile || s.Owner != "acme-app" || s.Line != 0 {
			t.Errorf("step %d: %+v", i, s)
		}
		// The acme fixture predates line attributes: no diff, a note instead.
		if s.Diff != "" || !strings.Contains(s.Note, "line not recorded") || !strings.Contains(s.Note, "acme-actions/deploy@<sha-of-main> # main") {
			t.Errorf("step %d without a line: diff %q note %q", i, s.Diff, s.Note)
		}
	}
	last := p.Steps[len(p.Steps)-1]
	if last.Kind != KindVerify || !strings.Contains(last.Note, "gop pin --action acme-actions/deploy@main") {
		t.Errorf("last step should resolve the SHA: %+v", last)
	}
	if p.Removes.Before.ConfirmedPairs <= p.Removes.After.ConfirmedPairs {
		t.Errorf("pin removes nothing: %+v", p.Removes)
	}
	if !hasCaveat(p, "no line number") {
		t.Errorf("missing no-line caveat: %v", p.Caveats)
	}
}

func hasCaveat(p Plan, sub string) bool {
	for _, c := range p.Caveats {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestPinWithLineAttrs(t *testing.T) {
	ix := index(t, linesPath)
	p := Build(ix, graph.PinRef{Action: deployRef})
	got := edits(p)
	type loc struct {
		repo, file string
		line       int
		unconf     bool
	}
	want := []loc{
		{"acme-actions/tools", ".github/workflows/build.yml", 9, false},
		{"acme-app/api", ".github/workflows/deploy.yml", 10, false},
		{"acme-app/web", ".github/workflows/ci.yml", 8, false},
		{"acme-app/web", ".github/workflows/release.yml", 12, false},
		{"acme-legacy/old-site", ".github/workflows/ci.yml", 0, true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d edit steps: %+v", len(got), got)
	}
	for i, w := range want {
		s := got[i]
		if s.Repo != w.repo || s.File != w.file || s.Line != w.line || s.Unconfirmed != w.unconf {
			t.Errorf("step %d: got %s %s:%d unconfirmed=%v, want %+v", i, s.Repo, s.File, s.Line, s.Unconfirmed, w)
		}
	}
	web := got[2]
	wantDiff := "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -8 +8 @@\n" +
		"-uses: acme-actions/deploy@main\n+uses: acme-actions/deploy@<sha-of-main> # main\n"
	if web.Diff != wantDiff || web.Col != 15 {
		t.Errorf("diff:\n%s\ncol %d", web.Diff, web.Col)
	}
	if !strings.Contains(got[0].Note, "nested") || got[0].FileRef != "main" {
		t.Errorf("reusable workflow consumer not marked nested: %+v", got[0])
	}
	// The not_visible consumer is last among all steps, after the verify step.
	last := p.Steps[len(p.Steps)-1]
	if !last.Unconfirmed || !strings.Contains(last.Note, ConfirmFirst) {
		t.Errorf("not_visible step not last: %+v", last)
	}
	if p.Steps[len(p.Steps)-2].Kind != KindVerify {
		t.Errorf("verify step should precede unconfirmed steps: %+v", p.Steps)
	}
	if !hasCaveat(p, "acme-actions/setup@main (acme-actions/deploy@main action.yml:6)") {
		t.Errorf("missing nested mutable caveat: %v", p.Caveats)
	}
}

func TestLowerDefaultPermListsRepos(t *testing.T) {
	ix := index(t, linesPath)
	p := Build(ix, graph.LowerDefaultPerm{Org: "org:acme-actions", To: "read"})
	var verify []Step
	var setting *Step
	for i, s := range p.Steps {
		switch s.Kind {
		case KindVerify:
			verify = append(verify, s)
		case KindChangeSetting:
			setting = &p.Steps[i]
		}
	}
	if setting == nil || !strings.Contains(setting.Setting, "Base permissions: Read") ||
		setting.API != `PATCH /orgs/acme-actions {"default_repository_permission": "read"}` {
		t.Fatalf("setting step: %+v", setting)
	}
	if len(verify) != 3 || verify[0].Repo != "acme-actions/deploy" || verify[1].Repo != "acme-actions/setup" ||
		verify[2].Repo != "acme-actions/tools" || !verify[2].Unconfirmed {
		t.Fatalf("verify steps: %+v", verify)
	}
	if !strings.Contains(verify[0].Note, "team:acme-actions/platform") {
		t.Errorf("other grants not listed: %s", verify[0].Note)
	}
	if !hasCaveat(p, "acme-actions/deploy, acme-actions/setup, acme-actions/tools [not visible]") {
		t.Errorf("caveat does not list repos: %v", p.Caveats)
	}
	if p.Steps[len(p.Steps)-1].Repo != "acme-actions/tools" {
		t.Errorf("unconfirmed step not last: %+v", p.Steps)
	}
}

func TestLowerNoOpAndUnknownPin(t *testing.T) {
	ix := index(t, linesPath)
	p := Build(ix, graph.LowerDefaultPerm{Org: "org:acme-actions", To: "write"})
	if len(p.Steps) != 0 || len(p.Caveats) != 1 {
		t.Errorf("no-op lower: %+v", p)
	}
	p = Build(ix, graph.PinRef{Action: "action:acme-actions/nothing@main"})
	if len(p.Steps) != 0 || !hasCaveat(p, "no workflow or action in this graph uses") {
		t.Errorf("unused pin: %+v", p)
	}
}

func TestGoldenRender(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		fix        graph.Fix
	}{
		{"pin_lines", linesPath, graph.PinRef{Action: deployRef}},
		{"pin_acme", acmePath, graph.PinRef{Action: deployRef}},
		{"lower_lines", linesPath, graph.LowerDefaultPerm{Org: "org:acme-actions", To: "read"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Build(index(t, tc.path), tc.fix)
			var txt, md, js bytes.Buffer
			WriteText(&txt, p)
			WriteMarkdown(&md, p)
			if err := WriteJSON(&js, p); err != nil {
				t.Fatal(err)
			}
			testutil.Golden(t, tc.name+".txt", txt.Bytes())
			testutil.Golden(t, tc.name+".md", md.Bytes())
			testutil.Golden(t, tc.name+".json", js.Bytes())
		})
	}
}

// TestNoCollectOrNetworkImports asserts fixplan works on a loaded graph only:
// no dependency, direct or transitive, on the collector or a network package.
func TestNoCollectOrNetworkImports(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not found")
	}
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case dep == "github.com/peleduri/gop/internal/collect",
			dep == "github.com/peleduri/gop/internal/mcpserver",
			dep == "net", strings.HasPrefix(dep, "net/"),
			dep == "os/exec":
			t.Errorf("internal/fixplan depends on %s", dep)
		}
	}
}
