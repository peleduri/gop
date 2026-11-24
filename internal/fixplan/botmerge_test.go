package fixplan

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestBuildBlockBotMerge(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	ix := graph.NewIndex(g)
	p := Build(ix, graph.BlockBotMerge{Repo: "repo:acme-app/web"})
	if p.Fix.Type != "block_bot_merge" || p.Fix.Repo != "repo:acme-app/web" || !strings.Contains(p.Description, "acme-app/web") {
		t.Errorf("spec = %+v %q", p.Fix, p.Description)
	}
	if len(p.Steps) != 4 {
		t.Fatalf("steps = %+v", p.Steps)
	}
	want := []struct{ kind, file, change string }{
		{KindChangeSetting, "", "Require a human approval that bots cannot give"},
		{KindChangeSetting, "", "Remove the GitHub App `77` from the bypass actors"},
		{KindEditWorkflow, ".github/workflows/ai-merge.yml", "Do not let PR authors trigger the merge"},
		{KindEditWorkflow, ".github/workflows/ai-review.yml", "Do not give the reviewer write or approve rights"},
	}
	for i, w := range want {
		s := p.Steps[i]
		if s.Kind != w.kind || s.File != w.file || !strings.HasPrefix(s.Change, w.change) || s.Repo != "acme-app/web" || s.Unconfirmed {
			t.Errorf("step %d = %+v", i, s)
		}
	}
	if p.Steps[2].Line != 22 {
		t.Errorf("merge step line = %d, want 22", p.Steps[2].Line)
	}
	if len(p.Removes.PerPrincipal) != 1 || p.Removes.PerPrincipal[0].Principal != "external:anyone" {
		t.Errorf("removes = %+v", p.Removes.PerPrincipal)
	}

	empty := Build(ix, graph.BlockBotMerge{Repo: "repo:acme-app/api"})
	if len(empty.Steps) != 0 || len(empty.Caveats) != 1 {
		t.Errorf("plan for a repo without the path = %+v", empty)
	}
}

// The script variant adds the script, re-review and merge key steps after
// the four that close the path.
func TestBuildBlockBotMergeScript(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge-script/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	p := Build(graph.NewIndex(g), graph.BlockBotMerge{Repo: "repo:acme-app/web"})
	if len(p.Steps) != 7 {
		t.Fatalf("steps = %+v", p.Steps)
	}
	want := []struct{ kind, file, change string }{
		{KindEditWorkflow, "tools/merge.py", "Stop counting DISMISSED reviews"},
		{KindEditWorkflow, ".github/workflows/ai-review.yml", "Re-run the AI review on every push"},
		{KindEditWorkflow, ".github/workflows/ai-review.yml", "Keep the merge key out of the AI step"},
	}
	for i, w := range want {
		s := p.Steps[4+i]
		if s.Kind != w.kind || s.File != w.file || !strings.HasPrefix(s.Change, w.change) {
			t.Errorf("step %d = %+v", 4+i, s)
		}
	}
	if p.Steps[2].Line != 24 {
		t.Errorf("merge step line = %d, want 24", p.Steps[2].Line)
	}
}
