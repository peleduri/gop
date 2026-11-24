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
		{KindChangeSetting, "", "Remove the GitHub App from the bypass actors"},
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
