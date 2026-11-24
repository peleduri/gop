package report

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// TestRenderBotMerge: the AI approve + self-merge section names the repo,
// the chain, who can use it and the fixes, and the risks table marks the
// principal that lands code through it.
func TestRenderBotMerge(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	md := render(t, g, "md")
	testutil.Golden(t, "botmerge.md", []byte(md), "dev")
	i := strings.Index(md, "## AI approve + self-merge")
	if i < 0 {
		t.Fatal("no AI approve + self-merge section")
	}
	sec := md[i:]
	for _, want := range []string{
		"### acme-app/web",
		"a PR author can get code onto \\`main\\` without human review: \\`ai-review.yml\\` + \\`ai-merge.yml\\`",
		"- Who: external:anyone",
		"- Why no human review: app\\_bypass",
		"Remove the GitHub App from the bypass actors",
		"Do not let PR authors trigger the merge",
		"Do not give the reviewer write or approve rights",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q", want)
		}
	}
	if !strings.Contains(md, "external:anyone can get code onto the default branch of 1 repo without human review [bot_self_merge]") {
		t.Error("risks table does not mark the bot self-merge principal")
	}

	acme, err := graph.LoadFile("../../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(render(t, acme, "md"), "self-merge") {
		t.Error("section rendered without a review bypass")
	}
}
