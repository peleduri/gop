package redact

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestRedactBotMergeApps: app IDs are replaced by keyed hashes that still
// match between the bypass list and the merge, and the review bypass attrs
// of #164 survive as gop's vocabulary.
func TestRedactBotMergeApps(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/botmerge-script/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Redact(g, Options{Salt: []byte("test-salt")})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range res.Graph.Nodes {
		a := n.Attrs
		if a[graph.AttrReviewBypass] == "" {
			continue
		}
		found = true
		bypass, merge := a[graph.AttrBranchBypassApps], a[graph.AttrBotMergeApps]
		if !strings.HasPrefix(bypass, "app-") || bypass != merge || bypass == "77" {
			t.Errorf("bypass apps %q, merge apps %q", bypass, merge)
		}
		if a[graph.AttrReviewBypassAppMatch] != graph.AppMatched || a[graph.AttrReviewBypassRecount] != graph.StaleSuspected {
			t.Errorf("redacted attrs %v", a)
		}
	}
	if !found {
		t.Fatal("no review bypass after redaction")
	}
	if out, _, ok := appList(&redactor{key: []byte("k")}, attrCtx{}, "unknown,acme-merge"); !ok || !strings.HasPrefix(out, "unknown,app-") {
		t.Errorf("appList = %q, %v", out, ok)
	}
}
