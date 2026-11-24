package collect

import (
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestPolicyFilesOwnership: in a repo where a bot can merge, CODEOWNERS
// decides which policy files a pull request can edit without a code owner.
func TestPolicyFilesOwnership(t *testing.T) {
	for _, mode := range []struct {
		name string
		rest bool
	}{{"graphql", false}, {"rest", true}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			botPlant(t, f, 1, false, false, actor("Integration", 77))
			f.extraFiles["acme-app/web/.github/CODEOWNERS"] = "/AGENTS.md @acme-app/security\n"
			f.extraFiles["acme-app/web/.github/copilot-instructions.md"] = "Be brief.\n"
			ix := collectMode(t, f, mode.rest)
			repo := ix.node(t, botRepo)
			wantAttrs(t, mode.name, repo, map[string]string{
				graph.AttrPolicyFiles:        ".github/copilot-instructions.md,AGENTS.md,REVIEW.md",
				graph.AttrPolicyFilesUnowned: ".github/copilot-instructions.md,REVIEW.md",
			})
			if got := graph.SelfEditablePolicy(repo); len(got) != 2 {
				t.Errorf("SelfEditablePolicy = %v", got)
			}
		})
	}
}

// TestPolicyFilesAllOwned: a catch-all CODEOWNERS rule owns every policy file.
func TestPolicyFilesAllOwned(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 1, false, false, actor("Integration", 77))
	f.extraFiles["acme-app/web/CODEOWNERS"] = "* @acme-app/maintainers\n"
	ix := collectMode(t, f, false)
	repo := ix.node(t, botRepo)
	wantAttrs(t, "graphql", repo, map[string]string{graph.AttrPolicyFilesUnowned: "none"})
	if got := graph.SelfEditablePolicy(repo); got != nil {
		t.Errorf("SelfEditablePolicy = %v, want nil", got)
	}
}

func TestCodeownersOwns(t *testing.T) {
	co := ParseCodeowners([]byte("* @acme/all\n/.cursor/ @acme/ai\n/REVIEW.md\n"))
	for path, want := range map[string]bool{
		"AGENTS.md":             true,  // catch-all
		".cursor/rules/gop.mdc": true,  // directory rule
		"REVIEW.md":             false, // the last matching rule names no owner
	} {
		if got := co.Owns(path); got != want {
			t.Errorf("Owns(%q) = %v, want %v", path, got, want)
		}
	}
	if (Codeowners{}).Owns("AGENTS.md") {
		t.Error("no CODEOWNERS owns nothing")
	}
}

func TestSelfEditablePolicyNeedsBypass(t *testing.T) {
	n := graph.Node{Kind: graph.KindRepo, Attrs: map[string]string{graph.AttrPolicyFilesUnowned: "AGENTS.md"}}
	if graph.SelfEditablePolicy(n) != nil {
		t.Error("a repo without a review bypass is not flagged")
	}
	n.Attrs[graph.AttrReviewBypass] = graph.ReviewBypassBotSelfMerge
	if got := graph.SelfEditablePolicy(n); len(got) != 1 || got[0] != "AGENTS.md" {
		t.Errorf("got %v", got)
	}
	n.Attrs[graph.AttrPolicyFilesUnowned] = "unknown"
	if graph.SelfEditablePolicy(n) != nil || !graph.PolicyUnknown(n) {
		t.Error("unknown ownership: not flagged, PolicyUnknown true")
	}
}
