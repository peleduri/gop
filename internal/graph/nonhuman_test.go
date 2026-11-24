package graph

import "testing"

func TestNonHuman(t *testing.T) {
	wf := func(id, conf string) Node {
		return Node{ID: id, Kind: KindWorkflow, Name: id, Attrs: map[string]string{AttrAgent: "claude-code-action", AttrAgentConfidence: conf}}
	}
	g := &Graph{
		Nodes: []Node{
			wf("workflow:acme-app/web/.github/workflows/claude.yml", AgentAction),
			wf("workflow:acme-app/web/.github/workflows/ai-notes.yml", AgentNameOnly), // name only: not counted
			wf("workflow:acme-app/api/.github/workflows/merge.yml", AgentCLI),         // agent and merger: counted once
			{ID: "identity:renovate[bot]", Kind: KindIdentity, Name: "renovate[bot]"},
			{ID: "identity:alice", Kind: KindIdentity, Name: "alice"},
			{ID: "repo:acme-app/api", Kind: KindRepo, Name: "api", Attrs: map[string]string{AttrBotMergeApps: "acme-merge-bot," + AppUnknown}},
			{ID: "repo:acme-app/docs", Kind: KindRepo, Name: "docs"},
		},
		Edges: []Edge{
			{From: "org_members:acme-app", To: "repo:acme-app/api", Kind: CanMergeViaBot, Evidence: Live,
				Attrs: map[string]string{AttrMergeWorkflow: "workflow:acme-app/api/.github/workflows/merge.yml",
					AttrApproveWorkflows: "workflow:acme-app/api/.github/workflows/approve.yml"}},
			{From: "identity:bob", To: "repo:acme-app/api", Kind: CanMergeViaBot, Evidence: NotVisible,
				Attrs: map[string]string{AttrMergeWorkflow: "workflow:acme-app/api/.github/workflows/merge.yml"}},
			{From: "org_members:acme-app", To: "repo:acme-app/docs", Kind: CanMergeViaBot, Evidence: NotVisible,
				Attrs: map[string]string{AttrMergeWorkflow: "workflow:acme-app/docs/.github/workflows/automerge.yml"}},
		},
	}
	got := NewIndex(g).NonHuman()
	// claude.yml, merge.yml, approve.yml, automerge.yml, renovate[bot], acme-merge-bot
	want := NonHuman{Actors: 6, Merge: 2, MergeConfirmed: 1, MergePossible: 1}
	if got != want {
		t.Fatalf("NonHuman() = %+v, want %+v", got, want)
	}
	if h := got.Headline(); h != "6 non-human actors; 2 can merge to a default branch without a human (1 confirmed, 1 possible)." {
		t.Errorf("Headline() = %q", h)
	}
}

func TestNonHumanHeadlineEdges(t *testing.T) {
	for _, c := range []struct {
		nh   NonHuman
		want string
	}{
		{NonHuman{}, "No non-human actors (AI agents, bot merges, bot accounts) in this graph."},
		{NonHuman{Actors: 1}, "1 non-human actor; none can merge to a default branch without a human."},
		{NonHuman{Actors: 2, Merge: 1, MergePossible: 1}, "2 non-human actors; 1 can merge to a default branch without a human (0 confirmed, 1 possible)."},
	} {
		if got := c.nh.Headline(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.nh, got, c.want)
		}
	}
}
