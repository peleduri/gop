package graph

import (
	"strings"
	"testing"
)

const botRepo = "repo:acme-app/web"

func loadBotMerge(t *testing.T) *Graph {
	t.Helper()
	g, err := LoadFile("../../testdata/botmerge/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// withBotEvidence returns g with every CAN_MERGE_VIA_BOT edge at ev, and the
// repo's review_bypass at ev.
func withBotEvidence(g *Graph, ev Evidence) *Graph {
	out := *g
	out.Edges = append([]Edge(nil), g.Edges...)
	for i := range out.Edges {
		if out.Edges[i].Kind == CanMergeViaBot {
			out.Edges[i].Evidence = ev
		}
	}
	out.Nodes = append([]Node(nil), g.Nodes...)
	for i, n := range out.Nodes {
		if n.ID == botRepo {
			ae := map[string]Evidence{}
			for k, v := range n.AttrEvidence {
				ae[k] = v
			}
			ae[AttrReviewBypass] = ev
			out.Nodes[i].AttrEvidence = ae
		}
	}
	return &out
}

// CAN_MERGE_VIA_BOT is a forward control hop: the repo is controlled, so
// its workflows' terminals are reached; BlockBotMerge removes it and is the
// greedy's pick for that reach.
func TestBotMergeReach(t *testing.T) {
	g := loadBotMerge(t)
	ix := NewIndex(g)
	if got := ix.BotMergeRepos(); len(got) != 1 || got[0] != botRepo {
		t.Fatalf("bot merge repos = %v", got)
	}
	r := ix.Reach("external:anyone", Options{})
	p, ok := r.Paths[botRepo]
	if !ok || p.Unverified || len(p.Hops) != 1 || p.Hops[0].Kind != CanMergeViaBot {
		t.Fatalf("path = %+v", p)
	}
	s := ix.BlastRadius("external:anyone")
	if s.BotSelfMerge != 1 || s.Confirmed.Repos != 1 || s.Confirmed.Secrets == 0 {
		t.Errorf("score = %+v", s)
	}

	fix := BlockBotMerge{Repo: botRepo}
	d := ix.WhatIf([]Fix{fix})
	for _, pd := range d.PerPrincipal {
		if pd.Principal == "external:anyone" && pd.After.Confirmed.Repos != 0 {
			t.Errorf("after block_bot_merge: %+v", pd.After)
		}
	}
	if len(FixEdges(ix, fix)) != 1 {
		t.Errorf("fix edges = %v", FixEdges(ix, fix))
	}
	found := false
	for _, sg := range ix.SuggestFixes(50) {
		if sg.FixID == fix.ID() {
			found = true
			if want := d.Before.ConfirmedPairs - d.After.ConfirmedPairs; sg.Removed > want || sg.Removed == 0 {
				t.Errorf("suggestion removes %d, what_if %d", sg.Removed, want)
			}
		}
	}
	if !found {
		t.Error("suggest_fixes does not pick block_bot_merge")
	}
}

// A not_visible bypass makes the path possible: no marker, no fix candidate,
// and a note that says what is unknown.
func TestBotMergePossible(t *testing.T) {
	g := withBotEvidence(loadBotMerge(t), NotVisible)
	for i, n := range g.Nodes {
		if n.ID == botRepo {
			a := map[string]string{}
			for k, v := range n.Attrs {
				a[k] = v
			}
			a[AttrBranchAppBypass] = "unknown"
			g.Nodes[i].Attrs = a
		}
	}
	ix := NewIndex(g)
	s := ix.BlastRadius("external:anyone")
	if s.BotSelfMerge != 0 || s.Confirmed.Repos != 0 || s.Possible.Repos != 1 {
		t.Errorf("score = %+v", s)
	}
	for _, c := range ix.Candidates() {
		if _, ok := c.(BlockBotMerge); ok {
			t.Errorf("candidate %s for a not_visible edge", c.ID())
		}
	}
	n, _ := ix.Node(botRepo)
	if got := BotMergeNote(n); !strings.HasPrefix(got, "a PR author may get code onto `main` without human review (the bypass list is not visible)") {
		t.Errorf("note = %q", got)
	}
}

func TestBotMergeNoteAndFixes(t *testing.T) {
	n := Node{ID: "repo:acme-app/api", Kind: KindRepo, Attrs: map[string]string{"default_branch": "trunk", AttrBranchProtected: "true",
		AttrReviewBypass: ReviewBypassBotSelfMerge, AttrReviewBypassReason: ReviewBypassApprovals,
		AttrReviewBypassMerge: ".github/workflows/merge.yml"}}
	if got, want := BotMergeNote(n), "a PR author can get code onto `trunk` without human review: `merge.yml`"; got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
	fx := BotMergeFixes(n)
	if len(fx) != 4 || !strings.Contains(fx[1], "keep apps and admins out of the bypass actors") || !strings.Contains(fx[2], "`merge.yml`") {
		t.Errorf("fixes = %q", fx)
	}
	if BotMergeFixes(Node{Kind: KindRepo}) != nil || BotMergeNote(Node{Kind: KindRepo}) != "" {
		t.Error("fixes or note for a repo without a review bypass")
	}
}
