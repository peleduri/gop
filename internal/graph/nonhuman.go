package graph

import (
	"fmt"
	"strings"
)

// NonHuman counts the non-human actors in a graph and those that can land
// code on a default branch with no human review.
type NonHuman struct {
	// Actors is the number of distinct non-human actors: confirmed AI agent
	// workflows, workflows that approve or merge through a bot, review
	// bypass Apps and bot accounts ([bot] logins).
	Actors int `json:"actors"`
	// Merge is the number of merging workflows on CAN_MERGE_VIA_BOT edges;
	// MergeConfirmed of them have a verified edge, MergePossible only
	// not_visible ones.
	Merge          int `json:"merge"`
	MergeConfirmed int `json:"merge_confirmed"`
	MergePossible  int `json:"merge_possible"`
}

// NonHuman counts the graph's non-human actors. Each actor counts once: a
// workflow that runs an agent and also merges is one actor.
func (ix *Index) NonHuman() NonHuman {
	actors := map[string]bool{}
	for _, id := range ix.AgentWorkflows() {
		if n, ok := ix.Node(id); ok && AgentConfirmed(n) {
			actors[id] = true
		}
	}
	merge := map[string]bool{} // merging workflow -> has a verified edge
	for _, e := range ix.g.Edges {
		if e.Kind != CanMergeViaBot {
			continue
		}
		for _, w := range splitAttr(e.Attrs[AttrApproveWorkflows]) {
			actors[w] = true
		}
		w := e.Attrs[AttrMergeWorkflow]
		if w == "" {
			continue
		}
		actors[w] = true
		merge[w] = merge[w] || Verified(e.Evidence)
	}
	for _, n := range ix.g.Nodes {
		switch n.Kind {
		case KindIdentity:
			if strings.HasSuffix(strings.ToLower(n.Name), "[bot]") {
				actors["bot:"+strings.ToLower(n.Name)] = true
			}
		case KindRepo:
			for _, app := range splitAttr(n.Attrs[AttrBotMergeApps]) {
				if app != AppUnknown {
					actors["app:"+strings.ToLower(app)] = true
				}
			}
		}
	}
	nh := NonHuman{Actors: len(actors), Merge: len(merge)}
	for _, ok := range merge {
		if ok {
			nh.MergeConfirmed++
		} else {
			nh.MergePossible++
		}
	}
	return nh
}

// Headline is the one-line summary of the non-human actors.
func (nh NonHuman) Headline() string {
	if nh.Actors == 0 {
		return "No non-human actors (AI agents, bot merges, bot accounts) in this graph."
	}
	actors := "non-human actors"
	if nh.Actors == 1 {
		actors = "non-human actor"
	}
	if nh.Merge == 0 {
		return fmt.Sprintf("%d %s; none can merge to a default branch without a human.", nh.Actors, actors)
	}
	return fmt.Sprintf("%d %s; %d can merge to a default branch without a human (%d confirmed, %d possible).",
		nh.Actors, actors, nh.Merge, nh.MergeConfirmed, nh.MergePossible)
}
