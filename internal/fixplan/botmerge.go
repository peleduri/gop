package fixplan

import (
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// buildBotMerge plans the changes that close a repo's AI approve +
// self-merge path (graph.BotMergeFixes): the branch rule first, then the
// merge workflow, then the approving workflows. Any one of the first three
// removes the CAN_MERGE_VIA_BOT edges; the plan lists them all.
func buildBotMerge(ix *graph.Index, f graph.BlockBotMerge, p *Plan) {
	repo := strings.TrimPrefix(f.Repo, "repo:")
	edges := graph.FixEdges(ix, f)
	if len(edges) == 0 {
		p.Caveats = append(p.Caveats, "this graph records no CAN_MERGE_VIA_BOT edge into "+repo+": there is nothing to change")
		return
	}
	n, _ := ix.Node(f.Repo)
	fixes := graph.BotMergeFixes(n)
	ev, unconfirmed := graph.NotVisible, true
	for _, e := range edges {
		if graph.Verified(e.Evidence) {
			ev, unconfirmed = graph.Live, false
		}
	}
	first := edges[0]
	step := func(s Step) {
		s.Repo, s.Owner, s.Edge, s.Evidence, s.Unconfirmed = repo, ownerOf(repo), edgeLabel(first), ev, unconfirmed
		if unconfirmed {
			s.Note = ConfirmFirst
		}
		p.Steps = append(p.Steps, s)
	}
	if len(fixes) > 0 {
		step(Step{Kind: KindChangeSetting, Change: fixes[0],
			Setting: "Settings > Rules > Rulesets > (the default branch ruleset) > Require a pull request before merging > Require review from Code Owners",
			API:     "PUT /repos/" + repo + "/rulesets/{ruleset_id}"})
	}
	if len(fixes) > 1 {
		step(Step{Kind: KindChangeSetting, Change: fixes[1],
			Setting: "Settings > Rules > Rulesets > (each default branch ruleset) > Bypass list",
			API:     "PUT /repos/" + repo + "/rulesets/{ruleset_id} (bypass_actors)"})
	}
	if m := first.Attrs[graph.AttrMergeWorkflow]; m != "" && len(fixes) > 2 {
		_, file := workflowLoc(ix, m)
		s := Step{Kind: KindEditWorkflow, File: file, Change: fixes[2],
			FileRef: first.Attrs[graph.AttrFileRef], Line: atoi(first.Attrs[graph.AttrLine])}
		if v := first.Attrs[graph.AttrFile]; v != "" {
			s.File = v
		}
		step(s)
	}
	if len(fixes) > 3 {
		for _, a := range splitList(first.Attrs[graph.AttrApproveWorkflows]) {
			_, file := workflowLoc(ix, a)
			step(Step{Kind: KindEditWorkflow, File: file, Change: fixes[3]})
		}
	}
	p.Caveats = append(p.Caveats, "Any one of the first three changes closes the path; the approving workflow change alone does not when the merging app bypasses the rules.")
}
