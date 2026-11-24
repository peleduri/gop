package collect

import (
	"slices"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestMergeApps(t *testing.T) {
	cases := []struct {
		name, yaml string
		want       []string
		scripts    map[string]*scriptFacts
	}{
		{"a literal app-id", readBotFixture(t, "ai-merge.yml"), []string{"77"}, nil},
		{"a vars reference: unknown", strings.Replace(readBotFixture(t, "ai-merge.yml"), "app-id: 77", "app-id: ${{ vars.MERGE_APP_ID }}", 1),
			[]string{graph.AppUnknown}, nil},
		{"an env indirection and a slug", `on: issue_comment
env:
  BOT_APP: "123456"
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - id: a
        uses: tibdex/github-app-token@v2
        with:
          app_id: ${{ env.BOT_APP }}
          private_key: ${{ secrets.BOT_KEY }}
      - id: b
        uses: actions/create-github-app-token@v2
        with:
          app-slug: Acme-Merge
          private-key: ${{ secrets.OTHER_KEY }}
      - run: gh pr merge 1 --squash
        env:
          GH_TOKEN: ${{ steps.a.outputs.token }}
      - run: gh pr merge 2 --squash
        env:
          GH_TOKEN: ${{ steps.b.outputs.token }}
`, []string{"123456", "acme-merge"}, nil},
		{"a script with a private key beside a literal APP_ID", readBotFixture(t, "script/ai-merge.yml"), []string{"77"},
			map[string]*scriptFacts{botScriptPath: {merge: true, app: true}}},
		{"not an App token: no apps", `on: issue_comment
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge 1 --squash
        env:
          GH_TOKEN: ${{ secrets.MERGE_PAT }}
`, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bf := parseBotFacts([]byte(c.yaml), []string{"issue_comment"}, c.scripts)
			if bf == nil {
				t.Fatal("no bot facts")
			}
			if !slices.Equal(bf.MergeApps, c.want) {
				t.Errorf("MergeApps = %q, want %q", bf.MergeApps, c.want)
			}
		})
	}
}

func TestBypassApps(t *testing.T) {
	src := func(apps map[int64]string) protSource { return protSource{app: "true", apps: apps} }
	for _, c := range []struct {
		name    string
		sources []protSource
		want    string
	}{
		{"one ruleset", []protSource{src(map[int64]string{77: "", 5: "acme-ci"})}, "5:acme-ci,77"},
		{"slug from another source", []protSource{src(map[int64]string{77: ""}), src(map[int64]string{77: "acme-merge", 9: ""})}, "77:acme-merge"},
		{"no common App", []protSource{src(map[int64]string{77: ""}), src(map[int64]string{9: ""})}, ""},
		{"a list gop could not read", []protSource{src(map[int64]string{77: ""}), src(nil)}, ""},
	} {
		if got := bypassApps(c.sources); got != c.want {
			t.Errorf("%s: bypassApps = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAppMatch(t *testing.T) {
	for _, c := range []struct{ bypass, merge, want string }{
		{"77", "77", graph.AppMatched},
		{"77:acme-merge", "acme-merge", graph.AppMatched},
		{"77", "unknown,77", graph.AppMatched},
		{"77", "88", graph.AppUnmatched},
		{"77", "unknown", graph.AppUnknown},
		{"77", "88,unknown", graph.AppUnknown},
		{"", "77", graph.AppUnknown},
		{"77", "", graph.AppUnknown},
	} {
		if got := appMatch(c.bypass, c.merge); got != c.want {
			t.Errorf("appMatch(%q, %q) = %q, want %q", c.bypass, c.merge, got, c.want)
		}
	}
}

// The merge mints a token for an App that is not the bypass actor, and the
// bot approvals do not meet the required reviews: possible, not confirmed.
func TestBotSelfMergeAppUnmatched(t *testing.T) {
	for _, mode := range []struct {
		name string
		rest bool
	}{{"graphql", false}, {"rest", true}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			botPlant(t, f, 2, false, false, actor("Integration", 88))
			ix := collectMode(t, f, mode.rest)
			repo := ix.node(t, botRepo)
			wantAttrs(t, mode.name, repo, map[string]string{
				graph.AttrBranchBypassApps: "88", graph.AttrBotMergeApps: "77",
				graph.AttrReviewBypass: graph.ReviewBypassBotSelfMerge, graph.AttrReviewBypassReason: graph.ReviewBypassApp,
				graph.AttrReviewBypassAppMatch: graph.AppUnmatched,
			})
			if repo.AttrEvidence[graph.AttrReviewBypass] != graph.NotVisible || repo.AttrEvidence[graph.AttrReviewBypassAppMatch] != graph.NotVisible {
				t.Errorf("evidence = %v, want review_bypass and its app match not_visible", repo.AttrEvidence)
			}
			if e := ix.mustEdge(t, externalAnyone, botRepo, graph.CanMergeViaBot); e.Evidence != graph.NotVisible {
				t.Errorf("edge evidence = %s, want not_visible", e.Evidence)
			}
			found := false
			for _, c := range ix.g.Coverage {
				if c.Scope == botRepo && c.Fact == graph.FactReviewBypass {
					found = strings.Contains(c.Reason, "GitHub App 77, which is not one of the bypass Apps gop read (88)")
				}
			}
			if !found {
				t.Errorf("no review_bypass coverage entry naming the unmatched App: %+v", ix.g.Coverage)
			}
			gx := graph.NewIndex(ix.g)
			p := gx.Reach(externalAnyone, graph.Options{}).Paths[botRepo]
			if !p.Unverified {
				t.Errorf("path = %+v, want possible", p)
			}
			if n := gx.PathNotes(p); len(n) != 1 || !strings.Contains(n[0], "the merging App is not one of the bypass Apps gop read") {
				t.Errorf("notes = %q", n)
			}
			if fx := graph.BotMergeFixes(repo); !strings.Contains(fx[1], "Check which GitHub App") {
				t.Errorf("fixes = %q", fx)
			}
		})
	}
}

// The workflow does not name its App (a vars reference): possible.
func TestBotSelfMergeAppUnnamed(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 2, false, false, actor("Integration", 77))
	f.extraWorkflows["acme-app/web/ai-merge.yml"] = strings.Replace(readBotFixture(t, "ai-merge.yml"), "app-id: 77", "app-id: ${{ vars.MERGE_APP_ID }}", 1)
	ix := collectFake(t, f)
	repo := ix.node(t, botRepo)
	wantAttrs(t, "", repo, map[string]string{
		graph.AttrBotMergeApps: graph.AppUnknown, graph.AttrReviewBypassAppMatch: graph.AppUnknown,
		graph.AttrReviewBypass: graph.ReviewBypassBotSelfMerge,
	})
	if repo.AttrEvidence[graph.AttrReviewBypass] != graph.NotVisible {
		t.Error("review_bypass is live, want not_visible for an App the workflow does not name")
	}
	gx := graph.NewIndex(ix.g)
	if s := gx.BlastRadius(externalAnyone); s.BotSelfMerge != 0 {
		t.Errorf("bot_self_merge = %d for a possible path, want 0", s.BotSelfMerge)
	}
	if n := gx.PathNotes(gx.Reach(externalAnyone, graph.Options{}).Paths[botRepo]); len(n) != 1 || !strings.Contains(n[0], "may get code onto") {
		t.Errorf("notes = %q", n)
	}
}

// A matched App with more approvals required than the bots give: still
// confirmed through the bypass, and the fix names the App.
func TestBotSelfMergeAppMatched(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 2, false, false, actor("Integration", 77))
	ix := collectFake(t, f)
	repo := ix.node(t, botRepo)
	wantAttrs(t, "", repo, map[string]string{
		graph.AttrReviewBypassReason: graph.ReviewBypassApp, graph.AttrReviewBypassAppMatch: graph.AppMatched,
	})
	if repo.AttrEvidence[graph.AttrReviewBypass] == graph.NotVisible {
		t.Error("review_bypass not_visible, want live for a matched App")
	}
	if fx := graph.BotMergeFixes(repo); !strings.Contains(fx[1], "Remove the GitHub App `77` from the bypass actors") {
		t.Errorf("fixes = %q", fx)
	}
}

// A possible CAN_MERGE_VIA_BOT path changes only the scores of the
// principals it starts from.
func TestBotSelfMergeUnmatchedScoresUnrelated(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 2, false, false, actor("Integration", 88))
	ix := collectFake(t, f)
	without := *ix.g
	without.Edges = nil
	from := map[string]bool{}
	for _, e := range ix.g.Edges {
		if e.Kind == graph.CanMergeViaBot {
			from[e.From] = true
			continue
		}
		without.Edges = append(without.Edges, e)
	}
	if len(from) == 0 {
		t.Fatal("no CAN_MERGE_VIA_BOT edge")
	}
	before := map[string]graph.Score{}
	for _, s := range graph.NewIndex(&without).Scores() {
		before[s.Principal] = s
	}
	for _, a := range graph.NewIndex(ix.g).Scores() {
		if from[a.Principal] {
			if a.Confirmed != before[a.Principal].Confirmed {
				t.Errorf("%s: confirmed reach changed through a possible path", a.Principal)
			}
			continue
		}
		b, ok := before[a.Principal]
		if !ok || a.Confirmed != b.Confirmed || a.Possible != b.Possible || a.Score != b.Score {
			t.Errorf("%s changed: %+v -> %+v", a.Principal, b, a)
		}
	}
}

// botTokenPlant: an AI review that approves with GITHUB_TOKEN on
// pull_request_target and a #ai-merge comment merge with a PAT, one
// required review and no bypass actor.
func botTokenPlant(t *testing.T, f *fakeGitHub, canApprove *bool, forbid bool) {
	t.Helper()
	botPlant(t, f, 1, false, true)
	f.extraWorkflows["acme-app/web/ai-review.yml"] = `on: pull_request_target
permissions:
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr review "$PR" --approve
        env:
          GH_TOKEN: ${{ github.token }}
          PR: ${{ github.event.pull_request.number }}
`
	f.extraWorkflows["acme-app/web/ai-merge.yml"] = strings.Replace(readBotFixture(t, "ai-merge.yml"), "GH_TOKEN: ${{ steps.app.outputs.token }}", "GH_TOKEN: ${{ secrets.MERGE_PAT }}", 1)
	fields := map[string]any{"visibility": "public", "default_branch": "main"}
	if canApprove != nil {
		fields["actions_can_approve_pull_request_reviews"] = *canApprove
	}
	fields["actions_workflow_permissions_forbidden"] = forbid
	setRepoFields(t, f, "acme-app", "web", fields)
}

// The "Allow GitHub Actions to create and approve pull requests" setting
// decides a GITHUB_TOKEN approval: on confirms the bypass, off rules it
// out, and a setting gop cannot read leaves it possible.
func TestBotSelfMergeActionsCanApprove(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name       string
		canApprove *bool
		forbid     bool // the repo setting answers 403
		hideOrg    bool // and the org setting too
		attr       string
		attrEv     graph.Evidence
		bypass     bool
		bypassEv   graph.Evidence
	}{
		{"allowed", &yes, false, false, "true", graph.Live, true, graph.Live},
		{"not allowed", &no, false, false, "false", graph.Live, false, ""},
		{"repo refused, org does not allow it", &yes, true, false, "false", graph.Live, false, ""},
		{"not visible", &yes, true, true, "unknown", graph.NotVisible, true, graph.NotVisible},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			botTokenPlant(t, f, c.canApprove, c.forbid)
			f.forbidWorkflowPerms = c.hideOrg
			ix := collectFake(t, f)
			repo := ix.node(t, botRepo)
			if got, ev := repo.Attrs[graph.AttrActionsCanApprove], attrEv(repo, graph.AttrActionsCanApprove); got != c.attr || ev != c.attrEv {
				t.Errorf("actions_can_approve_prs = %q (%q), want %q (%q)", got, ev, c.attr, c.attrEv)
			}
			_, has := repo.Attrs[graph.AttrReviewBypass]
			if has != c.bypass {
				t.Fatalf("review_bypass present = %v, want %v", has, c.bypass)
			}
			if !c.bypass {
				return
			}
			if repo.Attrs[graph.AttrReviewBypassReason] != graph.ReviewBypassApprovals || attrEv(repo, graph.AttrReviewBypass) != c.bypassEv {
				t.Errorf("review_bypass reason %q evidence %q, want bot_approvals %q", repo.Attrs[graph.AttrReviewBypassReason], attrEv(repo, graph.AttrReviewBypass), c.bypassEv)
			}
			fx := graph.BotMergeFixes(repo)
			turnOff := false
			for _, x := range fx {
				turnOff = turnOff || strings.Contains(x, "Turn off \"Allow GitHub Actions to create and approve pull requests\"")
			}
			if turnOff != (c.attr == "true") {
				t.Errorf("fixes = %q", fx)
			}
			if c.attr == "unknown" {
				covered := false
				for _, cv := range ix.g.Coverage {
					covered = covered || (cv.Scope == botRepo && cv.Fact == graph.AttrActionsCanApprove)
				}
				if !covered {
					t.Error("no actions_can_approve_prs coverage entry")
				}
			}
		})
	}
}

// No GITHUB_TOKEN approval: the setting is never read.
func TestActionsCanApproveNotReadWithoutTokenApproval(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 1, false, false, actor("Integration", 77))
	ix := collectFake(t, f)
	if v, ok := ix.node(t, botRepo).Attrs[graph.AttrActionsCanApprove]; ok {
		t.Errorf("actions_can_approve_prs = %q, want none", v)
	}
}

// attrEv is the effective evidence of a node attr.
func attrEv(n graph.Node, key string) graph.Evidence {
	if ev, ok := n.AttrEvidence[key]; ok {
		return ev
	}
	return n.Evidence
}
