package collect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

func readBotFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "botmerge", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseBotFacts(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want *botFacts
	}{
		{"AI review approves with an App token", readBotFixture(t, "ai-review.yml"), &botFacts{
			ApproveJobs: []string{"review"}, ApproveTokens: []string{graph.BotTokenApp}, ApproveStarter: graph.StarterPROpeners, ReReviews: true,
		}},
		{"author comment merges with the App", readBotFixture(t, "ai-merge.yml"), &botFacts{
			MergeJobs: []string{"merge"}, MergeTokens: []string{graph.BotTokenApp}, MergeStarter: graph.StarterPROpeners,
			MergeGate: graph.BotGateAuthor, MergeTriggers: []string{"issue_comment"}, MergeLine: 22, MergeKeys: []string{"REVIEW_APP_KEY"}, MergeApps: []string{"77"},
		}},
		{"author_association admits members", `on: issue_comment
jobs:
  merge:
    if: contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge "$N" --auto --squash
        env:
          GH_TOKEN: ${{ secrets.MERGE_BOT_TOKEN }}
`, &botFacts{MergeJobs: []string{"merge"}, MergeTokens: []string{graph.BotTokenPAT}, MergeStarter: graph.StarterMembers,
			MergeGate: graph.BotGateAssociation, MergeTriggers: []string{"issue_comment"}, MergeLine: 7, MergeKeys: []string{"MERGE_BOT_TOKEN"}}},
		{"a named actor only", `on: issue_comment
jobs:
  merge:
    if: github.event.comment.user.login == 'alice'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge 1 --merge
        env:
          GH_TOKEN: ${{ github.token }}
`, &botFacts{MergeJobs: []string{"merge"}, MergeTokens: []string{graph.BotTokenGitHub}, MergeStarter: graph.StarterMaintainers,
			MergeGate: graph.BotGateListed, MergeTriggers: []string{"issue_comment"}, MergeLine: 7}},
		{"pull_request: same-repo branches only", `on: pull_request
jobs:
  automerge:
    runs-on: ubuntu-latest
    steps:
      - uses: peter-evans/enable-pull-request-automerge@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          pull-request-number: ${{ github.event.pull_request.number }}
`, &botFacts{MergeJobs: []string{"automerge"}, MergeTokens: []string{graph.BotTokenGitHub}, MergeStarter: graph.StarterPushers,
			MergeGate: graph.BotGateNone, MergeTriggers: []string{"pull_request"}, MergeLine: 6, ReReviews: true}},
		{"workflow_dispatch: maintainers", `on: workflow_dispatch
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge 3 --admin
        env:
          GH_TOKEN: ${{ secrets.ADMIN_TOKEN }}
`, &botFacts{MergeJobs: []string{"merge"}, MergeTokens: []string{graph.BotTokenPAT}, MergeStarter: graph.StarterMaintainers,
			MergeGate: graph.BotGateNone, MergeAdmin: true, MergeLine: 6, MergeKeys: []string{"ADMIN_TOKEN"}}},
		{"github-script review and merge API calls", `on: pull_request_target
env:
  BOT: ${{ secrets.BOT_PAT }}
jobs:
  approve:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          github-token: ${{ env.BOT }}
          script: |
            await github.rest.pulls.createReview({...context.repo, pull_number: 1, event: 'APPROVE'})
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -X PUT -H "Authorization: Bearer $TOKEN" \
            https://api.github.com/repos/acme-app/web/pulls/1/merge
        env:
          TOKEN: ${{ secrets.MERGE_PAT }}
`, &botFacts{ApproveJobs: []string{"approve"}, ApproveTokens: []string{graph.BotTokenPAT}, ApproveStarter: graph.StarterPROpeners,
			MergeJobs: []string{"merge"}, MergeTokens: []string{graph.BotTokenPAT}, MergeStarter: graph.StarterPROpeners,
			MergeGate: graph.BotGateNone, MergeTriggers: []string{"pull_request_target"}, MergeLine: 16,
			MergeKeys: []string{"BOT_PAT", "MERGE_PAT"}, ReReviews: true}},
		{"agent allowed to approve, open to anyone", `on: pull_request_target
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          claude_args: --allowedTools "Bash(gh pr review:*)"
`, &botFacts{ApproveJobs: []string{"ai"}, ApproveTokens: []string{graph.BotTokenApp}, ApproveStarter: graph.StarterPROpeners, ReReviews: true}},
		{"agent allowed to approve, write access only", `on: pull_request_target
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          claude_args: --allowedTools "Bash(gh pr review:*)"
`, &botFacts{ApproveJobs: []string{"ai"}, ApproveTokens: []string{graph.BotTokenGitHub}, ApproveStarter: graph.StarterPushers, ReReviews: true}},
		{"a review comment is not an approval", `on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr review 1 --comment --body ok
        env:
          GH_TOKEN: ${{ github.token }}
      - run: |
          # gh pr merge 1
          echo done
`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(c.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got := parseBotFacts([]byte(c.yaml), f.Triggers, nil)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

// setRepoFields merges fields into one fixture repo.
func setRepoFields(t *testing.T, f *fakeGitHub, org, repo string, fields map[string]any) {
	t.Helper()
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login != org {
			continue
		}
		for j, raw := range f.fx.Orgs[i].Repos {
			var r map[string]any
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			if r["name"] != repo {
				continue
			}
			for k, v := range fields {
				r[k] = v
			}
			out, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			f.fx.Orgs[i].Repos[j] = out
			return
		}
	}
	t.Fatalf("no repo %s/%s in the fixture", org, repo)
}

const (
	botRepo     = "repo:acme-app/web"
	botReviewWF = "workflow:acme-app/web/.github/workflows/ai-review.yml"
	botMergeWF  = "workflow:acme-app/web/.github/workflows/ai-merge.yml"
)

// botPlant makes acme-app/web public with a default branch, plants the AI
// review and AI merge workflows (unless bare), and gives the branch one
// ruleset (46, a repo-unique ID: gop caches bypass actors by ruleset ID)
// with a pull request rule and a force-push block.
func botPlant(t *testing.T, f *fakeGitHub, reviews int, codeOwner, bare bool, bypass ...map[string]any) {
	t.Helper()
	setRepoFields(t, f, "acme-app", "web", map[string]any{"visibility": "public", "default_branch": "main"})
	if !bare {
		f.extraWorkflows["acme-app/web/ai-review.yml"] = readBotFixture(t, "ai-review.yml")
		f.extraWorkflows["acme-app/web/ai-merge.yml"] = readBotFixture(t, "ai-merge.yml")
	}
	f.rules["acme-app/web@main"] = raws(t, map[string]any{"type": "pull_request", "ruleset_id": 46, "ruleset_source_type": "Repository",
		"parameters": map[string]any{"required_approving_review_count": reviews, "require_code_owner_review": codeOwner}},
		typedRule("non_fast_forward", 46, "Repository"))
	f.rulesets["acme-app/web#46"] = raw(t, ruleset(46, bypass...))
}

// The acceptance fixture: an AI reviewer approves with an App token, the PR
// author's #ai-merge comment merges with the same App, and the App is a
// bypass actor of the default branch's ruleset.
func TestBotSelfMergeFixture(t *testing.T) {
	for _, mode := range []struct {
		name string
		rest bool
	}{{"graphql", false}, {"rest", true}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			botPlant(t, f, 1, false, false, actor("Integration", 77))
			ix := collectMode(t, f, mode.rest)

			wantAttrs(t, mode.name, ix.node(t, botReviewWF), map[string]string{
				graph.AttrBotApproves: "true", graph.AttrBotApproveToken: graph.BotTokenApp, graph.AttrBotApproveJobs: "review",
				graph.AttrBotApproveStart: graph.StarterPROpeners,
			})
			wantAttrs(t, mode.name, ix.node(t, botMergeWF), map[string]string{
				graph.AttrBotMerges: "true", graph.AttrBotMergeToken: graph.BotTokenApp, graph.AttrBotMergeJobs: "merge",
				graph.AttrBotMergeStart: graph.StarterPROpeners, graph.AttrBotMergeGate: graph.BotGateAuthor,
				graph.AttrBotMergeTriggers: "issue_comment",
			})
			repo := ix.node(t, botRepo)
			wantAttrs(t, mode.name, repo, map[string]string{
				graph.AttrBranchAppBypass: "true", graph.AttrReviewBypass: graph.ReviewBypassBotSelfMerge,
				graph.AttrReviewBypassReason: graph.ReviewBypassApp, graph.AttrReviewBypassMerge: ".github/workflows/ai-merge.yml",
				graph.AttrReviewBypassApprove: ".github/workflows/ai-review.yml",
			})
			if repo.AttrEvidence[graph.AttrReviewBypass] == graph.NotVisible {
				t.Errorf("review_bypass is not_visible, want live")
			}
			e := ix.mustEdge(t, externalAnyone, botRepo, graph.CanMergeViaBot)
			if e.Evidence != graph.Live || e.Attrs[graph.AttrMergeWorkflow] != botMergeWF || e.Attrs[graph.AttrApproveWorkflows] != botReviewWF ||
				e.Attrs[attrTrigger] != "issue_comment" || e.Attrs[graph.AttrFile] != ".github/workflows/ai-merge.yml" ||
				e.Attrs[graph.AttrLine] != "22" || e.Attrs[graph.AttrReviewBypassReason] != graph.ReviewBypassApp {
				t.Errorf("edge = %+v", e)
			}

			gx := graph.NewIndex(ix.g)
			s := gx.BlastRadius(externalAnyone)
			if s.BotSelfMerge != 1 {
				t.Errorf("external:anyone bot_self_merge = %d, want 1", s.BotSelfMerge)
			}
			r := gx.Reach(externalAnyone, graph.Options{})
			p, ok := r.Paths[botRepo]
			if !ok || p.Unverified {
				t.Fatalf("no confirmed path to %s: %+v", botRepo, p)
			}
			notes := gx.PathNotes(p)
			want := "a PR author can get code onto `main` without human review: `ai-review.yml` + `ai-merge.yml`"
			if len(notes) != 1 || notes[0] != want {
				t.Errorf("notes = %q, want %q", notes, want)
			}
			found := false
			for _, c := range gx.Candidates() {
				if c.ID() == "block_bot_merge:"+botRepo {
					found = true
				}
			}
			if !found {
				t.Errorf("no block_bot_merge candidate")
			}
			if fx := graph.BotMergeFixes(repo); len(fx) != 4 || !strings.Contains(fx[1], "bypass actors") {
				t.Errorf("fixes = %q", fx)
			}
			// bob pushes to web: his CAN_PUSH hop gets the same note
			// instead of "push needs 1 approval".
			if p, ok := gx.Reach("identity:bob", graph.Options{}).Paths[botRepo]; !ok {
				t.Error("bob does not reach web")
			} else if n := gx.PathNotes(p); len(n) != 1 || n[0] != want {
				t.Errorf("bob notes = %q", n)
			}
			if mode.rest {
				return
			}
			// The graph is the bot merge fixture of the report tests
			// (testdata/botmerge/graph.json at the repo root).
			g := *ix.g
			at := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
			g.CollectedAt, g.OrgCollectedAt = at, nil
			g.Edges = slices.Clone(ix.g.Edges)
			for i := range g.Edges {
				g.Edges[i].ObservedAt = at
			}
			var buf bytes.Buffer
			if err := WriteGraph(&buf, &g); err != nil {
				t.Fatal(err)
			}
			testutil.Golden(t, "../../../../testdata/botmerge/graph.json", buf.Bytes())
		})
	}
}

// The CAN_MERGE_VIA_BOT edges change only the scores of the principals
// they start from.
func TestBotSelfMergeScoresUnrelated(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 1, false, false, actor("Integration", 77))
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
		b, ok := before[a.Principal]
		switch {
		case from[a.Principal]:
			if a.Confirmed.Repos <= b.Confirmed.Repos {
				t.Errorf("%s: confirmed repos %d -> %d, want more", a.Principal, b.Confirmed.Repos, a.Confirmed.Repos)
			}
		case !ok:
			t.Errorf("%s: new scoring principal", a.Principal)
		case a.Confirmed != b.Confirmed || a.Possible != b.Possible || a.Score != b.Score:
			t.Errorf("%s changed: %+v -> %+v", a.Principal, b, a)
		}
	}
}

// No bypass actor and a CODEOWNERS review required: bots cannot satisfy
// the rule, so nothing is flagged.
func TestBotSelfMergeCodeOwnersNotFlagged(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 1, true, false)
	ix := collectFake(t, f)
	repo := ix.node(t, botRepo)
	if v, ok := repo.Attrs[graph.AttrReviewBypass]; ok {
		t.Errorf("review_bypass = %q, want none", v)
	}
	for _, e := range ix.g.Edges {
		if e.Kind == graph.CanMergeViaBot {
			t.Errorf("unexpected edge %+v", e)
		}
	}
}

// A bypass list the token cannot read, with more approvals required than
// the bots give: possible, not confirmed.
func TestBotSelfMergeHiddenBypassPossible(t *testing.T) {
	f := newFakeGitHub(t)
	botPlant(t, f, 2, false, false, actor("Integration", 77))
	f.hideBypass = true
	ix := collectFake(t, f)
	repo := ix.node(t, botRepo)
	if repo.Attrs[graph.AttrReviewBypass] != graph.ReviewBypassBotSelfMerge || repo.AttrEvidence[graph.AttrReviewBypass] != graph.NotVisible {
		t.Fatalf("review_bypass = %q (%s), want bot_self_merge not_visible", repo.Attrs[graph.AttrReviewBypass], repo.AttrEvidence[graph.AttrReviewBypass])
	}
	if e := ix.mustEdge(t, externalAnyone, botRepo, graph.CanMergeViaBot); e.Evidence != graph.NotVisible {
		t.Errorf("edge evidence = %s, want not_visible", e.Evidence)
	}
	covered := false
	for _, c := range ix.g.Coverage {
		if c.Scope == botRepo && c.Fact == graph.FactReviewBypass {
			covered = true
		}
	}
	if !covered {
		t.Error("no review_bypass coverage entry")
	}
	gx := graph.NewIndex(ix.g)
	if s := gx.BlastRadius(externalAnyone); s.BotSelfMerge != 0 {
		t.Errorf("bot_self_merge = %d for a possible path, want 0", s.BotSelfMerge)
	}
	p := gx.Reach(externalAnyone, graph.Options{}).Paths[botRepo]
	if !p.Unverified {
		t.Errorf("path = %+v, want possible", p)
	}
	if n := gx.PathNotes(p); len(n) != 1 || !strings.Contains(n[0], "may get code onto `main`") || !strings.Contains(n[0], "bypass list is not visible") {
		t.Errorf("notes = %q", n)
	}
}
