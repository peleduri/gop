package collect

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

func TestScriptCalls(t *testing.T) {
	cases := []struct {
		run, dir string
		want     []string
	}{
		{`python3 tools/merge.py --pr "$PR_NUMBER"`, "", []string{"tools/merge.py"}},
		{`python -u ./ci/merge.py`, "", []string{"ci/merge.py"}},
		{`node scripts/merge.mjs && bash ci/approve.sh`, "", []string{"scripts/merge.mjs", "ci/approve.sh"}},
		{`go run ./cmd/merge -pr 1`, "", []string{"cmd/merge/main.go"}},
		{`go run tools/merge.go`, "", []string{"tools/merge.go"}},
		{`./tools/merge.sh 1`, "", []string{"tools/merge.sh"}},
		{`npx tsx scripts/merge.ts`, "", []string{"scripts/merge.ts"}},
		{`python3 merge.py`, "tools", []string{"tools/merge.py"}},
		{`GH_TOKEN=x python3 tools/merge.py`, "", []string{"tools/merge.py"}},
		// Not followed: a module, inline code, a variable path, a path out of
		// the repo, an absolute path.
		{`python3 -m tools.merge`, "", nil},
		{`bash -c 'gh pr merge 1'`, "", nil},
		{`python3 "$SCRIPT"`, "", nil},
		{`python3 ../other/merge.py`, "", nil},
		{`python3 /opt/merge.py`, "", nil},
		{`echo python3 tools/merge.py`, "", nil},
	}
	for _, c := range cases {
		if got := scriptCalls(c.run, c.dir); !reflect.DeepEqual(got, c.want) {
			t.Errorf("scriptCalls(%q, %q) = %q, want %q", c.run, c.dir, got, c.want)
		}
	}
}

func TestScanScript(t *testing.T) {
	cases := []struct {
		name string
		text string
		want scriptFacts
	}{
		{"PyGithub merge counting dismissed approvals", readBotFixture(t, "script/merge.py"),
			scriptFacts{merge: true, app: true, stale: true, dismissed: true}},
		{"PyGithub merge of head-commit approvals only", readBotFixture(t, "script/merge-head.py"),
			scriptFacts{merge: true, app: true}},
		{"Octokit merge, stale commit compared and still counted", `
const reviews = await octokit.rest.pulls.listReviews({owner, repo, pull_number});
for (const r of reviews.data) {
  if (r.commit_id !== head) {
    core.info("approval on an older commit");
  }
  if (r.state === "APPROVED") approvals++;
}
await octokit.rest.pulls.merge({owner, repo, pull_number});
`, scriptFacts{merge: true, stale: true}},
		{"GraphQL mergePullRequest with a PAT", `curl -H "Authorization: bearer $TOKEN" -d '{"query":"mutation { mergePullRequest(input: {pullRequestId: \"x\"}) { clientMutationId } }"}' https://api.github.com/graphql`,
			scriptFacts{merge: true}},
		{"gh pr merge in a shell script", "#!/bin/sh\ngh pr merge \"$1\" --squash\n", scriptFacts{merge: true}},
		{"PyGithub approval", `pr.create_review(event="APPROVE", body="LGTM")`, scriptFacts{approve: true}},
		{"a comment only", "# pr.merge()\n// gh pr merge 1\nprint('hi')\n", scriptFacts{}},
		{"a dataframe merge is not a PR merge", "df = left.merge(right, on='id')\n", scriptFacts{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanScript([]byte(c.text)); got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestRereviews(t *testing.T) {
	cases := []struct {
		on   string
		want bool
	}{
		{"pull_request", true},
		{"[push, pull_request_target]", true},
		{"{pull_request_target: {types: [opened, synchronize]}}", true},
		{"{pull_request: null}", true},
		{"{pull_request_target: {types: [opened]}, issue_comment: {types: [created]}}", false},
		{"{pull_request: {types: opened}}", false},
		{"issue_comment", false},
	}
	for _, c := range cases {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("on: "+c.on+"\njobs: {}\n"), &doc); err != nil {
			t.Fatal(err)
		}
		w := &yamlWalk{}
		root, err := w.mapping(rootMap(&doc), "workflow")
		if err != nil {
			t.Fatal(err)
		}
		if got := rereviews(w, root); got != c.want {
			t.Errorf("on: %s rereviews = %v, want %v", c.on, got, c.want)
		}
	}
}

const (
	botScriptPath = "tools/merge.py"
	botScriptKey  = "/repos/acme-app/web/contents/tools/merge.py"
)

// botScriptPlant plants the script variant of the AI merge fixture on
// acme-app/web: ai-merge.yml runs tools/merge.py (script), ai-review.yml
// approves with the App. sync adds synchronize to the review's triggers.
func botScriptPlant(t *testing.T, f *fakeGitHub, script string, sync bool) {
	t.Helper()
	botPlant(t, f, 1, false, true, actor("Integration", 77))
	review := readBotFixture(t, "script/ai-review.yml")
	if sync {
		review = strings.Replace(review, "types: [opened]", "types: [opened, synchronize]", 1)
	}
	f.extraWorkflows["acme-app/web/ai-review.yml"] = review
	f.extraWorkflows["acme-app/web/ai-merge.yml"] = readBotFixture(t, "script/ai-merge.yml")
	if script != "" {
		f.extraFiles["acme-app/web/"+botScriptPath] = readBotFixture(t, "script/"+script)
	}
}

// The acceptance fixture of issue #152: the merge is in tools/merge.py,
// which counts dismissed approvals; the AI review does not re-run on push
// and holds the App's private key.
func TestBotScriptMergeFixture(t *testing.T) {
	for _, mode := range []struct {
		name string
		rest bool
	}{{"graphql", false}, {"rest", true}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			botScriptPlant(t, f, "merge.py", false)
			botDismissStale(t, f)
			ix := collectMode(t, f, mode.rest)

			if n := f.hitCount(botScriptKey); n != 1 {
				t.Errorf("script fetched %d times, want 1", n)
			}
			wf := ix.node(t, botMergeWF)
			wantAttrs(t, mode.name, wf, map[string]string{
				graph.AttrBotMerges: "true", graph.AttrBotMergeToken: graph.BotTokenApp, graph.AttrBotMergeJobs: "merge",
				graph.AttrBotMergeStart: graph.StarterPROpeners, graph.AttrBotMergeGate: graph.BotGateAuthor,
				graph.AttrBotMergeSource: "script:" + botScriptPath,
				graph.AttrBotMergeStale:  graph.StaleSuspected, graph.AttrBotMergeStaleConf: graph.StaleHeuristic,
			})
			if wf.AttrEvidence[graph.AttrBotMergeStale] != graph.NotVisible {
				t.Errorf("bot_merge_stale_approvals evidence = %q, want not_visible (heuristic)", wf.AttrEvidence[graph.AttrBotMergeStale])
			}
			repo := ix.node(t, botRepo)
			wantAttrs(t, mode.name, repo, map[string]string{
				graph.AttrReviewBypass: graph.ReviewBypassBotSelfMerge, graph.AttrReviewBypassReason: graph.ReviewBypassApp,
				graph.AttrReviewBypassMerge: ".github/workflows/ai-merge.yml", graph.AttrReviewBypassApprove: ".github/workflows/ai-review.yml",
				graph.AttrBotMergeSource: "script:" + botScriptPath,
				graph.AttrBotMergeStale:  graph.StaleSuspected, graph.AttrBotMergeStaleConf: graph.StaleHeuristic,
				graph.AttrReviewBypassStale:  graph.StaleSuspected,
				graph.AttrAgentHoldsMergeKey: "true", graph.AttrAgentMergeKeyWorkflows: ".github/workflows/ai-review.yml",
				graph.AttrBranchDismissStale: "true", graph.AttrReviewBypassRecount: graph.StaleSuspected,
				graph.AttrBotMergeApps: "77", graph.AttrReviewBypassAppMatch: graph.AppMatched,
			})
			for _, a := range []string{graph.AttrBotMergeStale, graph.AttrReviewBypassStale, graph.AttrReviewBypassRecount} {
				if repo.AttrEvidence[a] != graph.NotVisible {
					t.Errorf("repo %s evidence = %q, want not_visible", a, repo.AttrEvidence[a])
				}
			}
			if repo.AttrEvidence[graph.AttrReviewBypass] == graph.NotVisible {
				t.Error("review_bypass is not_visible, want live (the App bypasses the rules)")
			}
			covered := false
			for _, c := range ix.g.Coverage {
				if c.Scope == botMergeWF && c.Fact == graph.FactStaleApprovals {
					covered = strings.Contains(c.Reason, "suspected") && strings.Contains(c.NeedsFix, "confirm by hand")
				}
			}
			if !covered {
				t.Error("no bot_merge_stale_approvals coverage entry asking for a manual check")
			}
			e := ix.mustEdge(t, externalAnyone, botRepo, graph.CanMergeViaBot)
			if e.Attrs[graph.AttrMergeWorkflow] != botMergeWF || e.Attrs[graph.AttrLine] != "24" {
				t.Errorf("edge = %+v", e)
			}

			gx := graph.NewIndex(ix.g)
			p := gx.Reach(externalAnyone, graph.Options{}).Paths[botRepo]
			if p.Unverified {
				t.Fatalf("path = %+v, want confirmed", p)
			}
			want := "a PR author can get code onto `main` without human review: `ai-review.yml` + `ai-merge.yml` (merges in `tools/merge.py`); the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)"
			if notes := gx.PathNotes(p); len(notes) != 1 || notes[0] != want {
				t.Errorf("notes = %q\nwant %q", notes, want)
			}
			fx := graph.BotMergeFixes(repo)
			if len(fx) != 7 || !strings.Contains(fx[4], "the script re-counts approvals GitHub dismissed") || !strings.Contains(fx[5], "synchronize") ||
				!strings.Contains(fx[6], "Keep the merge key out of the AI step") {
				t.Errorf("fixes = %q", fx)
			}
			if mode.rest {
				return
			}
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
			testutil.Golden(t, "../../../../testdata/botmerge-script/graph.json", buf.Bytes())
		})
	}
}

// The script counts only head-commit approvals and the review re-runs on
// synchronize: still a script merge, no stale flag and no path note.
func TestBotScriptMergeHeadOnly(t *testing.T) {
	f := newFakeGitHub(t)
	botScriptPlant(t, f, "merge-head.py", true)
	ix := collectFake(t, f)
	wf := ix.node(t, botMergeWF)
	if wf.Attrs[graph.AttrBotMergeSource] != "script:"+botScriptPath {
		t.Errorf("bot_merge_source = %q", wf.Attrs[graph.AttrBotMergeSource])
	}
	repo := ix.node(t, botRepo)
	if repo.Attrs[graph.AttrReviewBypass] != graph.ReviewBypassBotSelfMerge {
		t.Fatalf("review_bypass = %q", repo.Attrs[graph.AttrReviewBypass])
	}
	for _, n := range []graph.Node{wf, repo} {
		for _, a := range []string{graph.AttrBotMergeStale, graph.AttrBotMergeStaleConf, graph.AttrReviewBypassStale} {
			if v, ok := n.Attrs[a]; ok {
				t.Errorf("%s %s = %q, want none", n.ID, a, v)
			}
		}
	}
	for _, c := range ix.g.Coverage {
		if c.Fact == graph.FactStaleApprovals {
			t.Errorf("unexpected coverage %+v", c)
		}
	}
	gx := graph.NewIndex(ix.g)
	for _, n := range gx.PathNotes(gx.Reach(externalAnyone, graph.Options{}).Paths[botRepo]) {
		if strings.Contains(n, "may not cover") {
			t.Errorf("note = %q", n)
		}
	}
}

// A stale merge script with a review that re-runs on synchronize: the
// script is still suspected, but the path note does not say the approval
// may not cover the merged code.
func TestBotScriptStaleWithRereview(t *testing.T) {
	f := newFakeGitHub(t)
	botScriptPlant(t, f, "merge.py", true)
	ix := collectFake(t, f)
	repo := ix.node(t, botRepo)
	if repo.Attrs[graph.AttrBotMergeStale] != graph.StaleSuspected {
		t.Errorf("bot_merge_stale_approvals = %q, want suspected", repo.Attrs[graph.AttrBotMergeStale])
	}
	if v, ok := repo.Attrs[graph.AttrReviewBypassStale]; ok {
		t.Errorf("review_bypass_stale_approval = %q, want none", v)
	}
	// The rules do not dismiss stale reviews: no re-count of dismissed
	// approvals, and the fix asks for head-commit approvals only.
	if v, ok := repo.Attrs[graph.AttrReviewBypassRecount]; ok {
		t.Errorf("review_bypass_recounts_dismissed = %q, want none", v)
	}
	if fx := graph.BotMergeFixes(repo); !strings.Contains(fx[4], "Count only approvals of the head commit") {
		t.Errorf("fixes = %q", fx)
	}
}

// botDismissStale makes the ruleset of botPlant dismiss stale reviews on push.
func botDismissStale(t *testing.T, f *fakeGitHub) {
	t.Helper()
	f.rules["acme-app/web@main"] = raws(t, map[string]any{"type": "pull_request", "ruleset_id": 46, "ruleset_source_type": "Repository",
		"parameters": map[string]any{"required_approving_review_count": 1, "require_code_owner_review": false, "dismiss_stale_reviews_on_push": true}},
		typedRule("non_fast_forward", 46, "Repository"))
}

// A missing script: no merge found, a coverage entry, and no review bypass.
func TestBotScriptMissing(t *testing.T) {
	f := newFakeGitHub(t)
	botScriptPlant(t, f, "", false)
	ix := collectFake(t, f)
	if v, ok := ix.node(t, botRepo).Attrs[graph.AttrReviewBypass]; ok {
		t.Errorf("review_bypass = %q, want none", v)
	}
	found := false
	for _, c := range ix.g.Coverage {
		if c.Scope == botMergeWF && c.Fact == "bot_script:"+botScriptPath {
			found = true
		}
	}
	if !found {
		t.Error("no coverage entry for the unreadable script")
	}
}

// A script over the size limit is not scanned.
func TestBotScriptTooLarge(t *testing.T) {
	f := newFakeGitHub(t)
	botScriptPlant(t, f, "merge.py", false)
	f.extraFiles["acme-app/web/"+botScriptPath] += strings.Repeat("#", botScriptMaxBytes)
	ix := collectFake(t, f)
	if v, ok := ix.node(t, botRepo).Attrs[graph.AttrReviewBypass]; ok {
		t.Errorf("review_bypass = %q, want none", v)
	}
	for _, c := range ix.g.Coverage {
		if c.Fact == "bot_script:"+botScriptPath && !strings.Contains(c.Reason, "scan limit") {
			t.Errorf("coverage = %+v", c)
		}
	}
}
