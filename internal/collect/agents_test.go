package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

func parseAgents(t *testing.T, src string) *WorkflowFacts {
	t.Helper()
	f, err := ParseWorkflow([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAgentActions(t *testing.T) {
	cases := []struct {
		name, src string
		want      AgentJob
	}{
		{
			name: "claude-code-action default: write access only",
			src: `on: issue_comment
permissions: {contents: write}
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`,
			want: AgentJob{Job: "claude", Kinds: []string{"claude-code-action"}, Sources: []string{"uses"}, Gate: graph.GateWriteAccess,
				Exposure: graph.ExposureMaintainer, Perms: []string{"contents:write"}, Secrets: []string{"ANTHROPIC_API_KEY"},
				Runner: RunnerHosted, RefKind: "tag", Line: 7},
		},
		{
			name: "owner case, SHA pin, allowed_non_write_users list",
			src: `on: [issues]
jobs:
  triage:
    runs-on: [self-hosted]
    permissions: {issues: write}
    steps:
      - uses: Anthropics/Claude-Code-Action@0123456789abcdef0123456789abcdef01234567
        with:
          allowed_non_write_users: carol,dave
          claude_args: '--allowedTools "Bash(gh issue edit:*)"'
`,
			want: AgentJob{Job: "triage", Kinds: []string{"claude-code-action"}, Sources: []string{"uses"}, Gate: graph.GateListed,
				Exposure: graph.ExposureListed, Perms: []string{"issues:write"}, Runner: RunnerSelfHosted,
				Tools: []string{"allowed_tools"}, RefKind: "sha", Line: 7},
		},
		{
			name: "codex-action allow-users star, title in prompt, unsafe strategy",
			src: `on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@main
        with:
          allow-users: "*"
          safety-strategy: unsafe
          prompt: |
            Review ${{ github.event.pull_request.title }}
            ${{ github.event.pull_request.body }}
`,
			want: AgentJob{Job: "review", Kinds: []string{"codex-action"}, Sources: []string{"uses"}, Gate: graph.GateAnyone,
				Exposure: graph.ExposureOutsiders, Perms: []string{"default"}, Runner: RunnerHosted,
				Prompt: []string{"github.event.pull_request.body", "github.event.pull_request.title"},
				Tools:  []string{"safety_strategy_unsafe"}, RefKind: "branch", Line: 6},
		},
		{
			name: "base action has no actor check",
			src: `on: issues
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-base-action@v0.0.63
        with:
          prompt: "Label: ${{ github.event.issue.title }}"
`,
			want: AgentJob{Job: "a", Kinds: []string{"claude-code-base-action"}, Sources: []string{"uses"}, Gate: graph.GateNone,
				Exposure: graph.ExposureOutsiders, Runner: RunnerHosted, Prompt: []string{"github.event.issue.title"}, RefKind: "tag", Line: 7},
		},
		{
			name: "opencode by path, unknown check",
			src: `on: issue_comment
jobs:
  oc:
    runs-on: ubuntu-latest
    steps:
      - uses: sst/opencode/github@latest
`,
			want: AgentJob{Job: "oc", Kinds: []string{"opencode-action"}, Sources: []string{"uses"}, Gate: graph.GateUnknown,
				Exposure: graph.ExposureOutsiders, Perms: []string{"default"}, Runner: RunnerHosted, RefKind: "branch", Line: 6},
		},
		{
			name: "copilot setup steps",
			src: `on: workflow_dispatch
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@v4
`,
			want: AgentJob{Job: "copilot-setup-steps", Kinds: []string{"copilot-coding-agent"}, Sources: []string{"setup"}, Gate: graph.GateWriteAccess,
				Exposure: graph.ExposureMaintainer, Runner: RunnerHosted, Line: 6},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := parseAgents(t, c.src)
			if len(f.Agents) != 1 {
				t.Fatalf("agents = %+v", f.Agents)
			}
			if got := f.Agents[0]; !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestAgentCLIs(t *testing.T) {
	cases := []struct {
		run, kind string
		tools     []string
	}{
		{`claude -p "fix the lint errors" --dangerously-skip-permissions`, "claude-cli", []string{"dangerously_skip_permissions"}},
		{`npx -y @anthropic-ai/claude-code@latest --print "summarize" --permission-mode bypassPermissions`, "claude-cli", []string{"bypass_permissions"}},
		{"set -e\nOPENAI_API_KEY=x codex exec --full-auto \\\n  \"review\"", "codex-cli", []string{"full_auto"}},
		{`cat prompt.md | cursor-agent -p`, "cursor-cli", nil},
		{`gemini --yolo -p "triage this issue"`, "gemini-cli", []string{"yolo"}},
		{`aider --yes-always --message "fix"`, "aider", []string{"yes_always"}},
		{`opencode run "fix it"`, "opencode-cli", nil},
		{`llm "summarize the diff"`, "llm-cli", nil},
		{`./node_modules/.bin/claude --print hi`, "claude-cli", nil},
		{`copilot -p "fix it" --allow-all-tools`, "copilot-cli", []string{"allow_all"}},
		{`npx -y @github/copilot --prompt "triage" --allow-all`, "copilot-cli", []string{"allow_all"}},
		{`copilot -p "lint" --allow-tool='shell(npm:*), write'`, "copilot-cli", []string{"allowed_tools"}},
		{`copilot -p "go" --yolo`, "copilot-cli", []string{"yolo"}},
		{`qwen -p "fix" --yolo`, "qwen-cli", []string{"yolo"}},
		{`qwen -p "fix" --approval-mode yolo`, "qwen-cli", []string{"yolo"}},
		{`qwen --approval-mode=yolo --prompt "fix"`, "qwen-cli", []string{"yolo"}},
		{`qwen -p "plan" --approval-mode plan`, "qwen-cli", nil},
		{`gemini -p "triage" --approval-mode=yolo`, "gemini-cli", []string{"yolo"}},
		{`goose run -t "update the changelog"`, "goose-cli", nil},
		{`goose run --recipe release.yaml`, "goose-cli", nil},
		{`crush run --yolo "summarize"`, "crush-cli", []string{"yolo"}},
		{`npx @charmland/crush run "explain"`, "crush-cli", nil},
		{`cline "run tests and fix failures"`, "cline-cli", nil},
		{`git diff | cline --json "review these changes"`, "cline-cli", nil},
		{`cn -p "write a commit message"`, "continue-cli", nil},
		{`echo "review" | npx @continuedev/cli -p`, "continue-cli", nil},
		{`amp -x "what changed?"`, "amp-cli", nil},
		{`amp --execute "fix the build"`, "amp-cli", nil},
		{`openhands --headless -f task.txt`, "openhands-cli", nil},
	}
	for _, c := range cases {
		cli, args, ok := matchAgentCLI(c.run)
		if !ok || cli.kind != c.kind {
			t.Errorf("%q: got %q, %v; want %q", c.run, cli.kind, ok, c.kind)
			continue
		}
		set := map[string]bool{}
		addToolFlags(set, args)
		if got := sortedSet(set); !reflect.DeepEqual(got, c.tools) {
			t.Errorf("%q: tools = %v, want %v", c.run, got, c.tools)
		}
	}
	for _, run := range []string{
		`claude --version`,
		`npm install -g @openai/codex`,
		`echo "run claude -p to try it"`,
		`codex`,
		`git log | llm-cost-report`,
		`# claude -p "commented out"`,
		`llm install llm-gpt4all`,
		`opencode --help`,
		// Near misses: another tool with the same name, a non-run
		// subcommand, a mention in text, or the name inside another word.
		`copilot svc deploy --name api --env prod`,
		`copilot init --app acme`,
		`goose -dir db/migrations postgres "$DATABASE_URL" up`,
		`goose up`,
		`goose session`,
		`crush --version`,
		`cline auth`,
		`cline --version`,
		`cn ls --json`,
		`cn login`,
		`amp --version`,
		`amp login`,
		`openhands --version`,
		`qwen --version`,
		`npm install -g cline @github/copilot @qwen-code/qwen-code`,
		`echo "try qwen -p or crush run locally"`,
		`./scripts/raider --message "not aider"`,
		`aider-lint --message x`,
		`ampx -x "x"`,
		`goosebump run -t x`,
		`docker run --rm acme/cn -p 8080:80`,
	} {
		if c, _, ok := matchAgentCLI(run); ok {
			t.Errorf("%q matched %s", run, c.kind)
		}
	}
}

// TestAgentCLIFixtures parses one synthetic workflow per agent CLI or
// action (testdata/agents/clis) and a near-miss workflow with none.
func TestAgentCLIFixtures(t *testing.T) {
	cases := []struct {
		file, kind, source string
		tools              []string
	}{
		{"copilot-cli.yml", "copilot-cli", "run", []string{"allow_all"}},
		{"qwen-cli.yml", "qwen-cli", "run", []string{"yolo"}},
		{"qwen-code-action.yml", "qwen-code-action", "uses", nil},
		{"goose-cli.yml", "goose-cli", "run", nil},
		{"crush-cli.yml", "crush-cli", "run", []string{"yolo"}},
		{"cline-cli.yml", "cline-cli", "run", nil},
		{"continue-cli.yml", "continue-cli", "run", nil},
		{"amp-cli.yml", "amp-cli", "run", nil},
		{"openhands-cli.yml", "openhands-cli", "run", nil},
	}
	read := func(file string) string {
		b, err := os.ReadFile(filepath.Join("testdata", "agents", "clis", file))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f := parseAgents(t, read(c.file))
			if len(f.Agents) != 1 {
				t.Fatalf("agents = %+v", f.Agents)
			}
			a := f.Agents[0]
			if !reflect.DeepEqual(a.Kinds, []string{c.kind}) || !reflect.DeepEqual(a.Sources, []string{c.source}) {
				t.Errorf("kinds %v sources %v, want %s %s", a.Kinds, a.Sources, c.kind, c.source)
			}
			if !reflect.DeepEqual(a.Tools, c.tools) {
				t.Errorf("tools = %v, want %v", a.Tools, c.tools)
			}
		})
	}
	if f := parseAgents(t, read("near-miss.yml")); len(f.Agents) != 0 {
		t.Errorf("near-miss agents = %+v", f.Agents)
	}
}

func TestAgentName(t *testing.T) {
	for _, s := range []string{"ai-review.yml", "Claude triage", "codex", "copilot-setup", "llm-summary", "run-ai-fix", "AI-Labeler"} {
		if !agentName(s) {
			t.Errorf("%q: no match", s)
		}
	}
	for _, s := range []string{"email-digest.yml", "ci.yml", "detail-page", "chai-tests", "release"} {
		if agentName(s) {
			t.Errorf("%q: matched", s)
		}
	}
}

func TestNonAgentWorkflow(t *testing.T) {
	f := parseAgents(t, "on: pull_request_target\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n")
	if len(f.Agents) != 0 {
		t.Errorf("agents = %+v", f.Agents)
	}
	for _, x := range f.UntrustedExec {
		if x.Kind == ExecAgent {
			t.Errorf("exec = %+v", x)
		}
	}
}

// Synthetic agent workflows planted on the acme collect fixture (see
// testdata/agents): repo-relative workflow file -> fixture file.
var agentFixtures = map[string]string{
	"acme-app/docs/claude.yml":            "claude.yml",
	"acme-app/docs/gemini-review.yml":     "gemini-review.yml",
	"acme-app/docs/ai-labeler.yml":        "ai-labeler.yml",
	"acme-app/docs/claude-nightly.yml":    "claude-nightly.yml",
	"acme-actions/setup/codex-review.yml": "codex-review.yml",
}

const (
	claudeWF  = "workflow:acme-app/docs/.github/workflows/claude.yml"
	geminiWF  = "workflow:acme-app/docs/.github/workflows/gemini-review.yml"
	labelerWF = "workflow:acme-app/docs/.github/workflows/ai-labeler.yml"
	codexWF   = "workflow:acme-actions/setup/.github/workflows/codex-review.yml"
	nightlyWF = "workflow:acme-app/docs/.github/workflows/claude-nightly.yml"
)

// collectAgents collects the acme fixture with acme-app/docs public and the
// agent workflows planted.
func collectAgents(t *testing.T) *index {
	t.Helper()
	return collectWith(t, func(f *fakeGitHub) {
		setVisibility(t, f, "acme-app", "docs", "public")
		for k, file := range agentFixtures {
			b, err := os.ReadFile(filepath.Join("testdata", "agents", file))
			if err != nil {
				t.Fatal(err)
			}
			f.extraWorkflows[k] = string(b)
		}
	})
}

func TestAgentFixtureGraph(t *testing.T) {
	ix := collectAgents(t)

	claude := ix.node(t, claudeWF).Attrs
	want := map[string]string{
		graph.AttrAgent: "claude-code-action", graph.AttrAgentSource: "uses", graph.AttrAgentConfidence: graph.AgentAction,
		graph.AttrAgentJobs: "claude", graph.AttrAgentGate: graph.GateAnyone, graph.AttrAgentExposure: graph.ExposureOutsiders,
		graph.AttrAgentPerms: "contents:write,issues:write,pull-requests:write", graph.AttrAgentSecrets: "1",
		graph.AttrAgentRunner: RunnerHosted, graph.AttrAgentTools: "dangerously_skip_permissions", graph.AttrAgentRefKind: "tag",
	}
	for k, v := range want {
		if claude[k] != v {
			t.Errorf("claude %s = %q, want %q", k, claude[k], v)
		}
	}
	if _, ok := claude[graph.AttrAgentPrompt]; ok {
		t.Errorf("claude prompt = %q, want none", claude[graph.AttrAgentPrompt])
	}
	e := ix.mustEdge(t, externalAnyone, claudeWF, graph.CanTrigger)
	if e.Evidence != graph.Live || e.Attrs[attrExec] != ExecAgent || e.Attrs[attrTrigger] != "issue_comment" ||
		e.Attrs[attrDetail] != "claude-code-action" || e.Attrs[graph.AttrLine] != "16" {
		t.Errorf("claude edge = %+v", e)
	}

	// claude.yml saves .claude/memory with cache-mode: write; the
	// maintainer-only nightly agent restores it by key prefix with a token
	// that can push (agentmemory.go).
	cn := ix.node(t, claudeWF)
	for k, v := range map[string]string{
		graph.AttrAgentMemoryStore: graph.MemoryStoreCache, graph.AttrAgentMemoryReaders: nightlyWF,
		graph.AttrAgentMemoryTriggers: "issue_comment", graph.AttrAgentMemoryPaths: ".claude/memory",
		graph.AttrAgentMemoryDirs: ".claude", graph.AttrAgentMemoryMatch: MatchPrefix, graph.AttrAgentMemoryLine: "23",
	} {
		if cn.Attrs[k] != v {
			t.Errorf("claude %s = %q, want %q", k, cn.Attrs[k], v)
		}
	}
	if !graph.AgentMemoryPoisoned(cn) || !graph.AgentMemoryConfirmed(cn) {
		t.Errorf("claude memory not confirmed: %v", cn.AttrEvidence)
	}
	if n := ix.node(t, nightlyWF); n.Attrs[graph.AttrAgentExposure] != graph.ExposureMaintainer || n.Attrs[graph.AttrAgentMemoryReaders] != "" {
		t.Errorf("nightly attrs = %v", n.Attrs)
	}
	ix.noEdge(t, externalAnyone, nightlyWF, graph.CanTrigger)

	codex := ix.node(t, codexWF).Attrs
	if codex[graph.AttrAgent] != "codex-cli" || codex[graph.AttrAgentConfidence] != graph.AgentCLI ||
		codex[graph.AttrAgentExposure] != graph.ExposureOutsiders || codex[graph.AttrAgentPrompt] != "github.event.pull_request.title" ||
		codex[graph.AttrAgentPerms] != "pull-requests:write" || codex[graph.AttrAgentTools] != "full_auto" || codex[graph.AttrAgentSecrets] != "1" {
		t.Errorf("codex attrs = %v", codex)
	}
	// acme-actions allows forks of internal repos: every org's members can
	// open the pull request. The injection exec (sorted first) and the agent
	// exec both start the job; the edge keeps the first.
	for _, m := range []string{"members:acme-app", "members:acme-secure"} {
		if e := ix.mustEdge(t, m, codexWF, graph.CanTrigger); e.Evidence != graph.Live {
			t.Errorf("%s codex edge = %+v", m, e)
		}
	}

	gem := ix.node(t, geminiWF).Attrs
	if gem[graph.AttrAgent] != "gemini-cli-action" || gem[graph.AttrAgentGate] != graph.GateUnknown ||
		gem[graph.AttrAgentExposure] != graph.ExposureForkRO || gem[graph.AttrAgentPerms] != "" {
		t.Errorf("gemini attrs = %v", gem)
	}
	ix.noEdge(t, externalAnyone, geminiWF, graph.CanTrigger)

	lab := ix.node(t, labelerWF).Attrs
	if lab[graph.AttrAgentConfidence] != graph.AgentNameOnly || lab[graph.AttrAgentSource] != "name" || lab[graph.AttrAgentExposure] != "" {
		t.Errorf("labeler attrs = %v", lab)
	}
	ix.noEdge(t, externalAnyone, labelerWF, graph.CanTrigger)

	// A non-agent workflow gets no agent attrs.
	for _, n := range ix.g.Nodes {
		if n.Kind != graph.KindWorkflow || slices.Contains([]string{claudeWF, geminiWF, labelerWF, codexWF, nightlyWF}, n.ID) {
			continue
		}
		for k := range n.Attrs {
			if len(k) >= 5 && k[:5] == "agent" {
				t.Errorf("%s has %s", n.ID, k)
			}
		}
	}

	// The graph is the shared agents fixture of the graph, sarif, report and
	// mcpserver tests (testdata/agents/graph.json at the repo root).
	g := *ix.g
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	g.CollectedAt, g.OrgCollectedAt = at, nil
	g.Edges = slices.Clone(ix.g.Edges)
	for i := range g.Edges {
		g.Edges[i].ObservedAt = at
	}
	var buf bytes.Buffer
	if err := WriteGraph(&buf, &g); err != nil {
		t.Fatal(err)
	}
	testutil.Golden(t, "../../../../testdata/agents/graph.json", buf.Bytes())
}
