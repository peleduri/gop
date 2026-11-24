package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func readIndirect(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "indirect", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parseWith(t *testing.T, src string, ind *Indirect) *WorkflowFacts {
	t.Helper()
	f, err := ParseWorkflowWith([]byte(src), ind)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func agentExecs(f *WorkflowFacts) []UntrustedExec {
	var out []UntrustedExec
	for _, x := range f.UntrustedExec {
		if x.Kind == ExecAgent {
			out = append(out, x)
		}
	}
	return out
}

func TestFollowRefs(t *testing.T) {
	src := `on: [pull_request_target]
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
jobs:
  call:
    uses: ./.github/workflows/called.yml
  org:
    uses: acme-app/web/.github/workflows/x.yml@main
  steps:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/review
      - uses: ./.github/actions/review
      - uses: actions/checkout@v4
      - run: python3 tools/ai.py
`
	f := parseWith(t, src, nil)
	want := FollowRefs{
		Actions:   []string{".github/actions/review"},
		Workflows: []string{"./.github/workflows/called.yml", "acme-app/web/.github/workflows/x.yml@main"},
		Scripts:   []string{"tools/ai.py"},
	}
	if !reflect.DeepEqual(f.Follow, want) {
		t.Errorf("follow = %+v, want %+v", f.Follow, want)
	}

	// A push-only workflow is not followed.
	if f := parseWith(t, strings.Replace(src, "[pull_request_target]", "[push]", 1), nil); !f.Follow.Empty() {
		t.Errorf("push follow = %+v, want none", f.Follow)
	}
	// A script run without a secret or model key is not followed.
	noKey := strings.Replace(src, "env:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n", "", 1)
	if f := parseWith(t, noKey, nil); len(f.Follow.Scripts) != 0 {
		t.Errorf("scripts = %v, want none", f.Follow.Scripts)
	}
}

// Acceptance: an agent inside a local composite action.
func TestAgentInCompositeAction(t *testing.T) {
	src := readIndirect(t, "composite-caller.yml")
	if f := parseWith(t, src, nil); len(f.Agents) != 0 {
		t.Fatalf("without the action: agents = %+v", f.Agents)
	}
	ind := &Indirect{Actions: map[string]IndirectFile{
		".github/actions/ai-review": {Path: ".github/actions/ai-review/action.yml", Data: []byte(readIndirect(t, "composite-action.yml"))},
	}}
	f := parseWith(t, src, ind)
	if len(f.Agents) != 1 {
		t.Fatalf("agents = %+v", f.Agents)
	}
	a := f.Agents[0]
	want := AgentJob{Job: "review", Kinds: []string{"claude-code-base-action"}, Sources: []string{"composite", "uses"},
		Gate: graph.GateNone, Exposure: graph.ExposureOutsiders, Prompt: []string{"github.event.pull_request.title", graph.PromptPRContent},
		Perms: []string{"pull-requests:write"}, Runner: RunnerHosted, RefKind: "tag",
		Line: 11, File: ".github/actions/ai-review/action.yml"}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("agent =\n%+v, want\n%+v", a, want)
	}
	x := agentExecs(f)
	if len(x) != 1 || x[0].File != want.File || x[0].Line != 11 || x[0].Unverified {
		t.Errorf("agent execs = %+v", x)
	}
	// The checkout in pr/ is read, not run: still read-only.
	if len(f.ReadOnlyCheckouts) != 1 {
		t.Errorf("read-only checkouts = %+v", f.ReadOnlyCheckouts)
	}
}

// Untrusted execution inside a composite action is found too, at its line in
// the action file.
func TestExecInCompositeAction(t *testing.T) {
	src := "on: issues\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/greet\n"
	action := "runs:\n  using: composite\n  steps:\n    - run: echo \"${{ github.event.issue.title }}\"\n      shell: bash\n"
	ind := &Indirect{Actions: map[string]IndirectFile{".github/actions/greet": {Path: ".github/actions/greet/action.yml", Data: []byte(action)}}}
	f := parseWith(t, src, ind)
	want := []UntrustedExec{{Job: "x", Trigger: "issues", Kind: ExecInjection, Detail: "github.event.issue.title", Line: 4, File: ".github/actions/greet/action.yml"}}
	if !reflect.DeepEqual(f.UntrustedExec, want) {
		t.Errorf("execs = %+v, want %+v", f.UntrustedExec, want)
	}
	// One level only: a composite action's own local action is not followed.
	nested := "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/greet\n"
	ind.Actions[".github/actions/outer"] = IndirectFile{Path: ".github/actions/outer/action.yml", Data: []byte(nested)}
	f = parseWith(t, strings.Replace(src, "greet", "outer", 1), ind)
	if len(f.UntrustedExec) != 0 {
		t.Errorf("two levels down: execs = %+v", f.UntrustedExec)
	}
}

// Acceptance: an agent inside a called reusable workflow.
func TestAgentInReusableWorkflow(t *testing.T) {
	src := readIndirect(t, "reusable-caller.yml")
	uses := "acme-app/web/.github/workflows/ai-triage.yml@main"
	ind := &Indirect{Workflows: map[string]IndirectFile{
		uses: {Where: "acme-app/web/.github/workflows/ai-triage.yml@main", Data: []byte(readIndirect(t, "reusable-called.yml"))},
	}}
	f := parseWith(t, src, ind)
	if len(f.Agents) != 1 {
		t.Fatalf("agents = %+v", f.Agents)
	}
	a := f.Agents[0]
	if !reflect.DeepEqual(a.Kinds, []string{"codex-cli"}) || !reflect.DeepEqual(a.Sources, []string{"reusable", "run"}) ||
		a.Exposure != graph.ExposureOutsiders || !reflect.DeepEqual(a.Prompt, []string{"github.event.comment.body"}) ||
		!reflect.DeepEqual(a.Tools, []string{"full_auto"}) || a.File != "" || a.Line != 9 {
		t.Errorf("agent = %+v", a)
	}
	x := agentExecs(f)
	if len(x) != 1 || x[0].Trigger != "issue_comment" || x[0].Line != 9 || x[0].File != "" || x[0].Unverified {
		t.Errorf("agent execs = %+v", x)
	}

	// A same-repo reusable workflow: the line is in the called file.
	local := strings.Replace(src, uses, "./.github/workflows/ai-triage.yml", 1)
	ind = &Indirect{Workflows: map[string]IndirectFile{
		"./.github/workflows/ai-triage.yml": {Path: ".github/workflows/ai-triage.yml", Data: []byte(readIndirect(t, "reusable-called.yml"))},
	}}
	f = parseWith(t, local, ind)
	if len(f.Agents) != 1 || f.Agents[0].File != ".github/workflows/ai-triage.yml" || f.Agents[0].Line != 13 {
		t.Errorf("local agents = %+v", f.Agents)
	}

	// Exec in a reusable workflow of another repo names the file in the
	// detail and points at the caller's uses: line.
	called := "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.comment.body }}\"\n"
	ind = &Indirect{Workflows: map[string]IndirectFile{uses: {Where: "acme-app/web/.github/workflows/ai-triage.yml@main", Data: []byte(called)}}}
	f = parseWith(t, src, ind)
	want := []UntrustedExec{{Job: "triage", Trigger: "issue_comment", Kind: ExecInjection,
		Detail: "github.event.comment.body (in acme-app/web/.github/workflows/ai-triage.yml@main)", Line: 9}}
	if !reflect.DeepEqual(f.UntrustedExec, want) {
		t.Errorf("execs = %+v, want %+v", f.UntrustedExec, want)
	}
}

// Acceptance: a CLI agent inside a repo script; a model API call in a
// script is a possible AI step.
func TestAgentInScript(t *testing.T) {
	src := readIndirect(t, "script-caller.yml")
	ind := &Indirect{Scripts: map[string][]byte{"ci/ai-summary.sh": []byte(readIndirect(t, "ai-summary.sh"))}}
	f := parseWith(t, src, ind)
	if len(f.Agents) != 1 {
		t.Fatalf("agents = %+v", f.Agents)
	}
	a := f.Agents[0]
	if !reflect.DeepEqual(a.Kinds, []string{"claude-cli"}) || !reflect.DeepEqual(a.Sources, []string{"run", "script"}) ||
		a.Gate != graph.GateNone || !reflect.DeepEqual(a.Prompt, []string{graph.PromptPRContent}) || a.Line != 10 {
		t.Errorf("agent = %+v", a)
	}
	if x := agentExecs(f); len(x) != 1 || x[0].Unverified {
		t.Errorf("agent execs = %+v", x)
	}

	py := "import os, requests\nbody = open(os.environ['GITHUB_EVENT_PATH']).read()\n" +
		"requests.post('https://api.openai.com/v1/chat/completions', json={'messages': [{'role': 'user', 'content': body}]})\n"
	src = strings.Replace(src, "bash ci/ai-summary.sh", "python3 ci/ai.py", 1)
	f = parseWith(t, src, &Indirect{Scripts: map[string][]byte{"ci/ai.py": []byte(py)}})
	if len(f.Agents) != 1 || !reflect.DeepEqual(f.Agents[0].Kinds, []string{LLMScriptKind}) ||
		!reflect.DeepEqual(f.Agents[0].Sources, []string{"script"}) || !reflect.DeepEqual(f.Agents[0].Prompt, []string{graph.PromptPRContent}) {
		t.Fatalf("agents = %+v", f.Agents)
	}
	if x := agentExecs(f); len(x) != 1 || !x[0].Unverified {
		t.Errorf("model API script execs = %+v, want possible only", x)
	}

	// A model API call that reads nothing an outsider writes is not an AI
	// step outsiders reach.
	quiet := "import requests\nrequests.post('https://api.openai.com/v1/chat/completions', json={'messages': []})\n"
	f = parseWith(t, src, &Indirect{Scripts: map[string][]byte{"ci/ai.py": []byte(quiet)}})
	if len(f.Agents) != 0 {
		t.Errorf("quiet script agents = %+v", f.Agents)
	}
	// A script with no AI at all.
	f = parseWith(t, src, &Indirect{Scripts: map[string][]byte{"ci/ai.py": []byte("print('hello')\n")}})
	if len(f.Agents) != 0 {
		t.Errorf("plain script agents = %+v", f.Agents)
	}
}

// Acceptance: a known agent reading a checkout of the pull request's head
// in pr/ gets pr_content; prose that says "pr" does not.
func TestKnownAgentReadsPRCheckout(t *testing.T) {
	src := readIndirect(t, "pr-dir.yml")
	f := parseWith(t, src, nil)
	if len(f.Agents) != 1 || !reflect.DeepEqual(f.Agents[0].Prompt, []string{graph.PromptPRContent}) {
		t.Fatalf("agents = %+v", f.Agents)
	}
	if len(f.ReadOnlyCheckouts) != 1 || len(f.UntrustedExec) != 1 || f.UntrustedExec[0].Kind != ExecAgent {
		t.Errorf("execs = %+v, read-only = %+v", f.UntrustedExec, f.ReadOnlyCheckouts)
	}
	prose := strings.Replace(src, "Review the files under pr/ and comment", "Review this pr and comment", 1)
	if f := parseWith(t, prose, nil); len(f.Agents) != 1 || len(f.Agents[0].Prompt) != 0 {
		t.Errorf("prose agents = %+v", f.Agents)
	}
	// A directory input naming the checkout.
	dirIn := strings.Replace(src, "prompt: Review the files under pr/ and comment on the pull request.", "prompt: Review it.\n          working_dir: pr", 1)
	if f := parseWith(t, dirIn, nil); len(f.Agents) != 1 || !reflect.DeepEqual(f.Agents[0].Prompt, []string{graph.PromptPRContent}) {
		t.Errorf("directory input agents = %+v", f.Agents)
	}
}

// Acceptance: gh pr checkout counts as exec only when something later runs
// code from it.
func TestPRCheckoutCommand(t *testing.T) {
	read := parseWith(t, readIndirect(t, "pr-checkout-read.yml"), nil)
	if len(read.UntrustedExec) != 0 {
		t.Errorf("read: execs = %+v", read.UntrustedExec)
	}
	if want := []UntrustedExec{{Job: "stat", Kind: ExecCheckout, Detail: "gh pr checkout", Line: 8}}; !reflect.DeepEqual(read.ReadOnlyCheckouts, want) {
		t.Errorf("read: read-only = %+v, want %+v", read.ReadOnlyCheckouts, want)
	}
	run := parseWith(t, readIndirect(t, "pr-checkout-run.yml"), nil)
	if want := []UntrustedExec{{Job: "test", Trigger: "issue_comment", Kind: ExecCheckout, Detail: "gh pr checkout", Line: 8}}; !reflect.DeepEqual(run.UntrustedExec, want) {
		t.Errorf("run: execs = %+v, want %+v", run.UntrustedExec, want)
	}
	for _, c := range []struct {
		run  string
		exec bool
	}{
		{"gh pr checkout 1 && make", true},
		{"gh pr checkout 1\nnpm test", true},
		{"git fetch origin pull/1/head:pr && git checkout pr && ./build.sh", true},
		{"gh pr checkout 1 && echo done", false},
		{"gh pr checkout 1 # then nothing", false},
		{"git fetch origin pull/1/head", false},
	} {
		src := "on: issue_comment\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          " +
			strings.ReplaceAll(c.run, "\n", "\n          ") + "\n"
		f := parseWith(t, src, nil)
		if got := len(f.UntrustedExec) > 0; got != c.exec {
			t.Errorf("%q: exec = %v, want %v (%+v)", c.run, got, c.exec, f.UntrustedExec)
		}
	}
}

// ---- collector ----

const (
	compositeWF = "workflow:acme-app/docs/.github/workflows/composite.yml"
	reusableWF  = "workflow:acme-app/docs/.github/workflows/triage.yml"
	scriptWF    = "workflow:acme-app/docs/.github/workflows/summarize.yml"
	prDirWF     = "workflow:acme-app/docs/.github/workflows/pr-dir.yml"
	readWF      = "workflow:acme-app/docs/.github/workflows/pr-checkout-read.yml"
	runWF       = "workflow:acme-app/docs/.github/workflows/pr-checkout-run.yml"
	actionKey   = "/repos/acme-app/docs/contents/.github/actions/ai-review/action.yml"
	scriptKey   = "/repos/acme-app/docs/contents/ci/ai-summary.sh"
)

// plantIndirect plants the issue #165 fixtures on the public acme-app/docs.
func plantIndirect(t *testing.T, f *fakeGitHub) {
	t.Helper()
	setVisibility(t, f, "acme-app", "docs", "public")
	for wf, file := range map[string]string{
		"acme-app/docs/composite.yml": "composite-caller.yml", "acme-app/docs/triage.yml": "reusable-caller.yml",
		"acme-app/web/ai-triage.yml": "reusable-called.yml", "acme-app/docs/summarize.yml": "script-caller.yml",
		"acme-app/docs/pr-dir.yml": "pr-dir.yml", "acme-app/docs/pr-checkout-read.yml": "pr-checkout-read.yml",
		"acme-app/docs/pr-checkout-run.yml": "pr-checkout-run.yml",
	} {
		f.extraWorkflows[wf] = readIndirect(t, file)
	}
	f.extraFiles["acme-app/docs/.github/actions/ai-review/action.yml"] = readIndirect(t, "composite-action.yml")
	f.extraFiles["acme-app/docs/ci/ai-summary.sh"] = readIndirect(t, "ai-summary.sh")
}

func TestIndirectCollect(t *testing.T) {
	for _, mode := range []struct {
		name string
		rest bool
	}{{"graphql", false}, {"rest", true}} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			plantIndirect(t, f)
			ix := collectMode(t, f, mode.rest)
			for _, key := range []string{actionKey, scriptKey} {
				if n := f.hitCount(key); n != 1 {
					t.Errorf("%s fetched %d times, want 1", key, n)
				}
			}

			wantAttrs(t, "composite", ix.node(t, compositeWF), map[string]string{
				graph.AttrAgent: "claude-code-base-action", graph.AttrAgentSource: "composite,uses", graph.AttrAgentConfidence: graph.AgentAction,
				graph.AttrAgentExposure: graph.ExposureOutsiders, graph.AttrAgentPrompt: "github.event.pull_request.title,pr_content",
				graph.AttrUntrustedCheckout: CheckoutReadOnly,
			})
			e := ix.mustEdge(t, externalAnyone, compositeWF, graph.CanTrigger)
			if e.Evidence != graph.Live || e.Attrs[attrExec] != ExecAgent || e.Attrs[graph.AttrFile] != ".github/actions/ai-review/action.yml" ||
				e.Attrs[graph.AttrLine] != "11" {
				t.Errorf("composite edge = %+v", e)
			}

			wantAttrs(t, "reusable", ix.node(t, reusableWF), map[string]string{
				graph.AttrAgent: "codex-cli", graph.AttrAgentSource: "reusable,run", graph.AttrAgentConfidence: graph.AgentCLI,
				graph.AttrAgentExposure: graph.ExposureOutsiders, graph.AttrAgentPrompt: "github.event.comment.body",
			})
			e = ix.mustEdge(t, externalAnyone, reusableWF, graph.CanTrigger)
			if e.Evidence != graph.Live || e.Attrs[attrTrigger] != "issue_comment" || e.Attrs[graph.AttrFile] != ".github/workflows/triage.yml" ||
				e.Attrs[graph.AttrLine] != "9" {
				t.Errorf("reusable edge = %+v", e)
			}

			wantAttrs(t, "script", ix.node(t, scriptWF), map[string]string{
				graph.AttrAgent: "claude-cli", graph.AttrAgentSource: "run,script", graph.AttrAgentConfidence: graph.AgentCLI,
				graph.AttrAgentPrompt: graph.PromptPRContent, graph.AttrAgentSecrets: "1",
			})
			if e := ix.mustEdge(t, externalAnyone, scriptWF, graph.CanTrigger); e.Evidence != graph.Live || e.Attrs[graph.AttrLine] != "10" {
				t.Errorf("script edge = %+v", e)
			}

			wantAttrs(t, "pr-dir", ix.node(t, prDirWF), map[string]string{graph.AttrAgentPrompt: graph.PromptPRContent})

			wantAttrs(t, "read", ix.node(t, readWF), map[string]string{graph.AttrUntrustedCheckout: CheckoutReadOnly})
			ix.noEdge(t, externalAnyone, readWF, graph.CanTrigger)
			wantAttrs(t, "run", ix.node(t, runWF), map[string]string{graph.AttrUntrustedCheckout: CheckoutExec})
			if e := ix.mustEdge(t, externalAnyone, runWF, graph.CanTrigger); e.Attrs[attrExec] != ExecCheckout || e.Attrs[attrDetail] != "gh pr checkout" {
				t.Errorf("run edge = %+v", e)
			}
		})
	}
}

// A composite action gop cannot read is a coverage gap; the workflow keeps
// what gop read without it.
func TestIndirectMissingAction(t *testing.T) {
	ix := collectWith(t, func(f *fakeGitHub) {
		setVisibility(t, f, "acme-app", "docs", "public")
		f.extraWorkflows["acme-app/docs/composite.yml"] = readIndirect(t, "composite-caller.yml")
	})
	if _, ok := hasCoverage(ix.g, compositeWF, "follow:.github/actions/ai-review/action.yml"); !ok {
		t.Error("no coverage entry for the unreadable action")
	}
	n := ix.node(t, compositeWF)
	if v, ok := n.Attrs[graph.AttrAgent]; ok {
		t.Errorf("agent = %q, want none", v)
	}
	if n.Attrs[graph.AttrUntrustedCheckout] != CheckoutReadOnly {
		t.Errorf("untrusted_checkout = %q", n.Attrs[graph.AttrUntrustedCheckout])
	}
}
