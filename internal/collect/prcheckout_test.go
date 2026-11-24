package collect

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// The synthetic workflow of issue #145: pull_request_target plus an
// author-gated issue_comment, the base branch's own script, the pull
// request's head checked out into pr/ only as files to read.
const prReadOnlyHead = `name: review
on:
  pull_request_target:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  review:
    if: github.event_name == 'pull_request_target' || contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: pr
          persist-credentials: false
      - uses: ./.github/actions/setup
      - run: python scripts/check.py --dir pr/
`

func TestPRCheckoutExec(t *testing.T) {
	const head = "ref: ${{ github.event.pull_request.head.sha }}"
	cases := []struct {
		name     string
		src      string
		exec     bool // a checkout exec on pull_request_target
		readOnly bool
	}{
		{name: "(a) head in pr/, only read by a base-branch script", src: prReadOnlyHead, readOnly: true},
		{name: "(b) cd pr && npm ci", src: prReadOnlyHead + "      - run: cd pr && npm ci\n", exec: true},
		{name: "(c) head at the root plus npm test", src: `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`, exec: true},
		{name: "head at the root, nothing after it", src: `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, readOnly: true},
		{name: "path is an expression: treated as the root", src: `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: ${{ inputs.dir }}
      - run: echo done
`, exec: true},
		{name: "workspace-prefixed path, local action from it", src: prReadOnlyHead + "      - uses: ./pr/.github/actions/lint\n", exec: true},
		{name: "working-directory in pr", src: prReadOnlyHead + "      - run: make\n        working-directory: ${{ github.workspace }}/pr\n", exec: true},
		{name: "job defaults working-directory", src: strings.Replace(prReadOnlyHead, "    runs-on: ubuntu-latest\n",
			"    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: pr\n", 1), exec: true},
		{name: "script run from pr", src: prReadOnlyHead + "      - run: bash pr/scripts/build.sh\n", exec: true},
		{name: "file in pr run directly", src: prReadOnlyHead + "      - run: ./pr/configure --fast\n", exec: true},
		{name: "build tool pointed at pr", src: prReadOnlyHead + "      - run: npm --prefix=pr install\n", exec: true},
		{name: "pip install -e pr", src: prReadOnlyHead + "      - run: pip install -e ./pr\n", exec: true},
		{name: "go run from pr", src: prReadOnlyHead + "      - run: go run ./pr/cmd/gen\n", exec: true},
		{name: "reading pr with cat and diff stays read-only", src: prReadOnlyHead + "      - run: |\n          cat pr/README.md\n          diff -r pr/docs docs\n", readOnly: true},
		{name: "interpreter on a base script that reads pr", src: prReadOnlyHead + "      - run: node scripts/summarize.js pr\n", readOnly: true},
		{name: "a step before the checkout does not count", src: strings.Replace(prReadOnlyHead, "      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n",
			"      - uses: actions/checkout@v4\n      - run: make -C pr\n      - uses: actions/checkout@v4\n", 1), readOnly: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			var exec bool
			for _, x := range f.UntrustedExec {
				if x.Kind == ExecCheckout && x.Trigger == "pull_request_target" && x.Detail == head {
					exec = true
				}
			}
			if exec != c.exec {
				t.Errorf("checkout exec = %v, want %v (execs %+v)", exec, c.exec, f.UntrustedExec)
			}
			if got := len(f.ReadOnlyCheckouts) > 0; got != c.readOnly {
				t.Errorf("read-only = %+v, want %v", f.ReadOnlyCheckouts, c.readOnly)
			}
		})
	}
}

func TestReadOnlyCheckoutFacts(t *testing.T) {
	f, err := ParseWorkflow([]byte(prReadOnlyHead))
	if err != nil {
		t.Fatal(err)
	}
	want := []UntrustedExec{{Job: "review", Kind: ExecCheckout, Detail: "ref: ${{ github.event.pull_request.head.sha }}", Line: 16}}
	if !reflect.DeepEqual(f.ReadOnlyCheckouts, want) {
		t.Errorf("read-only = %+v\nwant      %+v", f.ReadOnlyCheckouts, want)
	}
	if len(f.UntrustedExec) != 0 || len(f.Agents) != 0 {
		t.Errorf("execs %+v agents %+v, want none", f.UntrustedExec, f.Agents)
	}
}

func TestLLMScriptHeuristic(t *testing.T) {
	// (d): (a) plus a base-branch script with an LLM API key that reads pr/.
	const llm = "      - run: python scripts/ai_review.py --diff pr/\n        env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n"
	f, err := ParseWorkflow([]byte(prReadOnlyHead + llm))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Agents) != 1 {
		t.Fatalf("agents = %+v, want one", f.Agents)
	}
	a := f.Agents[0]
	if !reflect.DeepEqual(a.Kinds, []string{LLMScriptKind}) || !reflect.DeepEqual(a.Sources, []string{"heuristic"}) ||
		!reflect.DeepEqual(a.Prompt, []string{graph.PromptPRContent}) || a.Gate != graph.GateNone ||
		a.Exposure != graph.ExposureOutsiders || !reflect.DeepEqual(a.Secrets, []string{"ANTHROPIC_API_KEY"}) || a.Line != 21 {
		t.Errorf("agent = %+v", a)
	}
	if len(f.ReadOnlyCheckouts) != 1 {
		t.Errorf("read-only = %+v, want the pr/ checkout", f.ReadOnlyCheckouts)
	}
	var kinds []string
	for _, x := range f.UntrustedExec {
		kinds = append(kinds, x.Trigger+"/"+x.Kind)
		if x.Kind != ExecAgent || !x.Unverified {
			t.Errorf("exec = %+v, want an unverified agent exec", x)
		}
	}
	if want := []string{"issue_comment/agent", "pull_request_target/agent"}; !reflect.DeepEqual(kinds, want) {
		t.Errorf("execs = %v, want %v", kinds, want)
	}
	for _, x := range f.UntrustedExec {
		if x.Trigger == "issue_comment" && !reflect.DeepEqual(x.Assoc, []string{"COLLABORATOR", "MEMBER", "OWNER"}) {
			t.Errorf("issue_comment assoc = %v", x.Assoc)
		}
		if x.Trigger == "pull_request_target" && x.Assoc != nil {
			t.Errorf("pull_request_target assoc = %v, want none", x.Assoc)
		}
	}

	others := []struct{ name, src string }{
		{"key at workflow level, gh pr diff", "on: pull_request_target\nenv:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\njobs:\n  r:\n    steps:\n      - run: gh pr diff 1 | node review.js\n"},
		{"key under another name, PR body through env", "on: issues\njobs:\n  r:\n    steps:\n      - run: node triage.js\n        env:\n          KEY: ${{ secrets.MY_GEMINI_API_KEY }}\n          BODY: ${{ github.event.issue.body }}\n"},
	}
	for _, o := range others {
		f := parseAgents(t, o.src)
		if len(f.Agents) != 1 || f.Agents[0].Kinds[0] != LLMScriptKind {
			t.Errorf("%s: agents = %+v", o.name, f.Agents)
		}
	}
	nots := []struct{ name, src string }{
		{"no key", prReadOnlyHead + "      - run: python scripts/report.py pr/\n"},
		{"key but no PR content", prReadOnlyHead + "      - run: python scripts/release_notes.py\n        env:\n          OPENAI_API_KEY: x\n"},
		{"not a risky trigger", "on: pull_request\njobs:\n  r:\n    steps:\n      - run: gh pr diff | node review.js\n        env:\n          OPENAI_API_KEY: x\n"},
	}
	for _, o := range nots {
		if f := parseAgents(t, o.src); len(f.Agents) != 0 {
			t.Errorf("%s: agents = %+v, want none", o.name, f.Agents)
		}
	}
}

func TestAssocGate(t *testing.T) {
	cases := []struct {
		name, cond, trigger string
		want                []string
	}{
		{"fromJSON list", `contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)`, "issue_comment", []string{"MEMBER", "OWNER"}},
		{"in ${{ }}", `${{ github.event.comment.author_association == 'OWNER' }}`, "issue_comment", []string{"OWNER"}},
		{"other event or gate", `github.event_name == 'pull_request_target' || (github.event_name == 'issue_comment' && github.event.comment.author_association == 'COLLABORATOR')`, "issue_comment", []string{"COLLABORATOR"}},
		{"or with the same event: no gate", `github.event_name == 'issue_comment' || github.event.comment.author_association == 'OWNER'`, "issue_comment", nil},
		{"or with anything else: no gate", `github.event.issue.pull_request || github.event.comment.author_association == 'OWNER'`, "issue_comment", nil},
		{"negation: no gate", `github.event.comment.author_association != 'NONE'`, "issue_comment", nil},
		{"wrong context for the trigger", `github.event.comment.author_association == 'OWNER'`, "pull_request_review", nil},
		{"not a comment trigger", `github.event.comment.author_association == 'OWNER'`, "pull_request_target", nil},
		{"review", `github.event.review.author_association == 'MEMBER'`, "pull_request_review", []string{"MEMBER"}},
		{"no values", `contains(env.ALLOWED, github.event.comment.author_association)`, "issue_comment", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "on: [issue_comment, pull_request_review, pull_request_target]\njobs:\n  a:\n    if: " + yamlQuote(c.cond) + "\n    steps:\n      - run: echo hi\n"
			w := &yamlWalk{}
			job := parseJob(t, w, src)
			if got := assocGate(w, job, c.trigger); !reflect.DeepEqual(got, c.want) {
				t.Errorf("gate = %v, want %v", got, c.want)
			}
		})
	}
	for vals, want := range map[string]string{
		"OWNER,COLLABORATOR": assocCollaborators, "MEMBER": assocMembers, "OWNER,MEMBER,COLLABORATOR": assocMembers,
		"MEMBER,CONTRIBUTOR": assocOutsiders, "NONE": assocOutsiders,
	} {
		if got := assocClass(strings.Split(vals, ",")); got != want {
			t.Errorf("class(%s) = %s, want %s", vals, got, want)
		}
	}
}

// parseJob returns job a of a workflow source.
func parseJob(t *testing.T, w *yamlWalk, src string) *yamlMap {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	root, err := w.mapping(rootMap(&doc), "workflow")
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := w.mapping(field(root, "jobs"), "jobs")
	if err != nil {
		t.Fatal(err)
	}
	job, err := w.mapping(field(jobs, "a"), "job")
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func yamlQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func TestAuthorGateTriggers(t *testing.T) {
	const gated = "workflow:acme-app/docs/.github/workflows/gated.yml"
	src := func(vals string) string {
		return "on: issue_comment\njobs:\n  x:\n    if: contains(fromJSON('[" + vals + "]'), github.event.comment.author_association)\n" +
			"    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.comment.body }}\"\n"
	}
	t.Run("MEMBER: the org's members, not anyone", func(t *testing.T) {
		ix := collectWith(t, func(f *fakeGitHub) {
			setVisibility(t, f, "acme-app", "docs", "public")
			f.extraWorkflows["acme-app/docs/gated.yml"] = src(`"OWNER","MEMBER"`)
		})
		ix.noEdge(t, externalAnyone, gated, graph.CanTrigger)
		e := ix.mustEdge(t, "members:acme-app", gated, graph.CanTrigger)
		if e.Attrs[attrAssoc] != "MEMBER,OWNER" || e.Evidence != graph.Live {
			t.Errorf("edge = %+v", e)
		}
	})
	t.Run("OWNER and COLLABORATOR: no edge, coverage", func(t *testing.T) {
		ix := collectWith(t, func(f *fakeGitHub) {
			setVisibility(t, f, "acme-app", "docs", "public")
			f.extraWorkflows["acme-app/docs/gated.yml"] = src(`"OWNER","COLLABORATOR"`)
		})
		ix.noEdge(t, externalAnyone, gated, graph.CanTrigger)
		ix.noEdge(t, "members:acme-app", gated, graph.CanTrigger)
		if c, ok := hasCoverage(ix.g, "repo:acme-app/docs", factTriggering); !ok || !strings.Contains(c.Reason, "author_association") {
			t.Errorf("coverage = %+v (%v)", c, ok)
		}
	})
	t.Run("CONTRIBUTOR includes outsiders", func(t *testing.T) {
		ix := collectWith(t, func(f *fakeGitHub) {
			setVisibility(t, f, "acme-app", "docs", "public")
			f.extraWorkflows["acme-app/docs/gated.yml"] = src(`"MEMBER","CONTRIBUTOR"`)
		})
		if e := ix.mustEdge(t, externalAnyone, gated, graph.CanTrigger); e.Attrs[attrAssoc] != "CONTRIBUTOR,MEMBER" {
			t.Errorf("edge = %+v", e)
		}
	})
}

func TestReadOnlyCheckoutGraph(t *testing.T) {
	const (
		ro  = "workflow:acme-app/docs/.github/workflows/review.yml"
		llm = "workflow:acme-app/docs/.github/workflows/ai-review.yml"
	)
	ix := collectWith(t, func(f *fakeGitHub) {
		setVisibility(t, f, "acme-app", "docs", "public")
		f.extraWorkflows["acme-app/docs/review.yml"] = prReadOnlyHead
		f.extraWorkflows["acme-app/docs/ai-review.yml"] = prReadOnlyHead +
			"      - run: python scripts/ai_review.py pr\n        env:\n          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
	})
	// (a): untrusted input, not execution: no edge, not ranked.
	n := ix.node(t, ro)
	if n.Attrs[graph.AttrUntrustedCheckout] != CheckoutReadOnly {
		t.Errorf("untrusted_checkout = %q", n.Attrs[graph.AttrUntrustedCheckout])
	}
	ix.noEdge(t, externalAnyone, ro, graph.CanTrigger)
	if r := graph.Reach(ix.g, externalAnyone, graph.Options{}); contains(r.Confirmed.Workflows, ro) || contains(r.Possible.Workflows, ro) {
		t.Errorf("anyone reaches %s", ro)
	}
	// (d): a heuristic agent prompt injection, possible only, not exec.
	a := ix.node(t, llm).Attrs
	if a[graph.AttrAgent] != LLMScriptKind || a[graph.AttrAgentConfidence] != graph.AgentHeuristic ||
		a[graph.AttrAgentPrompt] != graph.PromptPRContent || a[graph.AttrAgentExposure] != graph.ExposureOutsiders ||
		a[graph.AttrUntrustedCheckout] != CheckoutReadOnly {
		t.Errorf("ai-review attrs = %v", a)
	}
	e := ix.mustEdge(t, externalAnyone, llm, graph.CanTrigger)
	if e.Attrs[attrExec] != ExecAgent || e.Evidence != graph.NotVisible || e.Attrs[attrDetail] != LLMScriptKind {
		t.Errorf("ai-review edge = %+v", e)
	}
	r := graph.Reach(ix.g, externalAnyone, graph.Options{})
	if contains(r.Confirmed.Workflows, llm) || !contains(r.Possible.Workflows, llm) {
		t.Errorf("ai-review: confirmed %v possible %v, want possible only", r.Confirmed.Workflows, r.Possible.Workflows)
	}
	if s := graph.BlastRadius(ix.g, externalAnyone); s.AgentExposed != 0 {
		t.Errorf("agent_exposed = %d, want 0 for a heuristic match", s.AgentExposed)
	}
}
