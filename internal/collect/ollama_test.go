package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestOllamaCLI(t *testing.T) {
	for _, run := range []string{
		`ollama run llama3 "summarize"`,
		`gh pr diff 7 | ollama run llama3`,
		`ollama run llama3 --ask "Is this change safe?" < diff.txt`,
		`ollama run llama3 < prompt.md`,
		`ollama run llama3 --format json "label this issue" > out.json`,
		`out=$(cat body.txt | ollama run llama3)`,
		`/usr/local/bin/ollama run llama3:8b 'review'`,
	} {
		c, _, ok := matchAgentCLI(run)
		if !ok || c.kind != "ollama-cli" {
			t.Errorf("%q: got %q, %v; want ollama-cli", run, c.kind, ok)
		}
	}
	for _, run := range []string{
		`ollama pull llama3`,
		`ollama serve`,
		`ollama --version`,
		`ollama run llama3`,
		`ollama run`,
		`ollama run llama3 --format json`,
		`ollama run llama3 --keepalive 5m > out.txt 2>&1`,
		`false || ollama run llama3`,
		`ollama list | grep llama3`,
		`echo "ollama run llama3 hi"`,
	} {
		if c, _, ok := matchAgentCLI(run); ok {
			t.Errorf("%q matched %s", run, c.kind)
		}
	}
}

func TestLLMKeyOllamaVLLM(t *testing.T) {
	for _, k := range []string{"OLLAMA_API_KEY", "VLLM_API_KEY", "MY_VLLM_API_KEY"} {
		if !llmKeyRe.MatchString(k) {
			t.Errorf("%s is not a model key", k)
		}
	}
	if llmKeyRe.MatchString("OLLAMA_HOST") {
		t.Error("OLLAMA_HOST is a model key")
	}
}

// The synthetic workflows of issue #153 planted on acme-app/web.
func TestOllamaVLLMFixtureGraph(t *testing.T) {
	const (
		ollamaWF = "workflow:acme-app/web/.github/workflows/ollama-review.yml"
		vllmWF   = "workflow:acme-app/web/.github/workflows/vllm-review.yml"
		pullWF   = "workflow:acme-app/web/.github/workflows/ollama-pull.yml"
	)
	ix := collectWith(t, func(f *fakeGitHub) {
		setVisibility(t, f, "acme-app", "web", "public")
		for _, file := range []string{"ollama-review.yml", "vllm-review.yml", "ollama-pull.yml"} {
			b, err := os.ReadFile(filepath.Join("testdata", "agents", file))
			if err != nil {
				t.Fatal(err)
			}
			f.extraWorkflows["acme-app/web/"+file] = string(b)
		}
	})

	// (a) gh pr diff | ollama run on pull_request_target.
	a := ix.node(t, ollamaWF).Attrs
	if a[graph.AttrAgent] != "ollama-cli" || a[graph.AttrAgentConfidence] != graph.AgentCLI ||
		a[graph.AttrAgentGate] != graph.GateNone || a[graph.AttrAgentExposure] != graph.ExposureOutsiders ||
		!strings.Contains(a[graph.AttrAgentPrompt], graph.PromptPRContent) || a[graph.AttrAgentPerms] != "contents:write" {
		t.Errorf("ollama attrs = %v", a)
	}
	e := ix.mustEdge(t, externalAnyone, ollamaWF, graph.CanTrigger)
	if e.Attrs[attrExec] != ExecAgent || e.Attrs[attrDetail] != "ollama-cli" {
		t.Errorf("ollama edge = %+v", e)
	}

	// (b) a VLLM_API_KEY step reading the head checkout.
	v := ix.node(t, vllmWF).Attrs
	if v[graph.AttrAgent] != LLMScriptKind || v[graph.AttrAgentConfidence] != graph.AgentHeuristic ||
		v[graph.AttrAgentPrompt] != graph.PromptPRContent || v[graph.AttrAgentExposure] != graph.ExposureOutsiders {
		t.Errorf("vllm attrs = %v", v)
	}

	// (c) ollama pull alone is not an agent.
	for k := range ix.node(t, pullWF).Attrs {
		if strings.HasPrefix(k, "agent") {
			t.Errorf("ollama-pull has %s", k)
		}
	}
	ix.noEdge(t, externalAnyone, pullWF, graph.CanTrigger)
}
