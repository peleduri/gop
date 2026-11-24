package collect

import (
	"slices"
	"testing"
)

// TestAgentrunCLI: agentrun runs start and template eval are agent runs, in
// every way the CLI is invoked; its other subcommands are not.
func TestAgentrunCLI(t *testing.T) {
	for _, run := range []string{
		`agentrun runs start release-notes --wait --timeout 300 --body '{"input":{}}'`,
		`npx @parcha/agentrun runs start triage --wait`,
		`npx -y @parcha/agentrun@0.1.0 template eval ./templates/review`,
		`~/.agentrun/bin/agentrun runs start review --max-cost-usd 0.25`,
		"set -e\nAGENTRUN_URL=http://localhost:3000 agentrun runs start review",
	} {
		c, _, ok := matchAgentCLI(run)
		if !ok || c.kind != "agentrun-cli" {
			t.Errorf("%q: got %q, %v; want agentrun-cli", run, c.kind, ok)
		}
	}
	for _, run := range []string{
		`npx @parcha/agentrun`,
		`agentrun doctor`,
		`~/.agentrun/bin/agentrun stop`,
		`npx @parcha/agentrun workflows validate flow.yaml`,
		`agentrun runs list`,
		`agentrun start runs`,
		`echo "agentrun runs start review"`,
		`npm install -g @parcha/agentrun`,
	} {
		if c, _, ok := matchAgentCLI(run); ok {
			t.Errorf("%q matched %s", run, c.kind)
		}
	}
}

// TestAgentrunImage: the agentrun server image as a job container, a service
// or a docker:// step marks the job as an agent job (source image).
func TestAgentrunImage(t *testing.T) {
	cases := map[string]string{
		"container string": `on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    container: ghcr.io/parcha-ai/agentrun-server:beta
    steps:
      - run: echo hi
`,
		"container mapping, digest": `on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    container:
      image: GHCR.IO/Parcha-AI/agentrun-server@sha256:0123
    steps:
      - run: echo hi
`,
		"service": `on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    services:
      agentrun:
        image: ghcr.io/parcha-ai/agentrun-server:v0.1.0-beta.56
    steps:
      - run: echo hi
`,
		"docker step": `on: issue_comment
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://ghcr.io/parcha-ai/agentrun-server:beta
`,
	}
	for name, src := range cases {
		f := parseAgents(t, src)
		if len(f.Agents) != 1 || !slices.Equal(f.Agents[0].Kinds, []string{"agentrun-server"}) || !slices.Equal(f.Agents[0].Sources, []string{"image"}) {
			t.Errorf("%s: agents = %+v", name, f.Agents)
		}
	}
	for name, src := range map[string]string{
		"other image": `on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    container: ghcr.io/parcha-ai/agentrun-server-docs:beta
    services:
      db:
        image: postgres:16
    steps:
      - uses: docker://alpine:3
`,
	} {
		if f := parseAgents(t, src); len(f.Agents) != 0 {
			t.Errorf("%s: agents = %+v", name, f.Agents)
		}
	}
}

func TestAgentConfidenceImage(t *testing.T) {
	if got := agentConfidence([]string{"image"}); got != "cli" {
		t.Errorf("image confidence = %q, want cli", got)
	}
}
