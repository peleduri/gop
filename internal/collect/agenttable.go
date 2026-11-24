package collect

import "github.com/peleduri/gop/internal/graph"

// The known AI coding agents, in one place so the list is easy to extend
// (see docs/agents-in-ci.md). Add a row here; nothing else needs to change
// for a new action or CLI to be detected.
//
// Action inputs and actor checks were read from each action's public README
// and action.yml (November 2026):
//
//   - anthropics/claude-code-action: prompt, claude_args, settings; only
//     actors with write access can start it, unless allowed_non_write_users
//     ('*' for everyone) or allowed_bots ('*' for every bot) widen it. The
//     v0 inputs direct_prompt, override_prompt, custom_instructions and
//     allowed_tools are deprecated but still read.
//   - anthropics/claude-code-base-action: prompt, claude_args, settings; no
//     actor check ("does not enforce any trust boundaries on its own").
//   - openai/codex-action: prompt, codex-args, safety-strategy, sandbox;
//     only actors with write access, plus the users in allow-users.
//
// The others are matched so they are listed, with an actor check gop does
// not know (GateUnknown): reach through them counts as possible only.

// agentAction is one known agent action, matched by owner/repo[/path]
// (lower case, any ref).
type agentAction struct {
	kind  string
	repos []string
	gate  string // the actor check with default inputs
	// args are the with: inputs that carry CLI flags or settings, scanned
	// for tool flags (agentToolFlag).
	args []string
	// widen lists the with: inputs that let actors without write access
	// start it: a list of users or bots widens the gate to GateListed, '*'
	// to GateAnyone, an expression to GateUnknown.
	widen map[string]bool
}

var agentActions = []agentAction{
	{
		kind: "claude-code-action", repos: []string{"anthropics/claude-code-action"}, gate: graph.GateWriteAccess,
		args:  []string{"claude_args", "settings", "allowed_tools"},
		widen: map[string]bool{"allowed_non_write_users": true, "allowed_bots": true},
	},
	{
		kind: "claude-code-base-action", repos: []string{"anthropics/claude-code-base-action"}, gate: graph.GateNone,
		args: []string{"claude_args", "settings", "allowed_tools"},
	},
	{kind: "claude-code-security-review", repos: []string{"anthropics/claude-code-security-review"}, gate: graph.GateUnknown},
	{
		kind: "codex-action", repos: []string{"openai/codex-action"}, gate: graph.GateWriteAccess,
		args:  []string{"codex-args", "safety-strategy", "sandbox"},
		widen: map[string]bool{"allow-users": true},
	},
	{kind: "gemini-cli-action", repos: []string{"google-github-actions/run-gemini-cli"}, gate: graph.GateUnknown, args: []string{"settings"}},
	{kind: "pr-agent", repos: []string{"qodo-ai/pr-agent", "codium-ai/pr-agent", "the-pr-agent/pr-agent"}, gate: graph.GateUnknown},
	{kind: "opencode-action", repos: []string{"sst/opencode/github", "anomalyco/opencode/github"}, gate: graph.GateUnknown},
}

// copilotSetupJob is the job id GitHub requires in
// .github/workflows/copilot-setup-steps.yml, the workflow that prepares
// the environment the Copilot coding agent runs in. Only people with write
// access can assign work to the agent.
const (
	copilotSetupJob  = "copilot-setup-steps"
	copilotAgentKind = "copilot-coding-agent"
)

// agentCLI is one known agent CLI invoked from a run: step. bins are the
// command and npm package names; markers are the arguments that make a run
// non-interactive (a prompt flag, a subcommand). A bare interactive
// invocation (claude --version) is not an agent run.
type agentCLI struct {
	kind    string
	bins    []string
	markers []string
	// quoted: a quoted first argument is a prompt (llm "...").
	quoted bool
}

var agentCLIs = []agentCLI{
	{kind: "claude-cli", bins: []string{"claude", "@anthropic-ai/claude-code"},
		markers: []string{"-p", "--print", "--dangerously-skip-permissions", "--output-format", "--allowedtools", "--permission-mode"}},
	{kind: "codex-cli", bins: []string{"codex", "@openai/codex"},
		markers: []string{"exec", "e", "--full-auto", "-q", "--quiet", "--dangerously-bypass-approvals-and-sandbox"}},
	{kind: "cursor-cli", bins: []string{"cursor-agent"}, markers: []string{"-p", "--print", "--force"}},
	{kind: "gemini-cli", bins: []string{"gemini", "@google/gemini-cli"}, markers: []string{"-p", "--prompt", "--yolo"}},
	{kind: "aider", bins: []string{"aider", "aider-chat"}, markers: []string{"-m", "--message", "--message-file", "--yes", "--yes-always"}},
	{kind: "opencode-cli", bins: []string{"opencode", "opencode-ai"}, markers: []string{"run"}},
	{kind: "llm-cli", bins: []string{"llm"}, markers: []string{"prompt", "-m", "--model", "-s", "--system", "-t", "--template", "-T", "--tool"}, quoted: true},
}

// agentToolFlags maps a lower-case substring of a run: command or an args
// input to its agent_tools value (graph.AgentToolFlags).
var agentToolFlags = []struct{ match, flag string }{
	{"--dangerously-skip-permissions", "dangerously_skip_permissions"},
	{"bypasspermissions", "bypass_permissions"},
	{"--dangerously-bypass-approvals-and-sandbox", "dangerously_bypass_approvals_and_sandbox"},
	{"--yolo", "yolo"},
	{"--full-auto", "full_auto"},
	{"danger-full-access", "sandbox_danger_full_access"},
	{"--yes-always", "yes_always"},
	{"--allowedtools", "allowed_tools"},
	{"--allowed-tools", "allowed_tools"},
	{"allowedtools", "allowed_tools"},
}

// agentNameWords are the weak name signals (agent_confidence=name_only),
// matched in the workflow name, the file name and job ids and names. "ai-"
// must start a word, so "email-" does not match.
var agentNameWords = []string{"claude", "codex", "copilot", "llm"}
