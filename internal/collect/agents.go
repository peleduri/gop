package collect

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// AI coding agents in GitHub Actions (docs/agents-in-ci.md). The parser
// finds agent steps by the table in agenttable.go and records, per agent
// job, who can start it, what untrusted text reaches it, and what its token,
// secrets, runner and tool settings give it. The collector writes them as
// agent attrs on the workflow node and adds principal -CAN_TRIGGER->
// workflow (exec=agent) for the principals who can start an agent job
// without push access.

// ExecAgent is the UntrustedExec kind of an agent job that people without
// push access can start on a risky trigger: the agent reads their text
// and acts with the job's token, secrets and tools.
const ExecAgent = "agent"

// AgentJob is one job that runs an AI coding agent.
type AgentJob struct {
	Job      string
	Kinds    []string // agent kinds, sorted
	Sources  []string // uses | run | setup, sorted
	Gate     string   // the weakest actor check of its agent steps (graph.Gate*)
	Exposure string   // graph.Exposure*
	Prompt   []string // attacker contexts interpolated into the agent steps, sorted
	Perms    []string // write scopes of its token: contents:write, ..., write-all; default when no permissions are declared
	Secrets  []string // secret names the job references, sorted (GITHUB_TOKEN excluded; "*" for dynamic access)
	Runner   string   // hosted | self_hosted | unknown ("" when runs-on is absent)
	Tools    []string // agent_tools values, sorted
	RefKind  string   // the least pinned ref of its agent actions: sha | tag | branch; "" for CLIs only
	Line     int      // 1-based line of its first agent step's uses:/run: key
	// File is the repo-relative file that holds Line when it is not the
	// workflow itself (an agent in a local composite action or a called
	// reusable workflow of the same repo); "" for the workflow.
	File string
}

// gateOpenness orders gates from closed to open: a job with several agent
// steps takes the most open one.
var gateOpenness = map[string]int{graph.GateWriteAccess: 0, graph.GateListed: 1, graph.GateUnknown: 2, graph.GateAnyone: 3, graph.GateNone: 4}

// exposureWidth orders exposures from narrow to wide.
var exposureWidth = map[string]int{graph.ExposureMaintainer: 0, graph.ExposureForkRO: 1, graph.ExposureListed: 2, graph.ExposureOutsiders: 3}

var refPin = map[string]int{"sha": 0, "tag": 1, "branch": 2}

// scopeRe is a permissions scope name gop records in agent_permissions.
var scopeRe = regexp.MustCompile(`^[a-z][a-z-]*$`)

// readAgents finds the agent jobs of a workflow (f.Agents), adds an
// ExecAgent untrusted execution for each one people without push access can
// start on a risky trigger, and records the names the weak name-only match
// reads (f.Name, f.JobNames). f.Triggers must be set. It is lenient like
// triggerFacts: a shape it does not understand yields nothing.
func (f *WorkflowFacts) readAgents(doc *yaml.Node, ind *Indirect) {
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(doc), "workflow")
	if err != nil {
		return
	}
	f.Name = strings.TrimSpace(scalarOf(w, field(root, "name")))
	wfPerms, wfDeclared, err := w.permissionsOf(field(root, "permissions"))
	if err != nil {
		return
	}
	wfMap := permMap(wfPerms, wfDeclared)
	_, jobsNode := root.get("jobs")
	jobs, err := w.mapping(jobsNode, "jobs")
	if err != nil {
		return
	}
	wfSecrets := secretsIn(field(root, "env"))
	wfEnv, _ := w.mapping(field(root, "env"), "env")
	var risky []string
	pullRequest := false
	for _, t := range f.Triggers {
		if riskyTriggers[t] {
			risky = append(risky, t)
		}
		if t == "pull_request" {
			pullRequest = true
		}
	}
	ids := append([]string(nil), jobs.keys...)
	sort.Strings(ids)
	for _, id := range ids {
		_, jv := jobs.get(id)
		job, err := w.mapping(jv, "job")
		if err != nil {
			continue
		}
		if name := strings.TrimSpace(scalarOf(w, field(job, "name"))); name != "" {
			if f.JobNames == nil {
				f.JobNames = map[string]string{}
			}
			f.JobNames[id] = name
		}
		aj, ok := agentJob(w, id, job, len(risky) > 0, wfEnv, ind)
		if !ok {
			continue
		}
		jobPerms, jobDeclared, err := w.permissionsOf(field(job, "permissions"))
		if err != nil {
			continue
		}
		perms, _ := resolvePermissions(wfMap, jobPerms, jobDeclared)
		aj.Perms = agentWriteScopes(perms)
		aj.Secrets = jobSecrets(job, wfSecrets)
		aj.Runner, _, _ = w.classifyRunsOn(field(job, "runs-on"))
		open := gateOpenness[aj.Gate] >= gateOpenness[graph.GateUnknown]
		switch {
		case len(risky) > 0 && open:
			aj.Exposure = graph.ExposureOutsiders
			// A heuristic match (no known agent, only a model API key next to
			// the pull request's content, or a model API call in a script)
			// gives possible reach only.
			heuristic := agentConfidence(aj.Sources) == graph.AgentHeuristic
			for _, t := range risky {
				f.UntrustedExec = append(f.UntrustedExec, UntrustedExec{Job: id, Trigger: t, Kind: ExecAgent, Detail: strings.Join(aj.Kinds, ","),
					Line: aj.Line, File: aj.File, Unverified: aj.Gate == graph.GateUnknown || heuristic, Assoc: assocGate(w, job, t)})
			}
		case len(risky) > 0 && aj.Gate == graph.GateListed:
			aj.Exposure = graph.ExposureListed
		case pullRequest && open:
			aj.Exposure = graph.ExposureForkRO
		default:
			aj.Exposure = graph.ExposureMaintainer
		}
		f.Agents = append(f.Agents, aj)
	}
	// Keep the untrusted executions in job order (addTriggerFacts keeps the
	// first one per principal).
	sort.SliceStable(f.UntrustedExec, func(i, j int) bool { return f.UntrustedExec[i].Job < f.UntrustedExec[j].Job })
}

// agentConfidence is the strongest signal of a set of agent sources.
func agentConfidence(sources []string) string {
	switch {
	case containsStr(sources, "uses") || containsStr(sources, "setup"):
		return graph.AgentAction
	case containsStr(sources, "run"):
		return graph.AgentCLI
	}
	return graph.AgentHeuristic
}

// agentAcc accumulates one job's agent facts.
type agentAcc struct {
	aj                            AgentJob
	kinds, sources, prompt, tools map[string]bool
	gate                          int
}

func (a *agentAcc) setGate(g string) {
	if gateOpenness[g] > a.gate {
		a.gate = gateOpenness[g]
		a.aj.Gate = g
	}
}

// at records an agent step's position: the first one, preferring the
// workflow's own file (file "") over a followed file.
func (a *agentAcc) at(file string, n *yaml.Node) {
	if n == nil {
		return
	}
	if a.aj.Line == 0 || (file == a.aj.File && n.Line < a.aj.Line) || (file == "" && a.aj.File != "") {
		a.aj.Line, a.aj.File = n.Line, file
	}
}

// agentJob reads one job's agent steps. ok is false when it has none.
// risky says the workflow has a risky trigger: only then does a job with no
// known agent get the heuristic match (llmSteps). ind, when set, holds the
// followed files one level down (indirect.go).
func agentJob(w *yamlWalk, id string, job *yamlMap, risky bool, wfEnv *yamlMap, ind *Indirect) (AgentJob, bool) {
	a := &agentAcc{aj: AgentJob{Job: id}, kinds: map[string]bool{}, sources: map[string]bool{}, prompt: map[string]bool{}, tools: map[string]bool{}, gate: -1}
	if id == copilotSetupJob {
		a.kinds[copilotAgentKind], a.sources["setup"] = true, true
		a.setGate(graph.GateWriteAccess)
		k, _ := job.get("steps")
		if k == nil {
			k, _ = job.get("runs-on")
		}
		a.at("", k)
	}
	// A called reusable workflow runs with this job's event: its agents are
	// this job's.
	if cf, ok := ind.called(w, job); ok {
		anchor, _ := job.get("uses")
		ids, jobs := calledJobs(w, cf.Data)
		with, _ := w.mapping(field(job, "with"), "with")
		for _, cid := range ids {
			cj, err := w.mapping(field(jobs, cid), "job")
			if err != nil {
				continue
			}
			steps, _ := w.sequence(field(cj, "steps"), "steps")
			if a.scan(w, cj, steps, cf, anchor, SourceReusable, false, nil, nil, nil) {
				a.injected(withValues(w, with)) // the caller's inputs reach the agent
			}
		}
	}
	steps, _ := w.sequence(field(job, "steps"), "steps")
	jobEnv, _ := w.mapping(field(job, "env"), "env")
	a.scan(w, job, steps, IndirectFile{}, nil, "", false, ind, jobEnv, wfEnv)
	if len(a.kinds) == 0 && risky {
		for _, l := range llmSteps(w, steps, jobEnv, wfEnv) {
			a.kinds[LLMScriptKind], a.sources["heuristic"] = true, true
			a.setGate(graph.GateNone)
			a.at("", l.at)
			for _, p := range l.prompt {
				a.prompt[p] = true
			}
		}
	}
	if len(a.kinds) == 0 {
		return AgentJob{}, false
	}
	aj := a.aj
	aj.Kinds, aj.Sources, aj.Prompt, aj.Tools = sortedSet(a.kinds), sortedSet(a.sources), sortedSet(a.prompt), sortedSet(a.tools)
	return aj, true
}

// injected adds the attacker contexts interpolated into vals to the prompt.
func (a *agentAcc) injected(vals []string) {
	for _, v := range vals {
		for _, c := range injectedContexts(v) {
			a.prompt[c] = true
		}
	}
}

// scan finds the known agent actions and CLIs among steps and reports
// whether it found one. job holds the steps; file is where they are (zero
// for the workflow); a file in another repo is reported at anchor, the
// caller's uses: key. via is the indirection ("" for the workflow's own
// steps, else a Source* value). prIn says a checkout of the pull request's
// head made before these steps is in their workspace and read by them. ind,
// set for the workflow's own steps only, follows the local composite
// actions and repo scripts they load (one level).
func (a *agentAcc) scan(w *yamlWalk, job *yamlMap, steps []*yaml.Node, file IndirectFile, anchor *yaml.Node, via string, prIn bool, ind *Indirect, jobEnv, wfEnv *yamlMap) bool {
	at := func(n *yaml.Node) {
		if file.Where != "" {
			n = anchor
		}
		a.at(file.Path, n)
	}
	hit := false
	checkouts := prCheckouts(w, steps)
	for i, sn := range steps {
		step, err := w.mapping(sn, "step")
		if err != nil {
			continue
		}
		readsPR := prIn
		for _, c := range checkouts {
			if c.step < i && agentReadsDir(w, step, c.dir) {
				readsPR = true
			}
		}
		found := false
		usesKey, _ := step.get("uses")
		if u, ok := ParseUses(scalarOf(w, field(step, "uses"))); ok {
			if ag, ok := matchAgentAction(u); ok {
				found = true
				a.kinds[ag.kind], a.sources["uses"] = true, true
				at(usesKey)
				with, _ := w.mapping(field(step, "with"), "with")
				a.setGate(actionGate(w, ag, with))
				for _, name := range ag.args {
					addToolFlags(a.tools, scalarOf(w, field(with, name)))
				}
				if ag.kind == "claude-code-action" || ag.kind == "claude-code-base-action" {
					if scalarOf(w, field(with, "allowed_tools")) != "" {
						a.tools["allowed_tools"] = true
					}
				}
				a.injected(withValues(w, with))
				if a.aj.RefKind == "" || refPin[u.RefKind] > refPin[a.aj.RefKind] {
					a.aj.RefKind = u.RefKind
				}
			}
		}
		run := scalarOf(w, field(step, "run"))
		runKey, _ := step.get("run")
		if c, args, ok := matchAgentCLI(run); ok {
			found = true
			a.kinds[c.kind], a.sources["run"] = true, true
			at(runKey)
			a.setGate(graph.GateNone)
			addToolFlags(a.tools, args)
			a.injected([]string{run})
			// The pull request's diff or text read in the same script (gh
			// pr diff | ollama run ...) is a prompt too.
			for _, cmd := range prTextCmds {
				if strings.Contains(run, cmd) {
					a.prompt[graph.PromptPRContent] = true
				}
			}
		}
		env, _ := w.mapping(field(step, "env"), "env")
		if found {
			a.injected(withValues(w, env))
			if readsPR {
				a.prompt[graph.PromptPRContent] = true
			}
		}
		if ind != nil {
			if a.followAction(w, steps, checkouts, i, step, ind) {
				found = true
			}
			if a.followScripts(w, job, step, runKey, readsPR, ind, jobEnv, wfEnv) {
				found = true
			}
		}
		if found {
			hit = true
			if via != "" {
				a.sources[via] = true
			}
		}
	}
	return hit
}

// followAction scans the followed local composite action step i loads.
func (a *agentAcc) followAction(w *yamlWalk, steps []*yaml.Node, checkouts []prCheckout, i int, step *yamlMap, ind *Indirect) bool {
	af, ok := ind.action(w, step)
	if !ok {
		return false
	}
	prIn := false
	for _, c := range checkouts {
		if c.step < i && agentReadsDir(w, step, c.dir) {
			prIn = true
		}
	}
	if !a.scan(w, &yamlMap{}, compositeSteps(w, af.Data), af, nil, SourceComposite, prIn, nil, nil, nil) {
		return false
	}
	with, _ := w.mapping(field(step, "with"), "with")
	env, _ := w.mapping(field(step, "env"), "env")
	a.injected(withValues(w, with)) // the action's inputs reach the agent
	a.injected(withValues(w, env))
	return true
}

// followScripts scans the followed repo scripts a run: step invokes: a known
// agent CLI counts like one in the step (gate none); a model API call
// counts as an AI step (kind llm-script, possible reach only) when
// attacker text reaches it: the pull request's head checkout, its diff or
// text, the event payload, or contexts in the step.
func (a *agentAcc) followScripts(w *yamlWalk, job, step *yamlMap, runKey *yaml.Node, readsPR bool, ind *Indirect, jobEnv, wfEnv *yamlMap) bool {
	run := scalarOf(w, field(step, "run"))
	if run == "" || len(ind.Scripts) == 0 {
		return false
	}
	env, _ := w.mapping(field(step, "env"), "env")
	stepText := append([]string{run}, withValues(w, env)...)
	found := false
	for _, p := range scriptCalls(run, stepWD(w, job, step)) {
		data, ok := ind.Scripts[p]
		if !ok {
			continue
		}
		s := scanScriptAgent(data)
		prompt := map[string]bool{}
		for _, v := range stepText {
			for _, c := range injectedContexts(v) {
				prompt[c] = true
			}
		}
		if readsPR || s.prText || s.payload {
			prompt[graph.PromptPRContent] = true
		}
		switch {
		case s.hasCLI:
			a.kinds[s.cli.kind], a.sources["run"] = true, true
			addToolFlags(a.tools, s.args)
		case s.api && len(prompt) > 0 && stepHoldsKey(w, step, jobEnv, wfEnv):
			a.kinds[LLMScriptKind] = true
		default:
			continue
		}
		found = true
		a.sources[SourceScript] = true
		a.setGate(graph.GateNone)
		a.at("", runKey)
		for c := range prompt {
			a.prompt[c] = true
		}
	}
	return found
}

// llmStep is one step found by heuristic: it holds a model API key and
// reads the pull request's content.
type llmStep struct {
	at     *yaml.Node // its run: or uses: key
	prompt []string   // pr_content and the attacker contexts it reads
}

// llmSteps finds the steps of a job with no known agent that hold a model
// API key (holdsLLMKey) and read the pull request's content: a checkout of
// its head made by an earlier step, its diff or text through gh, or
// attacker contexts in run:, with: or env:. Trusted code from the base
// branch that feeds this to a model is an AI step attacker text reaches,
// even though gop does not know the script.
func llmSteps(w *yamlWalk, steps []*yaml.Node, jobEnv, wfEnv *yamlMap) []llmStep {
	checkouts := prCheckouts(w, steps)
	var out []llmStep
	for i, sn := range steps {
		step, err := w.mapping(sn, "step")
		if err != nil || !holdsLLMKey(w, step, jobEnv, wfEnv) {
			continue
		}
		set := map[string]bool{}
		for _, c := range checkouts {
			if c.step < i && stepReadsDir(w, step, c.dir) {
				set[graph.PromptPRContent] = true
			}
		}
		run := scalarOf(w, field(step, "run"))
		for _, cmd := range prTextCmds {
			if strings.Contains(run, cmd) {
				set[graph.PromptPRContent] = true
			}
		}
		vals := []string{run}
		for _, k := range []string{"with", "env"} {
			m, _ := w.mapping(field(step, k), k)
			vals = append(vals, withValues(w, m)...)
		}
		for _, v := range vals {
			for _, c := range injectedContexts(v) {
				set[c] = true
			}
		}
		if len(set) == 0 {
			continue
		}
		k, _ := step.get("run")
		if k == nil {
			k, _ = step.get("uses")
		}
		out = append(out, llmStep{at: k, prompt: sortedSet(set)})
	}
	return out
}

// matchAgentAction finds u in the agent action table.
func matchAgentAction(u ActionUse) (agentAction, bool) {
	repo := strings.ToLower(u.Owner + "/" + u.Repo)
	full := repo
	if u.Path != "" {
		full += "/" + strings.ToLower(strings.Trim(u.Path, "/"))
	}
	for _, a := range agentActions {
		for _, r := range a.repos {
			if r == full || (strings.Count(r, "/") == 1 && r == repo && u.Path == "") {
				return a, true
			}
		}
	}
	return agentAction{}, false
}

// actionGate is the actor check of an agent action step: the action's
// default, widened by the inputs that admit actors without write access.
func actionGate(w *yamlWalk, a agentAction, with *yamlMap) string {
	g := a.gate
	names := make([]string, 0, len(a.widen))
	for name := range a.widen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := strings.TrimSpace(scalarOf(w, field(with, name)))
		var wide string
		switch {
		case v == "":
			continue
		case strings.Contains(v, "${{"):
			wide = graph.GateUnknown
		case strings.Contains(v, "*"):
			wide = graph.GateAnyone
		default:
			wide = graph.GateListed
		}
		if gateOpenness[wide] > gateOpenness[g] {
			g = wide
		}
	}
	return g
}

// withValues returns the scalar values of a with: or env: mapping, sorted by key.
func withValues(w *yamlWalk, m *yamlMap) []string {
	if m == nil {
		return nil
	}
	keys := append([]string(nil), m.keys...)
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		if v := scalarOf(w, field(m, k)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// addToolFlags records the agent_tools values found in s.
func addToolFlags(set map[string]bool, s string) {
	l := strings.ToLower(s)
	for _, f := range agentToolFlags {
		if strings.Contains(l, f.match) {
			set[f.flag] = true
		}
	}
	if strings.TrimSpace(l) == "unsafe" {
		set["safety_strategy_unsafe"] = true // codex-action safety-strategy: unsafe
	}
}

// agentWriteScopes lists the write scopes of resolved token permissions, sorted:
// <scope>:write, write-all, or default when nothing is declared (the repo
// or org default applies).
func agentWriteScopes(perms map[string]string) []string {
	if perms == nil {
		return []string{"default"}
	}
	set := map[string]bool{}
	for scope, level := range perms {
		if level != "write" {
			continue
		}
		switch {
		case scope == permAll:
			set["write-all"] = true
		case scopeRe.MatchString(scope):
			set[scope+":write"] = true
		}
	}
	return sortedSet(set)
}

// jobSecrets lists the secrets one job can read: the ones it references and
// the workflow-level env ones (wf), sorted.
func jobSecrets(job *yamlMap, wf map[string]bool) []string {
	names := map[string]bool{}
	for k := range wf {
		names[k] = true
	}
	for _, k := range job.keys {
		for n := range secretsIn(job.val[k]) {
			names[n] = true
		}
	}
	return sortedSet(names)
}

// secretsIn returns the secret names referenced under n (GITHUB_TOKEN
// excluded; "*" for dynamic secrets[...] access).
func secretsIn(n *yaml.Node) map[string]bool {
	names := map[string]bool{}
	for _, s := range scalars(n) {
		for _, m := range secretRefRe.FindAllStringSubmatch(s, -1) {
			if !strings.EqualFold(m[1], "GITHUB_TOKEN") {
				names[m[1]] = true
			}
		}
		if secretIdxRe.MatchString(s) {
			names["*"] = true
		}
	}
	return names
}

// shellSplit splits a run: script into command segments: lines (with
// backslash continuations joined) cut at && || ; | and $( .
var shellSplit = regexp.MustCompile(`&&|\|\||;|\||\$\(|` + "`")

// cmdPrefix are tokens that run the next word as the command.
var cmdPrefix = map[string]bool{
	"sudo": true, "env": true, "time": true, "nohup": true, "exec": true, "command": true,
	"npx": true, "bunx": true, "pnpx": true, "uvx": true, "pipx": true, "dlx": true,
	"-y": true, "--yes": true, "pnpm": true, "yarn": true, "bun": true, "run": true, "x": true,
}

// matchAgentCLI finds a non-interactive agent CLI invocation in a run:
// script. args is the rest of the matched command line.
func matchAgentCLI(run string) (agentCLI, string, bool) {
	if run == "" {
		return agentCLI{}, "", false
	}
	script := strings.ReplaceAll(run, "\\\n", " ")
	for _, line := range strings.Split(script, "\n") {
		if i := strings.Index(line, "#"); i == 0 || (i > 0 && line[i-1] == ' ') {
			line = line[:i]
		}
		segs, seps := shellSplit.Split(line, -1), shellSplit.FindAllString(line, -1)
		for si, seg := range segs {
			// piped: the segment reads the previous command's output.
			piped := si > 0 && seps[si-1] == "|"
			fields := strings.Fields(seg)
			i := 0
			for i < len(fields) && (cmdPrefix[fields[i]] || isEnvAssign(fields[i])) {
				i++
			}
			if i >= len(fields) {
				continue
			}
			bin := cliName(fields[i])
			rest := fields[i+1:]
			for _, c := range agentCLIs {
				if !containsStr(c.bins, bin) || !cliMarked(c, rest) || (c.model && !modelPrompted(c, rest, piped)) {
					continue
				}
				return c, strings.Join(rest, " "), true
			}
		}
	}
	return agentCLI{}, "", false
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isEnvAssign(s string) bool {
	eq := strings.Index(s, "=")
	return eq > 0 && envNameRe.MatchString(s[:eq])
}

// cliName normalizes a command word: path and npm version stripped, lower case.
func cliName(s string) string {
	s = strings.Trim(s, `"'`)
	if strings.HasPrefix(s, "@") {
		if i := strings.LastIndex(s, "@"); i > 0 {
			s = s[:i]
		}
	} else {
		if i := strings.Index(s, "@"); i > 0 {
			s = s[:i]
		}
		s = path.Base(s)
	}
	return strings.ToLower(s)
}

func cliMarked(c agentCLI, args []string) bool {
	for i, a := range args {
		a = strings.ToLower(strings.Trim(a, `"'`))
		if eq := strings.Index(a, "="); eq > 0 && strings.HasPrefix(a, "-") {
			a = a[:eq]
		}
		for _, m := range c.markers {
			if a == strings.ToLower(m) {
				// A subcommand marker (exec, run, prompt) must be the first argument.
				if !strings.HasPrefix(m, "-") && i != 0 {
					continue
				}
				return true
			}
		}
		if c.quoted && i == 0 && (strings.HasPrefix(args[0], `"`) || strings.HasPrefix(args[0], `'`)) {
			return true
		}
	}
	return false
}

// modelPrompted reports whether a model run (args: run MODEL ...) gets a
// prompt: a prompt argument, --ask, or stdin from a redirect or a pipe.
// Output redirects and the values of c.modelValueFlags are not prompts.
func modelPrompted(c agentCLI, args []string, piped bool) bool {
	if len(args) < 2 || strings.HasPrefix(args[1], "-") || strings.HasPrefix(args[1], "<") || strings.HasPrefix(args[1], ">") {
		return false
	}
	if piped {
		return true
	}
	for i := 2; i < len(args); i++ {
		a := strings.ToLower(args[i])
		switch {
		case a == "--ask" || strings.HasPrefix(a, "--ask="):
			return true
		case strings.HasPrefix(a, "<"):
			return true
		case outRedirect.MatchString(a):
			if strings.Trim(strings.TrimLeft(a, "0123456789&"), ">|") == "" {
				i++ // a bare > or 2>: the next word is its target
			}
		case strings.HasPrefix(a, "-"):
			if containsStr(c.modelValueFlags, a) {
				i++
			}
		default:
			return true
		}
	}
	return false
}

// outRedirect matches an output redirect word: > out, 2>&1, >>log, &>out.
var outRedirect = regexp.MustCompile(`^(?:[0-9]*|&)>`)

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// agentName reports whether a name carries a weak agent signal.
func agentName(s string) bool {
	l := strings.ToLower(s)
	for _, w := range agentNameWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	for i := strings.Index(l, "ai-"); i >= 0; {
		if i == 0 || !isAlnum(l[i-1]) {
			return true
		}
		j := strings.Index(l[i+1:], "ai-")
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return false
}

func isAlnum(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }

// ---- graph attrs ----

// addAgentFacts writes the agent attrs on a workflow node: from its agent
// jobs, or, when it has none, the weak name-only match.
func addAgentFacts(wn *graph.Node, f *WorkflowFacts) {
	if len(f.Agents) == 0 {
		var jobs []string
		named := agentName(f.Name) || agentName(path.Base(f.File))
		for _, id := range f.Jobs {
			if named || agentName(id) || agentName(f.JobNames[id]) {
				jobs = append(jobs, id)
			}
		}
		if !named && len(jobs) == 0 {
			return
		}
		setAttr(wn, graph.AttrAgent, "unknown", graph.Live)
		setAttr(wn, graph.AttrAgentSource, "name", graph.Live)
		setAttr(wn, graph.AttrAgentConfidence, graph.AgentNameOnly, graph.Live)
		if len(jobs) > 0 {
			setAttr(wn, graph.AttrAgentJobs, strings.Join(jobs, ","), graph.Live)
		}
		return
	}
	kinds, sources, jobs, prompt, perms, tools := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	gate, exposure, refKind, runner := "", "", "", ""
	secrets := map[string]bool{}
	confRank := map[string]int{graph.AgentHeuristic: 0, graph.AgentCLI: 1, graph.AgentAction: 2}
	conf := graph.AgentHeuristic
	for _, a := range f.Agents {
		jobs[a.Job] = true
		for _, set := range []struct {
			m  map[string]bool
			xs []string
		}{{kinds, a.Kinds}, {sources, a.Sources}, {prompt, a.Prompt}, {perms, a.Perms}, {tools, a.Tools}, {secrets, a.Secrets}} {
			for _, x := range set.xs {
				set.m[x] = true
			}
		}
		if gate == "" || gateOpenness[a.Gate] > gateOpenness[gate] {
			gate = a.Gate
		}
		if exposure == "" || exposureWidth[a.Exposure] > exposureWidth[exposure] {
			exposure = a.Exposure
		}
		if a.RefKind != "" && (refKind == "" || refPin[a.RefKind] > refPin[refKind]) {
			refKind = a.RefKind
		}
		runner = widerRunner(runner, a.Runner)
		c := agentConfidence(a.Sources)
		if confRank[c] > confRank[conf] {
			conf = c
		}
	}
	set := func(k string, m map[string]bool) {
		if len(m) > 0 {
			setAttr(wn, k, strings.Join(sortedSet(m), ","), graph.Live)
		}
	}
	set(graph.AttrAgent, kinds)
	set(graph.AttrAgentSource, sources)
	setAttr(wn, graph.AttrAgentConfidence, conf, graph.Live)
	set(graph.AttrAgentJobs, jobs)
	setAttr(wn, graph.AttrAgentGate, gate, graph.Live)
	setAttr(wn, graph.AttrAgentExposure, exposure, graph.Live)
	set(graph.AttrAgentPrompt, prompt)
	set(graph.AttrAgentPerms, perms)
	setAttr(wn, graph.AttrAgentSecrets, strconv.Itoa(len(secrets)), graph.Live)
	if runner != "" {
		setAttr(wn, graph.AttrAgentRunner, runner, graph.Live)
	}
	set(graph.AttrAgentTools, tools)
	if refKind != "" {
		setAttr(wn, graph.AttrAgentRefKind, refKind, graph.Live)
	}
}

// widerRunner keeps the riskier runner class: self_hosted, then unknown, then hosted.
func widerRunner(a, b string) string {
	rank := map[string]int{"": 0, RunnerHosted: 1, RunnerUnknown: 2, RunnerSelfHosted: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
