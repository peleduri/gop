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
func (f *WorkflowFacts) readAgents(doc *yaml.Node) {
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
		aj, ok := agentJob(w, id, job)
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
			for _, t := range risky {
				f.UntrustedExec = append(f.UntrustedExec, UntrustedExec{Job: id, Trigger: t, Kind: ExecAgent, Detail: strings.Join(aj.Kinds, ","),
					Line: aj.Line, Unverified: aj.Gate == graph.GateUnknown})
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

// agentJob reads one job's agent steps. ok is false when it has none.
func agentJob(w *yamlWalk, id string, job *yamlMap) (AgentJob, bool) {
	aj := AgentJob{Job: id}
	kinds, sources, prompt, tools := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	gate := -1
	setGate := func(g string) {
		if gateOpenness[g] > gate {
			gate = gateOpenness[g]
			aj.Gate = g
		}
	}
	at := func(n *yaml.Node) {
		if n != nil && (aj.Line == 0 || n.Line < aj.Line) {
			aj.Line = n.Line
		}
	}
	if id == copilotSetupJob {
		kinds[copilotAgentKind], sources["setup"] = true, true
		setGate(graph.GateWriteAccess)
		k, _ := job.get("steps")
		if k == nil {
			k, _ = job.get("runs-on")
		}
		at(k)
	}
	steps, _ := w.sequence(field(job, "steps"), "steps")
	for _, sn := range steps {
		step, err := w.mapping(sn, "step")
		if err != nil {
			continue
		}
		found := false
		usesKey, _ := step.get("uses")
		if u, ok := ParseUses(scalarOf(w, field(step, "uses"))); ok {
			if a, ok := matchAgentAction(u); ok {
				found = true
				kinds[a.kind], sources["uses"] = true, true
				at(usesKey)
				with, _ := w.mapping(field(step, "with"), "with")
				setGate(actionGate(w, a, with))
				for _, name := range a.args {
					addToolFlags(tools, scalarOf(w, field(with, name)))
				}
				if a.kind == "claude-code-action" || a.kind == "claude-code-base-action" {
					if scalarOf(w, field(with, "allowed_tools")) != "" {
						tools["allowed_tools"] = true
					}
				}
				for _, v := range withValues(w, with) {
					for _, c := range injectedContexts(v) {
						prompt[c] = true
					}
				}
				if aj.RefKind == "" || refPin[u.RefKind] > refPin[aj.RefKind] {
					aj.RefKind = u.RefKind
				}
			}
		}
		run := scalarOf(w, field(step, "run"))
		if c, args, ok := matchAgentCLI(run); ok {
			found = true
			kinds[c.kind], sources["run"] = true, true
			runKey, _ := step.get("run")
			at(runKey)
			setGate(graph.GateNone)
			addToolFlags(tools, args)
			for _, ctx := range injectedContexts(run) {
				prompt[ctx] = true
			}
		}
		if found {
			env, _ := w.mapping(field(step, "env"), "env")
			for _, v := range withValues(w, env) {
				for _, c := range injectedContexts(v) {
					prompt[c] = true
				}
			}
		}
	}
	if len(kinds) == 0 {
		return AgentJob{}, false
	}
	aj.Kinds, aj.Sources, aj.Prompt, aj.Tools = sortedSet(kinds), sortedSet(sources), sortedSet(prompt), sortedSet(tools)
	return aj, true
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
		for _, seg := range shellSplit.Split(line, -1) {
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
				if !containsStr(c.bins, bin) || !cliMarked(c, rest) {
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
	conf := graph.AgentCLI
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
		if containsStr(a.Sources, "uses") || containsStr(a.Sources, "setup") {
			conf = graph.AgentAction
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
