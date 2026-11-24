package collect

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// One level of indirection for agent and exec detection (issue #165). A
// workflow can hide an agent or the run of untrusted code one level down:
//
//   - in a local composite action (uses: ./.github/actions/x), read from
//     the default branch's action.yml (or action.yaml);
//   - in a called reusable workflow of the same repo (uses:
//     ./.github/workflows/x.yml) or of another repo in the same org (uses:
//     org/repo/.github/workflows/x.yml@ref), which runs with the caller's
//     event, so who can start the caller can start it;
//   - in a repo script a run: step invokes (python3 tools/review.py, bash
//     ci/ai.sh) while it holds a secret or a model API key: gop scans it for
//     a known agent CLI and for model API calls.
//
// Only workflows with a trigger outsiders can cause (riskyTriggers, or
// pull_request) are followed. After every workflow is read, followIndirect
// fetches each file once per repo and path with a read-only contents GET
// (through the response cache, capped at followMaxBytes; a reusable workflow
// that the nested expansion already read is not fetched again), then re-reads
// the workflow with them before its trigger and agent facts are written.
// gop never runs what it reads and never follows a second level.

const (
	// followMaxBytes caps the size of a followed file.
	followMaxBytes = botScriptMaxBytes
	// followPerWorkflow caps the files followed per workflow file.
	followPerWorkflow = 10
)

// Agent sources of an agent found one level down (agent_source values,
// alongside uses or run).
const (
	SourceComposite = "composite" // inside a local composite action
	SourceReusable  = "reusable"  // inside a called reusable workflow
	SourceScript    = "script"    // inside a repo script a run: step invokes
)

// FollowRefs are the files one level down that a workflow loads.
type FollowRefs struct {
	Actions   []string // local composite action directories (uses: ./dir), cleaned
	Workflows []string // called reusable workflows: the job's uses: value
	Scripts   []string // repo scripts run: steps invoke while holding a secret or model key
}

// Empty reports whether there is nothing to follow.
func (r FollowRefs) Empty() bool {
	return len(r.Actions) == 0 && len(r.Workflows) == 0 && len(r.Scripts) == 0
}

// IndirectFile is one followed file.
type IndirectFile struct {
	// Path is the file's path in the caller's repo; "" when it is in another
	// repo, which Where then names (owner/repo/path@ref).
	Path  string
	Where string
	Data  []byte
}

// Indirect holds the followed files of one workflow, by the reference that
// loads them (FollowRefs). A nil Indirect follows nothing.
type Indirect struct {
	Actions   map[string]IndirectFile
	Workflows map[string]IndirectFile
	Scripts   map[string][]byte
}

// ParseWorkflowWith is ParseWorkflow with the files one level down read.
func ParseWorkflowWith(data []byte, ind *Indirect) (*WorkflowFacts, error) {
	return parseWorkflow(data, ind)
}

// followsTriggers says whether a workflow's files one level down are worth
// reading: it has a trigger outsiders can cause.
func followsTriggers(triggers []string) bool {
	for _, t := range triggers {
		if riskyTriggers[t] || t == "pull_request" {
			return true
		}
	}
	return false
}

// localWorkflowRe matches a local reusable workflow reference.
var localWorkflowRe = regexp.MustCompile(`^\./\.github/workflows/[^/]+\.ya?ml$`)

// calledWorkflow reports whether a job's uses: value calls a reusable
// workflow gop can follow: one in the same repo, or a pinned owner/repo one.
func calledWorkflow(uses string) bool {
	if localWorkflowRe.MatchString(uses) {
		return true
	}
	u, ok := ParseUses(uses)
	return ok && u.IsReusableWorkflow()
}

// localAction returns the directory of a local action reference, or "".
func localAction(uses string) string {
	uses = strings.TrimSpace(uses)
	if !strings.HasPrefix(uses, "./") || strings.Contains(uses, "${{") || localWorkflowRe.MatchString(uses) {
		return ""
	}
	return cleanDir(uses)
}

// stepWD is a step's working directory: its own, else the job's defaults.run.
func stepWD(w *yamlWalk, job, step *yamlMap) string {
	if wd := scalarOf(w, field(step, "working-directory")); wd != "" {
		return wd
	}
	if d, err := w.mapping(field(job, "defaults"), "defaults"); err == nil {
		if r, err := w.mapping(field(d, "run"), "run"); err == nil {
			return scalarOf(w, field(r, "working-directory"))
		}
	}
	return ""
}

// stepHoldsKey reports whether a step can read a secret or a model API key.
func stepHoldsKey(w *yamlWalk, step, jobEnv, wfEnv *yamlMap) bool {
	if holdsLLMKey(w, step, jobEnv, wfEnv) {
		return true
	}
	for _, m := range []*yamlMap{jobEnv, wfEnv} {
		if m == nil {
			continue
		}
		for _, k := range m.keys {
			if len(secretsIn(m.val[k])) > 0 {
				return true
			}
		}
	}
	return len(secretsIn(field(step, "env"))) > 0 || len(secretsIn(field(step, "with"))) > 0
}

// followRefs lists the files one level down that a workflow loads, at most
// followPerWorkflow, or nothing when its triggers do not warrant it.
func followRefs(doc *yaml.Node, triggers []string) FollowRefs {
	var r FollowRefs
	if !followsTriggers(triggers) {
		return r
	}
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(doc), "workflow")
	if err != nil {
		return r
	}
	jobs, err := w.mapping(field(root, "jobs"), "jobs")
	if err != nil {
		return r
	}
	wfEnv, _ := w.mapping(field(root, "env"), "env")
	seen := map[string]bool{}
	n := 0
	add := func(list *[]string, kind, v string) {
		if v == "" || seen[kind+v] || n >= followPerWorkflow {
			return
		}
		seen[kind+v] = true
		n++
		*list = append(*list, v)
	}
	ids := append([]string(nil), jobs.keys...)
	sort.Strings(ids)
	for _, id := range ids {
		job, err := w.mapping(field(jobs, id), "job")
		if err != nil {
			continue
		}
		if u := strings.TrimSpace(scalarOf(w, field(job, "uses"))); calledWorkflow(u) {
			add(&r.Workflows, "w", u)
		}
		jobEnv, _ := w.mapping(field(job, "env"), "env")
		steps, _ := w.sequence(field(job, "steps"), "steps")
		for _, sn := range steps {
			step, err := w.mapping(sn, "step")
			if err != nil {
				continue
			}
			add(&r.Actions, "a", localAction(scalarOf(w, field(step, "uses"))))
			run := scalarOf(w, field(step, "run"))
			if run == "" || !stepHoldsKey(w, step, jobEnv, wfEnv) {
				continue
			}
			for _, p := range scriptCalls(run, stepWD(w, job, step)) {
				add(&r.Scripts, "s", p)
			}
		}
	}
	return r
}

// compositeSteps returns the steps of a composite action, or nil.
func compositeSteps(w *yamlWalk, data []byte) []*yaml.Node {
	var doc yaml.Node
	if len(data) > followMaxBytes || yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	root, err := w.mapping(rootMap(&doc), "action")
	if err != nil {
		return nil
	}
	runs, err := w.mapping(field(root, "runs"), "runs")
	if err != nil || strings.TrimSpace(scalarOf(w, field(runs, "using"))) != "composite" {
		return nil
	}
	steps, _ := w.sequence(field(runs, "steps"), "steps")
	return steps
}

// calledJobs returns the jobs of a called workflow, by sorted id.
func calledJobs(w *yamlWalk, data []byte) (ids []string, jobs *yamlMap) {
	var doc yaml.Node
	if len(data) > followMaxBytes || yaml.Unmarshal(data, &doc) != nil {
		return nil, nil
	}
	root, err := w.mapping(rootMap(&doc), "workflow")
	if err != nil {
		return nil, nil
	}
	jobs, err = w.mapping(field(root, "jobs"), "jobs")
	if err != nil {
		return nil, nil
	}
	ids = append([]string(nil), jobs.keys...)
	sort.Strings(ids)
	return ids, jobs
}

// indirectAction returns the followed composite action a step loads.
func (ind *Indirect) action(w *yamlWalk, step *yamlMap) (IndirectFile, bool) {
	if ind == nil {
		return IndirectFile{}, false
	}
	f, ok := ind.Actions[localAction(scalarOf(w, field(step, "uses")))]
	return f, ok
}

// called returns the followed reusable workflow a job calls.
func (ind *Indirect) called(w *yamlWalk, job *yamlMap) (IndirectFile, bool) {
	if ind == nil {
		return IndirectFile{}, false
	}
	f, ok := ind.Workflows[strings.TrimSpace(scalarOf(w, field(job, "uses")))]
	return f, ok
}

// ---- scripts ----

// modelAPIRe matches a model API call in a script: a provider's API host,
// a local model server's API, or an SDK's create or generate call. An
// import alone is not a call.
var modelAPIRe = regexp.MustCompile(`\bapi\.anthropic\.com\b|\bapi\.openai\.com\b|\.openai\.azure\.com\b|` +
	`\bgenerativelanguage\.googleapis\.com\b|\bapi\.mistral\.ai\b|\bapi\.groq\.com\b|\bapi\.deepseek\.com\b|` +
	`\bopenrouter\.ai/api\b|\bapi\.x\.ai\b|:11434/(?:api|v1)/|` +
	`\bmessages\.create\(|\bchat\.completions\.create\(|\bresponses\.create\(|\bgenerate_?[cC]ontent\(|` +
	`\bollama\.(?:chat|generate)\(`)

// eventPathRe matches a script that reads the triggering event's payload.
var eventPathRe = regexp.MustCompile(`\bGITHUB_EVENT_PATH\b|\bcontext\.payload\b`)

// scriptAgent is what a followed script does with AI.
type scriptAgent struct {
	cli     agentCLI
	args    string
	hasCLI  bool
	api     bool // it calls a model API
	prText  bool // it reads the pull request's diff or text (gh pr diff, gh pr view)
	payload bool // it reads the event payload
}

// scanScriptAgent reads one script's text for agent CLIs and model API
// calls. It never runs it.
func scanScriptAgent(data []byte) scriptAgent {
	text := stripScriptComments(string(data))
	var s scriptAgent
	s.cli, s.args, s.hasCLI = matchAgentCLI(text)
	s.api = modelAPIRe.MatchString(text)
	for _, cmd := range prTextCmds {
		if strings.Contains(text, cmd) {
			s.prText = true
		}
	}
	s.payload = eventPathRe.MatchString(text)
	return s
}

// ---- untrusted fetches ----

// harmlessCmds do not run code from the working tree.
var harmlessCmds = map[string]bool{
	"echo": true, "printf": true, "git": true, "gh": true, "cd": true, "pushd": true, "popd": true, "true": true,
	"false": true, "exit": true, "set": true, "export": true, "ls": true, "cat": true, "test": true, "[": true,
	"[[": true, ":": true, "sleep": true, "fi": true, "done": true, "esac": true, "}": true, "{": true,
}

// shellKeywords run the next word as the command.
var shellKeywords = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true, "!": true}

// laterCommand reports whether a run: script runs a command after the one
// that fetches the pull request's code (cmd) that may run code from it.
func laterCommand(run, cmd string) bool {
	i := strings.Index(run, cmd)
	if i < 0 {
		return false
	}
	rest := strings.ReplaceAll(run[i+len(cmd):], "\\\n", " ")
	// Skip the fetch command's own arguments.
	if loc := shellSplit.FindStringIndex(rest); loc != nil && (strings.IndexByte(rest, '\n') < 0 || loc[0] < strings.IndexByte(rest, '\n')) {
		rest = rest[loc[1]:]
	} else if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	} else {
		return false
	}
	for _, line := range strings.Split(rest, "\n") {
		if j := strings.Index(line, "#"); j == 0 || (j > 0 && line[j-1] == ' ') {
			line = line[:j]
		}
		for _, seg := range shellSplit.Split(line, -1) {
			f := strings.Fields(seg)
			k := 0
			for k < len(f) && (runPrefix[f[k]] || shellKeywords[f[k]] || isEnvAssign(f[k])) {
				k++
			}
			if k < len(f) && !harmlessCmds[strings.Trim(f[k], `"'`)] {
				return true
			}
		}
	}
	return false
}

// fetchRuns reports whether code from a pull request fetched by step i's
// run: (gh pr checkout, git fetch origin pull/...) runs: a later command
// in the same script, or a later step under #145's rule for a checkout in
// the step's working directory.
func fetchRuns(w *yamlWalk, job, step *yamlMap, steps []*yaml.Node, i int, run, cmd string) bool {
	if laterCommand(run, cmd) {
		return true
	}
	return checkoutRuns(w, job, steps, prCheckout{step: i, dir: cleanDir(stepWD(w, job, step))})
}

// agentReadsDir reports whether an agent step reads a checkout in dir: the
// workspace root, a directory input or working directory in it, a path into
// it in a prompt, env value or command (pr/, ./pr/src), or a cd into it.
// A bare word like "pr" in prose is not a path.
func agentReadsDir(w *yamlWalk, step *yamlMap, dir string) bool {
	if dir == "" {
		return true
	}
	if wd := scalarOf(w, field(step, "working-directory")); wd != "" && underDir(wd, dir) {
		return true
	}
	run := scalarOf(w, field(step, "run"))
	if run != "" && scriptRunsFrom(run, dir) {
		return true
	}
	vals := []string{run}
	for _, k := range []string{"with", "env"} {
		m, _ := w.mapping(field(step, k), k)
		for _, v := range withValues(w, m) {
			if t := strings.TrimSpace(v); !strings.ContainsAny(t, " \n") && underDir(t, dir) {
				return true // a directory input: path: pr
			}
			vals = append(vals, v)
		}
	}
	for _, v := range vals {
		for _, t := range pathTokens(workspacePrefix.ReplaceAllString(v, "")) {
			if strings.Contains(t, "/") && underDir(t, dir) {
				return true
			}
		}
	}
	return false
}

// ---- collector ----

// followWF is a workflow whose trigger and agent facts wait for the files
// one level down.
type followWF struct {
	o     *orgState
	repo  *graph.Node
	wid   string
	wn    *graph.Node
	path  string
	data  []byte
	facts *WorkflowFacts
}

// trackFollow defers a workflow's trigger and agent facts when it has files
// to follow, and reports whether it did.
func (k *collector) trackFollow(o *orgState, repo *graph.Node, wid string, wn *graph.Node, path string, data []byte, facts *WorkflowFacts) bool {
	if facts.Follow.Empty() {
		return false
	}
	k.followWFs = append(k.followWFs, followWF{o: o, repo: repo, wid: wid, wn: wn, path: path, data: data, facts: facts})
	return true
}

// followIndirect reads the files the tracked workflows load, once per repo,
// path and ref, re-reads each workflow with them and writes its trigger and
// agent facts. A file it cannot read is a coverage gap; the workflow then
// keeps the facts gop read without it.
func (k *collector) followIndirect(ctx context.Context) error {
	read := func(owner, repo, p, ref string) ([]byte, error) {
		return k.readScanned(ctx, owner, repo, p, ref, followMaxBytes)
	}
	for _, t := range k.followWFs {
		owner, repo := t.o.login, repoName(t.o, t.repo)
		ind := &Indirect{Actions: map[string]IndirectFile{}, Workflows: map[string]IndirectFile{}, Scripts: map[string][]byte{}}
		fail := func(p string, err error) {
			k.cover(t.wid, "follow:"+p, "could not read a file the workflow loads: "+err.Error(),
				k.fixFor(err, "read access to contents on "+owner+"/"+repo))
		}
		for _, dir := range t.facts.Follow.Actions {
			var lastErr error
			for _, name := range []string{"action.yml", "action.yaml"} {
				p := dir + "/" + name
				data, err := read(owner, repo, p, "")
				if err == nil {
					ind.Actions[dir], lastErr = IndirectFile{Path: p, Data: data}, nil
					break
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				lastErr = err
				if !IsNotFound(err) {
					break
				}
			}
			if lastErr != nil {
				fail(dir+"/action.yml", lastErr)
			}
		}
		for _, uses := range t.facts.Follow.Workflows {
			if strings.HasPrefix(uses, "./") {
				p := strings.TrimPrefix(uses, "./")
				data, err := read(owner, repo, p, "")
				switch {
				case err == nil:
					ind.Workflows[uses] = IndirectFile{Path: p, Data: data}
				case ctx.Err() != nil:
					return ctx.Err()
				default:
					fail(p, err)
				}
				continue
			}
			u, _ := ParseUses(uses)
			if !strings.EqualFold(u.Owner, owner) {
				continue // another org's workflow: not followed
			}
			where := owner + "/" + u.Repo + "/" + u.Path + "@" + u.Ref
			if data, ok := k.calledWFs["action:"+u.Raw]; ok {
				ind.Workflows[uses] = IndirectFile{Where: where, Data: data}
				continue
			}
			data, err := read(owner, u.Repo, u.Path, u.Ref)
			switch {
			case err == nil:
				ind.Workflows[uses] = IndirectFile{Where: where, Data: data}
			case ctx.Err() != nil:
				return ctx.Err()
			default:
				k.cover(t.wid, "follow:"+where, "could not read the reusable workflow a job calls: "+err.Error(),
					k.fixFor(err, "read access to contents on "+owner+"/"+u.Repo))
			}
		}
		for _, p := range t.facts.Follow.Scripts {
			data, err := read(owner, repo, p, "")
			switch {
			case err == nil:
				ind.Scripts[p] = data
			case ctx.Err() != nil:
				return ctx.Err()
			default:
				fail(p, err)
			}
		}
		facts := t.facts
		if f, err := ParseWorkflowWith(t.data, ind); err == nil {
			f.SetFile(t.facts.File, t.facts.FileRef)
			facts = f
		}
		k.addTriggerFacts(t.o, t.repo, t.wid, t.wn, facts)
		addAgentFacts(t.wn, facts)
	}
	return nil
}
