package collect

import (
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Untrusted checkout is not untrusted execution. A pull_request_target or
// workflow_run job that checks out the pull request's head runs the
// attacker's code only when a later step runs something from that
// checkout. A checkout into a subdirectory that only trusted code from the
// base branch reads is untrusted input: gop records it as
// untrusted_checkout=read_only and does not rank it as execution.
//
// gop counts a later step as running the checkout when:
//   - the checkout is at the workspace root (the actions/checkout default) or
//     at a path gop cannot resolve, and any step follows it;
//   - a uses: ./<dir>/... local action loads from it;
//   - a run: step works in it (working-directory, or defaults.run of the job)
//     or cds into it;
//   - a run: command is a file in it (pr/build.sh), an interpreter runs a
//     script from it (bash pr/x.sh, python pr/x.py), or a build or install
//     tool is pointed at it (npm --prefix pr ci, make -C pr, pip install -e
//     pr, go run ./pr/..., docker build pr).

// prCheckout is one actions/checkout step that selects the pull request's code.
type prCheckout struct {
	step   int        // index in the job's steps
	detail string     // "ref: ..." or "repository: ..."
	at     *yaml.Node // the with.ref / with.repository key
	dir    string     // with.path, cleaned; "" for the workspace root or a path gop cannot resolve
}

// UntrustedCheckout values (attr untrusted_checkout on a workflow).
const (
	CheckoutExec     = "exec"      // some job runs code from a checkout of the pull request's head
	CheckoutReadOnly = "read_only" // the pull request's head is checked out, but no step gop sees runs it
)

// prCheckouts returns the checkouts of the pull request's code among steps,
// one per matched with.ref or with.repository, in step order.
func prCheckouts(w *yamlWalk, steps []*yaml.Node) []prCheckout {
	var out []prCheckout
	for i, sn := range steps {
		step, err := w.mapping(sn, "step")
		if err != nil {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(scalarOf(w, field(step, "uses"))), "actions/checkout@") {
			continue
		}
		with, _ := w.mapping(field(step, "with"), "with")
		dir := cleanDir(scalarOf(w, field(with, "path")))
		for _, name := range []string{"ref", "repository"} {
			v := scalarOf(w, field(with, name))
			kn, _ := with.get(name)
			for _, u := range untrustedRefs {
				if strings.Contains(v, u) {
					out = append(out, prCheckout{step: i, detail: name + ": " + strings.TrimSpace(v), at: kn, dir: dir})
					break
				}
			}
		}
	}
	return out
}

// workspacePrefix matches the ways a workflow names the workspace root.
var workspacePrefix = regexp.MustCompile(`\$\{\{\s*github\.workspace\s*\}\}/?|\$\{?GITHUB_WORKSPACE\}?/?`)

// cleanDir normalizes a checkout path relative to the workspace: "" for the
// root, and for a path gop cannot resolve (an expression), which is then
// treated like the root.
func cleanDir(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	p = workspacePrefix.ReplaceAllString(p, "")
	if p == "" || strings.Contains(p, "${{") || strings.Contains(p, "$") {
		return ""
	}
	p = path.Clean(p)
	if p == "." || p == "/" || strings.HasPrefix(p, "../") || p == ".." {
		return ""
	}
	return strings.TrimPrefix(p, "./")
}

// underDir reports whether a path token points into dir (dir itself included).
func underDir(tok, dir string) bool {
	t := strings.Trim(tok, `"'`)
	t = workspacePrefix.ReplaceAllString(t, "")
	for strings.HasPrefix(t, "./") {
		t = t[2:]
	}
	t = strings.TrimSuffix(t, "/")
	return t == dir || strings.HasPrefix(t, dir+"/")
}

// checkoutRuns reports whether a step after c runs code from it. job is the
// job's mapping (for defaults.run.working-directory).
func checkoutRuns(w *yamlWalk, job *yamlMap, steps []*yaml.Node, c prCheckout) bool {
	jobWD := ""
	if d, err := w.mapping(field(job, "defaults"), "defaults"); err == nil {
		if r, err := w.mapping(field(d, "run"), "run"); err == nil {
			jobWD = scalarOf(w, field(r, "working-directory"))
		}
	}
	for _, sn := range steps[c.step+1:] {
		step, err := w.mapping(sn, "step")
		if err != nil {
			continue
		}
		if c.dir == "" {
			return true
		}
		if uses := scalarOf(w, field(step, "uses")); strings.HasPrefix(strings.TrimSpace(uses), "./") && underDir(strings.TrimSpace(uses), c.dir) {
			return true
		}
		run := scalarOf(w, field(step, "run"))
		if run == "" {
			continue
		}
		wd := scalarOf(w, field(step, "working-directory"))
		if wd == "" {
			wd = jobWD
		}
		if wd != "" && underDir(wd, c.dir) {
			return true
		}
		if scriptRunsFrom(run, c.dir) {
			return true
		}
	}
	return false
}

// shellInterpreters run the script file named by their first non-flag argument.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "source": true, ".": true,
	"python": true, "python3": true, "node": true, "deno": true, "bun": true, "ruby": true, "perl": true,
	"php": true, "pwsh": true, "powershell": true, "tsx": true, "ts-node": true,
}

// buildTools run code from a project directory named anywhere in their arguments.
var buildTools = map[string]bool{
	"npm": true, "npx": true, "pnpm": true, "yarn": true, "bun": true, "pip": true, "pip3": true, "pipx": true,
	"poetry": true, "uv": true, "tox": true, "nox": true, "go": true, "make": true, "cmake": true, "cargo": true,
	"mvn": true, "gradle": true, "gradlew": true, "bundle": true, "rake": true, "composer": true, "dotnet": true,
	"docker": true, "podman": true, "bazel": true, "deno": true, "mix": true, "sbt": true,
}

// runPrefix are words that run the next word as the command.
var runPrefix = map[string]bool{"sudo": true, "env": true, "time": true, "nohup": true, "exec": true, "command": true}

// scriptRunsFrom reports whether a run: script runs code from dir.
func scriptRunsFrom(run, dir string) bool {
	script := strings.ReplaceAll(run, "\\\n", " ")
	for _, line := range strings.Split(script, "\n") {
		if i := strings.Index(line, "#"); i == 0 || (i > 0 && line[i-1] == ' ') {
			line = line[:i]
		}
		for _, seg := range shellSplit.Split(line, -1) {
			fields := strings.Fields(seg)
			i := 0
			for i < len(fields) && (runPrefix[fields[i]] || isEnvAssign(fields[i])) {
				i++
			}
			if i >= len(fields) {
				continue
			}
			cmd, args := fields[i], fields[i+1:]
			if underDir(cmd, dir) {
				return true // pr/build.sh, ./pr/x
			}
			name := path.Base(strings.Trim(cmd, `"'`))
			switch {
			case name == "cd" || name == "pushd":
				for _, a := range args {
					if !strings.HasPrefix(a, "-") {
						if underDir(a, dir) {
							return true
						}
						break
					}
				}
			case buildTools[name]:
				for _, a := range args {
					if eq := strings.Index(a, "="); eq > 0 && strings.HasPrefix(a, "-") {
						a = a[eq+1:]
					}
					if underDir(a, dir) {
						return true
					}
				}
			case shellInterpreters[name]:
				for _, a := range args {
					if !strings.HasPrefix(a, "-") {
						if underDir(a, dir) {
							return true
						}
						break
					}
				}
			}
		}
	}
	return false
}

// pathTokens splits text into the words a path could be: on spaces, quotes,
// = and shell operators.
func pathTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '=', ';', '&', '|', '(', ')', '<', '>', ',', '`':
			return true
		}
		return false
	})
}

// stepReadsDir reports whether a step names dir in its run:, with: or env:
// values: it reads the checkout ("" is the workspace root, which any step can read).
func stepReadsDir(w *yamlWalk, step *yamlMap, dir string) bool {
	if dir == "" {
		return true
	}
	vals := []string{scalarOf(w, field(step, "run")), scalarOf(w, field(step, "working-directory"))}
	for _, k := range []string{"with", "env"} {
		m, _ := w.mapping(field(step, k), k)
		vals = append(vals, withValues(w, m)...)
	}
	for _, v := range vals {
		for _, t := range pathTokens(workspacePrefix.ReplaceAllString(v, "")) {
			if underDir(t, dir) {
				return true
			}
		}
	}
	return false
}

// ---- author_association gates ----

// assocContexts are the author_association contexts of the comment and
// review triggers, by trigger.
var assocContexts = map[string][]string{
	"issue_comment":               {"github.event.comment.author_association"},
	"pull_request_review_comment": {"github.event.comment.author_association"},
	"discussion_comment":          {"github.event.comment.author_association"},
	"pull_request_review":         {"github.event.review.author_association"},
	"issues":                      {"github.event.issue.author_association"},
	"discussion":                  {"github.event.discussion.author_association"},
}

var (
	assocValueRe = regexp.MustCompile(`\b(OWNER|MEMBER|COLLABORATOR|CONTRIBUTOR|FIRST_TIME_CONTRIBUTOR|FIRST_TIMER|MANNEQUIN|NONE)\b`)
	eventNameRe  = regexp.MustCompile(`github\.event_name\s*==\s*['"]([a-z_]+)['"]`)
)

// Author association classes (who an author_association gate lets in).
const (
	assocOutsiders     = "outsiders"     // CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER, NONE or MANNEQUIN: people outside the org
	assocMembers       = "members"       // MEMBER: the members of the repo's org
	assocCollaborators = "collaborators" // only OWNER and COLLABORATOR
)

// assocGate returns the author_association values a job's if: allows for
// trigger, sorted, or nil when the job has no such gate gop can read.
//
// The gate is read conservatively: every top-level || branch of the
// condition must either check the trigger's author_association or apply
// only to another event (github.event_name == '<other>'), and the condition
// must not negate (! or !=). Anything else is no gate.
func assocGate(w *yamlWalk, job *yamlMap, trigger string) []string {
	ctxs := assocContexts[trigger]
	if len(ctxs) == 0 {
		return nil
	}
	cond := strings.TrimSpace(scalarOf(w, field(job, "if")))
	if m := exprRe.FindStringSubmatch(cond); m != nil && strings.TrimSpace(m[0]) == cond {
		cond = m[1]
	}
	if cond == "" || strings.Contains(cond, "!") {
		return nil
	}
	set := map[string]bool{}
	for _, d := range disjuncts(cond) {
		checks := false
		for _, c := range ctxs {
			if strings.Contains(d, c) {
				checks = true
			}
		}
		if checks {
			vals := assocValueRe.FindAllString(d, -1)
			if len(vals) == 0 {
				return nil
			}
			for _, v := range vals {
				set[v] = true
			}
			continue
		}
		m := eventNameRe.FindStringSubmatch(d)
		if m == nil || m[1] == trigger {
			return nil
		}
	}
	return sortedSet(set)
}

// disjuncts splits an expression at its top-level ||, unwrapping branches
// that are wholly parenthesized.
func disjuncts(s string) []string {
	s = strings.TrimSpace(s)
	for len(s) > 1 && s[0] == '(' && closes(s) == len(s)-1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	depth, start := 0, 0
	var parts []string
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 && i+1 < len(s) && s[i+1] == '|' {
				parts = append(parts, s[start:i])
				start = i + 2
				i++
			}
		}
	}
	if len(parts) == 0 {
		return []string{s}
	}
	parts = append(parts, s[start:])
	var out []string
	for _, p := range parts {
		out = append(out, disjuncts(p)...)
	}
	return out
}

// closes returns the index of the parenthesis that closes s[0], or -1.
func closes(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// assocClass is who an author_association gate lets in. CONTRIBUTOR means
// anyone with a previously merged commit, which includes outside
// contributors, so it does not narrow the trigger.
func assocClass(vals []string) string {
	class := assocCollaborators
	for _, v := range vals {
		switch v {
		case "MEMBER":
			if class == assocCollaborators {
				class = assocMembers
			}
		case "OWNER", "COLLABORATOR":
		default:
			return assocOutsiders
		}
	}
	return class
}

// ---- LLM steps found by heuristic ----

// LLMScriptKind is the agent kind of a step gop finds by heuristic: it holds
// a model API key and reads the pull request's content.
const LLMScriptKind = "llm-script"

// llmKeyRe matches env and secret names of model API keys.
var llmKeyRe = regexp.MustCompile(`(?i)^(?:[A-Z0-9_]*_)?(?:ANTHROPIC|OPENAI|AZURE_OPENAI|GEMINI|MISTRAL|GROQ|COHERE|DEEPSEEK|XAI|OPENROUTER|TOGETHER|PERPLEXITY|FIREWORKS|LLM)_API_KEY$|^CLAUDE_CODE_OAUTH_TOKEN$`)

// prTextCmds are run: commands that read the pull request's diff or text.
var prTextCmds = []string{"gh pr diff", "gh pr view"}

// holdsLLMKey reports whether a step can read a model API key: by env name
// (its own env:, the job's or the workflow's) or by the secret it references.
func holdsLLMKey(w *yamlWalk, step *yamlMap, jobEnv, wfEnv *yamlMap) bool {
	stepEnv, _ := w.mapping(field(step, "env"), "env")
	for _, m := range []*yamlMap{stepEnv, jobEnv, wfEnv} {
		if m == nil {
			continue
		}
		for _, k := range m.keys {
			if llmKeyRe.MatchString(k) {
				return true
			}
			for n := range secretsIn(m.val[k]) {
				if llmKeyRe.MatchString(n) {
					return true
				}
			}
		}
	}
	with, _ := w.mapping(field(step, "with"), "with")
	for _, v := range withValues(w, with) {
		for _, m := range secretRefRe.FindAllStringSubmatch(v, -1) {
			if llmKeyRe.MatchString(m[1]) {
				return true
			}
		}
	}
	return false
}
