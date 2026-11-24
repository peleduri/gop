package collect

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// Bot merges and approvals implemented in a repo script (issue #152). A
// run: step that invokes a script from the repo (python3 tools/merge.py,
// node scripts/merge.js, bash ci/merge.sh, go run ./cmd/merge) with a token
// or key in its env is a candidate. After every workflow is read,
// followBotScripts fetches each candidate once from the default branch with
// a read-only contents GET (through the response cache, capped at
// botScriptMaxBytes) and scans the text for the same merge and approve calls
// as a workflow step, plus the stale-approval heuristic. gop never runs the
// script. The workflow's bot facts are then re-read with the script facts,
// so a script merge feeds the same join (addBotMergePaths) as a step merge.

const (
	// botScriptMaxBytes caps the size of a script gop scans.
	botScriptMaxBytes = 256 << 10
	// botScriptsPerWorkflow caps the scripts followed per workflow file.
	botScriptsPerWorkflow = 5
)

// scriptFacts is what one script does.
type scriptFacts struct {
	approve, merge bool
	app            bool // it mints a GitHub App token itself (from a private key)
	stale          bool // stale-approval heuristic matched
	dismissed      bool // the heuristic matched a DISMISSED review counted next to APPROVED
}

var (
	pyMergeRe    = regexp.MustCompile(`\b\w*(?:pr|pull|pull_request|pullrequest)\w*\.merge\(|\.merge\([^)\n]*\bmerge_method\b`)
	pyReviewRe   = regexp.MustCompile(`\bcreate_review\b|\bsubmit_review\b`)
	scriptAppRe  = regexp.MustCompile(`\bGithubIntegration\b|\bAuth\.AppAuth\b|\bAppAuthentication\b|\bcreateAppAuth\b|\bget_access_token\b|\binstallations/[^/\s"']+/access_tokens\b`)
	keyNameRe    = regexp.MustCompile(`(?i)private_?key|_pem$|app_key`)
	reviewsRe    = regexp.MustCompile(`\bget_reviews\b|/reviews\b|\blistReviews\b|\blatestReviews\b|\breviews\(|\bAPPROVED\b`)
	dismissedRe  = regexp.MustCompile(`\bDISMISSED\b`)
	approvedRe   = regexp.MustCompile(`\bAPPROVED\b`)
	staleCmpRe   = regexp.MustCompile(`\bcommit_id\b\s*!==?|!==?\s*\w*\.?commit_id\b|\bcommit\.oid\b\s*!==?`)
	skipRe       = regexp.MustCompile(`\b(continue|return|break|skip|next|false|False)\b`)
	scriptExtRe  = regexp.MustCompile(`\.(py|js|mjs|cjs|ts|sh|bash|rb|go)$`)
	interpreters = map[string]bool{"python": true, "python3": true, "node": true, "bash": true, "sh": true, "ruby": true, "tsx": true, "ts-node": true}
)

// scanScript reads one script's text. It never runs it.
func scanScript(data []byte) scriptFacts {
	text := stripScriptComments(string(data))
	var sf scriptFacts
	sf.merge = ghMergeRe.MatchString(text) || apiMergeRe.MatchString(text) || pyMergeRe.MatchString(text)
	sf.approve = ghApproveRe.MatchString(text) ||
		((apiReviewRe.MatchString(text) || createRevRe.MatchString(text) || pyReviewRe.MatchString(text)) && approveRe.MatchString(text))
	sf.app = scriptAppRe.MatchString(text)
	if sf.merge {
		sf.stale, sf.dismissed = staleApprovals(text)
	}
	return sf
}

// staleApprovals is the stale-approval heuristic: the script reads reviews
// and either counts a DISMISSED review next to APPROVED (on the same line:
// `state in ("APPROVED", "DISMISSED")`) or compares a review's commit with
// the head and goes on without skipping it. A text match, never proof.
// dismissed is set when the DISMISSED form matched.
func staleApprovals(text string) (stale, dismissed bool) {
	if !reviewsRe.MatchString(text) {
		return false, false
	}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if approvedRe.MatchString(line) && dismissedRe.MatchString(line) && !strings.Contains(line, "!=") {
			return true, true
		}
	}
	for i, line := range lines {
		if !staleCmpRe.MatchString(line) || skipRe.MatchString(line) {
			continue
		}
		// The next two non-empty lines: a skip there filters stale reviews out.
		skipped, seen := false, 0
		for _, next := range lines[i+1:] {
			if strings.TrimSpace(next) == "" {
				continue
			}
			if skipRe.MatchString(next) {
				skipped = true
			}
			if seen++; seen == 2 {
				break
			}
		}
		if !skipped {
			return true, false
		}
	}
	return false, false
}

// stripScriptComments drops whole-line #, // and -- comments.
func stripScriptComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// scriptCalls returns the repo scripts a run: script invokes, as clean
// repo-relative paths (dir is the step's working-directory). Only literal
// relative paths: anything with $, .., ~ or a glob is skipped.
func scriptCalls(run, dir string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string, goDir bool) {
		p = strings.Trim(p, `"'`)
		if p == "" || strings.ContainsAny(p, "$~*?{}`\\") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") {
			return
		}
		if dir != "" && !strings.ContainsAny(dir, "$~*?{}`\\") && !strings.HasPrefix(dir, "/") {
			p = dir + "/" + p
		}
		p = path.Clean(p)
		if p == "." || strings.HasPrefix(p, "../") || p == ".." {
			return
		}
		if goDir && !strings.HasSuffix(p, ".go") {
			p += "/main.go" // go run ./cmd/merge: its main package file, by convention
		}
		if !scriptExtRe.MatchString(p) || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, line := range strings.Split(cleanScript(run), "\n") {
		for _, seg := range shellSplit.Split(line, -1) {
			f := strings.Fields(seg)
			i := 0
			for i < len(f) && (isEnvAssign(f[i]) || f[i] == "sudo" || f[i] == "env" || f[i] == "exec" || f[i] == "time") {
				i++
			}
			if i >= len(f) {
				continue
			}
			bin := strings.Trim(f[i], `"'`)
			rest := f[i+1:]
			switch {
			case bin == "go" && len(rest) > 1 && rest[0] == "run":
				add(firstArg(rest[1:]), true)
			case (bin == "deno" && len(rest) > 1 && rest[0] == "run") || (bin == "npx" && len(rest) > 1 && (rest[0] == "tsx" || rest[0] == "ts-node")):
				add(firstArg(rest[1:]), false)
			case interpreters[path.Base(bin)]:
				if a := firstArg(rest); a != "" {
					add(a, false)
				}
			case strings.Contains(bin, "/") && scriptExtRe.MatchString(bin):
				add(bin, false) // ./tools/merge.sh
			}
		}
	}
	return out
}

// firstArg is the first word that is not a flag. "" when a flag like -m or
// -c takes the place of a script (python -m pkg, bash -c '...').
func firstArg(args []string) string {
	for _, a := range args {
		switch {
		case a == "-m" || a == "-c" || a == "-e" || a == "--eval":
			return ""
		case strings.HasPrefix(a, "-"):
			continue
		}
		return a
	}
	return ""
}

// stepHoldsToken reports whether a step's env hands a token or key to what
// it runs: a secret, an App token step's output or the workflow token.
func stepHoldsToken(env map[string]string) bool {
	for _, v := range env {
		if secretTokRe.MatchString(v) || appOutputRe.MatchString(v) || githubTokRe.MatchString(v) {
			return true
		}
	}
	return false
}

// scriptToken classifies the token a script step uses: an App token when the
// script mints one or the env hands it a private key secret, else the env's
// token source.
func scriptToken(sf scriptFacts, env map[string]string, appIDs map[string]bool) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if keyNameRe.MatchString(k) && secretTokRe.MatchString(env[k]) {
			return graph.BotTokenApp
		}
	}
	var exprs []string
	for _, k := range tokenEnv {
		if v, ok := env[k]; ok {
			exprs = append(exprs, v)
		}
	}
	for _, k := range keys {
		exprs = append(exprs, env[k])
	}
	t := tokenSource(exprs, env, appIDs)
	if sf.app && (t == graph.BotTokenPAT || t == "") {
		return graph.BotTokenApp
	}
	if t == "" {
		return graph.BotTokenUnknown
	}
	return t
}

// secretNames returns the secrets (GITHUB_TOKEN excluded) the values name.
func secretRefNames(vals ...string) []string {
	set := map[string]bool{}
	for _, v := range vals {
		for _, m := range secretTokRe.FindAllStringSubmatch(v, -1) {
			if m[1] != "GITHUB_TOKEN" {
				set[m[1]] = true
			}
		}
	}
	return sortedSet(set)
}

func mapValues(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// rereviews reports whether a workflow re-runs on a push to the pull request:
// a pull_request or pull_request_target trigger with no types (the default
// includes synchronize) or with synchronize listed.
func rereviews(w *yamlWalk, root *yamlMap) bool {
	n, err := w.resolve(field(root, "on"))
	if err != nil || n == nil {
		return false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		v := strings.TrimSpace(n.Value)
		return v == "pull_request" || v == "pull_request_target"
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c, err := w.resolve(c); err == nil && c.Kind == yaml.ScalarNode {
				if v := strings.TrimSpace(c.Value); v == "pull_request" || v == "pull_request_target" {
					return true
				}
			}
		}
	case yaml.MappingNode:
		m, err := w.mapping(n, "on")
		if err != nil {
			return false
		}
		for _, ev := range []string{"pull_request", "pull_request_target"} {
			k, v := m.get(ev)
			if k == nil {
				continue
			}
			cfg, err := w.mapping(v, ev)
			if err != nil || cfg == nil {
				return true // `pull_request:` with no settings: default types
			}
			tk, tv := cfg.get("types")
			if tk == nil {
				return true
			}
			tv, err = w.resolve(tv)
			if err != nil || tv == nil {
				return true
			}
			switch tv.Kind {
			case yaml.ScalarNode:
				if strings.TrimSpace(tv.Value) == "synchronize" {
					return true
				}
			case yaml.SequenceNode:
				for _, c := range tv.Content {
					if c, err := w.resolve(c); err == nil && c.Kind == yaml.ScalarNode && strings.TrimSpace(c.Value) == "synchronize" {
						return true
					}
				}
			}
		}
	}
	return false
}

// botScriptWF is a workflow whose steps run repo scripts gop follows.
type botScriptWF struct {
	wn       *graph.Node
	owner    string
	repo     string // repo name
	data     []byte
	triggers []string
	scripts  []string
}

// trackBotScripts keeps a workflow whose bot facts name scripts to follow.
func (k *collector) trackBotScripts(o *orgState, repo *graph.Node, wn *graph.Node, data []byte, triggers []string, bf *botFacts) {
	if bf == nil || len(bf.Scripts) == 0 {
		return
	}
	k.botScriptWFs = append(k.botScriptWFs, botScriptWF{
		wn: wn, owner: o.login, repo: repoName(o, repo), data: data, triggers: triggers, scripts: bf.Scripts,
	})
}

// followBotScripts fetches the scripts the tracked workflows run, once per
// repo and path, and re-reads those workflows' bot facts with them.
func (k *collector) followBotScripts(ctx context.Context) error {
	if len(k.botScriptWFs) == 0 {
		return nil
	}
	cache := map[string]*scriptFacts{} // owner/repo/path -> facts, nil when unreadable
	for _, t := range k.botScriptWFs {
		facts := map[string]*scriptFacts{}
		for _, p := range t.scripts {
			key := t.owner + "/" + t.repo + "/" + p
			sf, ok := cache[key]
			if !ok {
				data, err := k.getScript(ctx, t.owner, t.repo, p)
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					k.cover(t.wn.ID, "bot_script:"+p, "could not read the script a workflow step runs: "+err.Error(),
						k.fixFor(err, "read access to contents on "+t.owner+"/"+t.repo))
				} else {
					s := scanScript(data)
					sf = &s
				}
				cache[key] = sf
			}
			if sf != nil {
				facts[p] = sf
			}
		}
		if len(facts) == 0 {
			continue
		}
		bf := parseBotFacts(t.data, t.triggers, facts)
		k.addBotFacts(t.wn, bf)
	}
	return nil
}

// getScript reads one file of the default branch for scanning: a read-only
// contents GET (cached like every REST GET), refused above botScriptMaxBytes.
func (k *collector) getScript(ctx context.Context, owner, repo, p string) ([]byte, error) {
	return k.readScanned(ctx, owner, repo, p, "", botScriptMaxBytes)
}

// readScanned is getFileCapped read once per run: the bot script and the
// indirection followers (indirect.go) share what they read.
func (k *collector) readScanned(ctx context.Context, owner, repo, p, ref string, limit int64) ([]byte, error) {
	key := fmt.Sprintf("%s/%s/%s@%s#%d", strings.ToLower(owner), strings.ToLower(repo), p, ref, limit)
	if r, ok := k.scanned[key]; ok {
		return r.data, r.err
	}
	data, err := k.getFileCapped(ctx, owner, repo, p, ref, limit)
	if ctx.Err() != nil {
		return data, err // not remembered: the run is over
	}
	if k.scanned == nil {
		k.scanned = map[string]scannedFile{}
	}
	k.scanned[key] = scannedFile{data, err}
	return data, err
}

// scannedFile is one file readScanned read, or the error it got.
type scannedFile struct {
	data []byte
	err  error
}

// getFileCapped reads one file at ref ("" for the default branch) for
// scanning: a read-only contents GET (cached like every REST GET), refused
// above limit bytes.
func (k *collector) getFileCapped(ctx context.Context, owner, repo, p, ref string, limit int64) ([]byte, error) {
	var f struct {
		contentEntry
		Size int64 `json:"size"`
	}
	if err := k.cl(owner).GetJSON(ctx, contentsPath(owner, repo, p, ref), &f); err != nil {
		return nil, err
	}
	if f.Type != "" && f.Type != "file" {
		return nil, fmt.Errorf("%s is a %s, not a file", p, f.Type)
	}
	if f.Size > limit {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte scan limit", p, f.Size, limit)
	}
	if f.Encoding != "base64" {
		return nil, fmt.Errorf("%s: unsupported content encoding %q (file too large?)", p, f.Encoding)
	}
	data, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(f.Content))
	if err != nil {
		return nil, fmt.Errorf("%s: decoding base64: %w", p, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is over the %d byte scan limit", p, limit)
	}
	return data, nil
}

// isAgentStep reports whether a step runs a known AI agent action or CLI.
func isAgentStep(w *yamlWalk, step *yamlMap, u ActionUse, isUse bool) bool {
	if isUse {
		_, ok := matchAgentAction(u)
		return ok
	}
	_, _, ok := matchAgentCLI(scalarOf(w, field(step, "run")))
	return ok
}

func staleWhy(src string) string {
	where := "the merge step"
	if p, ok := strings.CutPrefix(src, graph.BotScriptPrefix); ok {
		where = p
	}
	return "suspected, heuristic: " + where + " seems to count approvals not tied to the head commit (a dismissed review, or a review of an older commit it does not skip); gop matched text and never ran it"
}

func staleFix(src string) string {
	where := "the merge script"
	if p, ok := strings.CutPrefix(src, graph.BotScriptPrefix); ok {
		where = p
	}
	return "confirm by hand: read " + where + " and check it counts only APPROVED reviews whose commit_id is the pull request's head SHA"
}
