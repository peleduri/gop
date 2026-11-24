package collect

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// AI approve + self-merge (docs/agents-in-ci.md). The parser finds the jobs
// that submit an approving review or merge a pull request with a bot token,
// with their token source and who can make them run, and writes them as
// bot_* attrs on the workflow node. After branch protection is read,
// addBotMergePaths joins each repo's bot merge workflows with its approving
// workflows and its default-branch rules: when the bot merge needs no human
// review, the repo gets review_bypass=bot_self_merge and the principals who
// can open a pull request get CAN_MERGE_VIA_BOT edges to it.

// appTokenActions mint a GitHub App installation token in a step; a later
// step reads it as steps.<id>.outputs.token.
var appTokenActions = map[string]bool{
	"actions/create-github-app-token":                true,
	"tibdex/github-app-token":                        true,
	"getsentry/action-github-app-token":              true,
	"peter-murray/workflow-application-token-action": true,
	"navikt/github-app-token-generator":              true,
	"jnwng/github-app-installation-token-action":     true,
}

// approveActions submit an approving review by themselves.
var approveActions = map[string]bool{
	"hmarr/auto-approve-action":                  true,
	"juliangruber/approve-pull-request-action":   true,
	"cognitedata/auto-approve-dependabot-action": true,
}

// mergeActions merge a pull request or turn on its auto-merge.
var mergeActions = map[string]bool{
	"peter-evans/enable-pull-request-automerge": true,
	"pascalgn/automerge-action":                 true,
	"ridedott/merge-me-action":                  true,
	"desbo/merge-pr-action":                     true,
	"reitermarkus/automerge":                    true,
}

// scriptActions run JavaScript against the API (with.script).
var scriptActions = map[string]bool{"actions/github-script": true}

// tokenInputs are the with: keys actions read a token from, in order.
var tokenInputs = []string{"github-token", "github_token", "token", "repo-token", "GITHUB_TOKEN"}

// tokenEnv are the env: keys gh and actions read a token from, in order.
var tokenEnv = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

var (
	ghReviewRe      = regexp.MustCompile(`\bgh\s+pr\s+review\b`)
	ghApproveRe     = regexp.MustCompile(`\bgh\s+pr\s+review\b[^\n;&|]*(--approve\b|\s-a\b)`)
	ghMergeRe       = regexp.MustCompile(`\bgh\s+pr\s+merge\b`)
	ghAdminRe       = regexp.MustCompile(`\bgh\s+pr\s+merge\b[^\n;&|]*--admin\b`)
	apiReviewRe     = regexp.MustCompile(`pulls/[^/\s"']+/reviews\b`)
	apiMergeRe      = regexp.MustCompile(`pulls/[^/\s"']+/merge\b|\bmergePullRequest\b|\benablePullRequestAutoMerge\b|\bpulls\.merge\b`)
	approveRe       = regexp.MustCompile(`\bAPPROVE\b`)
	createRevRe     = regexp.MustCompile(`\bcreateReview\b|\baddPullRequestReview\b|\bsubmitPullRequestReview\b`)
	appOutputRe     = regexp.MustCompile(`steps\.([A-Za-z0-9_-]+)\.outputs\.token\b`)
	githubTokRe     = regexp.MustCompile(`secrets\.GITHUB_TOKEN\b|\bgithub\.token\b`)
	secretTokRe     = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)
	envRefRe        = regexp.MustCompile(`\benv\.([A-Za-z_][A-Za-z0-9_]*)|\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	botAssocRe      = regexp.MustCompile(`author_association`)
	botAssocValueRe = regexp.MustCompile(`['"](OWNER|MEMBER|COLLABORATOR|CONTRIBUTOR|FIRST_TIME_CONTRIBUTOR|FIRST_TIMER|NONE|MANNEQUIN)['"]`)
	botAuthorRe     = regexp.MustCompile(`github\.event\.(issue|pull_request)\.user\.login`)
	botActorRe      = regexp.MustCompile(`github\.event\.comment\.user\.login|github\.event\.review\.user\.login|github\.actor\b|github\.triggering_actor\b|github\.event\.sender\.login`)
	botListedRe     = regexp.MustCompile(`(github\.actor|github\.triggering_actor|github\.event\.comment\.user\.login|github\.event\.review\.user\.login|github\.event\.sender\.login)\s*==\s*'[^']+'|'[^']+'\s*==\s*(github\.actor|github\.triggering_actor|github\.event\.comment\.user\.login|github\.event\.sender\.login)|fromJSON\([^)]*\)\s*,\s*(github\.actor|github\.triggering_actor|github\.event\.comment\.user\.login|github\.event\.sender\.login)`)
)

// botBaseTriggers run a job in the base repo's context (its secrets and a
// writable token) on an event someone who opened a pull request can cause.
var botBaseTriggers = map[string]bool{"issue_comment": true, "pull_request_target": true, "workflow_run": true}

// botForkTriggers run with a read-only token and no secrets for a fork's
// pull request: only same-repo pull requests (people who can push) get a
// bot token.
var botForkTriggers = map[string]bool{"pull_request": true, "pull_request_review": true, "pull_request_review_comment": true}

// starterWidth orders Starter* values from narrow to wide.
var starterWidth = map[string]int{graph.StarterMaintainers: 0, graph.StarterPushers: 1, graph.StarterMembers: 2, graph.StarterPROpeners: 3}

// botFacts are the bot approve and merge facts of one workflow.
type botFacts struct {
	ApproveJobs, MergeJobs     []string
	ApproveTokens, MergeTokens []string // BotToken* values, sorted
	ApproveStarter             string
	MergeStarter               string
	MergeGate                  string
	MergeAdmin                 bool
	MergeTriggers              []string
	MergeLine                  int // 1-based line of the first merging step's run:/uses: key

	// Scripts are the repo scripts run: steps with a token invoke, to
	// follow (botscript.go); MergeSource and ApproveSource name the script
	// a merge or approval was found in ("" when in the workflow itself),
	// and MergeStale is set when that merge script matched the
	// stale-approval heuristic.
	Scripts                    []string
	MergeSource, ApproveSource string
	MergeStale                 bool
	// MergeDismissed is set when that merge script counts DISMISSED
	// reviews (a form of MergeStale); MergeApps are the Apps the merging
	// steps' App tokens come from (app ids or slugs, unknown when the
	// workflow does not name one).
	MergeDismissed bool
	MergeApps      []string
	// MergeKeys are the secrets the merging jobs' token comes from (App
	// token step inputs and the merging steps' env); AgentKeys the secrets
	// in the env and with: of the workflow's AI agent steps; ReReviews is
	// set when the workflow re-runs on a push to the pull request.
	MergeKeys, AgentKeys []string
	ReReviews            bool
}

// parseBotFacts finds the approving and merging jobs of a workflow. scripts
// holds the facts of the repo scripts its steps run, when followed (nil on
// the first read). nil when it has no approving or merging job, no script to
// follow and no agent step holding a secret. Lenient like readAgents: a
// shape it does not understand yields nothing.
func parseBotFacts(data []byte, triggers []string, scripts map[string]*scriptFacts) *botFacts {
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(&doc), "workflow")
	if err != nil {
		return nil
	}
	_, jobsNode := root.get("jobs")
	jobs, err := w.mapping(jobsNode, "jobs")
	if err != nil {
		return nil
	}
	wfEnv := envMap(w, field(root, "env"))
	bf := &botFacts{ReReviews: rereviews(w, root)}
	approveTok, mergeTok, mergeTrig := map[string]bool{}, map[string]bool{}, map[string]bool{}
	scriptSet, mergeKeys, agentKeys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	mergeApps := map[string]bool{}
	gateRank := map[string]int{"": -1, graph.BotGateListed: 0, graph.BotGateAssociation: 1, graph.BotGateAuthor: 2, graph.BotGateNone: 3}
	ids := append([]string(nil), jobs.keys...)
	sort.Strings(ids)
	for _, id := range ids {
		_, jv := jobs.get(id)
		job, err := w.mapping(jv, "job")
		if err != nil {
			continue
		}
		jobIf := scalarOf(w, field(job, "if"))
		jobEnv := mergeEnv(wfEnv, envMap(w, field(job, "env")))
		steps, _ := w.sequence(field(job, "steps"), "steps")
		appIDs := map[string]bool{}
		appRefs := map[string]string{} // App token step id -> app id, slug or unknown
		var appKeys []string           // secrets the job's App token steps read
		approves, merges := false, false
		approveIf, mergeIf := jobIf, jobIf
		approveLimit, mergeLimit := "", ""
		for _, sn := range steps {
			step, err := w.mapping(sn, "step")
			if err != nil {
				continue
			}
			env := mergeEnv(jobEnv, envMap(w, field(step, "env")))
			stepIf := scalarOf(w, field(step, "if"))
			u, isUse := ParseUses(scalarOf(w, field(step, "uses")))
			name := ""
			if isUse {
				name = strings.ToLower(u.Owner + "/" + u.Repo)
				if appTokenActions[name] {
					with, _ := w.mapping(field(step, "with"), "with")
					if sid := strings.TrimSpace(scalarOf(w, field(step, "id"))); sid != "" {
						appIDs[sid] = true
						appRefs[sid] = appStepRef(w, with, env)
					}
					appKeys = append(appKeys, secretRefNames(withValues(w, with)...)...)
					continue
				}
			}
			if isAgentStep(w, step, u, isUse) {
				with, _ := w.mapping(field(step, "with"), "with")
				for _, s := range secretRefNames(append(mapValues(env), withValues(w, with)...)...) {
					agentKeys[s] = true
				}
			}
			bs := botStep(w, step, u, isUse, name, env, appIDs, scripts)
			for _, p := range bs.scripts {
				scriptSet[p] = true
			}
			if bs.approve {
				approves = true
				approveTok[bs.token] = true
				if bs.approveSrc != "" && bf.ApproveSource == "" {
					bf.ApproveSource = bs.approveSrc
				}
				approveIf = joinIf(approveIf, stepIf)
				approveLimit = widerLimit(approveLimit, bs.limit)
			}
			if bs.merge {
				merges = true
				mergeTok[bs.token] = true
				bf.MergeAdmin = bf.MergeAdmin || bs.admin
				mergeIf = joinIf(mergeIf, stepIf)
				mergeLimit = widerLimit(mergeLimit, bs.limit)
				if bs.key != nil && (bf.MergeLine == 0 || bs.key.Line < bf.MergeLine) {
					bf.MergeLine = bs.key.Line
				}
				if bs.mergeSrc != "" && bf.MergeSource == "" {
					bf.MergeSource = bs.mergeSrc
				}
				bf.MergeStale = bf.MergeStale || bs.stale
				bf.MergeDismissed = bf.MergeDismissed || bs.dismissed
				if bs.token == graph.BotTokenApp {
					with, _ := w.mapping(field(step, "with"), "with")
					for _, r := range mergeAppRefs(append(mapValues(env), withValues(w, with)...), env, appRefs) {
						mergeApps[r] = true
					}
				}
				for _, s := range append(appKeys, secretRefNames(mapValues(env)...)...) {
					mergeKeys[s] = true
				}
			}
		}
		if approves {
			bf.ApproveJobs = append(bf.ApproveJobs, id)
			_, limit := botGate(approveIf)
			bf.ApproveStarter = widerStarter(bf.ApproveStarter, botStarter(triggers, limit, approveLimit))
		}
		if merges {
			bf.MergeJobs = append(bf.MergeJobs, id)
			gate, limit := botGate(mergeIf)
			s := botStarter(triggers, limit, mergeLimit)
			if bf.MergeStarter == "" || starterWidth[s] > starterWidth[bf.MergeStarter] {
				bf.MergeStarter = s
			}
			if gateRank[gate] > gateRank[bf.MergeGate] {
				bf.MergeGate = gate
			}
			for _, t := range triggers {
				if botBaseTriggers[t] || botForkTriggers[t] {
					mergeTrig[t] = true
				}
			}
		}
	}
	bf.Scripts, bf.MergeKeys, bf.AgentKeys = sortedSet(scriptSet), sortedSet(mergeKeys), sortedSet(agentKeys)
	bf.MergeApps = sortedSet(mergeApps)
	if len(bf.Scripts) > botScriptsPerWorkflow {
		bf.Scripts = bf.Scripts[:botScriptsPerWorkflow]
	}
	if len(bf.ApproveJobs) == 0 && len(bf.MergeJobs) == 0 && len(bf.Scripts) == 0 && len(bf.AgentKeys) == 0 {
		return nil
	}
	bf.ApproveTokens, bf.MergeTokens, bf.MergeTriggers = sortedSet(approveTok), sortedSet(mergeTok), sortedSet(mergeTrig)
	return bf
}

// noLimit is a step limit that does not narrow who can start a job.
const noLimit = "*"

// widerLimit keeps the wider of two step limits: a job runs for whoever
// passes any of its approving (or merging) steps.
func widerLimit(a, b string) string {
	if a == noLimit || b == noLimit || b == "" {
		if b == "" {
			return a
		}
		return noLimit
	}
	return widerStarter(a, b)
}

// botStepFacts is what one step does: approve, merge (with --admin), the
// token source, its key node (run: or uses:) for the line, and limit, the
// widest Starter* the step itself admits (noLimit when it does not check
// the actor, "" when the step neither approves nor merges).
type botStepFacts struct {
	approve, merge, admin bool
	token, limit          string
	key                   *yaml.Node
	// scripts are the repo scripts the run: step invokes with a token in
	// its env; approveSrc and mergeSrc name the script (script:<path>) an
	// approval or merge came from; stale is set when that merge script
	// matched the stale-approval heuristic.
	scripts              []string
	approveSrc, mergeSrc string
	stale, dismissed     bool
}

// botStep reads one step.
func botStep(w *yamlWalk, step *yamlMap, u ActionUse, isUse bool, name string, env map[string]string, appIDs map[string]bool, scripts map[string]*scriptFacts) botStepFacts {
	if isUse {
		bs := botStepFacts{limit: noLimit}
		bs.key, _ = step.get("uses")
		with, _ := w.mapping(field(step, "with"), "with")
		def := graph.BotTokenGitHub
		switch {
		case approveActions[name]:
			bs.approve = true
		case mergeActions[name]:
			bs.merge = true
		case scriptActions[name]:
			script := scalarOf(w, field(with, "script"))
			bs.approve = createRevRe.MatchString(script) && approveRe.MatchString(script)
			bs.merge = apiMergeRe.MatchString(script)
		default:
			a, ok := matchAgentAction(u)
			if !ok {
				return botStepFacts{}
			}
			// An agent approves or merges when its tool settings or prompt
			// let it run gh pr review / gh pr merge.
			all := strings.Join(withValues(w, with), "\n")
			bs.approve = ghReviewRe.MatchString(all)
			bs.merge = ghMergeRe.MatchString(all)
			if a.kind == "claude-code-action" || a.kind == "claude-code-base-action" {
				def = graph.BotTokenApp // without github_token it uses the Claude GitHub App's token
			}
			// The agent's own actor check: write access (or named users) only.
			switch actionGate(w, a, with) {
			case graph.GateWriteAccess, graph.GateListed:
				bs.limit = graph.StarterPushers
			}
		}
		if !bs.approve && !bs.merge {
			return botStepFacts{}
		}
		var exprs []string
		for _, k := range tokenInputs {
			if v := scalarOf(w, field(with, k)); v != "" {
				exprs = append(exprs, v)
			}
		}
		for _, k := range tokenEnv {
			if v, ok := env[k]; ok {
				exprs = append(exprs, v)
			}
		}
		if bs.token = tokenSource(exprs, env, appIDs); bs.token == "" {
			bs.token = def
		}
		return bs
	}
	run := scalarOf(w, field(step, "run"))
	if run == "" {
		return botStepFacts{}
	}
	script := cleanScript(run)
	bs := botStepFacts{limit: noLimit}
	bs.approve = ghApproveRe.MatchString(script) || (apiReviewRe.MatchString(script) && approveRe.MatchString(script))
	bs.merge = ghMergeRe.MatchString(script) || apiMergeRe.MatchString(script)
	// A repo script the step runs with a token: followed from the default
	// branch (botscript.go), and once read, its calls count as the step's.
	var viaScript *scriptFacts
	if stepHoldsToken(env) {
		bs.scripts = scriptCalls(run, scalarOf(w, field(step, "working-directory")))
		for _, p := range bs.scripts {
			sf := scripts[p]
			if sf == nil {
				continue
			}
			if sf.approve && !bs.approve {
				bs.approve, bs.approveSrc = true, graph.BotScriptPrefix+p
				viaScript = sf
			}
			if sf.merge && !bs.merge {
				bs.merge, bs.mergeSrc, bs.stale, bs.dismissed = true, graph.BotScriptPrefix+p, sf.stale, sf.dismissed
				viaScript = sf
			}
		}
	}
	if !bs.approve && !bs.merge {
		return botStepFacts{scripts: bs.scripts}
	}
	bs.key, _ = step.get("run")
	bs.admin = ghAdminRe.MatchString(script)
	if viaScript != nil {
		bs.token = scriptToken(*viaScript, env, appIDs)
		return bs
	}
	var exprs []string
	for _, k := range tokenEnv {
		if v, ok := env[k]; ok {
			exprs = append(exprs, v)
		}
	}
	exprs = append(exprs, script)
	if bs.token = tokenSource(exprs, env, appIDs); bs.token == "" {
		bs.token = graph.BotTokenUnknown
	}
	return bs
}

// tokenSource classifies the first token expression in exprs: an App token
// step's output, GITHUB_TOKEN, another secret, or an env var that holds one.
// "" when none of them names a token.
func tokenSource(exprs []string, env map[string]string, appIDs map[string]bool) string {
	seen := map[string]bool{}
	var classify func(s string, depth int) string
	classify = func(s string, depth int) string {
		if m := appOutputRe.FindStringSubmatch(s); m != nil {
			if appIDs[m[1]] {
				return graph.BotTokenApp
			}
			return graph.BotTokenUnknown
		}
		if githubTokRe.MatchString(s) {
			return graph.BotTokenGitHub
		}
		if secretTokRe.MatchString(s) {
			return graph.BotTokenPAT
		}
		if depth > 2 {
			return ""
		}
		for _, m := range envRefRe.FindAllStringSubmatch(s, -1) {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			if v, ok := env[name]; ok && !seen[name] {
				seen[name] = true
				if t := classify(v, depth+1); t != "" {
					return t
				}
			}
		}
		return ""
	}
	for _, s := range exprs {
		if t := classify(s, 0); t != "" {
			return t
		}
	}
	return ""
}

// botGate reads the actor check of a job's if: conditions (joined with
// " && "). limit is the widest Starter* the check admits ("" when it does
// not narrow who can start the job).
func botGate(cond string) (gate, limit string) {
	switch {
	case botListedRe.MatchString(cond):
		return graph.BotGateListed, graph.StarterMaintainers
	case botAssocRe.MatchString(cond):
		if strings.Contains(cond, "!=") || strings.Contains(cond, "!contains") || strings.Contains(cond, "! contains") {
			return graph.BotGateAssociation, "" // an exclusion list: gop does not narrow it
		}
		vals := map[string]bool{}
		for _, m := range botAssocValueRe.FindAllStringSubmatch(cond, -1) {
			vals[m[1]] = true
		}
		wide := false
		for v := range vals {
			if v != "OWNER" && v != "MEMBER" && v != "COLLABORATOR" {
				wide = true
			}
		}
		switch {
		case len(vals) == 0 || wide:
			return graph.BotGateAssociation, ""
		case vals["MEMBER"]:
			return graph.BotGateAssociation, graph.StarterMembers
		}
		return graph.BotGateAssociation, graph.StarterMaintainers
	case botAuthorRe.MatchString(cond) && botActorRe.MatchString(cond):
		return graph.BotGateAuthor, ""
	}
	return graph.BotGateNone, ""
}

// botStarter is who can make a job run on these triggers, narrowed to the
// if: check's limit and the steps' own limit (noLimit or "": none).
func botStarter(triggers []string, limit, stepLimit string) string {
	s := graph.StarterMaintainers
	for _, t := range triggers {
		switch {
		case botBaseTriggers[t]:
			s = widerStarter(s, graph.StarterPROpeners)
		case botForkTriggers[t]:
			s = widerStarter(s, graph.StarterPushers)
		}
	}
	for _, l := range []string{limit, stepLimit} {
		if l != "" && l != noLimit && starterWidth[l] < starterWidth[s] {
			s = l
		}
	}
	return s
}

func widerStarter(a, b string) string {
	if a == "" || starterWidth[b] > starterWidth[a] {
		return b
	}
	return a
}

func joinIf(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " && " + b
}

// cleanScript joins backslash continuations and drops shell comments.
func cleanScript(run string) string {
	lines := strings.Split(strings.ReplaceAll(run, "\\\n", " "), "\n")
	for i, line := range lines {
		if j := strings.Index(line, "#"); j == 0 || (j > 0 && line[j-1] == ' ') {
			lines[i] = line[:j]
		}
	}
	return strings.Join(lines, "\n")
}

// envMap reads an env: mapping's scalar values.
func envMap(w *yamlWalk, n *yaml.Node) map[string]string {
	m, err := w.mapping(n, "env")
	if err != nil || m == nil {
		return nil
	}
	out := map[string]string{}
	for _, k := range m.keys {
		out[k] = scalarOf(w, field(m, k))
	}
	return out
}

func mergeEnv(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// addBotFacts writes the bot attrs on a workflow node and keeps the merging
// step's line for the CAN_MERGE_VIA_BOT edge.
func (k *collector) addBotFacts(wn *graph.Node, bf *botFacts) {
	if bf == nil {
		return
	}
	if k.botFacts == nil {
		k.botFacts = map[string]*botFacts{}
	}
	k.botFacts[wn.ID] = bf
	if bf.ApproveSource != "" {
		setAttr(wn, graph.AttrBotApproveSource, bf.ApproveSource, graph.Live)
	}
	if bf.MergeSource != "" {
		setAttr(wn, graph.AttrBotMergeSource, bf.MergeSource, graph.Live)
	}
	if bf.MergeStale {
		// A heuristic: the attr is never live, and a coverage entry asks
		// for a manual check.
		setAttr(wn, graph.AttrBotMergeStale, graph.StaleSuspected, graph.NotVisible)
		setAttr(wn, graph.AttrBotMergeStaleConf, graph.StaleHeuristic, graph.Live)
		k.cover(wn.ID, graph.FactStaleApprovals, staleWhy(bf.MergeSource), staleFix(bf.MergeSource))
	}
	if len(bf.ApproveJobs) > 0 {
		setAttr(wn, graph.AttrBotApproves, "true", graph.Live)
		setAttr(wn, graph.AttrBotApproveToken, strings.Join(bf.ApproveTokens, ","), graph.Live)
		setAttr(wn, graph.AttrBotApproveJobs, strings.Join(bf.ApproveJobs, ","), graph.Live)
		setAttr(wn, graph.AttrBotApproveStart, bf.ApproveStarter, graph.Live)
	}
	if len(bf.MergeJobs) > 0 {
		setAttr(wn, graph.AttrBotMerges, "true", graph.Live)
		setAttr(wn, graph.AttrBotMergeToken, strings.Join(bf.MergeTokens, ","), graph.Live)
		setAttr(wn, graph.AttrBotMergeJobs, strings.Join(bf.MergeJobs, ","), graph.Live)
		setAttr(wn, graph.AttrBotMergeStart, bf.MergeStarter, graph.Live)
		setAttr(wn, graph.AttrBotMergeGate, bf.MergeGate, graph.Live)
		if bf.MergeAdmin {
			setAttr(wn, graph.AttrBotMergeAdmin, "true", graph.Live)
		}
		if len(bf.MergeTriggers) > 0 {
			setAttr(wn, graph.AttrBotMergeTriggers, strings.Join(bf.MergeTriggers, ","), graph.Live)
		}
		if len(bf.MergeApps) > 0 {
			setAttr(wn, graph.AttrBotMergeApps, strings.Join(bf.MergeApps, ","), graph.Live)
		}
		if bf.MergeLine > 0 {
			if k.botLines == nil {
				k.botLines = map[string]int{}
			}
			k.botLines[wn.ID] = bf.MergeLine
		}
	}
}

// ---- the join ----

// botOutcome is one way a repo's bot merge needs no human review.
type botOutcome struct {
	merge    *graph.Node
	approve  []*graph.Node
	reason   string
	ev       graph.Evidence
	starter  string
	why, fix string // the coverage entry when ev is not_visible
	appMatch string // review_bypass_app_match of an app_bypass outcome
}

// better orders outcomes: confirmed first, then the wider population, then
// the merge workflow ID.
func (o botOutcome) better(b *botOutcome) bool {
	if b == nil {
		return true
	}
	if (o.ev == graph.Live) != (b.ev == graph.Live) {
		return o.ev == graph.Live
	}
	if starterWidth[o.starter] != starterWidth[b.starter] {
		return starterWidth[o.starter] > starterWidth[b.starter]
	}
	return o.merge.ID < b.merge.ID
}

// addBotMergePaths joins, per collected repo, the bot merge workflows with
// the approving workflows and the default-branch rules (collected first).
func (k *collector) addBotMergePaths() {
	byRepo := map[string][]*graph.Node{}
	for _, n := range k.nodes {
		if n.Kind == graph.KindWorkflow && (n.Attrs[graph.AttrBotApproves] == "true" || n.Attrs[graph.AttrBotMerges] == "true") {
			byRepo[n.Attrs["repo"]] = append(byRepo[n.Attrs["repo"]], n)
		}
	}
	if len(byRepo) == 0 {
		return
	}
	agents := map[string][]*graph.Node{} // repo -> workflows with an agent step holding a secret
	for id, bf := range k.botFacts {
		if n := k.nodes[id]; n != nil && len(bf.AgentKeys) > 0 {
			agents[n.Attrs["repo"]] = append(agents[n.Attrs["repo"]], n)
		}
	}
	for _, o := range k.orgs {
		for _, repo := range o.repos {
			wfs := byRepo[strings.TrimPrefix(repo.ID, "repo:")]
			if len(wfs) == 0 || repo.Attrs[graph.AttrArchived] == "true" {
				continue
			}
			sort.Slice(wfs, func(i, j int) bool { return wfs[i].ID < wfs[j].ID })
			k.agentMergeKey(repo, wfs, agents[strings.TrimPrefix(repo.ID, "repo:")])
			if best := botBest(repo, wfs); best != nil {
				k.applyBotOutcome(o, repo, best)
			}
		}
	}
}

// botBest decides the best review bypass of one repo, nil when none.
func botBest(repo *graph.Node, wfs []*graph.Node) *botOutcome {
	a := repo.Attrs
	prot := a[graph.AttrBranchProtected]
	if prot == "" {
		return nil // no default-branch facts (an empty repository)
	}
	full := strings.TrimPrefix(repo.ID, "repo:")
	var approvers []*graph.Node
	for _, n := range wfs {
		if n.Attrs[graph.AttrBotApproves] == "true" && n.Attrs[graph.AttrBotApproveStart] != graph.StarterMaintainers {
			approvers = append(approvers, n)
		}
	}
	usable := func(p string) []*graph.Node {
		var out []*graph.Node
		for _, n := range approvers {
			if starterWidth[n.Attrs[graph.AttrBotApproveStart]] >= starterWidth[p] {
				out = append(out, n)
			}
		}
		return out
	}
	var best *botOutcome
	consider := func(o botOutcome) {
		if o.better(best) {
			c := o
			best = &c
		}
	}
	for _, m := range wfs {
		ms := m.Attrs[graph.AttrBotMergeStart]
		if m.Attrs[graph.AttrBotMerges] != "true" || ms == "" || ms == graph.StarterMaintainers {
			continue
		}
		tokens := splitList(m.Attrs[graph.AttrBotMergeToken])
		base := botOutcome{merge: m, starter: ms, approve: usable(ms)}
		// No rule on the branch: the merge needs nothing.
		if prot == "false" {
			o := base
			o.reason, o.ev, o.approve = graph.ReviewBypassUnprotected, graph.Live, nil
			consider(o)
			continue
		}
		// The merging app bypasses every rule.
		if containsStr(tokens, graph.BotTokenApp) {
			switch a[graph.AttrBranchAppBypass] {
			case "true":
				o := base
				o.reason, o.ev = graph.ReviewBypassApp, graph.Live
				o.appMatch = appMatch(a[graph.AttrBranchBypassApps], m.Attrs[graph.AttrBotMergeApps])
				if o.appMatch != graph.AppMatched {
					o.ev = graph.NotVisible
					o.why, o.fix = appMatchWhy(m, a[graph.AttrBranchBypassApps], o.appMatch), "check which GitHub App "+m.Name+" mints its token for, and the bypass actors of the default branch rules on "+full
				}
				consider(o)
			case "unknown":
				o := base
				o.reason, o.ev = graph.ReviewBypassApp, graph.NotVisible
				o.why = "the bypass actors of the default branch rules are not visible: " + m.Name + " merges with a GitHub App token, which skips review if the app is a bypass actor"
				o.fix = "admin on " + full + " (ruleset bypass actors are visible to repo admins only)"
				consider(o)
			}
		}
		// --admin with a personal token: an admin's token skips the rules.
		if m.Attrs[graph.AttrBotMergeAdmin] == "true" && containsStr(tokens, graph.BotTokenPAT) {
			if v := a[graph.AttrBranchAdminBypass]; v == "true" || v == "unknown" {
				o := base
				o.reason, o.ev = graph.ReviewBypassAdmin, graph.NotVisible
				o.why = m.Name + " merges with --admin and a personal token; gop cannot see whether the token's owner is an admin"
				o.fix = "check the owner of the merge token in " + full
				consider(o)
			}
		}
		// Bot approvals satisfy the required reviews.
		if o, ok := botApprovals(repo, base, usable); ok {
			consider(o)
		}
	}
	return best
}

// botApprovals checks whether the bot approvals available to some
// population satisfy the default branch's required reviews.
func botApprovals(repo *graph.Node, base botOutcome, usable func(string) []*graph.Node) (botOutcome, bool) {
	a := repo.Attrs
	full := strings.TrimPrefix(repo.ID, "repo:")
	revs, co := a[graph.AttrBranchReviews], a[graph.AttrBranchCodeOwnerReview]
	if co == "true" {
		return botOutcome{}, false // a CODEOWNERS review: bots are not code owners
	}
	if revs == "unknown" || co == "unknown" {
		if len(base.approve) == 0 {
			return botOutcome{}, false
		}
		o := base
		o.reason, o.ev = graph.ReviewBypassApprovals, graph.NotVisible
		o.why = "the required reviews of the default branch are not visible: bot approvals from " + names(base.approve) + " may satisfy them"
		o.fix = "admin on " + full
		return o, true
	}
	need, err := strconv.Atoi(revs)
	if err != nil {
		return botOutcome{}, false
	}
	if need == 0 {
		o := base
		o.reason, o.ev, o.approve = graph.ReviewBypassApprovals, graph.Live, nil
		return o, true
	}
	// GITHUB_TOKEN approves only when the repo allows GitHub Actions to
	// approve pull requests (actions_can_approve_prs, botapprove.go).
	canApprove := a[graph.AttrActionsCanApprove]
	// Widest population first: each step down may add approvers.
	for _, p := range []string{graph.StarterPROpeners, graph.StarterMembers, graph.StarterPushers} {
		if starterWidth[p] > starterWidth[base.starter] {
			continue
		}
		var aps []*graph.Node
		classes := map[string]bool{}
		hidden := map[string]bool{}
		for _, n := range usable(p) {
			counts := false
			for _, t := range splitList(n.Attrs[graph.AttrBotApproveToken]) {
				if t == graph.BotTokenGitHub && canApprove == "false" {
					continue // the setting is off: its approval is refused
				}
				counts = true
				classes[t] = true
				if t == graph.BotTokenUnknown || (t == graph.BotTokenGitHub && canApprove != "true") {
					hidden[t] = true
				}
			}
			if counts {
				aps = append(aps, n)
			}
		}
		if len(classes) < need {
			continue
		}
		o := base
		o.starter, o.approve, o.reason, o.ev = p, aps, graph.ReviewBypassApprovals, graph.Live
		if len(classes)-len(hidden) < need {
			o.ev = graph.NotVisible
			if hidden[graph.BotTokenGitHub] {
				o.why = "bot approvals from " + names(aps) + " satisfy the required reviews only if their token can approve pull requests (GITHUB_TOKEN needs \"Allow GitHub Actions to create and approve pull requests\", which gop could not read)"
				o.fix = "check Settings > Actions > General > Workflow permissions on " + full
			} else {
				o.why = "bot approvals from " + names(aps) + " satisfy the required reviews only if their token can approve pull requests (gop could not tell which token the approving step uses)"
				o.fix = "check the token of the approving step in " + full
			}
		}
		return o, true
	}
	return botOutcome{}, false
}

func names(ns []*graph.Node) string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Attrs["path"])
	}
	return strings.Join(out, ", ")
}

// applyBotOutcome writes the repo's review bypass and the CAN_MERGE_VIA_BOT
// edges of the people who can open a pull request.
func (k *collector) applyBotOutcome(o *orgState, repo *graph.Node, b *botOutcome) {
	setAttr(repo, graph.AttrReviewBypass, graph.ReviewBypassBotSelfMerge, b.ev)
	setAttr(repo, graph.AttrReviewBypassReason, b.reason, graph.Live)
	setAttr(repo, graph.AttrReviewBypassMerge, b.merge.Attrs["path"], graph.Live)
	var approveFiles, approveIDs []string
	for _, n := range b.approve {
		approveFiles = append(approveFiles, n.Attrs["path"])
		approveIDs = append(approveIDs, n.ID)
	}
	sort.Strings(approveFiles)
	sort.Strings(approveIDs)
	if len(approveFiles) > 0 {
		setAttr(repo, graph.AttrReviewBypassApprove, strings.Join(approveFiles, ","), graph.Live)
	}
	k.applyBotScriptFacts(repo, b)
	if b.reason == graph.ReviewBypassApp && b.appMatch != "" {
		ev := graph.Live
		if b.appMatch != graph.AppMatched {
			ev = graph.NotVisible
		}
		setAttr(repo, graph.AttrReviewBypassAppMatch, b.appMatch, ev)
		if v := b.merge.Attrs[graph.AttrBotMergeApps]; v != "" {
			setAttr(repo, graph.AttrBotMergeApps, v, graph.Live)
		}
	}
	if b.ev == graph.NotVisible {
		k.cover(repo.ID, graph.FactReviewBypass, b.why, b.fix)
	}
	if b.starter != graph.StarterPROpeners && b.starter != graph.StarterMembers {
		return // only people who can push already: the path note says it
	}
	trig := splitList(b.merge.Attrs[graph.AttrBotMergeTriggers])
	attrs := func() map[string]string {
		m := map[string]string{
			graph.AttrMergeWorkflow:      b.merge.ID,
			graph.AttrReviewBypassReason: b.reason,
		}
		if len(approveIDs) > 0 {
			m[graph.AttrApproveWorkflows] = strings.Join(approveIDs, ",")
		}
		if len(trig) > 0 {
			m[attrTrigger] = trig[0]
		}
		locate(m, b.merge.Attrs["path"], repo.Attrs["default_branch"], k.botLines[b.merge.ID], 0)
		return m
	}
	// Who can open a pull request on the repo: the same population as a
	// fork-only trigger (triggers.go).
	for _, t := range k.triggerers(o, repo, UntrustedExec{Trigger: "pull_request_target"}) {
		p := t.principal
		if b.starter == graph.StarterMembers && !strings.HasPrefix(p, "members:") {
			p = "members:" + o.login // only org members pass the author_association check
		}
		if p == externalAnyone {
			k.node(externalAnyone, graph.KindExternal, "anyone on the internet")
		}
		ev := t.ev
		if b.ev == graph.NotVisible {
			ev = graph.NotVisible
		}
		k.edge(p, repo.ID, graph.CanMergeViaBot, ev, srcWorkflow, attrs())
	}
}

// applyBotScriptFacts copies the merge workflow's script source and
// stale-approval suspicion to the repo (the coverage entry asking for a
// manual check is on the merge workflow), and marks that the approval may not
// cover the merged code when an approving workflow does not re-run on a
// push. Both stay not_visible: a heuristic, never confirmed.
func (k *collector) applyBotScriptFacts(repo *graph.Node, b *botOutcome) {
	m := b.merge.Attrs
	if v := m[graph.AttrBotMergeSource]; v != "" {
		setAttr(repo, graph.AttrBotMergeSource, v, graph.Live)
	}
	if m[graph.AttrBotMergeStale] != graph.StaleSuspected {
		return
	}
	setAttr(repo, graph.AttrBotMergeStale, graph.StaleSuspected, graph.NotVisible)
	setAttr(repo, graph.AttrBotMergeStaleConf, graph.StaleHeuristic, graph.Live)
	// The rules dismiss stale reviews on push, and the script counts
	// DISMISSED reviews: it re-counts approvals GitHub dismissed.
	if bf := k.botFacts[b.merge.ID]; bf != nil && bf.MergeDismissed && repo.Attrs[graph.AttrBranchDismissStale] == "true" {
		setAttr(repo, graph.AttrReviewBypassRecount, graph.StaleSuspected, graph.NotVisible)
	}
	for _, a := range b.approve {
		if bf := k.botFacts[a.ID]; bf != nil && !bf.ReReviews {
			setAttr(repo, graph.AttrReviewBypassStale, graph.StaleSuspected, graph.NotVisible)
			return
		}
	}
}

// agentMergeKey marks a repo whose AI agent step holds the key its bot
// merge uses: the same secret name in an agent step's env (or with:) and in
// a merging job's token source.
func (k *collector) agentMergeKey(repo *graph.Node, wfs, agents []*graph.Node) {
	keys := map[string]bool{}
	for _, n := range wfs {
		if bf := k.botFacts[n.ID]; bf != nil && len(bf.MergeJobs) > 0 {
			for _, s := range bf.MergeKeys {
				keys[s] = true
			}
		}
	}
	if len(keys) == 0 {
		return
	}
	var files []string
	for _, n := range agents {
		for _, s := range k.botFacts[n.ID].AgentKeys {
			if keys[s] {
				files = append(files, n.Attrs["path"])
				break
			}
		}
	}
	if len(files) == 0 {
		return
	}
	sort.Strings(files)
	setAttr(repo, graph.AttrAgentHoldsMergeKey, "true", graph.Live)
	setAttr(repo, graph.AttrAgentMergeKeyWorkflows, strings.Join(files, ","), graph.Live)
}

// splitList splits a comma list attr, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
