package oidc

import (
	"regexp"
	"sort"
	"strings"
)

// MatchResult is the outcome of matching one Trust against the tokens one
// workflow can mint.
type MatchResult string

// Match results. Uncertain is never rounded to Matched or NoMatch: the
// caller records it as possible reach with the reason.
const (
	Matched   MatchResult = "match"
	NoMatch   MatchResult = "no_match"
	Uncertain MatchResult = "uncertain"
)

// envDynamic mirrors graph.EnvDynamic (the oidc package does not import graph
// for matching).
const envDynamic = "*dynamic*"

// WorkflowClaims are the claim inputs of one workflow's OIDC token, read from
// its EXECUTES_WITH edge to oidc (see graph.AttrJobs and friends).
type WorkflowClaims struct {
	// Workflow is the workflow node ID ("workflow:O/R/.github/workflows/x.yml");
	// its own jobs' job_workflow_ref is "O/R/.github/workflows/x.yml@<ref>".
	Workflow        string
	Repository      string // owner/repo
	RepositoryOwner string
	// Jobs are the id-token jobs. Empty with Known false means the edge
	// predates claim inputs: environments are then unknown.
	Jobs []string
	// Environments is the set of those jobs' environments (with "*dynamic*"
	// for an expression). It is a set across jobs: which job has which
	// environment, and whether some job has none, is not recorded.
	Environments []string
	// JobWorkflowRefs are called reusable workflows whose jobs mint the token
	// (owner/repo/path@ref).
	JobWorkflowRefs []string
	// Known is true when the edge carries claim inputs (a jobs attribute).
	Known bool
}

// Outcome is Match with the details gop records on a CAN_ASSUME edge.
type Outcome struct {
	Result     MatchResult
	Reason     string   // why the result is Uncertain; "" otherwise
	MatchedSub []string // the trust's sub patterns that matched (or may match)
	Claims     []string // the claims the trust checks, sorted
}

// Match decides whether a token minted by the workflow can satisfy t.
// The reason is set for Uncertain.
func Match(t Trust, w WorkflowClaims) (MatchResult, string) {
	o := Evaluate(t, w)
	return o.Result, o.Reason
}

// tri is a three-valued truth: no < maybe < yes.
type tri int

const (
	no tri = iota
	maybe
	yes
)

func minTri(a, b tri) tri {
	if a < b {
		return a
	}
	return b
}

func maxTri(a, b tri) tri {
	if a > b {
		return a
	}
	return b
}

// val is one possible value of a claim: the exact string, any string that
// starts with s (prefix), or no claim at all (absent).
type val struct {
	s      string
	prefix bool
	absent bool
}

func exact(s string) val  { return val{s: s} }
func prefix(s string) val { return val{s: s, prefix: true} }

var anyVal = prefix("")

// profile is one class of id-token job of the workflow: the values each claim
// can take for a job of that class. A claim missing from claims can be any
// value. exists is true when gop knows a job of this class runs.
type profile struct {
	exists bool
	claims map[string][]val
	why    map[string]string // reason a claim's value is not known exactly
	note   string            // reason the class may not exist
}

// Evaluate matches t against every class of job the workflow may run:
//
//   - one per known environment E: sub repo:R:environment:E, environment E;
//   - one for an environment set by an expression: sub repo:R:environment:<any>;
//   - one for jobs without an environment: sub repo:R:ref:<unknown> or
//     repo:R:pull_request (gop does not know the triggers), no environment
//     claim. When the workflow has environments, gop cannot tell whether some
//     job has none (environments is a set across jobs), so this class only
//     exists for sure when there are no environments; it is left out only for
//     a single id-token job with a literal environment.
//
// Every class shares repository and repository_owner; job_workflow_ref is the
// workflow's own file at an unknown ref or one of the called reusable
// workflows that mint the token (which one is not known). Claims gop never knows
// before a run (ref, actor, event_name, ids, CEL it could not parse) can be
// any value. The result is Matched when a class that surely runs (or every
// class) satisfies every condition, NoMatch when no class can, and Uncertain
// otherwise. The token's aud is not checked: the workflow chooses it.
func Evaluate(t Trust, w WorkflowClaims) Outcome {
	o := Outcome{Claims: trustClaims(t)}
	narrowed := narrowedKeys(t)
	ps := profiles(w)
	bestRes, bestIdx := no, -1
	var bestReasons []string
	allYes := len(ps) > 0
	for i, p := range ps {
		res, reasons := evalProfile(t, p, narrowed)
		if res != yes {
			allYes = false
		}
		if res > no && !p.exists {
			res = maybe
			reasons = append(reasons, p.note)
		}
		if res > bestRes {
			bestRes, bestIdx, bestReasons = res, i, reasons
		}
	}
	switch {
	case bestRes == yes || allYes:
		o.Result = Matched
		if bestIdx < 0 {
			bestIdx = 0
		}
	case bestRes == maybe:
		o.Result = Uncertain
		o.Reason = strings.Join(dedupe(bestReasons), "; ")
	default:
		if r := customSubHint(t, w); r != "" {
			o.Result, o.Reason = Uncertain, r
			o.MatchedSub = subRaws(t.Subjects)
			return o
		}
		o.Result = NoMatch
		return o
	}
	p := ps[bestIdx]
	for _, pat := range t.Subjects {
		if evalCond([]Pattern{pat}, p.claimVals("sub")) > no {
			o.MatchedSub = append(o.MatchedSub, pat.Raw)
		}
	}
	return o
}

func subRaws(ps []Pattern) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Raw)
	}
	return out
}

// trustClaims lists the claims t checks, sorted ("sub" when it has subjects).
func trustClaims(t Trust) []string {
	var out []string
	if len(t.Subjects) > 0 {
		out = append(out, "sub")
	}
	for k, v := range t.Claims {
		if len(v) > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (p profile) claimVals(key string) []val {
	if v, ok := p.claims[key]; ok {
		return v
	}
	return []val{anyVal}
}

func profiles(w WorkflowClaims) []profile {
	repo := w.Repository
	owner := w.RepositoryOwner
	if owner == "" {
		owner, _, _ = strings.Cut(repo, "/")
	}
	base := func() map[string][]val {
		m := map[string][]val{}
		if repo != "" {
			m["repository"] = []val{exact(repo)}
			m["sub"] = []val{prefix("repo:" + repo + ":")}
		}
		if owner != "" {
			m["repository_owner"] = []val{exact(owner)}
		}
		return m
	}
	why := map[string]string{
		"sub":         "the ref in sub is not known: gop does not read workflow triggers, so a branch-, tag- or pull_request-scoped sub may or may not match",
		"environment": "environment set by an expression: any environment is possible",
	}
	// job_workflow_ref of the workflow's own jobs: the file at an unknown ref.
	own := []val{anyVal}
	if path, ok := strings.CutPrefix(w.Workflow, "workflow:"); ok && path != "" {
		own = []val{prefix(path + "@")}
	}
	jwr := append([]val(nil), own...)
	for _, r := range w.JobWorkflowRefs {
		jwr = append(jwr, exact(r))
	}
	jwrWhy := "job_workflow_ref is not known exactly: the ref the workflow runs at, or which called reusable workflow mints the token"

	var envs []string
	dynamic := !w.Known
	for _, e := range w.Environments {
		if e == envDynamic {
			dynamic = true
		} else if e != "" {
			envs = append(envs, e)
		}
	}
	sort.Strings(envs)
	var out []profile
	for _, e := range envs {
		m := base()
		if repo != "" {
			m["sub"] = []val{exact("repo:" + repo + ":environment:" + e)}
		}
		m["environment"] = []val{exact(e)}
		m["job_workflow_ref"] = jwr
		out = append(out, profile{exists: true, claims: m, why: map[string]string{"job_workflow_ref": jwrWhy}})
	}
	if dynamic {
		m := base()
		if repo != "" {
			m["sub"] = []val{prefix("repo:" + repo + ":environment:")}
		}
		m["environment"] = []val{anyVal}
		m["job_workflow_ref"] = jwr
		note := "environment set by an expression: gop cannot tell which environment the token carries"
		pw := map[string]string{"sub": why["environment"], "environment": why["environment"], "job_workflow_ref": jwrWhy}
		if !w.Known {
			note = "the graph has no OIDC claim inputs for this workflow (collected before gop recorded them)"
			pw = map[string]string{"sub": note, "environment": note, "job_workflow_ref": note}
		}
		out = append(out, profile{exists: false, claims: m, why: pw, note: note})
	}
	// Jobs without an environment. Sure to exist only when no job has one and
	// claim inputs are known; ruled out only when the workflow has a single
	// id-token job, it has a literal environment, and it calls no reusable
	// workflow (whose jobs may have none). An expression may evaluate to no
	// environment, so a dynamic one never rules this class out.
	single := w.Known && len(w.Jobs) == 1 && len(w.JobWorkflowRefs) == 0 && len(envs) > 0 && !dynamic
	if !single {
		m := base()
		if repo != "" {
			m["sub"] = []val{prefix("repo:" + repo + ":ref:"), exact("repo:" + repo + ":pull_request")}
		}
		m["environment"] = []val{{absent: true}}
		m["job_workflow_ref"] = jwr
		sure := w.Known && len(envs) == 0 && !dynamic
		note := "gop cannot tell whether an id-token job runs without an environment (environments is a set across jobs, and an expression may be empty)"
		if !w.Known {
			note = "the graph has no OIDC claim inputs for this workflow (collected before gop recorded them)"
		}
		out = append(out, profile{exists: sure, claims: m, why: map[string]string{"sub": why["sub"], "job_workflow_ref": jwrWhy}, note: note})
	}
	return out
}

var (
	reAllHold  = regexp.MustCompile(`conditions on (\S+) must all hold`)
	reBothHold = regexp.MustCompile(`both constrain (\S+) and must both hold`)
	reNegative = regexp.MustCompile(`negative condition \S+ on (\S+) ignored`)
)

// narrowedKeys are claims whose real condition is narrower than the model
// (several ANDed conditions kept as any-of, or a negative condition dropped):
// a match on them is only possible.
func narrowedKeys(t Trust) map[string]string {
	out := map[string]string{}
	for _, w := range t.Warnings {
		for _, re := range []*regexp.Regexp{reAllHold, reBothHold, reNegative} {
			if m := re.FindStringSubmatch(w); m != nil {
				key := strings.TrimPrefix(m[1], "token.actions.githubusercontent.com:")
				if i := strings.LastIndex(key, ":"); i >= 0 {
					key = key[i+1:]
				}
				out[key] = "the trust's conditions on " + key + " are narrower than gop models (" + w + ")"
			}
		}
	}
	return out
}

func evalProfile(t Trust, p profile, narrowed map[string]string) (tri, []string) {
	res := yes
	var reasons []string
	check := func(key string, pats []Pattern) {
		if len(pats) == 0 {
			return
		}
		r := evalCond(pats, p.claimVals(key))
		if r == yes && narrowed[key] != "" {
			r = maybe
			reasons = append(reasons, narrowed[key])
		} else if r == maybe {
			reasons = append(reasons, condReason(key, pats, p))
		}
		res = minTri(res, r)
	}
	check("sub", t.Subjects)
	keys := make([]string, 0, len(t.Claims))
	for k := range t.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		check(k, t.Claims[k])
	}
	return res, reasons
}

func condReason(key string, pats []Pattern, p profile) string {
	for _, pt := range pats {
		if pt.Op == OpCEL {
			return "condition not understood: " + pt.Raw
		}
	}
	if r := p.why[key]; r != "" {
		if _, known := p.claims[key]; known {
			return r
		}
	}
	if _, known := p.claims[key]; !known {
		return "claim " + key + " is not known before the workflow runs"
	}
	return "claim " + key + " may or may not match"
}

// evalCond: the claim (one of alts) satisfies any of pats.
func evalCond(pats []Pattern, alts []val) tri {
	all, any := yes, no
	for _, v := range alts {
		b := no
		for _, p := range pats {
			b = maxTri(b, evalPat(p, v))
		}
		all = minTri(all, b)
		any = maxTri(any, b)
	}
	switch {
	case all == yes:
		return yes
	case any > no:
		return maybe
	}
	return no
}

func evalPat(p Pattern, v val) tri {
	if p.Op == OpCEL {
		return maybe
	}
	if v.absent {
		return no
	}
	if !v.prefix {
		ok := false
		switch p.Op {
		case OpEquals:
			ok = p.Raw == v.s
		case OpLike:
			ok = strings.HasPrefix(v.s, p.Raw)
		case OpGlob:
			ok = globMatch(p.Raw, v.s)
		default:
			return maybe
		}
		if ok {
			return yes
		}
		return no
	}
	switch p.Op {
	case OpEquals:
		if strings.HasPrefix(p.Raw, v.s) {
			return maybe
		}
	case OpLike:
		if strings.HasPrefix(v.s, p.Raw) {
			return yes
		}
		if strings.HasPrefix(p.Raw, v.s) {
			return maybe
		}
	case OpGlob:
		return globPrefix(p.Raw, v.s)
	default:
		return maybe
	}
	return no
}

// globClose adds the positions reachable by letting a '*' match nothing.
// In globRun '*' matches any run (including '/' and ':'), '?' one character.
func globClose(pat string, st map[int]bool) map[int]bool {
	stack := make([]int, 0, len(st))
	for i := range st {
		stack = append(stack, i)
	}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if i < len(pat) && pat[i] == '*' && !st[i+1] {
			st[i+1] = true
			stack = append(stack, i+1)
		}
	}
	return st
}

func globRun(pat, s string) map[int]bool {
	st := globClose(pat, map[int]bool{0: true})
	for k := 0; k < len(s) && len(st) > 0; k++ {
		next := map[int]bool{}
		for i := range st {
			if i >= len(pat) {
				continue
			}
			switch pat[i] {
			case '*':
				next[i] = true
			case '?':
				next[i+1] = true
			default:
				if pat[i] == s[k] {
					next[i+1] = true
				}
			}
		}
		st = globClose(pat, next)
	}
	return st
}

// globPrefix: yes when every string starting with s matches pat, maybe when
// some does, no when none does.
func globPrefix(pat, s string) tri {
	st := globRun(pat, s)
	if len(st) == 0 {
		return no
	}
	for i := range st {
		if strings.Trim(pat[min(i, len(pat)):], "*") == "" {
			return yes
		}
	}
	return maybe
}

// customSubHint keeps a trust whose sub names this repository but none of the
// default sub formats (repo:R:environment:, repo:R:ref:, repo:R:pull_request):
// the repository may use a custom sub template, which gop does not read.
func customSubHint(t Trust, w WorkflowClaims) string {
	if w.Repository == "" {
		return ""
	}
	pre := "repo:" + w.Repository + ":"
	for _, p := range t.Subjects {
		rest, ok := strings.CutPrefix(p.Raw, pre)
		if !ok || p.Op == OpCEL {
			continue
		}
		if strings.HasPrefix(rest, "environment:") || strings.HasPrefix(rest, "ref:") || rest == "pull_request" || strings.HasPrefix(rest, "*") || rest == "" {
			continue
		}
		// Other conditions must not rule the workflow out on their own.
		t2 := t.clone()
		t2.Subjects = nil
		if r := Evaluate(t2, w).Result; r == NoMatch {
			return ""
		}
		return "sub " + p.Raw + " names this repository but none of the default sub formats; the repository may use a custom sub template, which gop does not read"
	}
	return ""
}
