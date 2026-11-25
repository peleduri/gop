package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// Deployment environment protection rules as conditions on EXECUTES_WITH
// edges (docs/schema.md "Environment protection"). A job that names an
// environment gets its secrets and its OIDC token only after the
// environment's protection rules pass, so the rules are read for every
// environment an OIDC or secrets edge depends on and written onto that edge.
// Read with GET /repos/{o}/{r}/environments,
// .../environments/{name}/deployment_protection_rules and, for custom branch
// policies, .../environments/{name}/deployment-branch-policies.

// secretJobs returns the jobs that can read stored secrets, sorted: the jobs
// that reference secrets.NAME (aliases followed) or pass secrets: inherit.
// A reference outside every job (workflow-level env:) reaches every job.
func secretJobs(names []string, inherits bool, jobIDs []string, jobNodes map[string]*yaml.Node) []string {
	if len(names) == 0 && !inherits {
		return nil
	}
	covered := map[string]bool{}
	var out []string
	for _, id := range jobIDs {
		n := jobNodes[id]
		refs := secretNamesDeep(n)
		if len(refs) > 0 || jobInherits(n) {
			out = append(out, id)
		}
		for _, r := range refs {
			covered[r] = true
		}
	}
	for _, name := range names {
		if !covered[name] {
			return append([]string(nil), jobIDs...)
		}
	}
	return out
}

// secretNamesDeep is secretNames over one node, following YAML aliases.
func secretNamesDeep(n *yaml.Node) []string {
	set := map[string]bool{}
	seen := map[*yaml.Node]bool{}
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		switch n.Kind {
		case yaml.AliasNode:
			walk(n.Alias)
		case yaml.ScalarNode:
			for _, m := range secretRefRe.FindAllStringSubmatch(n.Value, -1) {
				if !strings.EqualFold(m[1], "GITHUB_TOKEN") {
					set[m[1]] = true
				}
			}
			if secretIdxRe.MatchString(n.Value) {
				set["*"] = true
			}
		default:
			for _, c := range n.Content {
				walk(c)
			}
		}
	}
	walk(n)
	return sortedSet(set)
}

// jobInherits reports whether a job passes secrets: inherit.
func jobInherits(n *yaml.Node) bool {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "secrets" {
			v := n.Content[i+1]
			for v.Kind == yaml.AliasNode && v.Alias != nil {
				v = v.Alias
			}
			return v.Kind == yaml.ScalarNode && strings.TrimSpace(v.Value) == "inherit"
		}
	}
	return false
}

// envJob is one job behind an edge and the environment it names ("" none).
type envJob struct {
	job, env string
}

// envEdge is an EXECUTES_WITH edge whose attrs gain the environment
// conditions once the repo's environments are read.
type envEdge struct {
	repo  string // owner/repo
	attrs map[string]string
	jobs  []envJob
}

// trackEnvEdge remembers an OIDC or secrets edge of a workflow when one of
// the jobs behind it names an environment.
func (k *collector) trackEnvEdge(full string, attrs map[string]string, jobs []string, f *WorkflowFacts) {
	named := false
	ej := make([]envJob, 0, len(jobs))
	for _, j := range jobs {
		env := f.JobEnvironments[j]
		named = named || env != ""
		ej = append(ej, envJob{job: j, env: env})
	}
	if !named {
		return
	}
	k.envEdges = append(k.envEdges, &envEdge{repo: full, attrs: attrs, jobs: ej})
}

// envRules is what gop read about one environment of a repo.
type envRules struct {
	exists      bool
	reviewers   int  // required reviewer entries; 0 when the rule is absent
	preventSelf bool // prevent_self_review on the reviewers rule
	waitTimer   int  // minutes
	branch      string
	patterns    []string // custom branch policy names; tags as tag:<name>
	branchErr   string   // why custom patterns are unknown
	custom      int      // enabled custom deployment protection rules; -1 unknown
}

// repoEnvs is the environments of one repo, or why they are unknown.
type repoEnvs struct {
	envs map[string]*envRules
	err  string
	fix  string
}

type apiEnvironment struct {
	Name            string `json:"name"`
	ProtectionRules []struct {
		Type              string            `json:"type"`
		WaitTimer         int               `json:"wait_timer"`
		PreventSelfReview bool              `json:"prevent_self_review"`
		Reviewers         []json.RawMessage `json:"reviewers"`
	} `json:"protection_rules"`
	DeploymentBranchPolicy *struct {
		ProtectedBranches    bool `json:"protected_branches"`
		CustomBranchPolicies bool `json:"custom_branch_policies"`
	} `json:"deployment_branch_policy"`
}

// collectEnvironments reads the environments the tracked edges depend on and
// writes their conditions onto the edges.
func (k *collector) collectEnvironments(ctx context.Context) error {
	if len(k.envEdges) == 0 {
		return nil
	}
	need := map[string]map[string]bool{}
	for _, e := range k.envEdges {
		if need[e.repo] == nil {
			need[e.repo] = map[string]bool{}
		}
		for _, j := range e.jobs {
			if j.env != "" && !strings.Contains(j.env, "${{") {
				need[e.repo][j.env] = true
			}
		}
	}
	repos := make([]string, 0, len(need))
	for r := range need {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	read := map[string]*repoEnvs{}
	for _, full := range repos {
		re, err := k.readEnvironments(ctx, full, need[full])
		if err != nil {
			return err
		}
		read[full] = re
		if re.err != "" {
			k.cover("repo:"+full, graph.FactEnvironments, "could not read deployment environments: "+re.err, re.fix)
		}
	}
	for _, e := range k.envEdges {
		k.applyEnvEdge(e, read[e.repo])
	}
	return nil
}

// readEnvironments lists a repo's environments and reads the custom rules and
// branch patterns of the ones in want. An error is returned only when the
// context ends; any other failure is recorded in repoEnvs.err.
func (k *collector) readEnvironments(ctx context.Context, full string, want map[string]bool) (*repoEnvs, error) {
	owner, name, _ := strings.Cut(full, "/")
	cl := k.cl(owner)
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/environments"
	re := &repoEnvs{envs: map[string]*envRules{}}
	err := cl.GetPages(ctx, base+"?per_page=100", func(page []byte) error {
		var body struct {
			Environments []apiEnvironment `json:"environments"`
		}
		if err := json.Unmarshal(page, &body); err != nil {
			return fmt.Errorf("decoding environments: %w", err)
		}
		for _, ae := range body.Environments {
			re.envs[strings.ToLower(ae.Name)] = envRulesOf(ae)
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		re.envs = nil
		re.err = err.Error()
		re.fix = k.fixFor(err, "read access to "+full+" (environments are readable with repository read access)")
		return re, nil
	}
	names := make([]string, 0, len(want))
	for w := range want {
		names = append(names, w)
	}
	sort.Strings(names)
	for _, env := range names {
		r := re.envs[strings.ToLower(env)]
		if r == nil {
			continue
		}
		ep := base + "/" + url.PathEscape(env)
		var cr struct {
			Rules []struct {
				Enabled bool `json:"enabled"`
			} `json:"custom_deployment_protection_rules"`
		}
		if err := cl.GetJSON(ctx, ep+"/deployment_protection_rules", &cr); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			r.custom = -1
			k.cover("repo:"+full, graph.FactEnvironments+":"+env, "could not read custom deployment protection rules: "+err.Error(),
				k.fixFor(err, "read access to "+full))
		} else {
			for _, c := range cr.Rules {
				if c.Enabled {
					r.custom++
				}
			}
		}
		if r.branch != "custom" {
			continue
		}
		perr := cl.GetPages(ctx, ep+"/deployment-branch-policies?per_page=100", func(page []byte) error {
			var bp struct {
				Policies []struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"branch_policies"`
			}
			if err := json.Unmarshal(page, &bp); err != nil {
				return fmt.Errorf("decoding deployment branch policies: %w", err)
			}
			for _, p := range bp.Policies {
				if p.Type == "tag" {
					r.patterns = append(r.patterns, "tag:"+p.Name)
				} else {
					r.patterns = append(r.patterns, p.Name)
				}
			}
			return nil
		})
		if perr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			r.patterns, r.branchErr = nil, perr.Error()
			k.cover("repo:"+full, graph.FactEnvironments+":"+env, "could not read deployment branch policies: "+perr.Error(),
				k.fixFor(perr, "read access to "+full))
		}
		sort.Strings(r.patterns)
	}
	return re, nil
}

func envRulesOf(ae apiEnvironment) *envRules {
	r := &envRules{exists: true, branch: "all"}
	for _, p := range ae.ProtectionRules {
		switch p.Type {
		case "required_reviewers":
			r.reviewers = len(p.Reviewers)
			r.preventSelf = p.PreventSelfReview
		case "wait_timer":
			r.waitTimer = p.WaitTimer
		}
	}
	if bp := ae.DeploymentBranchPolicy; bp != nil {
		switch {
		case bp.ProtectedBranches:
			r.branch = "protected"
		case bp.CustomBranchPolicies:
			r.branch = "custom"
		}
	}
	return r
}

// protection is the env_protection entry of one environment.
func (r *envRules) protection() string {
	var rules []string
	if r.reviewers > 0 {
		rules = append(rules, graph.EnvGateReviewers+"="+strconv.Itoa(r.reviewers))
		if r.preventSelf {
			rules = append(rules, "prevent_self_review")
		}
	}
	if r.waitTimer > 0 {
		rules = append(rules, "wait_timer="+strconv.Itoa(r.waitTimer))
	}
	if r.branch != "all" {
		rules = append(rules, "branch_policy="+r.branch)
	}
	switch {
	case r.custom < 0:
		rules = append(rules, "custom_rules=unknown")
	case r.custom > 0:
		rules = append(rules, "custom_rules="+strconv.Itoa(r.custom))
	}
	if len(rules) == 0 {
		return "none"
	}
	return strings.Join(rules, "+")
}

// branches is the env_branches value of one environment.
func (r *envRules) branches() string {
	if r.branch != "custom" {
		return r.branch
	}
	if r.branchErr != "" {
		return "unknown"
	}
	return "custom:" + strings.Join(r.patterns, "|")
}

// allowsBranch says whether a run on branch may use the environment:
// allowed, blocked or unknown. protected reads the repo's default-branch
// protection, so it is only decided for the default branch.
func (r *envRules) allowsBranch(branch, protected string) string {
	switch r.branch {
	case "all":
		return graph.EnvBranchAllowed
	case "protected":
		switch protected {
		case "true":
			return graph.EnvBranchAllowed
		case "false":
			return graph.EnvBranchBlocked
		}
		return graph.EnvBranchUnknown
	}
	if r.branchErr != "" || branch == "" {
		return graph.EnvBranchUnknown
	}
	for _, p := range r.patterns {
		if strings.HasPrefix(p, "tag:") {
			continue
		}
		if fnmatch(p, branch) {
			return graph.EnvBranchAllowed
		}
	}
	return graph.EnvBranchBlocked
}

// fnmatch matches a deployment branch policy name pattern the way GitHub
// does (Ruby File.fnmatch with FNM_PATHNAME): * and ? do not match /, [...]
// is a character class, and **/ matches zero or more directories. A pattern
// gop cannot translate matches nothing.
func fnmatch(pattern, name string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:[^/]*/)*")
			i += 2
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			j := strings.IndexByte(pattern[i:], ']')
			if j < 0 {
				return false
			}
			class := pattern[i+1 : i+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += j
		case c == '\\' && i+1 < len(pattern):
			i++
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(name)
}

// applyEnvEdge writes the conditions of one edge.
func (k *collector) applyEnvEdge(e *envEdge, re *repoEnvs) {
	repoNode := k.nodes["repo:"+e.repo]
	defBranch, protected := "", ""
	if repoNode != nil {
		defBranch, protected = repoNode.Attrs["default_branch"], repoNode.Attrs[graph.AttrBranchProtected]
	}
	prot, branches := map[string]string{}, map[string]string{}
	var ungated []string
	unknown, reason := false, ""
	allowed, blocked := false, 0
	for _, j := range e.jobs {
		if j.env == "" {
			ungated = append(ungated, j.job)
			allowed = true
			continue
		}
		if strings.Contains(j.env, "${{") {
			unknown = true
			reason = firstNonEmpty(reason, "environment of job "+j.job+" is an expression: "+j.env)
			continue
		}
		if re == nil || re.envs == nil {
			unknown = true
			prot[j.env], branches[j.env] = "unknown", "unknown"
			if re != nil {
				reason = firstNonEmpty(reason, "could not read the environments of "+e.repo+": "+re.err)
			}
			continue
		}
		r := re.envs[strings.ToLower(j.env)]
		if r == nil {
			// GitHub creates a missing environment, with no rules, on the
			// first run that names it.
			prot[j.env], branches[j.env] = "absent", "all"
			ungated = append(ungated, j.job)
			allowed = true
			continue
		}
		prot[j.env], branches[j.env] = r.protection(), r.branches()
		if r.reviewers == 0 {
			ungated = append(ungated, j.job)
		}
		switch r.allowsBranch(defBranch, protected) {
		case graph.EnvBranchAllowed:
			allowed = true
		case graph.EnvBranchBlocked:
			blocked++
		}
	}
	gate := graph.EnvGateReviewers
	switch {
	case len(ungated) > 0:
		gate = graph.EnvGateNone
		e.attrs[graph.AttrEnvUngatedJobs] = strings.Join(sortedUnique(ungated), ",")
	case unknown:
		gate = graph.EnvGateUnknown
		e.attrs[graph.AttrEnvGateReason] = reason
	}
	e.attrs[graph.AttrEnvGate] = gate
	if len(prot) > 0 {
		e.attrs[graph.AttrEnvProtection] = joinEnvMap(prot, ":")
		e.attrs[graph.AttrEnvBranches] = joinEnvMap(branches, "=")
	}
	switch {
	case allowed:
		e.attrs[graph.AttrEnvDefaultBranch] = graph.EnvBranchAllowed
	case blocked == len(e.jobs):
		e.attrs[graph.AttrEnvDefaultBranch] = graph.EnvBranchBlocked
	default:
		e.attrs[graph.AttrEnvDefaultBranch] = graph.EnvBranchUnknown
	}
}

func joinEnvMap(m map[string]string, sep string) string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+sep+v)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func sortedUnique(xs []string) []string {
	set := map[string]bool{}
	for _, x := range xs {
		set[x] = true
	}
	return sortedSet(set)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
