package collect

import (
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// Some triggers run a workflow in the base repo's context (its secrets, a
// possibly write GITHUB_TOKEN) on an event that people without push access can
// cause: opening a pull request from a fork, commenting on an issue. Such a
// workflow is attacker-controlled when it checks out and runs the pull
// request's code, or interpolates attacker text into a script. gop then emits
// principal -CAN_TRIGGER-> workflow for the principals who can cause the event.
//
// The heuristics below are deliberately narrow: a false positive is a loud
// finding, so they match exact context names rather than broad patterns.

// Untrusted execution kinds (UntrustedExec.Kind, CAN_TRIGGER attr exec).
const (
	ExecCheckout  = "checkout"  // the job checks out the pull request's head and runs code from it (prcheckout.go)
	ExecInjection = "injection" // attacker text is interpolated into a script
	// ExecAgent (agents.go): an AI coding agent reads attacker text and acts
	// with the job's token, secrets and tools.
)

// UntrustedExec is one job that runs attacker-controlled code under a risky trigger.
type UntrustedExec struct {
	Job     string
	Trigger string
	Kind    string // ExecCheckout | ExecInjection
	Detail  string // the matched value, e.g. "ref: ${{ github.event.pull_request.head.sha }}" or a context name
	Line    int    // 1-based line of the matched with.ref/with.repository, run: or script: key (0 if unknown)
	// File is the repo-relative file that holds Line when it is not the
	// workflow itself: a local composite action or a called reusable
	// workflow of the same repo (indirect.go). "" for the workflow.
	File string
	// Unverified is set when gop cannot tell whether the step lets these
	// principals in (an agent action with an unknown actor check): the
	// CAN_TRIGGER edge is not_visible, so it gives possible reach only.
	Unverified bool
	// Assoc are the author_association values the job's if: allows on this
	// trigger (assocGate), sorted; nil when it has no such gate.
	Assoc []string
}

// riskyTriggers run in the base repo's context with its secrets on events that
// people without push access can cause. Plain pull_request is not here: from a
// fork it gets a read-only token and no secrets.
var riskyTriggers = map[string]bool{
	"pull_request_target":         true,
	"workflow_run":                true,
	"issue_comment":               true,
	"pull_request_review":         true,
	"pull_request_review_comment": true,
	"discussion":                  true,
	"discussion_comment":          true,
	"issues":                      true,
}

// forkTriggers need a pull request from a fork (workflow_run: an upstream
// workflow that a fork's pull request starts). The others need only read
// access: anyone who can read a repo can open or comment on its issues and
// review its pull requests.
var forkTriggers = map[string]bool{
	"pull_request_target": true,
	"workflow_run":        true,
}

// RiskyTriggers returns the workflow's triggers that can run attacker input, sorted.
func (f *WorkflowFacts) RiskyTriggers() []string {
	var out []string
	for _, t := range f.Triggers {
		if riskyTriggers[t] {
			out = append(out, t)
		}
	}
	return out
}

// untrustedRefs are the values of actions/checkout with.ref or with.repository
// that select the pull request's code.
var untrustedRefs = []string{
	"github.event.pull_request.head.",
	"github.head_ref",
	"refs/pull/",
	"github.event.workflow_run.head_",
	"github.event.issue.pull_request",
}

// untrustedFetch are run: commands that fetch the pull request's code.
var untrustedFetch = []string{
	"gh pr checkout",
	"git fetch origin pull/",
}

// attackerContexts are expression contexts whose value the attacker writes.
var attackerContexts = regexp.MustCompile(`\bgithub\.(?:` +
	`event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body|head\.ref|head\.label)` +
	`|head_ref` +
	`|event\.workflow_run\.head_branch` +
	`|event\.commits(?:\.\*|\[[^\]]*\])\.message` +
	`)\b`)

// exprRe matches one ${{ ... }} expression.
var exprRe = regexp.MustCompile(`\$\{\{(.*?)\}\}`)

// triggerFacts reads the on: triggers and the untrusted execution patterns of
// every job. It is lenient: a shape it does not understand yields nothing
// rather than an error (GitHub rejects such files anyway), so it never turns a
// readable workflow into a parse error.
//
// readOnly lists the checkouts of the pull request's code that no later step
// runs (untrusted input, not execution), once per job and checkout.
func triggerFacts(doc *yaml.Node, ind *Indirect) (triggers []string, execs, readOnly []UntrustedExec) {
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(doc), "workflow")
	if err != nil {
		return nil, nil, nil
	}
	triggers = parseOn(w, field(root, "on"))
	var risky []string
	for _, t := range triggers {
		if riskyTriggers[t] {
			risky = append(risky, t)
		}
	}
	if len(risky) == 0 {
		return triggers, nil, nil
	}
	_, jobsNode := root.get("jobs")
	jobs, err := w.mapping(jobsNode, "jobs")
	if err != nil {
		return triggers, nil, nil
	}
	ids := append([]string(nil), jobs.keys...)
	sort.Strings(ids)
	for _, id := range ids {
		_, jv := jobs.get(id)
		job, err := w.mapping(jv, "job")
		if err != nil {
			continue
		}
		found, ro := jobPatterns(w, job, ind)
		for _, t := range risky {
			assoc := assocGate(w, job, t)
			for _, x := range found {
				execs = append(execs, UntrustedExec{Job: id, Trigger: t, Kind: x.Kind, Detail: x.Detail, Line: x.Line, File: x.File, Assoc: assoc})
			}
		}
		for _, x := range ro {
			x.Job = id
			readOnly = append(readOnly, x)
		}
	}
	return triggers, execs, readOnly
}

// parseOn reads on: as a string, a list or a map, sorted and deduplicated.
func parseOn(w *yamlWalk, n *yaml.Node) []string {
	n, err := w.resolve(n)
	if err != nil || isNullNode(n) {
		return nil
	}
	set := map[string]bool{}
	switch n.Kind {
	case yaml.ScalarNode:
		set[strings.TrimSpace(n.Value)] = true
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c, err := w.resolve(c); err == nil && c.Kind == yaml.ScalarNode {
				set[strings.TrimSpace(c.Value)] = true
			}
		}
	case yaml.MappingNode:
		m, err := w.mapping(n, "on")
		if err != nil {
			return nil
		}
		for _, k := range m.keys {
			set[strings.TrimSpace(k)] = true
		}
	}
	delete(set, "")
	return sortedSet(set)
}

// jobPatterns returns the untrusted execution patterns in one job's steps, in
// step order, at most one per (kind, detail, file) with the line of its first
// match, and the checkouts of the pull request's code that no later step
// runs. With ind it also reads the steps one level down: a followed local
// composite action a step loads, and the jobs of a followed reusable
// workflow the job calls.
func jobPatterns(w *yamlWalk, job *yamlMap, ind *Indirect) (out, readOnly []UntrustedExec) {
	p := &patterns{seen: map[patKey]bool{}, roSeen: map[patKey]bool{}}
	if cf, ok := ind.called(w, job); ok {
		anchor, _ := job.get("uses")
		ids, jobs := calledJobs(w, cf.Data)
		for _, id := range ids {
			cj, err := w.mapping(field(jobs, id), "job")
			if err != nil {
				continue
			}
			steps, _ := w.sequence(field(cj, "steps"), "steps")
			p.scan(w, cj, steps, cf, anchor, nil)
		}
	}
	steps, err := w.sequence(field(job, "steps"), "steps")
	if err != nil {
		return p.out, p.readOnly
	}
	p.scan(w, job, steps, IndirectFile{}, nil, ind)
	return p.out, p.readOnly
}

type patKey struct{ kind, detail, file string }

// patterns collects the untrusted execution patterns of one job.
type patterns struct {
	out, readOnly []UntrustedExec
	seen, roSeen  map[patKey]bool
}

// record adds one pattern. at is the matched node in file (the workflow
// when file is zero); a file in another repo is reported at anchor, the
// caller's uses: key, with the file named in the detail.
func (p *patterns) record(ro bool, kind, detail string, at *yaml.Node, file IndirectFile, anchor *yaml.Node) {
	detail = truncate(detail, 200)
	if file.Where != "" {
		detail = truncate(detail+" (in "+file.Where+")", 300)
		at = anchor
	}
	k := patKey{kind, detail, file.Path}
	seen := p.seen
	if ro {
		seen = p.roSeen
	}
	if seen[k] {
		return
	}
	seen[k] = true
	x := UntrustedExec{Kind: kind, Detail: detail, File: file.Path}
	if at != nil {
		x.Line = at.Line
	}
	if ro {
		p.readOnly = append(p.readOnly, x)
	} else {
		p.out = append(p.out, x)
	}
}

// scan reads one list of steps. job holds them (for defaults.run), file is
// where they are (zero for the workflow), and ind, when set, follows a local
// composite action a step loads (one level only: its steps get no ind).
func (p *patterns) scan(w *yamlWalk, job *yamlMap, steps []*yaml.Node, file IndirectFile, anchor *yaml.Node, ind *Indirect) {
	checkouts := map[int][]prCheckout{}
	for _, c := range prCheckouts(w, steps) {
		checkouts[c.step] = append(checkouts[c.step], c)
	}
	for i, sn := range steps {
		step, err := w.mapping(sn, "step")
		if err != nil {
			continue
		}
		uses := strings.ToLower(scalarOf(w, field(step, "uses")))
		with, _ := w.mapping(field(step, "with"), "with")
		for _, c := range checkouts[i] {
			p.record(!checkoutRuns(w, job, steps, c), ExecCheckout, c.detail, c.at, file, anchor)
		}
		run := scalarOf(w, field(step, "run"))
		runKey, _ := step.get("run")
		for _, cmd := range untrustedFetch {
			if strings.Contains(run, cmd) {
				p.record(!fetchRuns(w, job, step, steps, i, run, cmd), ExecCheckout, cmd, runKey, file, anchor)
			}
		}
		type script struct {
			src string
			at  *yaml.Node
		}
		scripts := []script{{run, runKey}}
		if strings.HasPrefix(uses, "actions/github-script@") {
			sk, _ := with.get("script")
			scripts = append(scripts, script{scalarOf(w, field(with, "script")), sk})
		}
		for _, s := range scripts {
			for _, ctx := range injectedContexts(s.src) {
				p.record(false, ExecInjection, ctx, s.at, file, anchor)
			}
		}
		if af, ok := ind.action(w, step); ok {
			p.scan(w, &yamlMap{}, compositeSteps(w, af.Data), af, nil, nil)
		}
	}
}

// injectedContexts returns the attacker-controlled contexts used inside ${{ }} in s.
func injectedContexts(s string) []string {
	if !strings.Contains(s, "${{") {
		return nil
	}
	var out []string
	for _, m := range exprRe.FindAllStringSubmatch(s, -1) {
		out = append(out, attackerContexts.FindAllString(m[1], -1)...)
	}
	return out
}

// scalarOf returns n's scalar value (alias-resolved), or "".
func scalarOf(w *yamlWalk, n *yaml.Node) string {
	n, err := w.resolve(n)
	if err != nil || n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// ---- who can trigger ----

// Workflow attribute keys and the coverage fact for triggers.
const (
	attrRiskyTriggers = "risky_triggers"     // comma list of the workflow's risky triggers
	attrTrigger       = "trigger"            // CAN_TRIGGER: the trigger
	attrExec          = "exec"               // CAN_TRIGGER: checkout | injection | agent
	attrJob           = "job"                // CAN_TRIGGER: the job id
	attrDetail        = "detail"             // CAN_TRIGGER: the matched value
	attrAssoc         = "author_association" // CAN_TRIGGER: the author_association values the job's if: allows
	factTriggering    = "triggering_principals"
)

// externalAnyone is the principal for anyone on the internet.
const externalAnyone = "external:anyone"

// trigger is one principal that can cause an untrusted execution.
type trigger struct {
	principal string
	ev        graph.Evidence
	exec      UntrustedExec
}

// addTriggerFacts records risky_triggers on the workflow and one CAN_TRIGGER
// edge per principal that can cause one of its untrusted executions.
func (k *collector) addTriggerFacts(o *orgState, repo *graph.Node, wid string, wn *graph.Node, f *WorkflowFacts) {
	if r := f.RiskyTriggers(); len(r) > 0 {
		setAttr(wn, attrRiskyTriggers, strings.Join(r, ","), graph.Live)
	}
	for _, x := range f.UntrustedExec {
		if x.Kind == ExecCheckout {
			setAttr(wn, graph.AttrUntrustedCheckout, CheckoutExec, graph.Live)
			break
		}
	}
	if len(f.ReadOnlyCheckouts) > 0 && wn.Attrs[graph.AttrUntrustedCheckout] == "" {
		setAttr(wn, graph.AttrUntrustedCheckout, CheckoutReadOnly, graph.Live)
	}
	if len(f.UntrustedExec) == 0 {
		return
	}
	best := map[string]trigger{}
	var order []string
	for _, x := range f.UntrustedExec {
		for _, t := range k.triggerers(o, repo, x) {
			if x.Unverified {
				t.ev = graph.NotVisible
			}
			old, ok := best[t.principal]
			if !ok {
				order = append(order, t.principal)
			}
			// The strongest evidence wins; ties keep the first exec (sorted by job).
			if !ok || (old.ev == graph.NotVisible && t.ev != graph.NotVisible) {
				best[t.principal] = t
			}
		}
	}
	for _, p := range order {
		t := best[p]
		if p == externalAnyone {
			k.node(externalAnyone, graph.KindExternal, "anyone on the internet")
		}
		attrs := map[string]string{
			attrTrigger: t.exec.Trigger,
			attrExec:    t.exec.Kind,
			attrJob:     t.exec.Job,
			attrDetail:  t.exec.Detail,
		}
		if len(t.exec.Assoc) > 0 {
			attrs[attrAssoc] = strings.Join(t.exec.Assoc, ",")
		}
		file := f.File
		if t.exec.File != "" {
			file = t.exec.File // a local composite action or reusable workflow on the same branch
		}
		locate(attrs, file, f.FileRef, t.exec.Line, 0)
		k.edge(p, wid, graph.CanTrigger, t.ev, srcWorkflow, attrs)
	}
}

// triggerers returns who can cause x's trigger on repo, by visibility:
//
//	public:   anyone on the internet.
//	internal: the members of every collected org (every enterprise member can
//	          read an internal repo).
//	private:  the members of the repo's org when its default permission is at
//	          least read; otherwise only collaborators and teams with read
//	          access can, which gop does not collect (coverage).
//
// A fork trigger on an internal or private repo also needs the repo's org to
// allow forking private and internal repos. A fact the token can't read makes
// the edge not_visible.
//
// A job whose if: checks the comment author's author_association (x.Assoc)
// narrows this: MEMBER lets in only the members of the repo's org; OWNER
// and COLLABORATOR alone let in only collaborators, whose read grants gop
// does not collect (coverage). CONTRIBUTOR, and the first-timer and NONE
// values, include people outside the org and do not narrow it.
func (k *collector) triggerers(o *orgState, repo *graph.Node, x UntrustedExec) []trigger {
	ev := graph.Live
	if repo.AttrEvidence[graph.AttrVisibility] == graph.NotVisible {
		ev = graph.NotVisible
	}
	vis := repo.Attrs[graph.AttrVisibility]
	if len(x.Assoc) > 0 {
		switch assocClass(x.Assoc) {
		case assocCollaborators:
			k.cover(repo.ID, factTriggering, "job "+x.Job+" runs on "+x.Trigger+" only for authors whose author_association is "+
				strings.Join(x.Assoc, " or ")+": collaborators with read access can trigger it, and gop collects push grants only",
				"none (gop does not collect read grants yet)")
			return nil
		case assocMembers:
			if vis == "public" || vis == "internal" {
				return []trigger{{principal: "members:" + o.login, ev: ev, exec: x}}
			}
		}
	}
	if vis == "public" || (vis != "internal" && vis != "private") {
		if vis != "public" {
			ev = graph.NotVisible // visibility unknown: maybe public
		}
		return []trigger{{principal: externalAnyone, ev: ev, exec: x}}
	}
	if forkTriggers[x.Trigger] {
		switch orgSetting(o, graph.AttrPrivateForks) {
		case "true":
		case "false":
			return nil // nobody without push access can open a pull request
		default:
			ev = graph.NotVisible
		}
	}
	if vis == "internal" {
		var out []trigger
		for _, other := range k.orgs {
			if !other.archived {
				out = append(out, trigger{principal: "members:" + other.login, ev: ev, exec: x})
			}
		}
		if k.entHidden {
			k.cover(repo.ID, factTriggering, "token cannot read enterprise "+k.enterprise+
				": members of enterprise orgs gop can't see can also trigger workflows in this internal repository",
				"enterprise owner on "+k.enterprise)
		}
		return out
	}
	switch orgSetting(o, graph.AttrDefaultPerm) {
	case "read", "write", "admin":
	case "none":
		k.cover(repo.ID, factTriggering, "org default permission is none: collaborators and teams with read access can trigger "+
			x.Trigger+", and gop collects push grants only", "none (gop does not collect read grants yet)")
		return nil
	default:
		ev = graph.NotVisible
	}
	return []trigger{{principal: "members:" + o.login, ev: ev, exec: x}}
}

// orgSetting returns an org attribute, or "unknown" when it is not visible.
func orgSetting(o *orgState, key string) string {
	if o.node.AttrEvidence[key] == graph.NotVisible {
		return "unknown"
	}
	if v := o.node.Attrs[key]; v != "" {
		return v
	}
	return "unknown"
}
