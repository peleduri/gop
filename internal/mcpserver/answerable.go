package mcpserver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Coverage facts that check_answerable checks. Each fact groups the coverage
// entries, not_visible edges, not_visible attributes and not_visible nodes
// about one kind of data (factOfName, factOfEdge, factOfNode).
const (
	factRepositories     = "repositories"
	factMembers          = "members"
	factTeams            = "teams"
	factCollaborators    = "collaborators"
	factDefaultPerm      = "default_permission"
	factBranchProtection = "branch_protection"
	factRulesets         = "rulesets"
	factWorkflows        = "workflows"
	factActions          = "actions"
	factTokenPerms       = "token_permissions"
	factTriggers         = "triggers"
	factOIDC             = "oidc"
	factRunners          = "runners_and_secrets"
	factOrgSettings      = "org_settings"
	// factOther is a gap gop cannot classify. Every question requires it, so
	// an unclassified gap is never ignored.
	factOther = "other"
)

// factDocs lists every fact in report order, with what it covers.
var factDocs = []struct{ Fact, Covers string }{
	{factRepositories, "the org itself and its repository list (org, installation, archived, enterprise membership, host repos gop did not list)"},
	{factMembers, "org members and owners, and owners' admin access"},
	{factTeams, "teams, team members and team repository grants"},
	{factCollaborators, "direct and outside collaborators and custom repository roles"},
	{factDefaultPerm, "the org's default repository permission and the push access it grants members"},
	{factBranchProtection, "branch protection and branch rulesets of mutable action refs, and their bypass actors"},
	{factRulesets, "tag rulesets and immutable releases that lock an action tag"},
	{factWorkflows, "workflow files: the list, their contents and parse errors, expression `uses:`"},
	{factActions, "action refs: nested `uses:`, ref kind, the actions access of the host repo, whether the owner is in the enterprise"},
	{factTokenPerms, "`GITHUB_TOKEN` write permission of workflows"},
	{factTriggers, "who can cause a risky trigger, and repo visibility"},
	{factOIDC, "OIDC tokens, their claims (environments) and cloud trust matches"},
	{factRunners, "self-hosted runners and secret scopes a workflow runs with"},
	{factOrgSettings, "org security settings that weight scores: SSO, two-factor, IP allow list and member privileges"},
	{factOther, "any gap gop cannot classify"},
}

// reachFacts are the facts reach depends on: every edge kind the control
// graph follows, and the attributes that gate it.
var reachFacts = []string{
	factRepositories, factMembers, factTeams, factCollaborators, factDefaultPerm,
	factBranchProtection, factRulesets, factWorkflows, factActions, factTokenPerms,
	factTriggers, factOIDC, factRunners,
}

// withFacts is base, then more, then factOther, which every question requires.
func withFacts(base []string, more ...string) []string {
	return append(append(append([]string{}, base...), more...), factOther)
}

// regionKind is the part of the graph a question's answer depends on.
type regionKind int

const (
	regionUpstream   regionKind = iota // the subject and every node with a control path into it
	regionDownstream                   // the subject and every node it has a control path to
	regionAll                          // the whole enterprise
)

// requirement says which facts a question kind depends on, and where.
type requirement struct {
	Kind   string
	Region regionKind
	Graph  string // the region in words, for the docs
	Facts  []string
}

// requiredFacts is the one table from question kind to required facts. The
// table in docs/mcp-clients.md is rendered from it (requirementsMarkdown) and
// a test keeps the two equal.
var requiredFacts = []requirement{
	{"who_can_reach", regionUpstream, "the subject (a node, or every repo of an org) and every node with a path into it", withFacts(reachFacts)},
	{"blast_radius", regionDownstream, "the subject principal (an org means its members) and everything it reaches", withFacts(reachFacts, factOrgSettings)},
	{"paths", regionDownstream, "the subject principal (an org means its members) and everything it reaches", withFacts(reachFacts)},
	{"top_risks", regionAll, "the whole enterprise", withFacts(reachFacts, factOrgSettings)},
	{"what_if", regionAll, "the whole enterprise (before and after totals are enterprise-wide)", withFacts(reachFacts)},
	{"fix_plan", regionAll, "the whole enterprise (the plan reports the enterprise-wide reach it removes)", withFacts(reachFacts)},
}

func requirementFor(kind string) (requirement, bool) {
	for _, r := range requiredFacts {
		if r.Kind == kind {
			return r, true
		}
	}
	return requirement{}, false
}

func questionKinds() []string {
	out := make([]string, len(requiredFacts))
	for i, r := range requiredFacts {
		out[i] = r.Kind
	}
	return out
}

// requirementsMarkdown renders requiredFacts and factDocs as Markdown tables.
func requirementsMarkdown() string {
	var b strings.Builder
	b.WriteString("| Question kind | Graph checked | Required facts |\n|---|---|---|\n")
	for _, r := range requiredFacts {
		fs := make([]string, len(r.Facts))
		for i, f := range r.Facts {
			fs[i] = "`" + f + "`"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r.Kind, r.Graph, strings.Join(fs, ", "))
	}
	b.WriteString("\n| Fact | Covers |\n|---|---|\n")
	for _, f := range factDocs {
		fmt.Fprintf(&b, "| `%s` | %s |\n", f.Fact, f.Covers)
	}
	return b.String()
}

// nameFacts maps coverage fact names and node attribute keys to facts.
// Collector names without an exported constant are spelled out.
var nameFacts = map[string]string{
	"repositories": factRepositories, "org": factRepositories, "orgs": factRepositories,
	"installation": factRepositories, "enterprise": factRepositories, "in_enterprise": factActions,
	graph.AttrArchived: factRepositories, "can_push": factRepositories,
	graph.AttrMembers: factMembers, "owners": factMembers,
	"can_push:teams":         factTeams,
	"can_push:collaborators": factCollaborators, "outside_collaborators": factCollaborators,
	"custom_repository_roles": factCollaborators, "collaborators": factCollaborators,
	"can_push:default_perm": factDefaultPerm, graph.AttrDefaultPerm: factDefaultPerm,
	graph.AttrRefProtected: factBranchProtection, graph.AttrRefProtection: factBranchProtection,
	graph.AttrBypass: factBranchProtection, "ref_bypass": factBranchProtection,
	graph.AttrRefImmutable: factRulesets,
	"workflows":            factWorkflows, "workflow_parse": factWorkflows, "dynamic_uses": factWorkflows,
	"nested_uses": factActions, "nested": factActions, graph.AttrRefKind: factActions,
	graph.AttrActionsAccess: factActions, graph.AttrActionsLock: factActions,
	"default_workflow_permissions": factTokenPerms, "token_write": factTokenPerms,
	"triggering_principals": factTriggers, graph.AttrVisibility: factTriggers,
	"cloud_trust": factOIDC, graph.AttrEnvironments: factOIDC,
	"runner_labels": factRunners,
	graph.AttrSSO:   factOrgSettings, graph.AttrTwoFactor: factOrgSettings, graph.AttrIPAllowList: factOrgSettings,
	graph.AttrIPAllowEntries: factOrgSettings, graph.AttrMembersCreate: factOrgSettings,
	graph.AttrChangeVisiblity: factOrgSettings, graph.AttrDeleteRepos: factOrgSettings,
	graph.AttrPrivateForks: factOrgSettings, graph.AttrIPAllowListEntries: factOrgSettings,
	graph.AttrIPAllowListApps: factOrgSettings,
}

// factOfName classifies a coverage entry's fact, or a node attribute, on
// node (or scope) id.
func factOfName(name, id string) string {
	if strings.HasPrefix(id, "team:") && (name == "repositories" || name == graph.AttrMembers) {
		return factTeams
	}
	switch {
	case strings.HasPrefix(name, "team_repos:"), strings.HasPrefix(name, "team_members:"):
		return factTeams
	case strings.HasPrefix(name, "workflow:"):
		return factWorkflows
	case strings.HasPrefix(name, graph.AttrActionsLock+":"):
		return factActions
	}
	if f, ok := nameFacts[name]; ok {
		return f
	}
	return factOther
}

// factOfEdge classifies an edge by kind (and CAN_PUSH provenance).
func factOfEdge(e graph.Edge) string {
	switch e.Kind {
	case graph.CanPush:
		switch e.Attrs[graph.AttrVia] {
		case graph.ViaDefaultPerm:
			return factDefaultPerm
		case graph.ViaUnknown:
			return factRepositories
		case graph.ViaOrgOwner:
			return factMembers
		case graph.ViaTeam:
			return factTeams
		case graph.ViaRefBypass:
			return factBranchProtection
		case graph.ViaTokenWrite:
			return factTokenPerms
		}
		return factCollaborators
	case graph.MemberOf:
		if strings.HasPrefix(e.To, "team:") {
			return factTeams
		}
		return factMembers
	case graph.Uses, graph.ResolvesTo:
		return factActions
	case graph.DefinedIn:
		return factWorkflows
	case graph.ExecutesWith:
		if graph.KindFromID(e.To) == graph.KindOIDC {
			return factOIDC
		}
		return factRunners
	case graph.CanTrigger:
		return factTriggers
	case graph.CanAssume:
		return factOIDC
	}
	return factOther
}

// factOfNode classifies a node whose own evidence is not_visible.
func factOfNode(n graph.Node) string {
	if strings.HasPrefix(n.ID, "team:") {
		return factTeams
	}
	switch n.Kind {
	case graph.KindEnterprise, graph.KindOrg, graph.KindRepo:
		return factRepositories
	case graph.KindOrgMembers, graph.KindIdentity:
		return factMembers
	case graph.KindWorkflow:
		return factWorkflows
	case graph.KindActionRef:
		return factActions
	case graph.KindSecret, graph.KindRunner:
		return factRunners
	case graph.KindOIDC, graph.KindCloudTarget:
		return factOIDC
	}
	return factOther
}

// gap is one thing gop could not see: a coverage entry, a not_visible (or
// stale audit) edge, a not_visible node attribute or a not_visible node.
type gap struct {
	fact     string
	scope    string // reported scope: a repo, org, enterprise or other node
	detail   string // a coverage reason, or a countable label
	coverage bool   // detail is a coverage reason
	needsFix string
	edge     *graph.Edge // set for edge gaps
	node     string      // node or scope ID for the other gaps
}

// gaps lists every gap in the indexed graph, in a stable order. An audit edge
// older than the graph's maximum audit age (half its audit_retention_days,
// else graph.DefaultMaxAuditAge) is stale and counts as not visible.
func gaps(ix *graph.Index) []gap {
	g := ix.Graph()
	maxAge := ix.MaxAuditAge(0)
	var out []gap
	for _, c := range g.Coverage {
		out = append(out, gap{fact: factOfName(c.Fact, c.Scope), scope: scopeOf(c.Scope), detail: c.Reason,
			coverage: true, needsFix: c.NeedsFix, node: c.Scope})
	}
	for _, n := range g.Nodes {
		if n.Evidence == graph.NotVisible {
			out = append(out, gap{fact: factOfNode(n), scope: scopeOf(n.ID), detail: "not_visible " + string(n.Kind) + " nodes", node: n.ID})
		}
		keys := make([]string, 0, len(n.AttrEvidence))
		for k, ev := range n.AttrEvidence {
			if ev == graph.NotVisible {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, gap{fact: factOfName(k, n.ID), scope: scopeOf(n.ID), detail: "not visible attribute " + k, node: n.ID})
		}
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		label := "not_visible " + string(e.Kind) + " edges"
		switch {
		case e.Evidence == graph.NotVisible:
		case ix.AuditStale(*e, maxAge):
			label = fmt.Sprintf("stale %s audit edges (older than %d days)", e.Kind, int(maxAge.Hours()/24))
		default:
			continue
		}
		if v := e.Attrs[graph.AttrVia]; v != "" {
			label += " via " + v
		}
		out = append(out, gap{fact: factOfEdge(*e), scope: edgeScope(*e), detail: label, edge: e})
	}
	return out
}

// scopeOf is the scope a gap on node id is reported under: the repo for
// repo-level nodes (an action's host repo), the org for org-level nodes, and
// the node itself otherwise.
func scopeOf(id string) string {
	prefix, rest, _ := strings.Cut(id, ":")
	switch prefix {
	case "action":
		rest, _, _ = strings.Cut(rest, "@")
		fallthrough
	case "repo", "workflow", "secret", "oidc", "runner":
		if parts := strings.SplitN(rest, "/", 3); len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return "repo:" + parts[0] + "/" + parts[1]
		}
	case "org", "members", "team":
		if o := graph.OrgOf(id); o != "" {
			return o
		}
	}
	return id
}

// edgeScope reports a workflow's edges under the workflow's repo, and other
// edges under their target's scope when it has an org.
func edgeScope(e graph.Edge) string {
	if graph.KindFromID(e.From) == graph.KindWorkflow || graph.OrgOf(e.To) == "" {
		return scopeOf(e.From)
	}
	return scopeOf(e.To)
}

// membersID maps an org node to its members principal, as the control graph does.
func membersID(id string) string {
	if rest, ok := strings.CutPrefix(id, "org:"); ok {
		return "members:" + rest
	}
	return id
}

// controlEnds lists the control hops (tail controls head) an edge can give.
func controlEnds(e graph.Edge) [][2]string {
	switch e.Kind {
	case graph.CanPush, graph.CanTrigger, graph.ExecutesWith, graph.CanAssume:
		return [][2]string{{e.From, e.To}}
	case graph.MemberOf:
		return [][2]string{{e.From, membersID(e.To)}}
	case graph.Uses, graph.ResolvesTo:
		return [][2]string{{e.To, e.From}}
	}
	return [][2]string{{e.From, e.To}, {e.To, e.From}}
}

// region is the part of the graph one answer depends on.
type region struct {
	kind   regionKind
	nodes  map[string]bool
	scopes map[string]bool // scopeOf and OrgOf of every node
}

func newRegion(kind regionKind, ids []string) region {
	r := region{kind: kind, nodes: map[string]bool{}, scopes: map[string]bool{}}
	for _, id := range ids {
		r.nodes[id] = true
		r.scopes[scopeOf(id)] = true
		if o := graph.OrgOf(id); o != "" {
			r.scopes[o] = true
		}
	}
	return r
}

// contains reports whether gap x can change an answer over r. An edge counts
// when it gives a control hop out of a downstream region or into an upstream
// one (a ref_bypass push gives its principal a hop into the action, so it
// counts when the principal is upstream). Any other gap counts when its
// scope (repo or org) has a node in r, or it is enterprise-wide.
func (r region) contains(x gap) bool {
	if r.kind == regionAll {
		return true
	}
	if e := x.edge; e != nil {
		if r.kind == regionUpstream && e.Kind == graph.CanPush && e.Attrs[graph.AttrVia] == graph.ViaRefBypass && r.nodes[e.From] {
			return true
		}
		for _, h := range controlEnds(*e) {
			if (r.kind == regionDownstream && r.nodes[h[0]]) || (r.kind == regionUpstream && r.nodes[h[1]]) {
				return true
			}
		}
		return false
	}
	return graph.KindFromID(x.node) == graph.KindEnterprise || r.nodes[x.node] || r.nodes[membersID(x.node)] || r.scopes[scopeOf(x.node)]
}

// CheckAnswerableInput is the check_answerable tool input.
type CheckAnswerableInput struct {
	QuestionKind string `json:"question_kind" jsonschema:"the query tool whose answer you want to give: who_can_reach, blast_radius, paths, top_risks, what_if or fix_plan"`
	Subject      string `json:"subject,omitempty" jsonschema:"node ID or org the question is about, e.g. repo:acme-app/web, members:acme-actions or acme-legacy; optional for top_risks, what_if and fix_plan, which always check the whole enterprise"`
}

// MissingFact is one required fact gop could not see in one scope.
type MissingFact struct {
	Fact     string `json:"fact"`
	Scope    string `json:"scope"`
	Reason   string `json:"reason"`
	NeedsFix string `json:"needs_fix,omitempty"`
}

// Answerability values.
const (
	AnswerYes     = "yes"
	AnswerPartial = "partial"
	AnswerNo      = "no"
)

// CheckAnswerableOutput says whether gop saw the facts an answer depends on.
type CheckAnswerableOutput struct {
	Summary        string        `json:"summary"`
	QuestionKind   string        `json:"question_kind"`
	Subject        string        `json:"subject"`
	Answerable     string        `json:"answerable" jsonschema:"yes (gop saw every required fact), partial (the answer is a lower bound) or no (gop cannot see the subject's data)"`
	Required       []string      `json:"required" jsonschema:"the facts this question kind depends on"`
	Missing        []MissingFact `json:"missing" jsonschema:"required facts gop could not see, per scope, with the access that fixes each when known"`
	ConfidenceNote string        `json:"confidence_note"`
}

// CheckAnswerable says, before an answer is trusted, whether gop could see
// the facts the named query tool depends on for subject. It is deterministic:
// it reads the coverage entries and the not_visible (or stale audit) facts in
// the part of the graph the answer depends on, and never says yes when one of
// the required facts is not visible there.
func (e *Engine) CheckAnswerable(in CheckAnswerableInput) (res CheckAnswerableOutput, _ error) {
	defer e.mark(&res.Summary)
	kind := strings.TrimSpace(in.QuestionKind)
	req, ok := requirementFor(kind)
	if !ok {
		return CheckAnswerableOutput{}, fmt.Errorf("question_kind must be one of %s, got %q", strings.Join(questionKinds(), ", "), kind)
	}
	subject, err := e.answerSubject(req, in.Subject)
	if err != nil {
		return CheckAnswerableOutput{}, err
	}
	reg := e.questionRegion(req, subject)
	required := map[string]bool{}
	for _, f := range req.Facts {
		required[f] = true
	}
	all := gaps(e.ix)
	type acc struct {
		m       MissingFact
		reasons []string
		fixes   []string
		counts  map[string]int
		labels  []string
	}
	byKey := map[string]*acc{}
	for _, x := range all {
		if !required[x.fact] || !reg.contains(x) {
			continue
		}
		k := x.fact + "\x00" + x.scope
		a := byKey[k]
		if a == nil {
			a = &acc{m: MissingFact{Fact: x.fact, Scope: x.scope}, counts: map[string]int{}}
			byKey[k] = a
		}
		switch {
		case x.coverage:
			a.reasons = appendNew(a.reasons, x.detail)
			if x.needsFix != "" {
				a.fixes = appendNew(a.fixes, x.needsFix)
			}
		default:
			if a.counts[x.detail] == 0 {
				a.labels = append(a.labels, x.detail)
			}
			a.counts[x.detail]++
		}
	}
	order := map[string]int{}
	for i, f := range factDocs {
		order[f.Fact] = i
	}
	missing := make([]MissingFact, 0, len(byKey))
	for _, a := range byKey {
		reasons := a.reasons
		for _, l := range a.labels {
			reasons = append(reasons, fmt.Sprintf("%s: %d", l, a.counts[l]))
		}
		a.m.Reason = strings.Join(reasons, "; ")
		a.m.NeedsFix = strings.Join(a.fixes, "; ")
		missing = append(missing, a.m)
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].Fact != missing[j].Fact {
			return order[missing[i].Fact] < order[missing[j].Fact]
		}
		return missing[i].Scope < missing[j].Scope
	})
	out := CheckAnswerableOutput{QuestionKind: kind, Subject: subject, Required: req.Facts, Missing: missing}
	scopes := map[string]bool{}
	for _, m := range missing {
		scopes[m.Scope] = true
	}
	switch blind := e.noData(subject, all); {
	case blind != "":
		out.Answerable = AnswerNo
		out.Summary = fmt.Sprintf("%s about %s: no; gop could not see %s", kind, q(subject), blindWhat(blind))
		out.ConfidenceNote = fmt.Sprintf("gop could not see %s, so any %s answer about %s would rest on no data. "+
			"Do not answer from this graph; ask for the access named in missing (needs_fix), then re-run gop collect.", blindWhat(blind), kind, q(subject))
	case len(missing) > 0:
		out.Answerable = AnswerPartial
		out.Summary = fmt.Sprintf("%s about %s: partial (a lower bound); %s not visible across %s", kind, q(subject),
			plural(len(missing), "required fact", "required facts"), plural(len(scopes), "scope", "scopes"))
		out.ConfidenceNote = "The answer is a lower bound: confirmed reach in it is real, but gop could not see " +
			"facts it depends on, so more reach may exist. Say so when you give the answer, and name the missing facts " +
			"and the access that would make them visible."
	default:
		out.Answerable = AnswerYes
		out.Summary = fmt.Sprintf("%s about %s: yes; every required fact was visible", kind, q(subject))
		out.ConfidenceNote = "gop saw every fact this answer depends on in this snapshot. The answer is complete " +
			"for the snapshot's collection time; it says nothing about changes made since."
	}
	return out, nil
}

func appendNew(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func blindWhat(id string) string {
	switch graph.KindFromID(id) {
	case graph.KindOrg:
		return "the repositories of " + q(id)
	case graph.KindEnterprise:
		return "the repositories of any org"
	}
	return q(id) + " itself (not_visible)"
}

// answerSubject resolves the subject: a node ID, or an org login. For a
// whole-enterprise question an empty subject means the enterprise.
func (e *Engine) answerSubject(req requirement, s string) (string, error) {
	s = strings.TrimSpace(s)
	ent := "enterprise:" + e.ix.Graph().Enterprise
	switch {
	case s == "" && req.Region == regionAll:
		return ent, nil
	case s != "" && e.set[s]:
		return s, nil
	case s != "" && !strings.Contains(s, ":") && e.set["org:"+s]:
		return "org:" + s, nil
	case req.Region == regionAll && (s == ent || s == e.ix.Graph().Enterprise):
		return ent, nil
	}
	return e.resolve("subject", s)
}

// questionRegion is the part of the graph the answer about subject depends on.
func (e *Engine) questionRegion(req requirement, subject string) region {
	switch req.Region {
	case regionUpstream:
		targets := []string{subject}
		if graph.KindFromID(subject) == graph.KindOrg {
			for _, n := range e.ix.Graph().Nodes {
				if n.Kind == graph.KindRepo && graph.OrgOf(n.ID) == subject {
					targets = append(targets, n.ID)
				}
			}
		}
		ids := append([]string{}, targets...)
		for _, t := range targets {
			ids = append(ids, e.ix.Upstream(t)...)
		}
		return newRegion(regionUpstream, ids)
	case regionDownstream:
		from := subject
		if m := membersID(subject); m != subject && e.set[m] {
			from = m
		}
		ids := []string{subject, from}
		for id := range e.ix.Reach(from, graph.Options{}).Paths {
			ids = append(ids, id)
		}
		return newRegion(regionDownstream, ids)
	}
	return region{kind: regionAll}
}

// noData returns what makes the question unanswerable: the subject node
// itself when it is not_visible, or the subject's org when gop could not see
// its repositories (for the enterprise: when it could see no org's). "" if
// neither.
func (e *Engine) noData(subject string, all []gap) string {
	if n, ok := e.ix.Node(subject); ok && n.Evidence == graph.NotVisible {
		return subject
	}
	blindOrgs := map[string]bool{}
	for _, x := range all {
		if x.fact == factRepositories && x.edge == nil && graph.KindFromID(x.scope) == graph.KindOrg {
			blindOrgs[x.scope] = true
		}
	}
	if graph.KindFromID(subject) == graph.KindEnterprise {
		var orgs []string
		for _, n := range e.ix.Graph().Nodes {
			if n.Kind == graph.KindOrg {
				if !blindOrgs[n.ID] {
					return ""
				}
				orgs = append(orgs, n.ID)
			}
		}
		if len(orgs) == 0 {
			return ""
		}
		return subject
	}
	if o := graph.OrgOf(subject); blindOrgs[o] {
		return o
	}
	return ""
}
