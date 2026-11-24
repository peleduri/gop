// Package sarif turns gop's fixable edges into SARIF 2.1.0 results, so teams
// that triage in a code-scanning style queue can route each one to the repo
// that owns the fix.
//
// SARIF output lists attack paths. Uploading it to code scanning shows them to
// everyone with alert access on the repo, so it is opt-in (gop sarif) and gop
// never uploads it: see docs/sarif.md. This package works only on a loaded
// graph and makes no network calls.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// Version is the SARIF version gop writes.
const Version = "2.1.0"

// SchemaURI is the $schema of every log gop writes.
const SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// InformationURI is the tool's home page.
const InformationURI = "https://github.com/peleduri/gop"

// HelpURI is the page every rule links to.
const HelpURI = InformationURI + "/blob/main/docs/sarif.md"

// FingerprintKey is the partialFingerprints key gop sets on every result.
const FingerprintKey = "gopFixableEdge/v1"

// Rule IDs.
const (
	RuleMutableRef  = "GOP001"
	RuleDefaultPerm = "GOP002"
	// RuleAdvisory: a workflow runs an action version with a known
	// advisory (OSV GitHub Actions). Ranked above every other rule.
	RuleAdvisory = "GOP003"
	// RuleAgent: an AI coding agent workflow that people without push
	// access can start on a trigger that holds the repo's token and secrets.
	RuleAgent = "GOP004"
)

// Severities, lowest first.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// ParseSeverity checks a --min-severity value ("" means low).
func ParseSeverity(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return SeverityLow, nil
	}
	if severityRank(s) < 0 {
		return "", fmt.Errorf("severity must be low, medium, high or critical, got %q", s)
	}
	return s, nil
}

func severityRank(s string) int {
	switch s {
	case SeverityLow:
		return 0
	case SeverityMedium:
		return 1
	case SeverityHigh:
		return 2
	case SeverityCritical:
		return 3
	}
	return -1
}

// Options tune Build.
type Options struct {
	// Version is the gop version written to tool.driver.version.
	Version string
	// Top keeps the first Top results after sorting (0 keeps all).
	Top int
	// MinSeverity drops results below it (low, medium, high, critical; "" is low).
	MinSeverity string
	// IncludePossible keeps results with no confirmed principal or with a
	// not_visible edge, at level note. They are dropped by default.
	IncludePossible bool
}

// Log is a SARIF log.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one SARIF run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes gop.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver is the tool component.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

// Rule is a reportingDescriptor.
type Rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     Message        `json:"shortDescription"`
	FullDescription      Message        `json:"fullDescription"`
	Help                 Help           `json:"help"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration Configuration  `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

// Configuration is a reportingConfiguration.
type Configuration struct {
	Level string `json:"level"`
}

// Message is a SARIF message (text only).
type Message struct {
	Text string `json:"text"`
}

// Help carries both renderings of a rule's help.
type Help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

// Result is one fixable edge.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          Properties        `json:"properties"`
}

// Location has a file position, a logical location, or both.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation is a file and, when known, a line.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a path relative to the repository root.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is a 1-based line and optional column.
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// LogicalLocation names what has no file: an org, or the workflow or action
// the edge starts at.
type LogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// Terminals counts the terminal impact behind a result.
type Terminals struct {
	OIDC         int `json:"oidc"`
	Secrets      int `json:"secrets"`
	Runners      int `json:"runners"`
	CloudTargets int `json:"cloud_targets"`
	Repos        int `json:"repos"`
}

// Properties is the gop property bag of a result.
type Properties struct {
	Severity string `json:"severity"`
	// Repository is the repo that owns the fix (GOP001): "acme-app/web".
	Repository string `json:"repository,omitempty"`
	// Org is the org that owns the fix (GOP002): "acme-actions".
	Org                 string          `json:"org,omitempty"`
	Edge                string          `json:"edge"`
	Evidence            graph.Evidence  `json:"evidence"`
	Possible            bool            `json:"possible,omitempty"`
	ConfirmedPrincipals []string        `json:"confirmed_principals"`
	PossiblePrincipals  []string        `json:"possible_principals"`
	Terminals           Terminals       `json:"terminals"`
	Fix                 fixplan.FixSpec `json:"fix"`
	ReachRemovedPct     float64         `json:"reach_removed_pct"`
	// Advisories are the advisory IDs behind a GOP003 result.
	Advisories []string `json:"advisories,omitempty"`
	// Agent is the agent kind list behind a GOP004 result (attr agent).
	Agent string `json:"agent,omitempty"`
	// AgentFixes are the changes that shrink a GOP004 result's exposure.
	AgentFixes []string `json:"agent_fixes,omitempty"`
}

// Rules returns the rules gop reports, in ruleIndex order.
func Rules() []Rule {
	tags := []string{"security", "supply-chain", "github-actions"}
	return []Rule{
		{
			ID:               RuleMutableRef,
			Name:             "mutable-action-ref-reachable",
			ShortDescription: Message{Text: "A workflow uses a mutable action ref whose host repo principals outside the consuming org can change"},
			FullDescription: Message{Text: "The workflow uses an action by branch or tag. Principals outside the consuming org can push to the repo that hosts the action, " +
				"so they can change the code the workflow runs and reach its secrets, OIDC tokens and runners."},
			Help: Help{
				Text: "Pin the action to a full commit SHA in this uses: line (keep the ref as a comment). Run gop fix-plan --pin <action> for every line to change, " +
					"or gop pin --action <owner/repo@ref> --graph graph.json for a git apply diff. Keep pins current with Dependabot or Renovate.",
				Markdown: "## Fix: pin the action to a commit SHA\n\n" +
					"The `uses:` line names a branch or tag. Whoever can push to the action's host repo can change what this workflow runs, " +
					"and with it reach the workflow's secrets, OIDC tokens and runners.\n\n" +
					"Replace the ref with the full commit SHA and keep the ref as a comment:\n\n" +
					"```diff\n-uses: acme-actions/deploy@main\n+uses: acme-actions/deploy@<40-hex-sha> # main\n```\n\n" +
					"- `gop fix-plan --graph graph.json --pin action:<owner>/<repo>@<ref>` lists every line to change, with a one-line diff when the graph has line numbers.\n" +
					"- `gop pin --action <owner>/<repo>@<ref> --graph graph.json` resolves the SHA with read-only calls and prints a `git apply` diff.\n" +
					"- Pinning the outer ref does not close paths through mutable refs the action uses itself; fix-plan lists those.\n" +
					"- Keep pins current with Dependabot or Renovate.\n\n" +
					"gop never makes this change: make it with your own access.",
			},
			HelpURI:              HelpURI,
			DefaultConfiguration: Configuration{Level: "error"},
			Properties:           map[string]any{"tags": tags, "precision": "high"},
		},
		{
			ID:               RuleDefaultPerm,
			Name:             "default-permission-grants-push",
			ShortDescription: Message{Text: "The org's default repository permission gives every member push access"},
			FullDescription: Message{Text: "The org's base permission is write or admin, so every member can push to repos where nothing else grants them push, " +
				"and through those repos reach the workflows, actions and terminals they control."},
			Help: Help{
				Text: "Lower the org's base permission to read (Organization settings > Member privileges > Base permissions) after giving teams push where members need it. " +
					"Run gop fix-plan --lower-default-perm org:<org> for the repos where members lose push.",
				Markdown: "## Fix: lower the org's default repository permission\n\n" +
					"The base permission gives every org member push to repos where no team, direct or owner grant does, " +
					"and with push, control of the workflows and actions in those repos.\n\n" +
					"1. Run `gop fix-plan --graph graph.json --lower-default-perm org:<org>` to list the repos where members lose push.\n" +
					"2. Give a team push on the repos members still need.\n" +
					"3. An org owner sets Organization settings > Member privileges > Base permissions to **Read** " +
					"(`PATCH /orgs/<org> {\"default_repository_permission\": \"read\"}`).\n\n" +
					"This result has no file: it is an org setting. gop never makes this change: make it with your own access.",
			},
			HelpURI:              HelpURI,
			DefaultConfiguration: Configuration{Level: "error"},
			Properties:           map[string]any{"tags": tags, "precision": "high"},
		},
		{
			ID:               RuleAdvisory,
			Name:             "action-with-known-advisory-reachable",
			ShortDescription: Message{Text: "A workflow runs an action version with a known compromise or vulnerability advisory"},
			FullDescription: Message{Text: "The uses: line names an action version that an OSV GitHub Actions advisory lists as affected, " +
				"for example a hijacked tag that shipped code stealing secrets. The workflow runs that code with its secrets, OIDC tokens and runners."},
			Help: Help{
				Text: "Move the action to the first fixed version the advisory names, or a commit SHA after it. Run gop fix-plan --pin <action> for every line to change. " +
					"When the advisory is a compromise, also rotate the secrets and cloud credentials the workflow could reach while it ran the affected version.",
				Markdown: "## Fix: move off the affected version\n\n" +
					"An [OSV](https://osv.dev) advisory lists this action version as affected. A compromised action runs the attacker's code with " +
					"the workflow's secrets, OIDC tokens and runners.\n\n" +
					"- Move the `uses:` line to the first fixed version (`advisory_fixed` on the action node) or a commit SHA after it; " +
					"`gop fix-plan --graph graph.json --pin action:<owner>/<repo>@<ref>` lists every line with a diff.\n" +
					"- With no fixed version, remove or replace the action.\n" +
					"- For a compromise, rotate the secrets and cloud credentials the workflow reached while it ran the affected version, and check its run logs.\n\n" +
					"See docs/advisories.md for where the data comes from. gop never makes this change: make it with your own access.",
			},
			HelpURI:              HelpURI,
			DefaultConfiguration: Configuration{Level: "error"},
			Properties:           map[string]any{"tags": tags, "precision": "high"},
		},
		{
			ID:               RuleAgent,
			Name:             "agent-workflow-exposed",
			ShortDescription: Message{Text: "People without push access can start an AI coding agent that runs with the repo's token and secrets"},
			FullDescription: Message{Text: "The workflow runs an AI coding agent (a known agent action or CLI) on a trigger that people without push access can cause, " +
				"and the agent's own actor check does not stop them. The agent reads their text (a comment, an issue, a pull request) and acts with the job's " +
				"GITHUB_TOKEN, secrets, OIDC token and tools, so a prompt injection uses all of them."},
			Help: Help{
				Text: "Restrict who can start the agent (keep the action's write-access check, drop allowed_non_write_users or allow-users, or require approval for " +
					"outside contributors), give the agent job a read-only token and do writes in a separate job, pin the agent action to a commit SHA, drop " +
					"--dangerously-skip-permissions and similar flags, and scope the allowed tools. See docs/agents-in-ci.md.",
				Markdown: "## Fix: close the agent to outsiders and shrink what it holds\n\n" +
					"An AI coding agent reads the text of whoever triggered it. When that can be anyone without push access, a prompt injection " +
					"acts with the job's token, secrets, OIDC token and tools.\n\n" +
					"- Restrict who can start it: keep the action's write-access check (remove `allowed_non_write_users` / `allow-users`), move it off " +
					"`pull_request_target`, `issue_comment` and `issues`, or require approval for outside contributors.\n" +
					"- Give the agent job `permissions: contents: read` and make changes in a separate job that takes the agent's output.\n" +
					"- Pin the agent action to a full commit SHA.\n" +
					"- Drop `--dangerously-skip-permissions`, `--yolo`, `bypassPermissions`, `safety-strategy: unsafe` and similar flags.\n" +
					"- Scope the allowed tools, for example `--allowedTools \"Bash(gh pr comment:*)\"`.\n\n" +
					"`properties.agent_fixes` lists the changes for this workflow. See docs/agents-in-ci.md. gop never makes this change: make it with your own access.",
			},
			HelpURI:              HelpURI,
			DefaultConfiguration: Configuration{Level: "error"},
			Properties:           map[string]any{"tags": []string{"security", "supply-chain", "github-actions", "ai-agent"}, "precision": "medium"},
		},
	}
}

func ruleIndex(id string) int {
	for i, r := range Rules() {
		if r.ID == id {
			return i
		}
	}
	return -1
}

// engine caches reach per node across results.
type engine struct {
	ix     *graph.Index
	reach  map[string]graph.Result
	princs []string
}

func (en *engine) reachOf(id string) graph.Result {
	if r, ok := en.reach[id]; ok {
		return r
	}
	r := en.ix.Reach(id, graph.Options{})
	en.reach[id] = r
	return r
}

// Build computes the SARIF log for g: one result per fixable edge of every
// PinRef (GOP001) and LowerDefaultPerm (GOP002) candidate fix, filtered and
// sorted by Options.
func Build(g *graph.Graph, opts Options) (*Log, error) {
	minSev, err := ParseSeverity(opts.MinSeverity)
	if err != nil {
		return nil, err
	}
	if opts.Top < 0 {
		return nil, fmt.Errorf("top must not be negative, got %d", opts.Top)
	}
	ix := graph.NewIndex(g)
	en := &engine{ix: ix, reach: map[string]graph.Result{}, princs: ix.Principals()}
	var results []Result
	for _, a := range ix.AdvisoryActions() {
		results = append(results, en.advisoryResults(a)...)
	}
	for _, w := range ix.AgentWorkflows() {
		if r, ok := en.agentResult(w); ok {
			results = append(results, r)
		}
	}
	for _, f := range ix.Candidates() {
		switch v := f.(type) {
		case graph.PinRef:
			results = append(results, en.pinResults(v)...)
		case graph.LowerDefaultPerm:
			if r, ok := en.lowerResult(v); ok {
				results = append(results, r)
			}
		}
	}
	kept := results[:0]
	for _, r := range results {
		if r.Properties.Possible && !opts.IncludePossible {
			continue
		}
		if severityRank(r.Properties.Severity) < severityRank(minSev) {
			continue
		}
		kept = append(kept, r)
	}
	results = kept
	sortResults(results)
	if opts.Top > 0 && len(results) > opts.Top {
		results = results[:opts.Top]
	}
	if results == nil {
		results = []Result{}
	}
	return newLog(opts.Version, results), nil
}

func newLog(version string, results []Result) *Log {
	return &Log{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{{
			Tool:    Tool{Driver: Driver{Name: "gop", Version: version, InformationURI: InformationURI, Rules: Rules()}},
			Results: results,
		}},
	}
}

func sortResults(rs []Result) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if aa, ba := a.RuleID == RuleAdvisory, b.RuleID == RuleAdvisory; aa != ba {
			return aa
		}
		if aa, ba := a.RuleID == RuleAgent && !a.Properties.Possible, b.RuleID == RuleAgent && !b.Properties.Possible; aa != ba {
			return aa
		}
		if a.Properties.Possible != b.Properties.Possible {
			return !a.Properties.Possible
		}
		if sa, sb := severityRank(a.Properties.Severity), severityRank(b.Properties.Severity); sa != sb {
			return sa > sb
		}
		if a.Properties.ReachRemovedPct != b.Properties.ReachRemovedPct {
			return a.Properties.ReachRemovedPct > b.Properties.ReachRemovedPct
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Properties.Repository != b.Properties.Repository {
			return a.Properties.Repository < b.Properties.Repository
		}
		if a.Properties.Org != b.Properties.Org {
			return a.Properties.Org < b.Properties.Org
		}
		return a.Properties.Edge < b.Properties.Edge
	})
}

// removedPct is the share of baseline confirmed (principal, repo) pairs the
// fix removes on its own, rounded to one decimal.
func removedPct(d graph.Delta) float64 {
	b, a := d.Before.ConfirmedPairs, d.After.ConfirmedPairs
	if b == 0 {
		return 0
	}
	return math.Round(1000*float64(b-a)/float64(b)) / 10
}

// insideOrg reports whether principal p belongs to org (login): the org's
// members, one of its teams, or an identity with a MEMBER_OF edge to it.
func (en *engine) insideOrg(p, org string) bool {
	switch graph.KindFromID(p) {
	case graph.KindOrgMembers:
		return p == "members:"+org
	case graph.KindExternal:
		return false
	}
	if strings.HasPrefix(p, "team:") {
		return graph.OrgOf(p) == org
	}
	for _, e := range en.ix.Out(p) {
		if e.Kind == graph.MemberOf && e.To == "org:"+org {
			return true
		}
	}
	return false
}

// severityOf maps terminal impact to a severity: critical for OIDC or a cloud
// role, high for secrets or self-hosted runners, medium for repo CI only, low
// for nothing at all.
func severityOf(t Terminals) string {
	switch {
	case t.OIDC > 0 || t.CloudTargets > 0:
		return SeverityCritical
	case t.Secrets > 0 || t.Runners > 0:
		return SeverityHigh
	case t.Repos > 0:
		return SeverityMedium
	}
	return SeverityLow
}

func count(r graph.Reached) Terminals {
	return Terminals{OIDC: len(r.OIDC), Secrets: len(r.Secrets), Runners: len(r.Runners), CloudTargets: len(r.CloudTargets), Repos: len(r.Repos)}
}

func union(a, b graph.Reached) graph.Reached {
	cat := func(x, y []string) []string { return append(append([]string{}, x...), y...) }
	return graph.Reached{
		Repos: cat(a.Repos, b.Repos), OIDC: cat(a.OIDC, b.OIDC), Secrets: cat(a.Secrets, b.Secrets),
		Runners: cat(a.Runners, b.Runners), CloudTargets: cat(a.CloudTargets, b.CloudTargets),
	}
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func level(sev string, possible bool) string {
	if possible {
		return "note"
	}
	switch sev {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	}
	return "note"
}

func terminalPhrase(t Terminals) string {
	var parts []string
	add := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, "1 "+one)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n, many))
		}
	}
	add(t.CloudTargets, "cloud role", "cloud roles")
	add(t.OIDC, "OIDC token", "OIDC tokens")
	add(t.Secrets, "secrets scope", "secrets scopes")
	add(t.Runners, "self-hosted runner pool", "self-hosted runner pools")
	if len(parts) == 0 {
		if t.Repos > 0 {
			return "repo CI"
		}
		return "no terminal"
	}
	return strings.Join(parts, ", ")
}

// whoPhrase is listPhrase over principals, with every set of principals
// whose confirmed reach is identical (graph.GroupKey) folded into one item
// that names the group ("the 14 owners of acme"), at its first member's
// place. A set of max or fewer is listed by name: the names fit.
// The result's principal lists stay complete; only the message folds.
func (en *engine) whoPhrase(ps []string, max int) string {
	bucket := map[string][]string{}
	keys := make([]string, len(ps))
	for i, p := range ps {
		keys[i] = en.ix.GroupKey(en.reachOf(p))
		if keys[i] != "" {
			bucket[keys[i]] = append(bucket[keys[i]], p)
		}
	}
	items := make([]string, 0, len(ps))
	done := map[string]bool{}
	for i, p := range ps {
		b := bucket[keys[i]]
		if len(b) <= max {
			items = append(items, p)
			continue
		}
		if done[keys[i]] {
			continue
		}
		done[keys[i]] = true
		g := graph.RiskGroup{GroupScore: graph.Score{Principal: b[0]}, Members: b}
		g.Via, g.ViaScope = en.ix.SharedVia(b)
		items = append(items, mcpserver.GroupWho(en.ix, g))
	}
	return listPhrase(items, max)
}

func listPhrase(ps []string, max int) string {
	if len(ps) <= max {
		return strings.Join(ps, ", ")
	}
	return strings.Join(ps[:max], ", ") + fmt.Sprintf(" and %d more", len(ps)-max)
}

// pinResults makes one GOP001 result per uses: line of the action whose
// controllers include a principal outside the consuming org.
func (en *engine) pinResults(f graph.PinRef) []Result {
	plan := fixplan.Build(en.ix, f)
	pct := removedPct(plan.Removes)
	uses := strings.TrimPrefix(f.Action, "action:")
	var conf, poss []string
	for _, p := range en.princs {
		path, ok := en.reachOf(p).Paths[f.Action]
		if !ok {
			continue
		}
		if path.Unverified {
			poss = append(poss, p)
		} else {
			conf = append(conf, p)
		}
	}
	var out []Result
	for _, s := range plan.Steps {
		if s.Kind != fixplan.KindEditWorkflow {
			continue
		}
		from, _, _ := strings.Cut(s.Edge, " "+string(graph.Uses)+" ")
		var c, p []string
		for _, x := range conf {
			if !en.insideOrg(x, s.Owner) {
				c = append(c, x)
			}
		}
		for _, x := range poss {
			if !en.insideOrg(x, s.Owner) {
				p = append(p, x)
			}
		}
		if len(c) == 0 && len(p) == 0 {
			continue
		}
		if s.Unconfirmed {
			p = append(c, p...)
			sort.Strings(p)
			c = nil
		}
		possible := len(c) == 0
		rr := en.reachOf(from)
		reached := rr.Confirmed
		if possible {
			reached = union(rr.Confirmed, rr.Possible)
		}
		t := count(reached)
		sev := severityOf(t)
		ev := s.Evidence
		if possible {
			ev = graph.NotVisible
		}
		who := en.whoPhrase(c, 3)
		if possible {
			who = en.whoPhrase(p, 3) + " (possible: a hop is not visible to the token)"
		}
		where := s.File
		if where == "" {
			where = logical(from).Name
		}
		msg := fmt.Sprintf("%s uses %s, a mutable ref that %s can change; this reaches %s. Pin %s to a commit SHA.",
			where, uses, who, terminalPhrase(t), uses)
		loc := Location{LogicalLocations: []LogicalLocation{logical(from)}}
		if s.File != "" {
			loc.PhysicalLocation = &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: s.File}}
			if s.Line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: s.Line, StartColumn: s.Col}
			}
		}
		out = append(out, Result{
			RuleID: RuleMutableRef, RuleIndex: ruleIndex(RuleMutableRef), Level: level(sev, possible),
			Message:             Message{Text: msg},
			Locations:           []Location{loc},
			PartialFingerprints: map[string]string{FingerprintKey: fingerprint(RuleMutableRef, s.Repo, s.File, uses)},
			Properties: Properties{
				Severity: sev, Repository: s.Repo, Edge: s.Edge, Evidence: ev, Possible: possible,
				ConfirmedPrincipals: nonNil(c), PossiblePrincipals: nonNil(p), Terminals: t,
				Fix: plan.Fix, ReachRemovedPct: pct,
			},
		})
	}
	return out
}

// advisoryResults makes one GOP003 result per uses: line of an action with
// a known advisory on its ref, and per uses: line an actions.lock pins to a
// commit an advisory lists as affected (only those lines: the others run
// the ref). Severity is the higher of the terminal impact and the
// advisory's own (high when the advisory gives none).
func (en *engine) advisoryResults(action string) []Result {
	n, _ := en.ix.Node(action)
	plan := fixplan.Build(en.ix, graph.PinRef{Action: action})
	uses := strings.TrimPrefix(action, "action:")
	_, ref := fixplanSplit(uses)
	ids := strings.Join(graph.AdvisoryIDs(n), ", ")
	advSev := n.Attrs[graph.AttrAdvisorySeverity]
	if severityRank(advSev) < 0 {
		advSev = SeverityHigh
	}
	fix := "Remove or replace it: the advisory names no fixed version."
	if t := fixplan.FixedRef(n, ref); t != "" {
		fix = fmt.Sprintf("Move to %s or a commit SHA after it.", t)
	}
	// One line per uses: gop could edit, plus one per uses: an actions.lock
	// pins to a commit the advisory lists as affected.
	type line struct {
		from, repo, file, edge string
		line, col              int
		ev                     graph.Evidence
		possible               bool
		lock                   *fixplan.LockUse
	}
	var lines []line
	for _, s := range plan.Steps {
		// An edit line runs the ref: report it only when the advisory names
		// the ref, not when only a lock elsewhere pins an affected commit.
		if s.Kind != fixplan.KindEditWorkflow || !graph.HasAdvisory(n) {
			continue
		}
		from, _, _ := strings.Cut(s.Edge, " "+string(graph.Uses)+" ")
		lines = append(lines, line{from: from, repo: s.Repo, file: s.File, edge: s.Edge, line: s.Line, col: s.Col, ev: s.Evidence, possible: s.Unconfirmed})
	}
	for _, u := range fixplan.LockGoverned(en.ix, action) {
		if u.State != graph.LockLocked || u.Advisories == "" {
			continue
		}
		e := u.Edge
		col, _ := strconv.Atoi(e.Attrs[graph.AttrCol])
		lines = append(lines, line{from: e.From, repo: u.Repo, file: u.File, edge: e.From + " " + string(e.Kind) + " " + e.To,
			line: u.Line, col: col, ev: e.Evidence, possible: !graph.Verified(e.Evidence), lock: &u})
	}
	var out []Result
	for _, s := range lines {
		rr := en.reachOf(s.from)
		reached := rr.Confirmed
		if s.possible {
			reached = union(rr.Confirmed, rr.Possible)
		}
		t := count(reached)
		sev := severityOf(t)
		lineSev := advSev
		if s.lock != nil {
			lineSev = s.lock.Edge.Attrs[graph.AttrLockAdvisorySeverity]
			if severityRank(lineSev) < 0 {
				lineSev = SeverityHigh
			}
		}
		if severityRank(lineSev) > severityRank(sev) {
			sev = lineSev
		}
		ev := s.ev
		if s.possible {
			ev = graph.NotVisible
		}
		where := s.file
		if where == "" {
			where = logical(s.from).Name
		}
		advs := graph.AdvisoryIDs(n)
		msg := fmt.Sprintf("%s uses %s, a version with a known advisory (%s); it runs with %s. %s",
			where, uses, ids, terminalPhrase(t), fix)
		if s.lock != nil {
			advs = strings.Split(s.lock.Advisories, ",")
			lfix := "Remove or replace it, then rerun gh actions-lock: the advisory names no fixed version."
			if s.lock.Fixed != "" {
				lfix = fmt.Sprintf("Rerun gh actions-lock after moving to %s.", s.lock.Fixed)
			}
			msg = fmt.Sprintf("%s uses %s, which actions.lock pins to %s, a commit with a known advisory (%s); it runs with %s. %s",
				where, uses, s.lock.SHA, strings.Join(advs, ", "), terminalPhrase(t), lfix)
		}
		loc := Location{LogicalLocations: []LogicalLocation{logical(s.from)}}
		if s.file != "" {
			loc.PhysicalLocation = &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: s.file}}
			if s.line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: s.line, StartColumn: s.col}
			}
		}
		out = append(out, Result{
			RuleID: RuleAdvisory, RuleIndex: ruleIndex(RuleAdvisory), Level: level(sev, s.possible),
			Message:             Message{Text: msg},
			Locations:           []Location{loc},
			PartialFingerprints: map[string]string{FingerprintKey: fingerprint(RuleAdvisory, s.repo, s.file, uses)},
			Properties: Properties{
				Severity: sev, Repository: s.repo, Edge: s.edge, Evidence: ev, Possible: s.possible,
				ConfirmedPrincipals: []string{}, PossiblePrincipals: []string{}, Terminals: t,
				Fix: plan.Fix, Advisories: advs,
			},
		})
	}
	return out
}

// agentResult makes the GOP004 result for an agent workflow that people
// without push access can start (exposure outsiders, a strong agent
// signal): one per workflow, located at the agent step its CAN_TRIGGER
// edges name. It is possible when no such edge is verified (the agent's
// actor check is unknown, or who can trigger is not visible).
func (en *engine) agentResult(w string) (Result, bool) {
	n, _ := en.ix.Node(w)
	if !graph.AgentConfirmed(n) || n.Attrs[graph.AttrAgentExposure] != graph.ExposureOutsiders {
		return Result{}, false
	}
	var conf, poss []string
	var at *graph.Edge
	for _, e := range en.ix.In(w) {
		// The collector keeps one CAN_TRIGGER edge per principal: an agent
		// job under an injection or checkout exec of the same trigger may
		// carry that exec instead. Every one of them starts the workflow.
		if e.Kind != graph.CanTrigger {
			continue
		}
		if graph.Verified(e.Evidence) {
			conf = append(conf, e.From)
		} else {
			poss = append(poss, e.From)
		}
		if at == nil || edgeRank(e) > edgeRank(*at) {
			e := e
			at = &e
		}
	}
	if at == nil {
		return Result{}, false
	}
	sort.Strings(conf)
	sort.Strings(poss)
	possible := len(conf) == 0
	rr := en.reachOf(w)
	reached := rr.Confirmed
	if possible {
		reached = union(rr.Confirmed, rr.Possible)
	}
	t := count(reached)
	sev := severityOf(t)
	if len(graph.AgentImpact(n)) > 0 && severityRank(sev) < severityRank(SeverityHigh) {
		sev = SeverityHigh // the agent's own token or secrets: it can write or leak them
	}
	repo, file := n.Attrs["repo"], n.Attrs["path"]
	if f := at.Attrs[graph.AttrFile]; f != "" {
		file = f
	}
	who := en.whoPhrase(conf, 3)
	if possible {
		who = en.whoPhrase(poss, 3) + " (possible)"
	}
	holds := strings.Join(graph.AgentImpact(n), ", ")
	if holds == "" {
		holds = "a read-only token"
	}
	msg := fmt.Sprintf("%s runs %s, which %s can start on %s; the agent job holds %s and reaches %s.",
		orDefault(file, logical(w).Name), n.Attrs[graph.AttrAgent], who, at.Attrs["trigger"], holds, terminalPhrase(t))
	if p := n.Attrs[graph.AttrAgentPrompt]; p != "" {
		msg += " Untrusted text reaches the prompt: " + strings.ReplaceAll(p, ",", ", ") + "."
	}
	fixes := graph.AgentFixes(n)
	if len(fixes) > 0 {
		msg += " " + fixes[0]
	}
	loc := Location{LogicalLocations: []LogicalLocation{logical(w)}}
	if file != "" {
		loc.PhysicalLocation = &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: file}}
		if l, _ := strconv.Atoi(at.Attrs[graph.AttrLine]); l > 0 {
			loc.PhysicalLocation.Region = &Region{StartLine: l}
		}
	}
	ev := at.Evidence
	if possible {
		ev = graph.NotVisible
	}
	spec, _ := fixplan.Spec(graph.HardenTrigger{Workflow: w})
	return Result{
		RuleID: RuleAgent, RuleIndex: ruleIndex(RuleAgent), Level: level(sev, possible),
		Message:             Message{Text: msg},
		Locations:           []Location{loc},
		PartialFingerprints: map[string]string{FingerprintKey: fingerprint(RuleAgent, repo, file)},
		Properties: Properties{
			Severity: sev, Repository: repo, Edge: at.From + " " + string(at.Kind) + " " + at.To, Evidence: ev, Possible: possible,
			ConfirmedPrincipals: nonNil(conf), PossiblePrincipals: nonNil(poss), Terminals: t,
			Fix: spec, Agent: n.Attrs[graph.AttrAgent], AgentFixes: fixes,
		},
	}, true
}

// edgeRank prefers a verified edge, then one the agent exec created.
func edgeRank(e graph.Edge) int {
	r := 0
	if graph.Verified(e.Evidence) {
		r += 2
	}
	if e.Attrs["exec"] == "agent" {
		r++
	}
	return r
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// fixplanSplit splits "O/R[/path]@ref" at the last "@".
func fixplanSplit(uses string) (base, ref string) {
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		return uses[:i], uses[i+1:]
	}
	return uses, ""
}

func logical(id string) LogicalLocation {
	kind := string(graph.KindFromID(id))
	name := id
	if _, rest, ok := strings.Cut(id, ":"); ok {
		name = rest
	}
	return LogicalLocation{Name: name, FullyQualifiedName: id, Kind: kind}
}

// lowerResult makes the GOP002 result for an org: one per org, since the fix
// is one setting and the result has no file.
func (en *engine) lowerResult(f graph.LowerDefaultPerm) (Result, bool) {
	plan := fixplan.Build(en.ix, f)
	org := strings.TrimPrefix(f.Org, "org:")
	var c, p []string
	lost := map[string]map[string]bool{}
	for _, pd := range plan.Removes.PerPrincipal {
		if pd.Before.Confirmed == pd.After.Confirmed {
			p = append(p, pd.Principal)
			continue
		}
		c = append(c, pd.Principal)
		before := en.reachOf(pd.Principal).Confirmed
		after := en.ix.Reach(pd.Principal, graph.Options{Fixes: []graph.Fix{f}}).Confirmed
		diff := func(kind string, b, a []string) {
			have := map[string]bool{}
			for _, id := range a {
				have[id] = true
			}
			for _, id := range b {
				if !have[id] {
					if lost[kind] == nil {
						lost[kind] = map[string]bool{}
					}
					lost[kind][id] = true
				}
			}
		}
		diff("repos", before.Repos, after.Repos)
		diff("oidc", before.OIDC, after.OIDC)
		diff("secrets", before.Secrets, after.Secrets)
		diff("runners", before.Runners, after.Runners)
		diff("cloud", before.CloudTargets, after.CloudTargets)
	}
	if len(c) == 0 && len(p) == 0 {
		return Result{}, false
	}
	possible := len(c) == 0
	t := Terminals{OIDC: len(lost["oidc"]), Secrets: len(lost["secrets"]), Runners: len(lost["runners"]),
		CloudTargets: len(lost["cloud"]), Repos: len(lost["repos"])}
	sev := severityOf(t)
	ev := graph.Live
	var edges []string
	for _, s := range plan.Steps {
		if s.Kind == fixplan.KindChangeSetting && s.Evidence != "" {
			ev = s.Evidence
		}
		if s.Kind == fixplan.KindVerify && s.Edge != "" && !s.Unconfirmed {
			edges = append(edges, s.Edge)
		}
	}
	if possible {
		ev = graph.NotVisible
	}
	n, _ := en.ix.Node(f.Org)
	cur := n.Attrs[graph.AttrDefaultPerm]
	if cur == "" {
		cur = "write"
	}
	who := en.whoPhrase(c, 3)
	if possible {
		who = en.whoPhrase(p, 3) + " (possible: a hop is not visible to the token)"
	}
	msg := fmt.Sprintf("The default repository permission of %s is %s. Lowering it to read removes reach to %d repos (%s) for %s.",
		org, cur, t.Repos, terminalPhrase(t), who)
	edge := f.Org + " " + graph.AttrDefaultPerm + "=" + cur
	if len(edges) > 0 {
		edge = edges[0]
		if len(edges) > 1 {
			edge += fmt.Sprintf(" (+%d more)", len(edges)-1)
		}
	}
	return Result{
		RuleID: RuleDefaultPerm, RuleIndex: ruleIndex(RuleDefaultPerm), Level: level(sev, possible),
		Message:             Message{Text: msg},
		Locations:           []Location{{LogicalLocations: []LogicalLocation{{Name: org, FullyQualifiedName: f.Org, Kind: "organization"}}}},
		PartialFingerprints: map[string]string{FingerprintKey: fingerprint(RuleDefaultPerm, f.Org)},
		Properties: Properties{
			Severity: sev, Org: org, Edge: edge, Evidence: ev, Possible: possible,
			ConfirmedPrincipals: nonNil(c), PossiblePrincipals: nonNil(p), Terminals: t,
			Fix: plan.Fix, ReachRemovedPct: removedPct(plan.Removes),
		},
	}, true
}

// Split groups results by the repo that owns the fix: the key is "owner/repo"
// for GOP001 and "org:<login>" for GOP002. Each log carries all rules.
func Split(l *Log) map[string]*Log {
	out := map[string]*Log{}
	if len(l.Runs) == 0 {
		return out
	}
	run := l.Runs[0]
	for _, r := range run.Results {
		key := r.Properties.Repository
		if key == "" {
			key = "org:" + r.Properties.Org
		}
		sub, ok := out[key]
		if !ok {
			sub = newLog(run.Tool.Driver.Version, []Result{})
			out[key] = sub
		}
		sub.Runs[0].Results = append(sub.Runs[0].Results, r)
	}
	return out
}

// Write writes the log as indented JSON.
func Write(w io.Writer, l *Log) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(l)
}
