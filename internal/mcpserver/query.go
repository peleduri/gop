// Package mcpserver answers gop's graph questions. Engine holds the query
// logic shared by the MCP server (NewServer, Serve) and the CLI (gop paths,
// gop who). Every answer keeps confirmed reach (every hop live, inferred,
// fresh audit or supplied) apart from possible reach (at least one hop not_visible);
// summaries lead with confirmed numbers. A summary that includes a path
// through a supplied trust file says so (graph.Path.SuppliedNote).
package mcpserver

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
)

// Default limits for optional inputs.
const (
	DefaultTopN   = 10
	DefaultBudget = 3
	maxSuggest    = 5
)

// Engine answers questions over one read-only graph. Safe for concurrent use.
type Engine struct {
	g    *graph.Graph
	ix   *graph.Index
	ids  []string // every node ID seen in nodes or edges, sorted
	set  map[string]bool
	demo bool // synthetic graph from gop demo: summaries say so
}

// DemoMarker prefixes every summary computed over a demo graph.
const DemoMarker = "[demo data]"

// mark prefixes a non-empty summary with DemoMarker on a demo graph.
func (e *Engine) mark(s *string) {
	if e.demo && *s != "" {
		*s = DemoMarker + " " + *s
	}
}

// NewEngine indexes g. g must not be modified afterwards.
func NewEngine(g *graph.Graph) *Engine {
	e := &Engine{g: g, ix: graph.NewIndex(g), set: map[string]bool{}, demo: graph.IsDemo(g)}
	add := func(id string) {
		if id != "" && !e.set[id] {
			e.set[id] = true
			e.ids = append(e.ids, id)
		}
	}
	for _, n := range e.ix.Graph().Nodes {
		add(n.ID)
	}
	for _, ed := range e.ix.Graph().Edges {
		add(ed.From)
		add(ed.To)
	}
	sort.Strings(e.ids)
	return e
}

// Index returns the underlying index.
func (e *Engine) Index() *graph.Index { return e.ix }

// UnknownNodeError is returned for a node ID the graph does not contain.
type UnknownNodeError struct {
	Field       string
	ID          string
	Suggestions []string
}

func (u *UnknownNodeError) Error() string {
	msg := fmt.Sprintf("unknown %s %q: no such node in the graph", u.Field, u.ID)
	if len(u.Suggestions) > 0 {
		return msg + ". Did you mean: " + strings.Join(u.Suggestions, ", ") + "?"
	}
	return msg + `. Node IDs look like "members:<org>", "identity:<login>", "repo:<org>/<repo>", "action:<owner>/<repo>@<ref>"`
}

// Suggest returns up to 5 node IDs close to id: IDs that start with it (with or
// without the "kind:" prefix), else IDs sharing the longest prefix with it.
func (e *Engine) Suggest(id string) []string {
	q := strings.ToLower(strings.TrimSpace(id))
	match := func(p string) []string {
		var out []string
		for _, c := range e.ids {
			lc := strings.ToLower(c)
			_, rest, _ := strings.Cut(lc, ":")
			if strings.HasPrefix(lc, p) || strings.HasPrefix(rest, p) {
				out = append(out, c)
				if len(out) == maxSuggest {
					break
				}
			}
		}
		return out
	}
	if q == "" {
		return nil
	}
	if out := match(q); len(out) > 0 {
		return out
	}
	for n := len(q) - 1; n >= 3; n-- {
		if out := match(q[:n]); len(out) > 0 {
			return out
		}
	}
	return nil
}

func (e *Engine) resolve(field, id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if e.set[id] {
		return id, nil
	}
	return "", &UnknownNodeError{Field: field, ID: id, Suggestions: e.Suggest(id)}
}

// Display returns a short human label for a principal ID.
func (e *Engine) Display(id string) string { return Display(e.ix, id) }

// Display returns a short human label for a principal ID ("members of acme-actions").
func Display(ix *graph.Index, id string) string {
	if ix.Kind(id) == graph.KindOrgMembers {
		return "members of " + strings.TrimPrefix(id, "members:")
	}
	return id
}

func splitPaths(ps []graph.Path) (conf, poss []graph.Path) {
	conf, poss = []graph.Path{}, []graph.Path{}
	for _, p := range ps {
		if p.Unverified {
			poss = append(poss, p)
		} else {
			conf = append(conf, p)
		}
	}
	return conf, poss
}

// suppliedNote is the caveat for a set of paths: "" when none has a hop from a
// supplied file, else "cloud hop from supplied trust file F[, G], not read
// from the cloud".
func suppliedNote(ps ...graph.Path) string {
	var files []string
	seen := map[string]bool{}
	for _, p := range ps {
		for _, f := range p.SuppliedFiles() {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	if len(files) == 0 {
		return ""
	}
	sort.Strings(files)
	return graph.Path{Hops: []graph.Hop{{SourceAPI: graph.SourceSupplied + strings.Join(files, ", ")}}}.SuppliedNote()
}

// withNote appends a supplied-file caveat to a summary.
func withNote(s, note string) string {
	if note == "" {
		return s
	}
	return s + " (" + note + ")"
}

// cloudPaths returns the paths of r to cloud targets (confirmed and possible).
func cloudPaths(r graph.Result) []graph.Path {
	var out []graph.Path
	for _, l := range [][]string{r.Confirmed.CloudTargets, r.Possible.CloudTargets} {
		for _, id := range l {
			out = append(out, r.Paths[id])
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// WhoCanReachInput is the who_can_reach tool input.
type WhoCanReachInput struct {
	Target string `json:"target" jsonschema:"node ID of a repo, workflow, action, secret, oidc, runner or cloud target, e.g. repo:acme-app/web or cloud:aws:arn:aws:iam::111111111111:role/deploy"`
	DetailInput
}

// WhoCanReachOutput lists principals with a path to the target.
type WhoCanReachOutput struct {
	Summary   string       `json:"summary"`
	Target    string       `json:"target"`
	Confirmed []graph.Path `json:"confirmed" jsonschema:"principals with a path where every hop is live, inferred, audit or supplied"`
	Possible  []graph.Path `json:"possible" jsonschema:"principals whose only path has at least one not_visible hop"`
	Brief     *Brief       `json:"brief,omitempty"`
}

// WhoCanReach lists every principal that can control target, one shortest path each.
func (e *Engine) WhoCanReach(in WhoCanReachInput) (res WhoCanReachOutput, _ error) {
	defer e.mark(&res.Summary)
	t, err := e.resolve("target", in.Target)
	if err != nil {
		return WhoCanReachOutput{}, err
	}
	conf, poss := splitPaths(e.ix.WhoCanReach(t))
	return WhoCanReachOutput{
		Summary: withNote(fmt.Sprintf("%s can control %s (confirmed); %d more possible through a not visible hop",
			plural(len(conf), "principal", "principals"), t, len(poss)), suppliedNote(append(append([]graph.Path{}, conf...), poss...)...)),
		Target: t, Confirmed: conf, Possible: poss,
	}, nil
}

// BlastRadiusInput is the blast_radius tool input.
type BlastRadiusInput struct {
	Principal string `json:"principal" jsonschema:"principal node ID, e.g. members:acme-actions or identity:bob"`
	DetailInput
}

// BlastRadiusOutput is a principal's score and reach sets.
type BlastRadiusOutput struct {
	Summary   string        `json:"summary"`
	Score     graph.Score   `json:"score"`
	Confirmed graph.Reached `json:"confirmed"`
	Possible  graph.Reached `json:"possible"`
	Brief     *Brief        `json:"brief,omitempty"`
}

// ReachSentence is the headline sentence for a score, confirmed numbers first.
func ReachSentence(s graph.Score) string {
	c := s.Confirmed
	out := fmt.Sprintf("%s can control %s across %s (confirmed)", s.Principal,
		plural(c.Repos, "repo", "repos"), plural(c.Orgs, "org", "orgs"))
	var term []string
	if c.CloudTargets > 0 {
		term = append(term, plural(c.CloudTargets, "cloud role", "cloud roles"))
	}
	if c.OIDC > 0 {
		term = append(term, plural(c.OIDC, "OIDC trust", "OIDC trusts"))
	}
	if c.Secrets > 0 {
		term = append(term, plural(c.Secrets, "secret scope", "secret scopes"))
	}
	if c.Runners > 0 {
		term = append(term, plural(c.Runners, "self-hosted runner pool", "self-hosted runner pools"))
	}
	if len(term) > 0 {
		out += ", including " + strings.Join(term, ", ")
	}
	return out + fmt.Sprintf("; %d more possible", s.Possible.Repos)
}

// BlastRadius scores a principal.
func (e *Engine) BlastRadius(in BlastRadiusInput) (res BlastRadiusOutput, _ error) {
	defer e.mark(&res.Summary)
	p, err := e.resolve("principal", in.Principal)
	if err != nil {
		return BlastRadiusOutput{}, err
	}
	s := e.ix.BlastRadius(p)
	r := e.ix.Reach(p, graph.Options{})
	return BlastRadiusOutput{Summary: withNote(ReachSentence(s), suppliedNote(cloudPaths(r)...)), Score: s, Confirmed: r.Confirmed, Possible: r.Possible}, nil
}

// PathsInput is the paths tool input.
type PathsInput struct {
	From string `json:"from" jsonschema:"principal node ID to start from"`
	To   string `json:"to,omitempty" jsonschema:"optional target node ID; omit to list paths to everything reachable"`
	DetailInput
}

// PathsOutput lists paths from a principal.
type PathsOutput struct {
	Summary   string       `json:"summary"`
	From      string       `json:"from"`
	To        string       `json:"to,omitempty"`
	Confirmed []graph.Path `json:"confirmed"`
	Possible  []graph.Path `json:"possible"`
	Brief     *Brief       `json:"brief,omitempty"`
}

// Paths returns shortest paths from a principal, optionally only to one target.
func (e *Engine) Paths(in PathsInput) (res PathsOutput, _ error) {
	defer e.mark(&res.Summary)
	from, err := e.resolve("from", in.From)
	if err != nil {
		return PathsOutput{}, err
	}
	out := PathsOutput{From: from, Confirmed: []graph.Path{}, Possible: []graph.Path{}}
	r := e.ix.Reach(from, graph.Options{})
	if strings.TrimSpace(in.To) != "" {
		to, err := e.resolve("to", in.To)
		if err != nil {
			return PathsOutput{}, err
		}
		out.To = to
		p, ok := r.Paths[to]
		switch {
		case !ok:
			out.Summary = fmt.Sprintf("%s has no path to %s, confirmed or possible", from, to)
		case p.Unverified:
			out.Possible = append(out.Possible, p)
			out.Summary = withNote(fmt.Sprintf("%s can possibly reach %s in %s; a hop is not visible, so it is unconfirmed", from, to, plural(len(p.Hops), "hop", "hops")), suppliedNote(p))
		default:
			out.Confirmed = append(out.Confirmed, p)
			out.Summary = withNote(fmt.Sprintf("%s can reach %s in %s (confirmed)", from, to, plural(len(p.Hops), "hop", "hops")), suppliedNote(p))
		}
		return out, nil
	}
	ps := make([]graph.Path, 0, len(r.Paths))
	for _, p := range r.Paths {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if len(ps[i].Hops) != len(ps[j].Hops) {
			return len(ps[i].Hops) < len(ps[j].Hops)
		}
		return ps[i].To < ps[j].To
	})
	out.Confirmed, out.Possible = splitPaths(ps)
	out.Summary = withNote(fmt.Sprintf("%s has confirmed paths to %s; %d more possible", from,
		plural(len(out.Confirmed), "node", "nodes"), len(out.Possible)), suppliedNote(ps...))
	return out, nil
}

// TopRisksInput is the top_risks tool input.
type TopRisksInput struct {
	N int `json:"n,omitempty" jsonschema:"how many principals to return (default 10)"`
	DetailInput
}

// TopRisksOutput ranks principals by confirmed score.
type TopRisksOutput struct {
	Summary string        `json:"summary"`
	Risks   []graph.Score `json:"risks"`
	Brief   *Brief        `json:"brief,omitempty"`
}

// TopRisks ranks principals by confirmed blast radius.
func (e *Engine) TopRisks(in TopRisksInput) (res TopRisksOutput, _ error) {
	defer e.mark(&res.Summary)
	n := in.N
	if n < 0 {
		return TopRisksOutput{}, fmt.Errorf("n must be positive, got %d", n)
	}
	if n == 0 {
		n = DefaultTopN
	}
	risks := e.ix.TopPaths(n)
	if risks == nil {
		risks = []graph.Score{}
	}
	out := TopRisksOutput{Risks: risks}
	if len(risks) == 0 {
		out.Summary = "the graph has no principals"
	} else {
		out.Summary = withNote("top risk: "+ReachSentence(risks[0]), suppliedNote(cloudPaths(e.ix.Reach(risks[0].Principal, graph.Options{}))...))
	}
	return out, nil
}

// FixSpec describes one hypothetical fix. It is the fixplan type, so what_if,
// suggest_fixes and fix_plan take and return the same shape.
type FixSpec = fixplan.FixSpec

// WhatIfInput is the what_if tool input.
type WhatIfInput struct {
	Fixes []FixSpec `json:"fixes" jsonschema:"fixes to apply together"`
}

// WhatIfOutput compares reach before and after the fixes.
type WhatIfOutput struct {
	Summary string      `json:"summary"`
	Delta   graph.Delta `json:"delta"`
}

func (e *Engine) toFix(i int, f FixSpec) (graph.Fix, error) {
	switch f.Type {
	case "pin_ref":
		a, err := e.resolve(fmt.Sprintf("fixes[%d].action", i), f.Action)
		if err != nil {
			return nil, err
		}
		if e.ix.Kind(a) != graph.KindActionRef {
			return nil, fmt.Errorf("fixes[%d].action: %s is not an action ref", i, a)
		}
		return graph.PinRef{Action: a}, nil
	case "lower_default_perm":
		o, err := e.resolve(fmt.Sprintf("fixes[%d].org", i), f.Org)
		if err != nil {
			return nil, err
		}
		if e.ix.Kind(o) != graph.KindOrg {
			return nil, fmt.Errorf("fixes[%d].org: %s is not an org", i, o)
		}
		if f.To != "read" && f.To != "none" {
			return nil, fmt.Errorf("fixes[%d].to: want read or none, got %q", i, f.To)
		}
		return graph.LowerDefaultPerm{Org: o, To: f.To}, nil
	case "restrict_token", "harden_trigger":
		w, err := e.resolve(fmt.Sprintf("fixes[%d].workflow", i), f.Workflow)
		if err != nil {
			return nil, err
		}
		if e.ix.Kind(w) != graph.KindWorkflow {
			return nil, fmt.Errorf("fixes[%d].workflow: %s is not a workflow", i, w)
		}
		if f.Type == "restrict_token" {
			return graph.RestrictToken{Workflow: w}, nil
		}
		return graph.HardenTrigger{Workflow: w}, nil
	}
	return nil, fmt.Errorf("fixes[%d].type: want %s, got %q", i, fixTypes, f.Type)
}

func pct(before, after int) float64 {
	if before == 0 {
		return 0
	}
	return 100 * float64(before-after) / float64(before)
}

// WhatIf applies fixes hypothetically.
func (e *Engine) WhatIf(in WhatIfInput) (res WhatIfOutput, _ error) {
	defer e.mark(&res.Summary)
	if len(in.Fixes) == 0 {
		return WhatIfOutput{}, fmt.Errorf("fixes is empty: give at least one of %s", fixShapes)
	}
	fixes := make([]graph.Fix, 0, len(in.Fixes))
	for i, f := range in.Fixes {
		fx, err := e.toFix(i, f)
		if err != nil {
			return WhatIfOutput{}, err
		}
		fixes = append(fixes, fx)
	}
	d := e.ix.WhatIf(fixes)
	b, a := d.Before, d.After
	return WhatIfOutput{
		Summary: fmt.Sprintf("confirmed (principal, repo) pairs: %d -> %d (%.0f%% removed); possible pairs: %d -> %d",
			b.ConfirmedPairs, a.ConfirmedPairs, pct(b.ConfirmedPairs, a.ConfirmedPairs), b.PossiblePairs, a.PossiblePairs),
		Delta: d,
	}, nil
}

// SuggestFixesInput is the suggest_fixes tool input.
type SuggestFixesInput struct {
	Budget int `json:"budget,omitempty" jsonschema:"maximum number of fixes (default 3)"`
	DetailInput
}

// FixOut is one suggested fix.
type FixOut struct {
	FixID             string   `json:"fix_id"`
	Fix               FixSpec  `json:"fix"`
	Description       string   `json:"description"`
	Edges             []string `json:"edges"`
	Removed           int      `json:"removed" jsonschema:"confirmed (principal, repo) pairs this fix removes on top of earlier fixes"`
	CumulativeRemoved int      `json:"cumulative_removed"`
	Remaining         int      `json:"remaining"`
	CumulativePct     float64  `json:"cumulative_pct" jsonschema:"percent of baseline confirmed pairs removed by this and earlier fixes"`
	Caveat            string   `json:"caveat,omitempty" jsonschema:"what gop could not see that may make this fix less effective, e.g. unknown nested references"`
}

// SuggestFixesOutput is the greedy fix list.
type SuggestFixesOutput struct {
	Summary string   `json:"summary"`
	Fixes   []FixOut `json:"fixes"`
	Brief   *Brief   `json:"brief,omitempty"`
}

// DescribeFix returns the FixSpec and a sentence for a graph fix.
func DescribeFix(f graph.Fix) (FixSpec, string) { return fixplan.Spec(f) }

// fixTypes and fixShapes name the fix types in error messages.
const (
	fixTypes  = "pin_ref, lower_default_perm, restrict_token or harden_trigger"
	fixShapes = `{type:"pin_ref",action}, {type:"lower_default_perm",org,to}, {type:"restrict_token",workflow} or {type:"harden_trigger",workflow}`
)

// SuggestFixes runs the budgeted greedy.
func (e *Engine) SuggestFixes(in SuggestFixesInput) (res SuggestFixesOutput, _ error) {
	defer e.mark(&res.Summary)
	b := in.Budget
	if b < 0 {
		return SuggestFixesOutput{}, fmt.Errorf("budget must be positive, got %d", b)
	}
	if b == 0 {
		b = DefaultBudget
	}
	out := SuggestFixesOutput{Fixes: []FixOut{}}
	for _, s := range e.ix.SuggestFixes(b) {
		spec, desc := DescribeFix(s.Fix)
		es := s.Edges
		if es == nil {
			es = []string{}
		}
		out.Fixes = append(out.Fixes, FixOut{FixID: s.FixID, Fix: spec, Description: desc, Edges: es,
			Removed: s.Removed, CumulativeRemoved: s.CumulativeRemoved, Remaining: s.Remaining, CumulativePct: s.CumulativePct,
			Caveat: s.Caveat})
	}
	if len(out.Fixes) == 0 {
		out.Summary = "no candidate fix removes confirmed reach"
	} else {
		last := out.Fixes[len(out.Fixes)-1]
		out.Summary = fmt.Sprintf("%s remove %.0f%% of confirmed (principal, repo) pairs; first: %s",
			plural(len(out.Fixes), "fix", "fixes"), last.CumulativePct, out.Fixes[0].Description)
	}
	return out, nil
}

// ExplainInput is the explain tool input.
type ExplainInput struct {
	From string `json:"from" jsonschema:"edge source node ID (a hop's from)"`
	To   string `json:"to" jsonschema:"edge target node ID (a hop's to)"`
	Kind string `json:"kind,omitempty" jsonschema:"optional edge kind, e.g. CAN_PUSH, USES, RESOLVES_TO, DEFINED_IN, EXECUTES_WITH, MEMBER_OF, CAN_ASSUME"`
}

// EdgeOut is one evidence edge.
type EdgeOut struct {
	From       string            `json:"from"`
	To         string            `json:"to"`
	Kind       string            `json:"kind"`
	Evidence   string            `json:"evidence"`
	SourceAPI  string            `json:"source_api"`
	ObservedAt string            `json:"observed_at"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	Reversed   bool              `json:"reversed,omitempty" jsonschema:"true when the evidence edge points the other way from the hop asked about"`
	Rule       string            `json:"rule,omitempty" jsonschema:"inferred edges: the rule that derived the fact from other observed facts, e.g. default_perm"`
	AgeDays    *int              `json:"age_days,omitempty" jsonschema:"audit edges: whole days between the audit fact and the snapshot"`
	Stale      *bool             `json:"stale,omitempty" jsonschema:"audit edges: true when the fact is older than the maximum audit age, so it counts as not visible (possible reach only)"`
}

// ExplainOutput lists matching evidence edges.
type ExplainOutput struct {
	Summary string    `json:"summary"`
	Edges   []EdgeOut `json:"edges"`
}

func edgeOut(ix *graph.Index, ed graph.Edge, rev bool) EdgeOut {
	at := ""
	if !ed.ObservedAt.IsZero() {
		at = ed.ObservedAt.UTC().Format(time.RFC3339)
	}
	out := EdgeOut{From: ed.From, To: ed.To, Kind: string(ed.Kind), Evidence: string(ed.Evidence),
		SourceAPI: ed.SourceAPI, ObservedAt: at, Attrs: ed.Attrs, Reversed: rev}
	if ed.Evidence == graph.Inferred {
		out.Rule = ed.Attrs[graph.AttrRule]
	}
	if ed.Evidence == graph.Audit {
		if d, ok := ix.AuditAgeDays(ed); ok {
			out.AgeDays = &d
		}
		stale := ix.AuditStale(ed, ix.MaxAuditAge(0))
		out.Stale = &stale
	}
	return out
}

// EvidenceLabel is the human label for an evidence level. not_visible is
// "not visible", never "off" or "absent".
func EvidenceLabel(ev graph.Evidence) string {
	switch ev {
	case graph.Live:
		return "live"
	case graph.Inferred:
		return "inferred"
	case graph.Audit:
		return "audit"
	case graph.Supplied:
		return "supplied file"
	}
	return "not visible"
}

// HopEvidenceLabel is EvidenceLabel for a path hop: a hop demoted for a stale
// audit fact reads "audit, stale".
func HopEvidenceLabel(h graph.Hop) string {
	if h.Stale {
		return string(graph.Audit) + ", stale"
	}
	return EvidenceLabel(h.Evidence)
}

// Explain returns the evidence edges between two nodes. Path hops traverse
// some edges backwards (DEFINED_IN, RESOLVES_TO, USES), so a hop's from/to is
// also matched against the reversed edge.
func (e *Engine) Explain(in ExplainInput) (res ExplainOutput, _ error) {
	defer e.mark(&res.Summary)
	from, err := e.resolve("from", in.From)
	if err != nil {
		return ExplainOutput{}, err
	}
	to, err := e.resolve("to", in.To)
	if err != nil {
		return ExplainOutput{}, err
	}
	kind := strings.ToUpper(strings.TrimSpace(in.Kind))
	out := ExplainOutput{Edges: []EdgeOut{}}
	collect := func(a, b string, rev bool) {
		for _, ed := range e.ix.Out(a) {
			if ed.To == b && (kind == "" || string(ed.Kind) == kind) {
				out.Edges = append(out.Edges, edgeOut(e.ix, ed, rev))
			}
		}
	}
	collect(from, to, false)
	collect(to, from, true)
	// MEMBER_OF points identity -> org:X, while hops use members:X.
	if strings.HasPrefix(to, "members:") {
		collect(from, "org:"+strings.TrimPrefix(to, "members:"), false)
	}
	if len(out.Edges) == 0 {
		k := ""
		if kind != "" {
			k = " of kind " + kind
		}
		out.Summary = fmt.Sprintf("no edge%s between %s and %s", k, from, to)
		return out, nil
	}
	first := out.Edges[0]
	out.Summary = fmt.Sprintf("%s %s %s: evidence %s, from %s at %s", first.From, first.Kind, first.To,
		EvidenceLabel(graph.Evidence(first.Evidence)), first.SourceAPI, first.ObservedAt)
	if loc := fileLine(first.Attrs); loc != "" {
		out.Summary += ", at " + loc
	}
	if first.Evidence == string(graph.Inferred) {
		rule := first.Rule
		if rule == "" {
			rule = "unknown"
		}
		out.Summary += ", rule " + rule
	}
	if first.Stale != nil {
		if first.AgeDays != nil {
			out.Summary += fmt.Sprintf(", age_days %d", *first.AgeDays)
		}
		out.Summary += fmt.Sprintf(", stale=%t", *first.Stale)
		if *first.Stale {
			out.Summary += " (older than the maximum audit age: counts as not visible)"
		}
	}
	if strings.HasPrefix(first.SourceAPI, graph.SourceSupplied) {
		out.Summary += ", read from a supplied file, not from the cloud"
	}
	if r := first.Attrs[graph.AttrReason]; r != "" && first.Evidence == string(graph.NotVisible) {
		out.Summary += "; undecided: " + r
	}
	if len(out.Edges) > 1 {
		out.Summary += fmt.Sprintf(" (+%d more)", len(out.Edges)-1)
	}
	return out, nil
}

// fileLine renders an edge's source position as file:line (or file, when
// the line is unknown). It is "" when the edge has no file attribute.
func fileLine(attrs map[string]string) string {
	f := attrs[graph.AttrFile]
	if f == "" {
		return ""
	}
	if l := attrs[graph.AttrLine]; l != "" {
		f += ":" + l
	}
	if r := attrs[graph.AttrFileRef]; r != "" {
		f += " (" + r + ")"
	}
	return f
}

// CoverageInput is the coverage tool input (no fields).
type CoverageInput struct{}

// CoverageOutput lists what the collector could not see.
type CoverageOutput struct {
	Summary string           `json:"summary"`
	Entries []graph.Coverage `json:"entries"`
	// Orgs counts not_visible nodes, edges and attributes and coverage
	// entries per org (graph.CoverageSummary).
	Orgs []graph.OrgCoverage `json:"orgs" jsonschema:"per org (and enterprise) counts of not_visible nodes, edges and attributes and of coverage entries"`
}

// Coverage lists the facts the token could not see and the access that fixes each.
func (e *Engine) Coverage(CoverageInput) (res CoverageOutput, _ error) {
	defer e.mark(&res.Summary)
	ents := append([]graph.Coverage{}, e.ix.Graph().Coverage...)
	out := CoverageOutput{Entries: ents, Orgs: graph.CoverageSummary(e.ix.Graph())}
	if len(ents) == 0 {
		out.Summary = "every fact gop looked for was visible to the token"
		return out, nil
	}
	scopes := map[string]bool{}
	for _, c := range ents {
		scopes[c.Scope] = true
	}
	out.Summary = fmt.Sprintf("%s not visible across %s; each entry names the access that fixes it",
		plural(len(ents), "fact", "facts"), plural(len(scopes), "scope", "scopes"))
	return out, nil
}
