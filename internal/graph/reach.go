package graph

import (
	"regexp"
	"sort"
	"strings"
)

// The control graph is directed controller -> controlled. It is derived from the
// evidence graph by these rules (attacker holds the left side, gains the right):
//
//	principal -CAN_PUSH->     repo       push access controls the repo
//	identity  -MEMBER_OF->    members:X  an identity gets what all members of X get
//	repo      -DEFINED_IN->   workflow   (reversed) code pushed to a repo changes its workflows
//	workflow  -DEFINED_IN->   repo       a controlled workflow runs in that repo's CI. The repo
//	                                     is counted as reached ("CI reach") but NOT expanded:
//	                                     running CI is not the same as being able to push.
//	workflow  -CAN_PUSH->     repo       ...unless the workflow's GITHUB_TOKEN has contents: write
//	                                     (via=token_write): then the workflow can push to its repo,
//	                                     so this is a full control hop like any CAN_PUSH and the
//	                                     repo is expanded. A not_visible edge (default workflow
//	                                     permissions not readable) makes that control possible.
//	                                     The token can't edit .github/workflows/, but workflows run
//	                                     repo code, so DEFINED_IN (reversed) still expands. A
//	                                     RestrictToken fix drops the workflow's token_write edges.
//	repo      -RESOLVES_TO->  action     (reversed) pushing to the host repo changes the action,
//	                                     only when the ref is mutable (branch or tag). A sha ref
//	                                     (or a PinRef fix) blocks this hop. Branch protection
//	                                     gates it through the action's ref_protected attr:
//	                                       true:    no repo -> action hop. Instead each CAN_PUSH
//	                                                edge into the host repo with via=ref_bypass
//	                                                and ref equal to the action's ref becomes a
//	                                                principal -> action hop. When bypass=unknown
//	                                                the repo -> action hop stays, not_visible.
//	                                       unknown: the repo -> action hop is not_visible, so the
//	                                                path is possible, never confirmed.
//	                                       false or missing: the hop is unchanged.
//	                                     A tag (node ref_kind=tag) is gated the same way
//	                                     through ref_immutable instead (an immutable release
//	                                     or a tag ruleset blocking update and deletion), with
//	                                     ref_bypass edges whose ref is the tag. A ref with
//	                                     ref_ambiguous=true (both a tag and a branch) is not
//	                                     gated at all: the more mutable reading wins.
//	                                     Only this hop is gated. DEFINED_IN stays unconditional:
//	                                     a push to any unprotected branch runs that branch's copy
//	                                     of an on: push workflow with the repo's secrets.
//	action    -USES->         workflow   (reversed) whoever controls an action's content controls
//	action    -USES->         action     every workflow or composite action that uses it. This
//	                                     hop ignores the ref: a sha-pinned action that itself USES
//	                                     a nested branch/tag action stays controllable through the
//	                                     nested one. A sha pin only blocks a path when the whole
//	                                     nested chain is immutable. The only gate is the host
//	                                     repo's actions_access (Actions "Access" setting), checked
//	                                     against the consumer's repo by actionsAccessAllows: a
//	                                     disallowed hop is dropped, and an unknown setting makes a
//	                                     cross-org hop not_visible. No attr: the hop is unchanged.
//	principal -CAN_TRIGGER->  workflow   the principal can cause a risky trigger (pull_request_target,
//	                                     workflow_run, issue_comment, ...) of a workflow that runs
//	                                     attacker-controlled code: a forward control hop like CAN_PUSH.
//	                                     The workflow is controlled, so its EXECUTES_WITH terminals are
//	                                     reached, its repo counts as CI reach, and a via=token_write
//	                                     CAN_PUSH expands to the repo. A HardenTrigger fix drops
//	                                     every CAN_TRIGGER edge into its workflow.
//	workflow  -EXECUTES_WITH-> secret|oidc|runner   terminal impact
//	workflow  -CAN_ASSUME->   cloud_target  terminal impact: a token the workflow mints matches a
//	                                     supplied cloud trust policy (gop enrich --oidc-trust). The
//	                                     hop starts at the workflow, not at the repo's shared oidc
//	                                     node, because each workflow's own claims (environments,
//	                                     job_workflow_ref) decide the match. Evidence supplied counts
//	                                     as confirmed and sets Path.Supplied; an undecided match is
//	                                     not_visible, so possible.
type controlGraph struct {
	out map[string][]cedge
}

type cedge struct {
	to  string
	hop Hop
	ci  bool // reaches a repo's CI only; the target is recorded but not expanded
}

// Hop is one step of an attack path, in control order (From controls To).
// Reverse is true when the underlying evidence edge points the other way
// (DEFINED_IN, RESOLVES_TO and USES are traversed backwards).
type Hop struct {
	Kind      EdgeKind `json:"kind"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Evidence  Evidence `json:"evidence"`
	SourceAPI string   `json:"source_api,omitempty"`
	Reverse   bool     `json:"reverse,omitempty"`
	// Reason says why gop could not decide an undecided CAN_ASSUME match
	// (the edge's attrs.reason); such a hop is not_visible.
	Reason string `json:"reason,omitempty"`
}

// Path is one shortest control path from a principal to a node. Evidence is the
// weakest hop. Unverified is true when any hop is not_visible: such a path is
// "possible" reach, never "confirmed". Supplied is true when a hop comes from a
// user-supplied file (source_api "supplied:<file>"), not from GitHub or the
// cloud: SuppliedNote says which.
type Path struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Hops       []Hop    `json:"hops"`
	Evidence   Evidence `json:"evidence"`
	Unverified bool     `json:"unverified"`
	Supplied   bool     `json:"supplied,omitempty"`
}

// SuppliedFiles lists the supplied files the path's hops were read from, in
// hop order without repeats.
func (p Path) SuppliedFiles() []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range p.Hops {
		if f, ok := strings.CutPrefix(h.SourceAPI, SourceSupplied); ok && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// SuppliedNote is the caveat every summary of a supplied path carries:
// "cloud hop from supplied trust file F, not read from the cloud". "" when the
// path has no supplied hop.
func (p Path) SuppliedNote() string {
	fs := p.SuppliedFiles()
	if len(fs) == 0 {
		return ""
	}
	return "cloud hop from supplied trust file " + strings.Join(fs, ", ") + ", not read from the cloud"
}

func hopsSupplied(hops []Hop) bool {
	for _, h := range hops {
		if h.Evidence == Supplied || strings.HasPrefix(h.SourceAPI, SourceSupplied) {
			return true
		}
	}
	return false
}

// Reached lists node IDs by kind. Orgs are the orgs of the reached repos.
type Reached struct {
	Repos     []string `json:"repos"`
	Workflows []string `json:"workflows"`
	Actions   []string `json:"actions"`
	Secrets   []string `json:"secrets"`
	OIDC      []string `json:"oidc"`
	Runners   []string `json:"runners"`
	Orgs      []string `json:"orgs"`
	// CloudTargets are cloud roles reached through CAN_ASSUME (supplied trust files).
	CloudTargets []string `json:"cloud_targets,omitempty"`
}

// Result of Reach. Confirmed holds nodes reachable through a path where every hop
// is live or audit. Possible holds nodes reachable only through paths with at least
// one not_visible hop; it never overlaps Confirmed. Paths has one shortest path for
// every node in either set (confirmed nodes get a fully verified path).
type Result struct {
	From      string          `json:"from"`
	Confirmed Reached         `json:"confirmed"`
	Possible  Reached         `json:"possible"`
	Paths     map[string]Path `json:"paths"`
}

// Options tune a traversal.
type Options struct {
	// Fixes are applied hypothetically before traversal (see WhatIf).
	Fixes []Fix
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// actionMutable decides whether pushing to an action's host repo changes what
// consumers run. Order: node attr ref_kind, then incoming USES ref_kind attrs
// (any branch/tag wins), then the ref itself (40 hex = sha). Unknown is treated
// as mutable: gop does not assume a pin it did not see.
func (ix *Index) actionMutable(action string) bool {
	if n, ok := ix.nodes[action]; ok {
		switch n.Attrs[AttrRefKind] {
		case "sha":
			return false
		case "branch", "tag":
			return true
		}
	}
	sawSha := false
	for _, e := range ix.in[action] {
		if e.Kind != Uses {
			continue
		}
		switch e.Attrs[AttrRefKind] {
		case "branch", "tag":
			return true
		case "sha":
			sawSha = true
		}
	}
	if sawSha {
		return false
	}
	if i := strings.LastIndex(action, "@"); i >= 0 && shaRe.MatchString(action[i+1:]) {
		return false
	}
	return true
}

// refLock is the one gate on an action's repo -> action hop, shared by branch
// protection and tag immutability: "true" (pushing alone cannot change the
// ref; only ref_bypass principals can), "unknown" (not visible: the hop stays,
// not_visible) or "" (no gate). A tag reads ref_immutable, anything else reads
// ref_protected, and ref_ambiguous=true (both a tag and a branch) is never
// gated.
func refLock(n Node) string {
	if n.Attrs[AttrRefAmbiguous] == "true" {
		return ""
	}
	v := n.Attrs[AttrRefProtected]
	if n.Attrs[AttrRefKind] == "tag" {
		v = n.Attrs[AttrRefImmutable]
	}
	if v == "true" || v == "unknown" {
		return v
	}
	return ""
}

// RefState says whether an action ref can change without a new pin (see
// Index.RefState).
type RefState string

const (
	// RefPinned: the ref is a commit SHA.
	RefPinned RefState = "pinned"
	// RefLocked: a branch or tag that refLock gates ("true"), with known
	// bypass actors and no via=ref_bypass edge for it: pushing cannot move it.
	RefLocked RefState = "locked"
	// RefPossiblyMutable: the gate is not visible (refLock "unknown", or
	// locked with bypass=unknown). Reach keeps the hop as not_visible.
	RefPossiblyMutable RefState = "possibly_mutable"
	// RefMutable: unlocked, ambiguous (tag and branch), or locked with a
	// bypass edge that applies.
	RefMutable RefState = "mutable"
)

// RefState classifies action with the same decision buildControl makes for
// its repo -> action hop: actionMutable first (a SHA pin is RefPinned), then
// refLock and the via=ref_bypass edges into each RESOLVES_TO host.
func (ix *Index) RefState(action string) RefState {
	if !ix.actionMutable(action) {
		return RefPinned
	}
	n := ix.nodes[action]
	switch refLock(n) {
	case "unknown":
		return RefPossiblyMutable
	case "true":
		for _, e := range ix.out[action] {
			if e.Kind == ResolvesTo && len(ix.bypassEdges(n, e.To)) > 0 {
				return RefMutable
			}
		}
		if n.Attrs[AttrBypass] == "unknown" {
			return RefPossiblyMutable
		}
		return RefLocked
	}
	return RefMutable
}

// MutabilityNote is the label for a RefPossiblyMutable action ref, naming the
// gate gop could not see; it is "" for any other state.
func (ix *Index) MutabilityNote(action string) string {
	if ix.RefState(action) != RefPossiblyMutable {
		return ""
	}
	n := ix.nodes[action]
	switch {
	case refLock(n) == "true":
		return "possibly mutable (bypass actors not visible)"
	case n.Attrs[AttrRefKind] == "tag":
		return "possibly mutable (immutability not visible)"
	default:
		return "possibly mutable (protection not visible)"
	}
}

// bypassEdges lists the via=ref_bypass CAN_PUSH edges into host that apply to
// action node n (their ref is the action's ref).
func (ix *Index) bypassEdges(n Node, host string) []Edge {
	ref := actionRef(n)
	var out []Edge
	for _, p := range ix.in[host] {
		if p.Kind == CanPush && p.Attrs[AttrVia] == ViaRefBypass && p.Attrs[AttrRef] == ref {
			out = append(out, p)
		}
	}
	return out
}

// addResolves adds the control hops for one RESOLVES_TO edge of a mutable,
// unpinned action, gated by refLock (see the rules above).
func (ix *Index) addResolves(e Edge, add func(from, to string, e Edge, reverse, ci bool)) {
	n := ix.nodes[e.From]
	hidden := e
	hidden.Evidence = NotVisible
	switch refLock(n) {
	case "true":
		if n.Attrs[AttrBypass] == "unknown" {
			add(e.To, e.From, hidden, true, false)
		}
		for _, p := range ix.bypassEdges(n, e.To) {
			add(p.From, e.From, p, false, false)
		}
	case "unknown":
		add(e.To, e.From, hidden, true, false)
	default:
		add(e.To, e.From, e, true, false)
	}
}

// lockedNoBypass reports whether the RESOLVES_TO edge e is fully gated: its
// action's ref is locked (refLock "true"), its bypass actors are known, and no
// ref_bypass edge applies. A pin then changes nothing.
func (ix *Index) lockedNoBypass(e Edge) bool {
	n := ix.nodes[e.From]
	return refLock(n) == "true" && n.Attrs[AttrBypass] != "unknown" && len(ix.bypassEdges(n, e.To)) == 0
}

// actionRef is the ref of an action_ref node: its ref attr, else the part of
// the ID after the last "@".
func actionRef(n Node) string {
	if r := n.Attrs[AttrRef]; r != "" {
		return r
	}
	if i := strings.LastIndex(n.ID, "@"); i >= 0 {
		return n.ID[i+1:]
	}
	return ""
}

func (ix *Index) membersOf(orgID string) string {
	if strings.HasPrefix(orgID, "org:") {
		return "members:" + strings.TrimPrefix(orgID, "org:")
	}
	return orgID
}

func (ix *Index) buildControl(fixes []Fix) *controlGraph {
	var fs fixSet
	for _, f := range fixes {
		f.apply(&fs)
	}
	type key struct {
		from, to string
		ci       bool
	}
	best := map[key]cedge{}
	add := func(from, to string, e Edge, reverse, ci bool) {
		k := key{from, to, ci}
		ce := cedge{to: to, ci: ci, hop: Hop{Kind: e.Kind, From: from, To: to, Evidence: e.Evidence, SourceAPI: e.SourceAPI, Reverse: reverse}}
		if e.Kind == CanAssume && e.Evidence == NotVisible {
			ce.hop.Reason = e.Attrs[AttrReason]
		}
		// Parallel evidence edges collapse to one control edge: the strongest
		// evidence wins, ties go to the smallest (kind, source_api). Without the
		// tie-break the kept hop, and so the source_api in reported paths,
		// depended on the order of g.Edges.
		if old, ok := best[k]; ok {
			or, nr := evRank(old.hop.Evidence), evRank(e.Evidence)
			if or > nr || (or == nr && (old.hop.Kind < e.Kind || (old.hop.Kind == e.Kind && old.hop.SourceAPI <= e.SourceAPI))) {
				return
			}
		}
		best[k] = ce
	}
	mutable := map[string]bool{}
	for i, e := range ix.g.Edges {
		switch e.Kind {
		case CanPush:
			if fs.removesPush(e) {
				continue
			}
			add(e.From, e.To, e, false, false)
		case MemberOf:
			add(e.From, ix.membersOf(e.To), e, false, false)
		case DefinedIn:
			add(e.To, e.From, e, true, false)
			add(e.From, e.To, e, false, true)
		case ResolvesTo:
			m, ok := mutable[e.From]
			if !ok {
				m = ix.actionMutable(e.From)
				mutable[e.From] = m
			}
			if m && !fs.pinned[e.From] {
				ix.addResolves(e, add)
			}
		case Uses:
			if ix.gates != nil {
				switch ix.gates[i] {
				case gateClosed:
					continue
				case gateHidden:
					e.Evidence = NotVisible
				}
			}
			add(e.To, e.From, e, true, false)
		case CanTrigger:
			if fs.removesTrigger(e) {
				continue
			}
			add(e.From, e.To, e, false, false)
		case ExecutesWith, CanAssume:
			add(e.From, e.To, e, false, false)
		}
	}
	cg := &controlGraph{out: map[string][]cedge{}}
	for k, ce := range best {
		cg.out[k.from] = append(cg.out[k.from], ce)
	}
	for _, es := range cg.out {
		sort.Slice(es, func(i, j int) bool {
			if es[i].to != es[j].to {
				return es[i].to < es[j].to
			}
			return !es[i].ci && es[j].ci
		})
	}
	return cg
}

func (ix *Index) control(fixes []Fix) *controlGraph {
	if len(fixes) == 0 {
		return ix.base
	}
	return ix.buildControl(fixes)
}

type visit struct {
	path       []Hop // first (shortest) path found, reported
	ctrlPath   []Hop // shortest path that gives full control (used for expansion)
	controlled bool
}

func pathEvidence(hops []Hop) Evidence {
	ev := Live
	for _, h := range hops {
		ev = weakest(ev, h.Evidence)
	}
	return ev
}

// bfs walks the control graph in layers. Among equally short candidate paths it
// keeps the one with the strongest evidence (ties: first in sorted order), so the
// output is deterministic. verifiedOnly skips not_visible hops.
func (cg *controlGraph) bfs(from string, verifiedOnly bool) map[string]*visit {
	seen := map[string]*visit{from: {controlled: true}}
	frontier := []string{from}
	type cand struct {
		path []Hop
		ev   Evidence
		ctrl bool
	}
	for len(frontier) > 0 {
		next := map[string]*cand{}
		for _, u := range frontier {
			base := seen[u].ctrlPath
			for _, e := range cg.out[u] {
				if verifiedOnly && !Verified(e.hop.Evidence) {
					continue
				}
				if st := seen[e.to]; st != nil && (st.controlled || e.ci) {
					continue
				}
				p := make([]Hop, len(base)+1)
				copy(p, base)
				p[len(base)] = e.hop
				c := &cand{path: p, ev: pathEvidence(p), ctrl: !e.ci}
				old := next[e.to]
				if old == nil || (c.ctrl && !old.ctrl) || (c.ctrl == old.ctrl && evRank(c.ev) > evRank(old.ev)) {
					next[e.to] = c
				}
			}
		}
		frontier = frontier[:0]
		for _, v := range sortedCandKeys(next) {
			c := next[v]
			st := seen[v]
			if st == nil {
				st = &visit{path: c.path}
				seen[v] = st
			}
			if c.ctrl {
				st.controlled = true
				st.ctrlPath = c.path
				frontier = append(frontier, v)
			}
		}
	}
	return seen
}

func sortedCandKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Reach is a BFS over the control graph from a principal (e.g. "members:acme-actions",
// "identity:bob" or "repo:O/R"). The start node itself is not listed.
func Reach(g *Graph, from string, opts Options) Result {
	return NewIndex(g).Reach(from, opts)
}

// Reach on a prebuilt index.
func (ix *Index) Reach(from string, opts Options) Result {
	return ix.reach(ix.control(opts.Fixes), from)
}

func (ix *Index) reach(cg *controlGraph, from string) Result {
	conf := cg.bfs(from, true)
	all := cg.bfs(from, false)
	res := Result{From: from, Paths: map[string]Path{}}
	confOrgs, possOrgs := map[string]bool{}, map[string]bool{}
	for _, id := range sortedCandKeys(all) {
		if id == from {
			continue
		}
		var (
			hops []Hop
			r    *Reached
		)
		if v, ok := conf[id]; ok {
			hops, r = v.path, &res.Confirmed
		} else {
			hops, r = all[id].path, &res.Possible
		}
		ev := pathEvidence(hops)
		res.Paths[id] = Path{From: from, To: id, Hops: hops, Evidence: ev, Unverified: !Verified(ev), Supplied: hopsSupplied(hops)}
		switch ix.Kind(id) {
		case KindRepo:
			r.Repos = append(r.Repos, id)
			if o := OrgOf(id); o != "" {
				if r == &res.Confirmed {
					confOrgs[o] = true
				} else {
					possOrgs[o] = true
				}
			}
		case KindWorkflow:
			r.Workflows = append(r.Workflows, id)
		case KindActionRef:
			r.Actions = append(r.Actions, id)
		case KindSecret:
			r.Secrets = append(r.Secrets, id)
		case KindOIDC:
			r.OIDC = append(r.OIDC, id)
		case KindRunner:
			r.Runners = append(r.Runners, id)
		case KindCloudTarget:
			r.CloudTargets = append(r.CloudTargets, id)
		}
	}
	res.Confirmed.Orgs = sortedKeys(confOrgs)
	for o := range confOrgs {
		delete(possOrgs, o)
	}
	res.Possible.Orgs = sortedKeys(possOrgs)
	return res
}

// WhoCanReach lists, for each principal that can control target (a repo, workflow,
// action, terminal or cloud_target), one shortest path. Confirmed paths come first, then
// unverified ones; within each group shorter paths first, then by principal ID.
func WhoCanReach(g *Graph, target string) []Path {
	return NewIndex(g).WhoCanReach(target)
}

// WhoCanReach on a prebuilt index.
func (ix *Index) WhoCanReach(target string) []Path {
	var out []Path
	for _, p := range ix.Principals() {
		if p == target {
			continue
		}
		if path, ok := ix.reach(ix.base, p).Paths[target]; ok {
			out = append(out, path)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Unverified != out[j].Unverified {
			return !out[i].Unverified
		}
		if len(out[i].Hops) != len(out[j].Hops) {
			return len(out[i].Hops) < len(out[j].Hops)
		}
		return out[i].From < out[j].From
	})
	return out
}

// PinnedExposure is a SHA-pinned (or locked) action that a principal can still
// change, because the pinned action (a composite action or reusable workflow)
// itself uses a mutable ref. Pinning the outer action alone does not block the
// path.
type PinnedExposure struct {
	Action    string `json:"action"`             // the SHA-pinned or locked action ref
	Via       string `json:"via"`                // the mutable action ref on the path that opens it
	ViaNote   string `json:"via_note,omitempty"` // MutabilityNote of Via, when it is only possibly mutable
	Consumers int    `json:"consumers"`          // workflows that use Action directly
	Path      Path   `json:"path"`               // one shortest path to Action, confirmed preferred
}

// PinnedExposures lists every action that cannot change without a new pin
// (RefState RefPinned or RefLocked) that some principal can still control
// through a nested mutable action, sorted by action ID. The paths come from
// Reach, so a nested ref that refLock locks opens nothing, and one whose gate
// is not visible gives a possible path with ViaNote set. Each gets one path,
// chosen like WhoCanReach: confirmed first, then fewer hops, then principal
// ID.
func (ix *Index) PinnedExposures() []PinnedExposure {
	cands := map[string]bool{}
	for _, e := range ix.g.Edges {
		if e.Kind == Uses && ix.Kind(e.From) == KindActionRef && !cands[e.From] {
			if st := ix.RefState(e.From); st == RefPinned || st == RefLocked {
				cands[e.From] = true
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	better := func(a, b Path) bool {
		if a.Unverified != b.Unverified {
			return !a.Unverified
		}
		if len(a.Hops) != len(b.Hops) {
			return len(a.Hops) < len(b.Hops)
		}
		return a.From < b.From
	}
	best := map[string]Path{}
	for _, p := range ix.Principals() {
		r := ix.reach(ix.base, p)
		for a := range cands {
			if path, ok := r.Paths[a]; ok {
				if old, seen := best[a]; !seen || better(path, old) {
					best[a] = path
				}
			}
		}
	}
	out := make([]PinnedExposure, 0, len(best))
	for _, a := range sortedCandKeys(best) {
		pe := PinnedExposure{Action: a, Path: best[a]}
		for _, h := range pe.Path.Hops {
			// The hop into the nested ref: host -> action (RESOLVES_TO,
			// reversed), or a via=ref_bypass CAN_PUSH straight into it.
			if h.Kind == ResolvesTo || (h.Kind == CanPush && ix.Kind(h.To) == KindActionRef) {
				pe.Via = h.To
			}
		}
		if pe.Via != "" {
			pe.ViaNote = ix.MutabilityNote(pe.Via)
		}
		for _, e := range ix.in[a] {
			if e.Kind == Uses && ix.Kind(e.From) == KindWorkflow {
				pe.Consumers++
			}
		}
		out = append(out, pe)
	}
	return out
}
