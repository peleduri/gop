// Package diff compares two gop graph snapshots and reports posture drift:
// new and removed attack paths, setting changes, edge changes, score deltas and
// coverage gaps opened or closed.
//
// gop never turns "couldn't see" into "off". A setting, edge or path that
// disappears because the newer snapshot could not see it is reported as lost
// visibility, never as turned off or removed.
package diff

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Path change statuses.
const (
	// Added: the pair is reachable in new and was not in old.
	Added = "added"
	// Removed: the pair was reachable in old, is not in new, and new can see the
	// nodes on the old path.
	Removed = "removed"
	// Upgraded: possible in old, confirmed in new.
	Upgraded = "upgraded"
	// Downgraded: confirmed in old, possible in new. A hop became not visible:
	// an evidence change, not a fix.
	Downgraded = "downgraded"
	// LostVisibility: the pair (or setting, or edge) is gone from new, but new
	// cannot see part of what made it up. Unknown, not absent.
	LostVisibility = "lost_visibility"
	// GainedVisibility: new can see a fact old could not see.
	GainedVisibility = "gained_visibility"
)

// Setting change statuses (in addition to LostVisibility and GainedVisibility).
const (
	// Changed: both snapshots see the setting and its value differs.
	Changed = "changed"
	// NodeAdded: the node is new in the newer snapshot.
	NodeAdded = "node_added"
	// NodeRemoved: the node is gone and the newer snapshot has no visibility gap for it.
	NodeRemoved = "node_removed"
)

// Errors returned by Compare when the snapshots are not comparable.
var (
	ErrEnterpriseMismatch = errors.New("diff: snapshots are of different enterprises")
	ErrSchemaMismatch     = errors.New("diff: snapshots have different major schema versions")
	ErrHostMismatch       = errors.New("diff: snapshots are from different GitHub hosts")
)

// Meta identifies one snapshot.
type Meta struct {
	Enterprise  string    `json:"enterprise"`
	CollectedAt time.Time `json:"collected_at"`
	Schema      string    `json:"schema"`
}

// PathChange is the change of one (principal, target) pair. Target is a repo,
// secret, oidc or runner node. Old or New is nil when the pair is absent on that
// side. Principals are the scoring principals (graph.Index.ScoringPrincipals),
// the set TopPaths and WhatIf count, so an identity that only inherits its
// org's reach is not repeated.
type PathChange struct {
	Principal  string         `json:"principal"`
	Target     string         `json:"target"`
	TargetKind graph.NodeKind `json:"target_kind"`
	Status     string         `json:"status"`
	Old        *graph.Path    `json:"old,omitempty"`
	New        *graph.Path    `json:"new,omitempty"`
}

// PathChanges lists path changes ordered by status, then severity
// (oidc > secret > runner > repo), then principal and target.
type PathChanges []PathChange

// Count returns how many changes have this status. For Added, confirmed selects
// pairs whose new path is fully verified (true) or not (false).
func (pc PathChanges) Count(status string, confirmed bool) int {
	n := 0
	for _, c := range pc {
		if c.Status != status {
			continue
		}
		if status == Added && c.New != nil && c.New.Unverified == confirmed {
			continue
		}
		n++
	}
	return n
}

// SettingChange is one node attribute that changed. Evidence is the effective
// evidence of the attribute on each side (attr_evidence, else node evidence).
type SettingChange struct {
	Node        string         `json:"node"`
	Key         string         `json:"key"`
	Status      string         `json:"status"`
	Old         string         `json:"old"`
	New         string         `json:"new"`
	OldEvidence graph.Evidence `json:"old_evidence,omitempty"`
	NewEvidence graph.Evidence `json:"new_evidence,omitempty"`
}

// EdgeFact is one side of an edge change.
type EdgeFact struct {
	Evidence  graph.Evidence    `json:"evidence"`
	SourceAPI string            `json:"source_api,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// EdgeChange is a change to the edge (From, Kind, To).
type EdgeChange struct {
	From   string         `json:"from"`
	Kind   graph.EdgeKind `json:"kind"`
	To     string         `json:"to"`
	Status string         `json:"status"`
	Old    *EdgeFact      `json:"old,omitempty"`
	New    *EdgeFact      `json:"new,omitempty"`
}

// EdgeChanges groups edge changes. Each list is sorted by kind, from, to.
// LostVisibility holds edges that are gone (or now not_visible) where the newer
// snapshot cannot see an endpoint: they are not reported as removed.
type EdgeChanges struct {
	Added          []EdgeChange `json:"added"`
	Removed        []EdgeChange `json:"removed"`
	Changed        []EdgeChange `json:"changed"`
	LostVisibility []EdgeChange `json:"lost_visibility"`
}

// ScoreDelta is one principal's blast radius before and after. A principal
// missing on one side has a zero Score there. Confirmed and possible deltas
// are kept separate.
type ScoreDelta struct {
	Principal      string      `json:"principal"`
	Old            graph.Score `json:"old"`
	New            graph.Score `json:"new"`
	DeltaConfirmed float64     `json:"delta_confirmed"`
	DeltaPossible  float64     `json:"delta_possible"`
}

// CoverageChanges lists coverage gaps that opened (in new only) or closed (in old only).
type CoverageChanges struct {
	Opened []graph.Coverage `json:"opened"`
	Closed []graph.Coverage `json:"closed"`
}

// TotalsDelta holds enterprise totals on each side. ConfirmedPairs and
// PossiblePairs count (principal, repo) pairs.
type TotalsDelta struct {
	Old graph.Totals `json:"old"`
	New graph.Totals `json:"new"`
}

// Report is the result of Compare.
type Report struct {
	// Summary is the one-sentence Headline of the full report, kept when Only
	// hides sections so the summary still describes every change.
	Summary  string          `json:"summary"`
	Old      Meta            `json:"old"`
	New      Meta            `json:"new"`
	Paths    PathChanges     `json:"paths"`
	Settings []SettingChange `json:"settings"`
	Edges    EdgeChanges     `json:"edges"`
	Scores   []ScoreDelta    `json:"scores"`
	Coverage CoverageChanges `json:"coverage"`
	Totals   TotalsDelta     `json:"totals"`
}

// Empty reports whether nothing changed between the snapshots.
func (r Report) Empty() bool {
	return len(r.Paths) == 0 && len(r.Settings) == 0 && len(r.Edges.Added) == 0 &&
		len(r.Edges.Removed) == 0 && len(r.Edges.Changed) == 0 && len(r.Edges.LostVisibility) == 0 &&
		len(r.Scores) == 0 && len(r.Coverage.Opened) == 0 && len(r.Coverage.Closed) == 0 &&
		r.Totals.Old.ConfirmedPairs == r.Totals.New.ConfirmedPairs &&
		r.Totals.Old.PossiblePairs == r.Totals.New.PossiblePairs
}

// Options tune Compare.
type Options struct {
	// Force compares snapshots of different enterprises, GitHub hosts or major
	// schema versions.
	Force bool
}

// Compare diffs two snapshots. It refuses snapshots of different enterprises,
// GitHub hosts or major schema versions; use CompareWith and Options.Force to
// override.
func Compare(old, new *graph.Graph) (Report, error) {
	return CompareWith(old, new, Options{})
}

// CompareWith is Compare with options.
func CompareWith(old, new *graph.Graph, opts Options) (Report, error) {
	if old == nil || new == nil {
		return Report{}, errors.New("diff: both snapshots are required")
	}
	if !opts.Force {
		if old.Enterprise != new.Enterprise {
			return Report{}, fmt.Errorf("%w: %q vs %q (use --force to compare anyway)", ErrEnterpriseMismatch, old.Enterprise, new.Enterprise)
		}
		// A graph that does not record its host (older or synthetic) is
		// compared with any host.
		if ho, hn := graph.Host(old), graph.Host(new); ho != "" && hn != "" && ho != hn {
			return Report{}, fmt.Errorf("%w: %q vs %q (use --force to compare anyway)", ErrHostMismatch, ho, hn)
		}
		if mo, mn := schemaMajor(old.Schema), schemaMajor(new.Schema); mo != mn {
			return Report{}, fmt.Errorf("%w: %q vs %q (use --force to compare anyway)", ErrSchemaMismatch, old.Schema, new.Schema)
		}
	}
	oix, nix := graph.NewIndex(old), graph.NewIndex(new)
	ovis, nvis := newVisibility(old, oix), newVisibility(new, nix)
	r := Report{
		Old:      Meta{Enterprise: old.Enterprise, CollectedAt: old.CollectedAt, Schema: old.Schema},
		New:      Meta{Enterprise: new.Enterprise, CollectedAt: new.CollectedAt, Schema: new.Schema},
		Paths:    PathChanges{},
		Settings: []SettingChange{},
		Edges:    EdgeChanges{Added: []EdgeChange{}, Removed: []EdgeChange{}, Changed: []EdgeChange{}, LostVisibility: []EdgeChange{}},
		Scores:   []ScoreDelta{},
		Coverage: CoverageChanges{Opened: []graph.Coverage{}, Closed: []graph.Coverage{}},
	}
	r.Paths = comparePaths(oix, nix, ovis, nvis)
	r.Settings = compareSettings(oix, nix, ovis, nvis)
	r.Edges = compareEdges(old, new, ovis, nvis)
	r.Scores, r.Totals = compareScores(oix, nix)
	r.Coverage = compareCoverage(old, new)
	r.Summary = r.Headline()
	return r, nil
}

// schemaMajor returns "gop.graph/v1" for "gop.graph/v1" and "gop.graph/v1.2".
func schemaMajor(s string) string {
	i := strings.LastIndex(s, "/v")
	if i < 0 {
		return s
	}
	if j := strings.Index(s[i:], "."); j >= 0 {
		return s[:i+j]
	}
	return s
}

// visibility answers "could this snapshot see node X?".
type visibility struct {
	ix  *graph.Index
	gap map[string]map[string]bool // coverage scope -> facts
	ent string
}

func newVisibility(g *graph.Graph, ix *graph.Index) visibility {
	v := visibility{ix: ix, gap: map[string]map[string]bool{}, ent: "enterprise:" + g.Enterprise}
	for _, c := range g.Coverage {
		if v.gap[c.Scope] == nil {
			v.gap[c.Scope] = map[string]bool{}
		}
		v.gap[c.Scope][c.Fact] = true
	}
	return v
}

// settingKeys are per-node settings. A coverage gap on one of them (e.g.
// ip_allow_list) does not hide the scope's structure (repos, workflows, push access).
var settingKeys = map[string]bool{
	graph.AttrSSO: true, graph.AttrTwoFactor: true, graph.AttrDefaultPerm: true,
	graph.AttrMembersCreate: true, graph.AttrChangeVisiblity: true, graph.AttrDeleteRepos: true,
	graph.AttrPrivateForks: true, graph.AttrIPAllowList: true, graph.AttrIPAllowEntries: true,
	graph.AttrIPAllowListEntries: true, graph.AttrIPAllowListApps: true,
	graph.AttrMembers: true, graph.AttrArchived: true, graph.AttrVisibility: true,
}

func (v visibility) scopes(id string) []string {
	out := []string{id, v.ent}
	if o := graph.OrgOf(id); o != "" && o != id {
		out = append(out, o)
	}
	return out
}

// hiddenNode reports whether the snapshot cannot fully see the node: it is
// declared not_visible, or a coverage gap on a structural fact covers its scope
// (the node itself, its org, or the enterprise).
func (v visibility) hiddenNode(id string) bool {
	if id == "" {
		return false
	}
	if n, ok := v.ix.Node(id); ok && n.Evidence == graph.NotVisible {
		return true
	}
	for _, s := range v.scopes(id) {
		for fact := range v.gap[s] {
			if !settingKeys[fact] {
				return true
			}
		}
	}
	return false
}

// hiddenSetting reports whether a coverage gap names this setting on the node's scope.
func (v visibility) hiddenSetting(id, key string) bool {
	for _, s := range v.scopes(id) {
		if v.gap[s][key] {
			return true
		}
	}
	return false
}

func (v visibility) hiddenPath(p *graph.Path) bool {
	if p == nil {
		return false
	}
	if v.hiddenNode(p.From) || v.hiddenNode(p.To) {
		return true
	}
	for _, h := range p.Hops {
		if v.hiddenNode(h.From) || v.hiddenNode(h.To) {
			return true
		}
	}
	return false
}

// severity orders target kinds: cloud_target > oidc > secret > runner > repo.
func severity(k graph.NodeKind) int {
	switch k {
	case graph.KindCloudTarget:
		return -1
	case graph.KindOIDC:
		return 0
	case graph.KindSecret:
		return 1
	case graph.KindRunner:
		return 2
	case graph.KindRepo:
		return 3
	}
	return 4
}

var pathStatusOrder = map[string]int{Added: 0, Upgraded: 1, Downgraded: 2, LostVisibility: 3, Removed: 4, GainedVisibility: 5}

func targets(r graph.Reached) []string {
	var out []string
	for _, l := range [][]string{r.Repos, r.Secrets, r.OIDC, r.Runners, r.CloudTargets} {
		out = append(out, l...)
	}
	return out
}

// reachMap returns target -> path for every repo, secret, oidc, runner and cloud target the
// principal reaches (confirmed or possible).
func reachMap(ix *graph.Index, principal string) map[string]graph.Path {
	res := ix.Reach(principal, graph.Options{})
	out := map[string]graph.Path{}
	for _, t := range append(targets(res.Confirmed), targets(res.Possible)...) {
		out[t] = res.Paths[t]
	}
	return out
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func comparePaths(oix, nix *graph.Index, ovis, nvis visibility) PathChanges {
	out := PathChanges{}
	for _, p := range union(oix.ScoringPrincipals(), nix.ScoringPrincipals()) {
		om, nm := reachMap(oix, p), reachMap(nix, p)
		keys := make([]string, 0, len(om)+len(nm))
		for t := range om {
			keys = append(keys, t)
		}
		for t := range nm {
			if _, ok := om[t]; !ok {
				keys = append(keys, t)
			}
		}
		for _, t := range keys {
			op, oOK := om[t]
			np, nOK := nm[t]
			c := PathChange{Principal: p, Target: t}
			if oOK {
				c.Old = &op
				c.TargetKind = oix.Kind(t)
			}
			if nOK {
				c.New = &np
				c.TargetKind = nix.Kind(t)
			}
			switch {
			case oOK && nOK:
				switch {
				case op.Unverified && !np.Unverified:
					c.Status = Upgraded
				case !op.Unverified && np.Unverified:
					c.Status = Downgraded
				default:
					continue
				}
			case oOK:
				c.Status = Removed
				if nvis.hiddenPath(c.Old) {
					c.Status = LostVisibility
				}
			default:
				c.Status = Added
				if ovis.hiddenPath(c.New) {
					c.Status = GainedVisibility
				}
			}
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if pathStatusOrder[a.Status] != pathStatusOrder[b.Status] {
			return pathStatusOrder[a.Status] < pathStatusOrder[b.Status]
		}
		if severity(a.TargetKind) != severity(b.TargetKind) {
			return severity(a.TargetKind) < severity(b.TargetKind)
		}
		if a.Principal != b.Principal {
			return a.Principal < b.Principal
		}
		return a.Target < b.Target
	})
	return out
}

// effective returns an attribute's value and evidence, and whether it is known:
// present, not "unknown"/"not_visible", and not not_visible evidence.
func effective(n graph.Node, key string, vis visibility) (string, graph.Evidence, bool) {
	val, has := n.Attrs[key]
	ev := n.Evidence
	if e, ok := n.AttrEvidence[key]; ok {
		ev = e
	}
	known := has && val != "" && val != "unknown" && val != string(graph.NotVisible) &&
		ev != graph.NotVisible && !vis.hiddenSetting(n.ID, key)
	return val, ev, known
}

func nodeIDs(g *graph.Graph) []string {
	ids := make([]string, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		ids = append(ids, n.ID)
	}
	return ids
}

func attrKeys(a, b graph.Node) []string {
	set := map[string]bool{}
	for k := range a.Attrs {
		set[k] = true
	}
	for k := range a.AttrEvidence {
		set[k] = true
	}
	for k := range b.Attrs {
		set[k] = true
	}
	for k := range b.AttrEvidence {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func compareSettings(oix, nix *graph.Index, ovis, nvis visibility) []SettingChange {
	out := []SettingChange{}
	for _, id := range union(nodeIDs(oix.Graph()), nodeIDs(nix.Graph())) {
		on, oOK := oix.Node(id)
		nn, nOK := nix.Node(id)
		for _, k := range attrKeys(on, nn) {
			ov, oev, oKnown := effective(on, k, ovis)
			nv, nev, nKnown := effective(nn, k, nvis)
			c := SettingChange{Node: id, Key: k, Old: ov, New: nv}
			if oOK {
				c.OldEvidence = oev
			}
			if nOK {
				c.NewEvidence = nev
			}
			switch {
			case oOK && !nOK:
				if !oKnown {
					continue
				}
				c.Status = NodeRemoved
				if nvis.hiddenNode(id) {
					c.Status = LostVisibility
				}
			case !oOK && nOK:
				if !nKnown {
					continue
				}
				c.Status = NodeAdded
				if ovis.hiddenNode(id) {
					c.Status = GainedVisibility
				}
			case oKnown && !nKnown:
				c.Status = LostVisibility
			case !oKnown && nKnown:
				c.Status = GainedVisibility
			case oKnown && nKnown && ov != nv:
				c.Status = Changed
			default:
				continue
			}
			out = append(out, c)
		}
	}
	return out
}

type edgeKey struct {
	from string
	kind graph.EdgeKind
	to   string
}

func evRank(e graph.Evidence) int {
	switch e {
	case graph.Live:
		return 3
	case graph.Inferred:
		return 2
	case graph.Audit:
		return 1
	}
	return 0
}

// edgeFacts collapses parallel edges (same from, kind, to) to the strongest evidence.
func edgeFacts(g *graph.Graph) map[edgeKey]EdgeFact {
	out := map[edgeKey]EdgeFact{}
	for _, e := range g.Edges {
		k := edgeKey{e.From, e.Kind, e.To}
		f := EdgeFact{Evidence: e.Evidence, SourceAPI: e.SourceAPI, Attrs: e.Attrs}
		if old, ok := out[k]; ok {
			if evRank(old.Evidence) > evRank(f.Evidence) ||
				(evRank(old.Evidence) == evRank(f.Evidence) && old.SourceAPI <= f.SourceAPI) {
				continue
			}
		}
		out[k] = f
	}
	return out
}

func sameAttrs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func compareEdges(old, new *graph.Graph, ovis, nvis visibility) EdgeChanges {
	of, nf := edgeFacts(old), edgeFacts(new)
	out := EdgeChanges{Added: []EdgeChange{}, Removed: []EdgeChange{}, Changed: []EdgeChange{}, LostVisibility: []EdgeChange{}}
	for k, o := range of {
		c := EdgeChange{From: k.from, Kind: k.kind, To: k.to, Old: &o}
		n, ok := nf[k]
		switch {
		case !ok:
			if nvis.hiddenNode(k.from) || nvis.hiddenNode(k.to) {
				c.Status = LostVisibility
				out.LostVisibility = append(out.LostVisibility, c)
			} else {
				c.Status = Removed
				out.Removed = append(out.Removed, c)
			}
		case o.Evidence != n.Evidence || !sameAttrs(o.Attrs, n.Attrs):
			c.New = &n
			switch {
			case graph.Verified(o.Evidence) && !graph.Verified(n.Evidence):
				c.Status = LostVisibility
				out.LostVisibility = append(out.LostVisibility, c)
			case !graph.Verified(o.Evidence) && graph.Verified(n.Evidence):
				c.Status = GainedVisibility
				out.Changed = append(out.Changed, c)
			default:
				c.Status = Changed
				out.Changed = append(out.Changed, c)
			}
		}
	}
	for k, n := range nf {
		if _, ok := of[k]; ok {
			continue
		}
		c := EdgeChange{From: k.from, Kind: k.kind, To: k.to, Status: Added, New: &n}
		if ovis.hiddenNode(k.from) || ovis.hiddenNode(k.to) {
			c.Status = GainedVisibility
		}
		out.Added = append(out.Added, c)
	}
	for _, l := range [][]EdgeChange{out.Added, out.Removed, out.Changed, out.LostVisibility} {
		sort.Slice(l, func(i, j int) bool {
			a, b := l[i], l[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.From != b.From {
				return a.From < b.From
			}
			return a.To < b.To
		})
	}
	return out
}

func compareScores(oix, nix *graph.Index) ([]ScoreDelta, TotalsDelta) {
	oldScores, newScores := oix.Scores(), nix.Scores()
	t := TotalsDelta{Old: oix.Totals(), New: nix.Totals()}
	om, nm := map[string]graph.Score{}, map[string]graph.Score{}
	for _, s := range oldScores {
		om[s.Principal] = s
	}
	for _, s := range newScores {
		nm[s.Principal] = s
	}
	out := []ScoreDelta{}
	for _, p := range union(oix.ScoringPrincipals(), nix.ScoringPrincipals()) {
		o, ok := om[p]
		if !ok {
			o = graph.Score{Principal: p}
		}
		n, ok := nm[p]
		if !ok {
			n = graph.Score{Principal: p}
		}
		if o.Score == n.Score && o.PossibleScore == n.PossibleScore && o.Confirmed == n.Confirmed && o.Possible == n.Possible {
			continue
		}
		out = append(out, ScoreDelta{Principal: p, Old: o, New: n, DeltaConfirmed: n.Score - o.Score, DeltaPossible: n.PossibleScore - o.PossibleScore})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DeltaConfirmed != out[j].DeltaConfirmed {
			return out[i].DeltaConfirmed > out[j].DeltaConfirmed
		}
		if out[i].DeltaPossible != out[j].DeltaPossible {
			return out[i].DeltaPossible > out[j].DeltaPossible
		}
		return out[i].Principal < out[j].Principal
	})
	return out, t
}

func covKey(c graph.Coverage) string { return c.Scope + "\x00" + c.Fact }

func compareCoverage(old, new *graph.Graph) CoverageChanges {
	om, nm := map[string]graph.Coverage{}, map[string]graph.Coverage{}
	for _, c := range old.Coverage {
		om[covKey(c)] = c
	}
	for _, c := range new.Coverage {
		nm[covKey(c)] = c
	}
	out := CoverageChanges{Opened: []graph.Coverage{}, Closed: []graph.Coverage{}}
	for k, c := range nm {
		if _, ok := om[k]; !ok {
			out.Opened = append(out.Opened, c)
		}
	}
	for k, c := range om {
		if _, ok := nm[k]; !ok {
			out.Closed = append(out.Closed, c)
		}
	}
	for _, l := range [][]graph.Coverage{out.Opened, out.Closed} {
		sort.Slice(l, func(i, j int) bool { return covKey(l[i]) < covKey(l[j]) })
	}
	return out
}
