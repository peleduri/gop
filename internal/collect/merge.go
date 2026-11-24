package collect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// MergeOptions tune Merge.
type MergeOptions struct {
	// Force merges graphs collected with different enterprise visibility (one
	// token could read the enterprise and the other could not). The result
	// then mixes enterprise-level facts from two token modes; this is not
	// supported and off by default.
	Force bool
}

// Merge folds fresh, a collection limited to orgs (Config.Orgs), into base, an
// earlier collection of the same enterprise, so one org can be refreshed
// without a full run and without losing cross-org joins. See MergeWith.
func Merge(base, fresh *graph.Graph, orgs []string) (*graph.Graph, error) {
	return MergeWith(base, fresh, orgs, MergeOptions{})
}

// MergeWith is Merge with options. It never modifies base or fresh.
//
// Every node, edge and coverage entry belongs to the org it was read from
// (nodeOrg, ownerOrg, coverageOrg). Everything base holds for the
// re-collected orgs is replaced by what fresh holds for them; everything else
// in base is kept as it was, so USES edges from other orgs' workflows into the
// re-collected orgs' actions stay. Facts fresh holds about orgs base collected
// but fresh did not are base's to keep: fresh only adds the ones base lacks.
// Facts that belong to no collected org (identities, actions outside the
// enterprise, stub repos) are united, fresh winning. A stub repo node
// (collected=false) is replaced by the real node when either graph has it,
// together with the stub's not_visible push edges and coverage. RESOLVES_TO
// edges are rebuilt from the USES edges that remain. Nodes that only base
// held and that nothing references any more are dropped.
//
// Evidence levels are never inspected, so this works for any schema version
// graph.Load accepts. Both graphs must have the same enterprise, the same
// schema after graph.Load, and the same host (graph.Host) when both record
// one, and both or neither must have read the enterprise unless opts.Force.
// The result is sorted like a collection, has fresh's collected_at, and
// org_collected_at records each org's freshness. It is checked: every edge
// endpoint is a declared node or an ID whose kind graph.KindFromID infers,
// and no edge is duplicated.
func MergeWith(base, fresh *graph.Graph, orgs []string, opts MergeOptions) (*graph.Graph, error) {
	if base == nil || fresh == nil {
		return nil, errors.New("merge: base and fresh graphs are required")
	}
	b, err := reload(base)
	if err != nil {
		return nil, fmt.Errorf("merge: base graph: %w", err)
	}
	f, err := reload(fresh)
	if err != nil {
		return nil, fmt.Errorf("merge: fresh graph: %w", err)
	}
	re := orgSet(orgs)
	if len(re) == 0 {
		return nil, errors.New("merge: name at least one re-collected org")
	}
	if err := mergeCompatible(b, f, opts); err != nil {
		return nil, err
	}
	m := newMerger(b, f, re)
	m.nodes()
	m.edges()
	m.carryOver()
	m.resolves()
	m.dropOrphans()
	m.coverage()
	out := m.result()
	if err := validateMerged(out); err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	return out, nil
}

// reload round-trips g through JSON and graph.Load: it checks the schema,
// upgrades older versions the way Load does, and gives Merge its own copy.
func reload(g *graph.Graph) (*graph.Graph, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(g); err != nil {
		return nil, err
	}
	return graph.Load(&buf)
}

// orgSet returns the lower-case logins of orgs ("acme-actions" or "org:acme-actions").
func orgSet(orgs []string) map[string]bool {
	set := map[string]bool{}
	for _, o := range orgs {
		o = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(o, "org:")))
		if o != "" {
			set[o] = true
		}
	}
	return set
}

func mergeCompatible(b, f *graph.Graph, opts MergeOptions) error {
	if !strings.EqualFold(b.Enterprise, f.Enterprise) {
		return fmt.Errorf("merge: enterprise %q of the fresh graph is not %q of the base graph", f.Enterprise, b.Enterprise)
	}
	if b.Schema != f.Schema {
		return fmt.Errorf("merge: schema %q of the fresh graph is not %q of the base graph", f.Schema, b.Schema)
	}
	if hb, hf := graph.Host(b), graph.Host(f); hb != "" && hf != "" && hb != hf {
		return fmt.Errorf("merge: the fresh graph is from host %s, the base graph from %s: graphs of different GitHub instances cannot be merged", hf, hb)
	}
	vb, okb := entVisible(b)
	vf, okf := entVisible(f)
	if okb && okf && vb != vf && !opts.Force {
		return fmt.Errorf("merge: only the %s graph could read enterprise %s: merging graphs from different token modes is not supported (force to merge anyway)",
			map[bool]string{true: "base", false: "fresh"}[vb], b.Enterprise)
	}
	return nil
}

// entNode returns the graph's enterprise node.
func entNode(g *graph.Graph) (graph.Node, bool) {
	for _, n := range g.Nodes {
		if n.Kind == graph.KindEnterprise || strings.HasPrefix(n.ID, "enterprise:") {
			return n, true
		}
	}
	return graph.Node{}, false
}

// entVisible reports whether the token that collected g could read the
// enterprise (the enterprise node's org count is not not_visible); ok is
// false when g has no enterprise node.
func entVisible(g *graph.Graph) (visible, ok bool) {
	n, ok := entNode(g)
	if !ok {
		return false, false
	}
	return n.AttrEvidence["orgs"] != graph.NotVisible, true
}

// orgLogin is the lower-case login of the org an ID carries (graph.OrgOf), or "".
func orgLogin(id string) string {
	return strings.ToLower(strings.TrimPrefix(graph.OrgOf(id), "org:"))
}

// nodeOrg is the org a node belongs to: the org its ID names. Actions belong
// to their host org (their attributes are read from the host repo).
// Identities, external principals, cloud targets and the enterprise belong to
// no org ("").
func nodeOrg(id string) string { return orgLogin(id) }

// ownerOrg is the org whose collection produced an edge (lower-case login):
//
//   - CAN_PUSH, MEMBER_OF, CAN_TRIGGER, CAN_MERGE_VIA_BOT: the org of the
//     target repo, org, team or workflow; the facts were read from that org.
//   - USES, DEFINED_IN, EXECUTES_WITH: the org of the workflow or action that
//     From names; the facts were read from that repo's files.
//   - RESOLVES_TO: "", derived: Merge rebuilds it from the USES edges that
//     remain, taking fresh's edge when fresh has one from the same action.
//   - CAN_ASSUME: "", added by gop enrich, not collection: kept while its
//     workflow is.
//   - Any other kind: the org of From.
func ownerOrg(e graph.Edge) string {
	switch e.Kind {
	case graph.CanPush, graph.MemberOf, graph.CanTrigger, graph.CanMergeViaBot:
		return orgLogin(e.To)
	case graph.Uses, graph.DefinedIn, graph.ExecutesWith:
		return orgLogin(e.From)
	case graph.ResolvesTo, graph.CanAssume:
		return ""
	}
	return orgLogin(e.From)
}

// coverageOrg is the org a coverage entry belongs to: the org of its scope.
// Enterprise-scope entries belong to no org and are handled on their own.
func coverageOrg(c graph.Coverage) string { return orgLogin(c.Scope) }

// edgeKey identifies an edge the way the collector does: (from, kind, to),
// plus the ref for via=ref_bypass edges, which sit next to a normal grant.
func edgeKey(e graph.Edge) string {
	k := e.From + "\x00" + string(e.Kind) + "\x00" + e.To
	if e.Attrs[graph.AttrVia] == graph.ViaRefBypass {
		k += "\x00" + graph.ViaRefBypass + "\x00" + e.Attrs[graph.AttrRef]
	}
	return k
}

func coverageKey(c graph.Coverage) string { return c.Scope + "\x00" + c.Fact }

func isStub(n graph.Node) bool {
	return n.Kind == graph.KindRepo && n.Attrs[attrCollected] == "false"
}

// stubArtifact reports whether e is an edge the collector adds only for a
// stub repo (pushToStubs: members -CAN_PUSH-> repo, via=unknown).
func stubArtifact(e graph.Edge) bool {
	return e.Kind == graph.CanPush && e.Attrs[graph.AttrVia] == graph.ViaUnknown
}

// side says which input a kept item came from.
type side int

const (
	fromBase side = iota
	fromFresh
)

type merger struct {
	b, f *graph.Graph
	re   map[string]bool // re-collected orgs
	// foreign are the orgs base collected and fresh did not re-collect:
	// base is authoritative for their facts.
	foreign map[string]bool
	// freshEnt: take the enterprise node and enterprise-scope coverage from fresh.
	freshEnt bool

	baseNodes, freshNodes map[string]graph.Node
	nodeSet               map[string]graph.Node
	nodeSide              map[string]side
	// stubbed: node ID -> the side whose stub was replaced by the other
	// side's real node; that side's stub artifacts are dropped.
	stubbed map[string]side

	edgeSet  map[string]graph.Edge
	edgeSide map[string]side
	// freshBypass: "repoID\x00ref" of every via=ref_bypass edge in fresh.
	freshBypass map[string]bool
	// dropped: base-only nodes dropped as orphans; their edges and coverage go too.
	dropped map[string]bool
}

func newMerger(b, f *graph.Graph, re map[string]bool) *merger {
	m := &merger{b: b, f: f, re: re, foreign: map[string]bool{},
		baseNodes: map[string]graph.Node{}, freshNodes: map[string]graph.Node{},
		nodeSet: map[string]graph.Node{}, nodeSide: map[string]side{}, stubbed: map[string]side{},
		edgeSet: map[string]graph.Edge{}, edgeSide: map[string]side{}, freshBypass: map[string]bool{},
		dropped: map[string]bool{}}
	for _, n := range b.Nodes {
		m.baseNodes[n.ID] = n
		if n.Kind == graph.KindOrg {
			if o := nodeOrg(n.ID); !re[o] {
				m.foreign[o] = true
			}
		}
	}
	for _, n := range f.Nodes {
		m.freshNodes[n.ID] = n
	}
	for _, e := range f.Edges {
		if e.Attrs[graph.AttrVia] == graph.ViaRefBypass {
			m.freshBypass[e.To+"\x00"+e.Attrs[graph.AttrRef]] = true
		}
	}
	// Enterprise facts come from fresh only when fresh read the enterprise.
	vf, okf := entVisible(f)
	_, okb := entVisible(b)
	m.freshEnt = (okf && vf) || !okb
	return m
}

func (m *merger) put(n graph.Node, s side) {
	m.nodeSet[n.ID] = n
	m.nodeSide[n.ID] = s
}

// nodes merges every node but the enterprise node (result adds it).
func (m *merger) nodes() {
	for _, n := range m.b.Nodes {
		if n.Kind == graph.KindEnterprise || m.re[nodeOrg(n.ID)] {
			continue
		}
		m.put(n, fromBase)
	}
	for _, n := range m.f.Nodes {
		if n.Kind == graph.KindEnterprise {
			continue
		}
		o := nodeOrg(n.ID)
		cur, ok := m.nodeSet[n.ID]
		switch {
		case m.re[o] || !ok:
			m.put(n, fromFresh)
		case isStub(cur) && !isStub(n):
			m.put(n, fromFresh)
			m.stubbed[n.ID] = fromBase
		case !isStub(cur) && isStub(n):
			m.stubbed[n.ID] = fromFresh
		case !m.foreign[o]:
			// Shared (an identity, an action outside the enterprise, a stub
			// of an org neither graph collected): fresh is newer.
			m.put(n, fromFresh)
		}
	}
}

// keepEdge reports whether the edge from side s survives stub replacement.
func (m *merger) keepEdge(e graph.Edge, s side) bool {
	if st, ok := m.stubbed[e.To]; ok && st == s && stubArtifact(e) {
		return false
	}
	return true
}

func (m *merger) putEdge(e graph.Edge, s side) {
	k := edgeKey(e)
	m.edgeSet[k] = e
	m.edgeSide[k] = s
}

// edges merges every edge but RESOLVES_TO (resolves rebuilds it).
func (m *merger) edges() {
	for _, e := range m.b.Edges {
		if e.Kind == graph.ResolvesTo || m.re[ownerOrg(e)] || !m.keepEdge(e, fromBase) {
			continue
		}
		if e.Kind == graph.CanAssume {
			if _, ok := m.nodeSet[e.From]; !ok {
				continue
			}
		}
		m.putEdge(e, fromBase)
	}
	for _, e := range m.f.Edges {
		if e.Kind == graph.ResolvesTo || !m.keepEdge(e, fromFresh) {
			continue
		}
		if _, ok := m.edgeSet[edgeKey(e)]; ok && m.foreign[ownerOrg(e)] {
			continue // base is authoritative for orgs fresh did not re-collect
		}
		m.putEdge(e, fromFresh)
	}
}

// usesTargets returns the To of every kept USES edge.
func (m *merger) usesTargets() map[string]bool {
	set := map[string]bool{}
	for _, e := range m.edgeSet {
		if e.Kind == graph.Uses {
			set[e.To] = true
		}
	}
	return set
}

// carryOver keeps base's view of an action of a re-collected org that fresh
// did not read but that a kept USES edge still uses (fresh was collected
// without Config.MergeInto, so nothing asked it to read the action): its
// node, its nested USES and RESOLVES_TO edges, its coverage and the
// via=ref_bypass edges of its ref. Stale, but never a silent loss of reach.
func (m *merger) carryOver() {
	baseOut := map[string][]graph.Edge{}
	for _, e := range m.b.Edges {
		baseOut[e.From] = append(baseOut[e.From], e)
	}
	for changed := true; changed; {
		changed = false
		used := m.usesTargets()
		for id := range used {
			n, inBase := m.baseNodes[id]
			if _, kept := m.nodeSet[id]; kept || !inBase || n.Kind != graph.KindActionRef || !m.re[nodeOrg(id)] {
				continue
			}
			m.put(n, fromBase)
			changed = true
			for _, e := range baseOut[id] {
				if e.Kind == graph.ResolvesTo {
					continue // resolves picks it up from base
				}
				if _, ok := m.edgeSet[edgeKey(e)]; !ok {
					m.putEdge(e, fromBase)
				}
			}
			m.carryBypass(n, baseOut)
		}
	}
}

// carryBypass keeps base's via=ref_bypass edges for a carried action's ref
// when fresh has none for that (repo, ref).
func (m *merger) carryBypass(an graph.Node, baseOut map[string][]graph.Edge) {
	ref := an.Attrs[graph.AttrRef]
	for _, r := range baseOut[an.ID] {
		if r.Kind != graph.ResolvesTo || ref == "" || m.freshBypass[r.To+"\x00"+ref] {
			continue
		}
		for _, e := range m.b.Edges {
			if e.To == r.To && e.Kind == graph.CanPush && e.Attrs[graph.AttrVia] == graph.ViaRefBypass && e.Attrs[graph.AttrRef] == ref {
				if _, ok := m.edgeSet[edgeKey(e)]; !ok {
					m.putEdge(e, fromBase)
				}
			}
		}
	}
}

// resolves rebuilds RESOLVES_TO: for every action a kept USES edge uses,
// fresh's edges from it when fresh has any, else base's.
func (m *merger) resolves() {
	used := m.usesTargets()
	byFrom := func(g *graph.Graph) map[string][]graph.Edge {
		out := map[string][]graph.Edge{}
		for _, e := range g.Edges {
			if e.Kind == graph.ResolvesTo && used[e.From] {
				out[e.From] = append(out[e.From], e)
			}
		}
		return out
	}
	fb, ff := byFrom(m.b), byFrom(m.f)
	for id := range used {
		es, s := ff[id], fromFresh
		if len(es) == 0 {
			es, s = fb[id], fromBase
		}
		for _, e := range es {
			m.putEdge(e, s)
		}
	}
}

// dropOrphans removes what only base held and the merge left unused: stub
// repos no RESOLVES_TO points at any more, then base-only nodes of no
// re-collected or foreign org (identities, actions outside the enterprise,
// members of stub orgs, cloud targets) that base referenced and nothing
// references now, with the edges into dropped stubs.
func (m *merger) dropOrphans() {
	resolved := map[string]bool{}
	for _, e := range m.edgeSet {
		if e.Kind == graph.ResolvesTo {
			resolved[e.To] = true
		}
	}
	shared := func(id string) bool {
		o := nodeOrg(id)
		return m.nodeSide[id] == fromBase && !m.re[o] && !m.foreign[o]
	}
	for id, n := range m.nodeSet {
		if isStub(n) && shared(id) && !resolved[id] {
			m.dropNode(id)
		}
	}
	m.dropDanglingEdges()
	baseRef := map[string]bool{}
	for _, e := range m.b.Edges {
		baseRef[e.From], baseRef[e.To] = true, true
	}
	ref := map[string]bool{}
	for _, e := range m.edgeSet {
		ref[e.From], ref[e.To] = true, true
	}
	for id, n := range m.nodeSet {
		if n.Kind != graph.KindOrg && shared(id) && baseRef[id] && !ref[id] {
			m.dropNode(id)
		}
	}
}

func (m *merger) dropNode(id string) {
	delete(m.nodeSet, id)
	m.dropped[id] = true
}

func (m *merger) dropDanglingEdges() {
	for k, e := range m.edgeSet {
		if m.dropped[e.From] || m.dropped[e.To] {
			delete(m.edgeSet, k)
		}
	}
}

// coverage merges coverage entries with the same ownership rules as nodes.
// A foreign entry from fresh is added only for a node base did not have, so
// fresh's partial view of an org it did not re-collect never adds gaps base
// had not seen.
func (m *merger) coverage() []graph.Coverage {
	set := map[string]graph.Coverage{}
	entScope := func(c graph.Coverage) bool { return strings.HasPrefix(c.Scope, "enterprise:") }
	drop := func(c graph.Coverage, s side) bool {
		if m.dropped[c.Scope] {
			return true
		}
		st, ok := m.stubbed[c.Scope]
		return ok && st == s && c.Fact == "can_push"
	}
	carried := func(c graph.Coverage) bool {
		n, ok := m.nodeSet[c.Scope]
		return ok && m.nodeSide[c.Scope] == fromBase && n.Kind == graph.KindActionRef
	}
	for _, c := range m.b.Coverage {
		switch {
		case drop(c, fromBase):
		case entScope(c):
			if !m.freshEnt {
				set[coverageKey(c)] = c
			}
		case m.re[coverageOrg(c)] && !carried(c):
		default:
			set[coverageKey(c)] = c
		}
	}
	for _, c := range m.f.Coverage {
		o := coverageOrg(c)
		_, have := set[coverageKey(c)]
		_, baseNode := m.baseNodes[c.Scope]
		switch {
		case drop(c, fromFresh):
		case entScope(c):
			if m.freshEnt {
				set[coverageKey(c)] = c
			}
		case m.foreign[o] && (have || baseNode):
		default:
			set[coverageKey(c)] = c
		}
	}
	out := make([]graph.Coverage, 0, len(set))
	for _, c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Fact < out[j].Fact
	})
	return out
}

// enterprise returns the merged enterprise node: fresh's when fresh read the
// enterprise, else base's with fresh's host and server version (read on
// every run).
func (m *merger) enterprise() (graph.Node, bool) {
	bn, okb := entNode(m.b)
	fn, okf := entNode(m.f)
	switch {
	case !okb && !okf:
		return graph.Node{}, false
	case !okb || (okf && m.freshEnt):
		return fn, true
	case !okf:
		return bn, true
	}
	for _, a := range []string{graph.AttrHost, graph.AttrGHESVersion} {
		v, ok := fn.Attrs[a]
		if !ok {
			continue
		}
		if bn.Attrs == nil {
			bn.Attrs = map[string]string{}
		}
		bn.Attrs[a] = v
		if ev, ok := fn.AttrEvidence[a]; ok {
			if bn.AttrEvidence == nil {
				bn.AttrEvidence = map[string]graph.Evidence{}
			}
			bn.AttrEvidence[a] = ev
		} else {
			delete(bn.AttrEvidence, a)
		}
	}
	return bn, true
}

// orgTimes returns org_collected_at: base's (each base org at base's
// collected_at when base does not record it), with the re-collected orgs at
// fresh's times.
func (m *merger) orgTimes() map[string]time.Time {
	out := map[string]time.Time{}
	if m.b.OrgCollectedAt != nil {
		for o, t := range m.b.OrgCollectedAt {
			out[o] = t
		}
	} else {
		for _, n := range m.b.Nodes {
			if n.Kind == graph.KindOrg {
				out[strings.TrimPrefix(n.ID, "org:")] = m.b.CollectedAt
			}
		}
	}
	for o := range out {
		if m.re[strings.ToLower(o)] {
			delete(out, o)
		}
	}
	if m.f.OrgCollectedAt != nil {
		for o, t := range m.f.OrgCollectedAt {
			if m.re[strings.ToLower(o)] {
				out[o] = t
			}
		}
	} else {
		for _, n := range m.f.Nodes {
			if login := strings.TrimPrefix(n.ID, "org:"); n.Kind == graph.KindOrg && m.re[strings.ToLower(login)] {
				out[login] = m.f.CollectedAt
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m *merger) result() *graph.Graph {
	g := &graph.Graph{
		Schema: m.f.Schema, CollectedAt: m.f.CollectedAt, Enterprise: m.f.Enterprise,
		Nodes: make([]graph.Node, 0, len(m.nodeSet)+1), Edges: make([]graph.Edge, 0, len(m.edgeSet)),
		Coverage: m.coverage(), OrgCollectedAt: m.orgTimes(),
		AuditRetentionDays: m.f.AuditRetentionDays,
	}
	if g.AuditRetentionDays == 0 {
		g.AuditRetentionDays = m.b.AuditRetentionDays
	}
	// A partial graph stays partial through a merge: fresh's reason first.
	switch {
	case m.f.Partial:
		g.Partial, g.PartialReason = true, m.f.PartialReason
	case m.b.Partial:
		g.Partial, g.PartialReason = true, m.b.PartialReason
	}
	if n, ok := m.enterprise(); ok {
		g.Nodes = append(g.Nodes, n)
	}
	for _, n := range m.nodeSet {
		g.Nodes = append(g.Nodes, n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	for _, e := range m.edgeSet {
		g.Edges = append(g.Edges, e)
	}
	sortEdges(g.Edges)
	return g
}

// validateMerged checks a merged graph: node IDs are unique, every edge
// endpoint is a declared node or an ID whose kind graph.KindFromID infers,
// and no edge is duplicated (by edgeKey: (from, kind, to), plus the ref of a
// via=ref_bypass edge). The error names the first violation.
func validateMerged(g *graph.Graph) error {
	nodes := make(map[string]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		if nodes[n.ID] {
			return fmt.Errorf("duplicate node %s", n.ID)
		}
		nodes[n.ID] = true
	}
	seen := make(map[string]bool, len(g.Edges))
	for _, e := range g.Edges {
		for _, id := range []string{e.From, e.To} {
			if !nodes[id] && graph.KindFromID(id) == "" {
				return fmt.Errorf("edge %s -%s-> %s: endpoint %s is not a declared node and its kind cannot be inferred", e.From, e.Kind, e.To, id)
			}
		}
		k := edgeKey(e)
		if seen[k] {
			return fmt.Errorf("duplicate edge %s -%s-> %s", e.From, e.Kind, e.To)
		}
		seen[k] = true
	}
	return nil
}

// ---- collector hook (Config.MergeInto) ----

// checkMergeInto refuses a MergeInto run that cannot merge, before collecting.
func (cfg Config) checkMergeInto() error {
	base := cfg.MergeInto
	if base == nil {
		return nil
	}
	if len(orgSet(cfg.Orgs)) == 0 {
		return errors.New("collect: MergeInto needs Orgs, the orgs to re-collect")
	}
	if !strings.EqualFold(base.Enterprise, cfg.Enterprise) {
		return fmt.Errorf("collect: MergeInto is a graph of enterprise %q, not %q", base.Enterprise, cfg.Enterprise)
	}
	if hb, h := graph.Host(base), cfg.host(); hb != "" && h != "" && hb != h {
		return fmt.Errorf("collect: MergeInto is a graph of host %s, not %s: graphs of different GitHub instances cannot be merged", hb, h)
	}
	return nil
}

// seedFromBase lets references from the re-collected orgs resolve against
// MergeInto: every repo node of another org (stubs included) is known, so a
// USES edge into it resolves to that node instead of a new stub. When the
// token cannot read the enterprise, MergeInto's orgs also count as
// enterprise orgs. Repos of the re-collected orgs are not seeded: they are
// listed again, and a reference to one that is gone becomes a stub, as in a
// full collection.
func (k *collector) seedFromBase() {
	base := k.cfg.MergeInto
	if base == nil {
		return
	}
	re := orgSet(k.cfg.Orgs)
	for _, n := range base.Nodes {
		switch {
		case n.Kind == graph.KindOrg && k.entHidden:
			login := strings.TrimPrefix(n.ID, "org:")
			if _, ok := k.entOrgs[strings.ToLower(login)]; !ok {
				k.entOrgs[strings.ToLower(login)] = login
			}
		case n.Kind == graph.KindRepo && !re[nodeOrg(n.ID)]:
			full := strings.ToLower(strings.TrimPrefix(n.ID, "repo:"))
			if _, ok := k.repoIDs[full]; !ok {
				k.repoIDs[full] = n.ID
			}
		}
	}
}

// seedBaseActions queues the actions of the re-collected orgs that other
// orgs' workflows and actions use in MergeInto, at the nesting depth
// MergeInto has them, so they are read again (node, nested references, ref
// kind, protection and immutability) exactly as a full collection would. The
// USES edges into them stay MergeInto's.
func (k *collector) seedBaseActions() {
	base := k.cfg.MergeInto
	if base == nil {
		return
	}
	re := orgSet(k.cfg.Orgs)
	depth := actionDepths(base)
	seen := map[string]bool{}
	var ids []string
	for _, e := range base.Edges {
		if e.Kind != graph.Uses || seen[e.To] || re[ownerOrg(e)] || !re[nodeOrg(e.To)] {
			continue
		}
		seen[e.To] = true
		ids = append(ids, e.To)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u, ok := ParseUses(strings.TrimPrefix(id, "action:"))
		if !ok {
			continue
		}
		d := depth[id]
		if d < 1 {
			d = 1
		}
		k.resolveAction(k.actionNode(u), u, d)
	}
}

// actionDepths is the nesting depth of every action g's workflows reach
// through USES edges: 1 for a workflow's own references, one more per
// composite action or reusable workflow in between (shortest chain).
func actionDepths(g *graph.Graph) map[string]int {
	out := map[string][]string{}
	depth := map[string]int{}
	var queue []string
	for _, e := range g.Edges {
		if e.Kind != graph.Uses {
			continue
		}
		out[e.From] = append(out[e.From], e.To)
		if graph.KindFromID(e.From) == graph.KindWorkflow {
			if _, ok := depth[e.To]; !ok {
				depth[e.To] = 1
				queue = append(queue, e.To)
			}
		}
	}
	for i := 0; i < len(queue); i++ {
		a := queue[i]
		for _, b := range out[a] {
			if _, ok := depth[b]; !ok {
				depth[b] = depth[a] + 1
				queue = append(queue, b)
			}
		}
	}
	return depth
}
