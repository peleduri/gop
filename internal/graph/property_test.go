package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Property tests: P1 to P11 from the engine's documented guarantees, checked
// over random graphs from genGraph. The reach-set properties (P3, P4, and the
// path lengths in P5) compare the engine against refReach, a small reference
// BFS written from the rules comment at the top of reach.go. It shares no code
// with buildControl or bfs, so the engine is not tested against itself.
//
// The default run uses 300 seeds (graph sizes 5 to 200 nodes). For a larger
// sweep: GOP_PROPERTY_SEEDS=5000 go test ./internal/graph -run Property
// (ignored with -short).

const defaultPropertySeeds = 300

func propertySeeds(t *testing.T) int {
	n := defaultPropertySeeds
	if v := os.Getenv("GOP_PROPERTY_SEEDS"); v != "" && !testing.Short() {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n <= 0 {
			t.Fatalf("GOP_PROPERTY_SEEDS=%q: want a positive integer", v)
		}
	}
	return n
}

// propSize maps a seed to a graph size in [5, 200].
func propSize(seed uint64) int { return 5 + int(seed%196) }

func propRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, 0x6f70)) }

type property struct {
	name  string
	check func(g *Graph, r *rand.Rand) error
}

var properties = []property{
	{"P1_disjoint", propDisjoint},
	{"P2_confirmed_sound", propConfirmedSound},
	{"P3_confirmed_complete", propConfirmedComplete},
	{"P4_union", propUnion},
	{"P5_path_validity", propPathValidity},
	{"P6_fix_monotonic", propFixMonotonic},
	{"P7_edge_removal_monotonic", propEdgeRemovalMonotonic},
	{"P8_evidence_monotonic", propEvidenceMonotonic},
	{"P9_suggest_fixes_consistent", propSuggestFixesConsistent},
	{"P10_deterministic", propDeterministic},
	{"P11_principal_kinds", propPrincipalKinds},
}

func TestPropertyReach(t *testing.T) {
	n := propertySeeds(t)
	for seed := uint64(0); seed < uint64(n); seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			g := genGraph(propRand(seed), propSize(seed))
			for _, p := range properties {
				// Each property gets its own rand stream so a failure reproduces
				// from (seed, property) alone, and minimization replays it.
				if err := p.check(g, propRand(seed)); err != nil {
					small := minimizeGraph(g, func(h *Graph) bool { return p.check(h, propRand(seed)) != nil })
					minErr := p.check(small, propRand(seed))
					js, _ := json.MarshalIndent(small, "", "  ")
					t.Errorf("%s failed (seed=%d size=%d): %v\nminimized graph fails with: %v\n%s",
						p.name, seed, propSize(seed), err, minErr, js)
				}
			}
		})
	}
}

// minimizeGraph shrinks g while fails still holds: it drops chunks of edges
// (halving the chunk size down to single edges), then nodes, and returns the
// smallest failing graph found within minimizeBudget.
func minimizeGraph(g *Graph, fails func(*Graph) bool) *Graph {
	deadline := time.Now().Add(minimizeBudget)
	cur := cloneGraph(g)
	shrink := func(n func(*Graph) int, drop func(h *Graph, i, k int)) {
		for chunk := max(1, n(cur)/2); chunk >= 1; chunk /= 2 {
			for i := 0; i < n(cur) && time.Now().Before(deadline); {
				try := cloneGraph(cur)
				drop(try, i, min(chunk, n(cur)-i))
				if fails(try) {
					cur = try
					continue
				}
				i += chunk
			}
		}
	}
	shrink(func(h *Graph) int { return len(h.Edges) }, func(h *Graph, i, k int) {
		h.Edges = append(h.Edges[:i:i], h.Edges[i+k:]...)
	})
	shrink(func(h *Graph) int { return len(h.Nodes) }, func(h *Graph, i, k int) {
		h.Nodes = append(h.Nodes[:i:i], h.Nodes[i+k:]...)
	})
	return cur
}

const minimizeBudget = 5 * time.Second

func cloneGraph(g *Graph) *Graph {
	c := *g
	c.Nodes = append([]Node(nil), g.Nodes...)
	c.Edges = append([]Edge(nil), g.Edges...)
	return &c
}

// ---- reference model -------------------------------------------------------

// refEdge is one control edge in the reference model (controller -> controlled).
type refEdge struct {
	from, to  string
	kind      EdgeKind
	ev        Evidence
	sourceAPI string
	reverse   bool
	ci        bool // workflow -> repo it is defined in: recorded, never expanded
	old       bool // the evidence edge is older than the maximum audit age
	stale     bool // an audit hop demoted to not_visible because it is old
}

// refOld reports whether e was observed more than the maximum audit age
// before g was collected: half the audit retention when the graph records
// one, else 90 days. Written from the docs, not from AuditStale.
func refOld(g *Graph, e Edge) bool {
	maxAge := 90 * 24 * time.Hour
	if g.AuditRetentionDays > 0 {
		maxAge = time.Duration(g.AuditRetentionDays) * 12 * time.Hour
	}
	return !e.ObservedAt.IsZero() && !g.CollectedAt.IsZero() && g.CollectedAt.Sub(e.ObservedAt) > maxAge
}

var refSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// refMutable follows the reach.go rule for RESOLVES_TO: the node's ref_kind
// attr decides; else any incoming USES with ref_kind branch/tag makes it
// mutable, else any with sha makes it immutable; else a 40-hex ref is a sha;
// anything unknown is mutable.
func refMutable(g *Graph, action string) bool {
	for _, n := range g.Nodes {
		if n.ID == action {
			switch n.Attrs[AttrRefKind] {
			case "sha":
				return false
			case "branch", "tag":
				return true
			}
		}
	}
	mutable, pinned := false, false
	for _, e := range g.Edges {
		if e.Kind == Uses && e.To == action {
			switch e.Attrs[AttrRefKind] {
			case "branch", "tag":
				mutable = true
			case "sha":
				pinned = true
			}
		}
	}
	if mutable {
		return true
	}
	if pinned {
		return false
	}
	at := strings.LastIndex(action, "@")
	return at < 0 || !refSHA.MatchString(action[at+1:])
}

// refFixSet is the reference reading of a fix list (see refFixes).
type refFixSet struct {
	pinned, lowered, restricted, hardened, botBlocked map[string]bool
}

// refFixes reads the hypothetical changes out of fixes: pinned action IDs,
// orgs whose default-permission CAN_PUSH edges from members:X are removed,
// workflows whose via=token_write CAN_PUSH edges are removed (RestrictToken),
// workflows whose incoming CAN_TRIGGER edges are removed (HardenTrigger),
// and repos whose incoming CAN_MERGE_VIA_BOT edges are removed (BlockBotMerge).
func refFixes(fixes []Fix) refFixSet {
	fs := refFixSet{pinned: map[string]bool{}, lowered: map[string]bool{}, restricted: map[string]bool{}, hardened: map[string]bool{}, botBlocked: map[string]bool{}}
	for _, f := range fixes {
		switch f := f.(type) {
		case PinRef:
			fs.pinned[f.Action] = true
		case LowerDefaultPerm:
			if f.To == "read" || f.To == "none" {
				fs.lowered[f.Org] = true
			}
		case RestrictToken:
			fs.restricted[f.Workflow] = true
		case HardenTrigger:
			fs.hardened[f.Workflow] = true
		case BlockBotMerge:
			fs.botBlocked[f.Repo] = true
		}
	}
	return fs
}

// refControl derives the control edges of g under fixes, one per evidence
// edge (parallel evidence edges give parallel control edges).
func refControl(g *Graph, fixes []Fix) []refEdge {
	fx := refFixes(fixes)
	mutable := map[string]bool{}
	var out []refEdge
	for _, e := range g.Edges {
		old := refOld(g, e)
		fwd := refEdge{from: e.From, to: e.To, kind: e.Kind, ev: e.Evidence, sourceAPI: e.SourceAPI, old: old}
		rev := refEdge{from: e.To, to: e.From, kind: e.Kind, ev: e.Evidence, sourceAPI: e.SourceAPI, reverse: true, old: old}
		switch e.Kind {
		case CanPush:
			// Any source pushes, including workflow -> repo (via=token_write):
			// a write GITHUB_TOKEN controls the repo, it is not CI reach only.
			if org, ok := strings.CutPrefix(e.From, "members:"); ok && e.Attrs[AttrVia] == ViaDefaultPerm && fx.lowered["org:"+org] {
				continue
			}
			// RestrictToken: the workflow's token is contents: read.
			if e.Attrs[AttrVia] == ViaTokenWrite && fx.restricted[e.From] {
				continue
			}
			out = append(out, fwd)
		case MemberOf:
			if org, ok := strings.CutPrefix(e.To, "org:"); ok {
				fwd.to = "members:" + org
			}
			out = append(out, fwd)
		case DefinedIn:
			ci := fwd
			ci.ci = true
			out = append(out, rev, ci)
		case ResolvesTo:
			m, ok := mutable[e.From]
			if !ok {
				m = refMutable(g, e.From)
				mutable[e.From] = m
			}
			if m && !fx.pinned[e.From] {
				out = append(out, refResolves(g, e, rev)...)
			}
		case Uses:
			switch refAccess(g, e) {
			case "drop":
				continue
			case "hidden":
				rev.ev = NotVisible
			}
			out = append(out, rev)
		case ExecutesWith, CanAssume:
			out = append(out, fwd)
		case CanTrigger:
			// A principal that can cause a risky trigger of a workflow running
			// attacker code controls the workflow, like a push would, unless
			// HardenTrigger removed the untrusted execution.
			if fx.hardened[e.To] {
				continue
			}
			out = append(out, fwd)
		case CanMergeViaBot:
			// Anyone in the principal lands code on the repo through a bot
			// approve and merge, like a push, unless BlockBotMerge closed it.
			if fx.botBlocked[e.To] {
				continue
			}
			out = append(out, fwd)
		}
	}
	// A hop that is still audit after the gates, from an old audit fact,
	// counts as not visible.
	for i := range out {
		if out[i].ev == Audit && out[i].old {
			out[i].ev, out[i].stale = NotVisible, true
		}
	}
	return out
}

// refResolves applies the ref gate (reach.go, RESOLVES_TO) to the reverse
// hop rev of one RESOLVES_TO edge e of a mutable, unpinned action. It is
// written from the rule table, not from refLock:
//
//	ref_ambiguous=true                 the hop is kept as is
//	gate = ref_immutable when the node's ref_kind is tag, else ref_protected
//	gate true                          no repo -> action hop; every CAN_PUSH into
//	                                   the host repo with via=ref_bypass and ref
//	                                   equal to the action's ref (ref attr, else
//	                                   the ID after the last "@") becomes a
//	                                   principal -> action hop with that edge's
//	                                   evidence; bypass=unknown keeps the
//	                                   repo -> action hop, not_visible
//	gate unknown                       the hop, not_visible
//	anything else                      the hop as is
func refResolves(g *Graph, e Edge, rev refEdge) []refEdge {
	var attrs map[string]string
	declared := false
	for _, n := range g.Nodes {
		if n.ID == e.From {
			attrs, declared = n.Attrs, true
			break
		}
	}
	if !declared || attrs["ref_ambiguous"] == "true" {
		return []refEdge{rev}
	}
	gate := attrs["ref_protected"]
	if attrs["ref_kind"] == "tag" {
		gate = attrs["ref_immutable"]
	}
	hidden := rev
	hidden.ev = NotVisible
	switch gate {
	case "true":
		var out []refEdge
		if attrs["bypass"] == "unknown" {
			out = append(out, hidden)
		}
		ref := attrs["ref"]
		if ref == "" {
			ref = e.From[strings.LastIndex(e.From, "@")+1:]
		}
		for _, p := range g.Edges {
			if p.Kind == CanPush && p.To == e.To && p.Attrs["via"] == "ref_bypass" && p.Attrs["ref"] == ref {
				out = append(out, refEdge{from: p.From, to: e.From, kind: CanPush, ev: p.Evidence, sourceAPI: p.SourceAPI, old: refOld(g, p)})
			}
		}
		return out
	case "unknown":
		return []refEdge{hidden}
	}
	return []refEdge{rev}
}

// refAccess applies the actions access rule (reach.go, USES) to one USES
// edge: "open", "hidden" (the hop becomes not_visible) or "drop". It is written
// from the rule table, not from actionsAccessAllows. A graph where no repo has
// actions_access is always open. The host repos are the action's RESOLVES_TO
// targets, else the repo in its ID; the consumer repos are a workflow's
// DEFINED_IN targets (else the repo in its ID) or a consuming action's hosts.
// The most permissive (host, consumer) pair wins.
func refAccess(g *Graph, e Edge) string {
	levels := map[string]string{}
	for _, n := range g.Nodes {
		if l := n.Attrs[AttrActionsAccess]; l != "" {
			levels[n.ID] = l
		}
	}
	if len(levels) == 0 {
		return "open"
	}
	idRepo := func(id string) []string {
		kind, rest, _ := strings.Cut(id, ":")
		if kind == "action" {
			if at := strings.LastIndex(rest, "@"); at >= 0 {
				rest = rest[:at]
			}
		} else if kind != "workflow" {
			return nil
		}
		seg := strings.Split(rest, "/")
		if len(seg) < 2 || seg[0] == "" || seg[1] == "" {
			return nil
		}
		return []string{"repo:" + seg[0] + "/" + seg[1]}
	}
	targets := func(from string, kind EdgeKind) []string {
		var out []string
		for _, x := range g.Edges {
			if x.From == from && x.Kind == kind {
				out = append(out, x.To)
			}
		}
		if len(out) == 0 {
			out = idRepo(from)
		}
		return out
	}
	hosts := targets(e.To, ResolvesTo)
	if len(hosts) == 0 {
		return "open"
	}
	consumerKind := KindFromID(e.From)
	for _, n := range g.Nodes {
		if n.ID == e.From && n.Kind != "" {
			consumerKind = n.Kind
		}
	}
	var consumers []string
	if consumerKind == KindActionRef {
		consumers = targets(e.From, ResolvesTo)
	} else {
		consumers = targets(e.From, DefinedIn)
	}
	owner := func(repo string) string {
		o, _, _ := strings.Cut(strings.TrimPrefix(repo, "repo:"), "/")
		return strings.ToLower(o)
	}
	verdict := "drop"
	for _, h := range hosts {
		level := levels[h]
		if level == "" || level == "public" || level == "enterprise" {
			return "open"
		}
		if len(consumers) == 0 {
			verdict = "hidden"
		}
		for _, c := range consumers {
			sameOrg := owner(h) == owner(c)
			sameRepo := strings.EqualFold(h, c)
			switch level {
			case "organization", "user":
				if sameOrg {
					return "open"
				}
			case "none":
				if sameRepo {
					return "open"
				}
			default: // unknown, or a value gop does not know
				if sameOrg {
					return "open"
				}
				verdict = "hidden"
			}
		}
	}
	return verdict
}

// refReach returns every node reachable from `from` (excluding it) with its
// shortest path length. With verifiedOnly it walks only live and audit control
// edges (confirmed reach), else every control edge (confirmed plus possible).
// The control edges come from the whole graph either way: the actions access
// rule reads DEFINED_IN and RESOLVES_TO edges whatever their evidence.
// Controlled nodes expand through every non-CI edge; a CI edge only records its
// target.
func refReach(g *Graph, from string, fixes []Fix, verifiedOnly bool) map[string]int {
	adj := map[string][]refEdge{}
	for _, e := range refControl(g, fixes) {
		if verifiedOnly && !refVerified(e.ev) {
			continue
		}
		adj[e.from] = append(adj[e.from], e)
	}
	ctrl := map[string]int{from: 0}
	queue := []string{from}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range adj[u] {
			if _, ok := ctrl[e.to]; !ok && !e.ci {
				ctrl[e.to] = ctrl[u] + 1
				queue = append(queue, e.to)
			}
		}
	}
	out := map[string]int{}
	for v, d := range ctrl {
		if v != from {
			out[v] = d
		}
	}
	for u, d := range ctrl {
		for _, e := range adj[u] {
			if !e.ci || e.to == from {
				continue
			}
			if old, ok := out[e.to]; !ok || d+1 < old {
				out[e.to] = d + 1
			}
		}
	}
	return out
}

// refBucket sorts a reached set into Reached lists the way Result reports them.
// orgsExclude removes orgs already counted elsewhere (confirmed orgs from possible).
func refBucket(g *Graph, ids map[string]int, orgsExclude []string) Reached {
	kinds := map[string]NodeKind{}
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	kindOf := func(id string) NodeKind {
		if k := kinds[id]; k != "" {
			return k
		}
		return KindFromID(id)
	}
	var r Reached
	orgs := map[string]bool{}
	for _, id := range sortedIntKeys(ids) {
		switch kindOf(id) {
		case KindRepo:
			r.Repos = append(r.Repos, id)
			if o := OrgOf(id); o != "" {
				orgs[o] = true
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
	for _, o := range orgsExclude {
		delete(orgs, o)
	}
	r.Orgs = sortedKeys(orgs)
	return r
}

func sortedIntKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- helpers over engine results -------------------------------------------

func reachedLists(r Reached) map[string][]string {
	return map[string][]string{"repos": r.Repos, "workflows": r.Workflows, "actions": r.Actions,
		"secrets": r.Secrets, "oidc": r.OIDC, "runners": r.Runners, "orgs": r.Orgs, "cloud_targets": r.CloudTargets}
}

// confirmedIDs and allIDs read the node sets out of Paths, which covers every
// reached node (including principals and members sets not listed in Reached).
func confirmedIDs(res Result) map[string]bool {
	out := map[string]bool{}
	for id, p := range res.Paths {
		if !p.Unverified {
			out[id] = true
		}
	}
	return out
}

func allIDs(res Result) map[string]bool {
	out := map[string]bool{}
	for id := range res.Paths {
		out[id] = true
	}
	return out
}

func notSubset(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sameKeys(a map[string]bool, b map[string]int) error {
	var extra, missing []string
	for k := range a {
		if _, ok := b[k]; !ok {
			extra = append(extra, k)
		}
	}
	for k := range b {
		if !a[k] {
			missing = append(missing, k)
		}
	}
	if len(extra)+len(missing) == 0 {
		return nil
	}
	sort.Strings(extra)
	sort.Strings(missing)
	return fmt.Errorf("engine has extra %v, misses %v", extra, missing)
}

// ---- properties ------------------------------------------------------------

// propPrincipalKinds (P11): every principal is an org_members, identity or
// external node, or an undeclared MEMBER_OF source. A workflow with a write
// token is the source of a CAN_PUSH edge but never a principal. Every
// org_members or external node, and every CAN_TRIGGER source of those kinds,
// is a principal.
func propPrincipalKinds(g *Graph, _ *rand.Rand) error {
	kinds := map[string]NodeKind{}
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	memberOf := map[string]bool{}
	for _, e := range g.Edges {
		if e.Kind == MemberOf {
			memberOf[e.From] = true
		}
	}
	for _, p := range NewIndex(g).Principals() {
		k, declared := kinds[p]
		if !declared || k == "" {
			k = KindFromID(p)
		}
		if k != KindOrgMembers && k != KindIdentity && k != KindExternal && !memberOf[p] {
			return fmt.Errorf("principal %s has kind %q", p, k)
		}
	}
	kindOf := func(id string) NodeKind {
		if k := kinds[id]; k != "" {
			return k
		}
		return KindFromID(id)
	}
	ps := map[string]bool{}
	for _, p := range NewIndex(g).Principals() {
		ps[p] = true
	}
	for _, e := range g.Edges {
		if k := kindOf(e.From); (e.Kind == CanTrigger || e.Kind == CanMergeViaBot) && (k == KindOrgMembers || k == KindIdentity || k == KindExternal) && !ps[e.From] {
			return fmt.Errorf("%s source %s (%s) is not a principal", e.Kind, e.From, k)
		}
	}
	for _, n := range g.Nodes {
		if n.Kind == KindExternal && !ps[n.ID] {
			return fmt.Errorf("external node %s is not a principal", n.ID)
		}
	}
	return nil
}

func propDisjoint(g *Graph, _ *rand.Rand) error {
	ix := NewIndex(g)
	for _, p := range ix.Principals() {
		res := ix.Reach(p, Options{})
		poss := reachedLists(res.Possible)
		for kind, conf := range reachedLists(res.Confirmed) {
			set := map[string]bool{}
			for _, id := range conf {
				set[id] = true
			}
			for _, id := range poss[kind] {
				if set[id] {
					return fmt.Errorf("%s: %s %s is both confirmed and possible", p, kind, id)
				}
			}
		}
	}
	return nil
}

func propConfirmedSound(g *Graph, _ *rand.Rand) error {
	ix := NewIndex(g)
	for _, p := range ix.Principals() {
		res := ix.Reach(p, Options{})
		for kind, ids := range reachedLists(res.Confirmed) {
			if kind == "orgs" {
				continue // orgs are derived from repos, they have no path of their own
			}
			for _, id := range ids {
				path, ok := res.Paths[id]
				if !ok {
					return fmt.Errorf("%s: confirmed %s has no path", p, id)
				}
				if path.Unverified {
					return fmt.Errorf("%s: confirmed %s has an unverified path", p, id)
				}
				for _, h := range path.Hops {
					if !refVerified(h.Evidence) {
						return fmt.Errorf("%s: confirmed %s path has a %s hop %s -> %s", p, id, h.Evidence, h.From, h.To)
					}
				}
			}
		}
	}
	return nil
}

func propConfirmedComplete(g *Graph, _ *rand.Rand) error {
	ix := NewIndex(g)
	for _, p := range ix.Principals() {
		res := ix.Reach(p, Options{})
		ref := refReach(g, p, nil, true)
		if err := sameKeys(confirmedIDs(res), ref); err != nil {
			return fmt.Errorf("%s: confirmed != reach without not_visible edges: %v", p, err)
		}
		if want := refBucket(g, ref, nil); !reflect.DeepEqual(res.Confirmed, want) {
			return fmt.Errorf("%s: Confirmed = %+v, want %+v", p, res.Confirmed, want)
		}
	}
	return nil
}

func propUnion(g *Graph, _ *rand.Rand) error {
	ix := NewIndex(g)
	for _, p := range ix.Principals() {
		res := ix.Reach(p, Options{})
		all := refReach(g, p, nil, false)
		if err := sameKeys(allIDs(res), all); err != nil {
			return fmt.Errorf("%s: confirmed+possible != reach with all edges live: %v", p, err)
		}
		conf := refReach(g, p, nil, true)
		poss := map[string]int{}
		for id, d := range all {
			if _, ok := conf[id]; !ok {
				poss[id] = d
			}
		}
		if want := refBucket(g, poss, refBucket(g, conf, nil).Orgs); !reflect.DeepEqual(res.Possible, want) {
			return fmt.Errorf("%s: Possible = %+v, want %+v", p, res.Possible, want)
		}
	}
	return nil
}

type hopKey struct {
	from, to  string
	kind      EdgeKind
	ev        Evidence
	sourceAPI string
	reverse   bool
	stale     bool
}

func checkPaths(g *Graph, p string, res Result, fixes []Fix) error {
	ctl := map[hopKey][]bool{} // -> ci flags of matching control edges
	for _, e := range refControl(g, fixes) {
		k := hopKey{e.from, e.to, e.kind, e.ev, e.sourceAPI, e.reverse, e.stale}
		ctl[k] = append(ctl[k], e.ci)
	}
	confDist := refReach(g, p, fixes, true)
	allDist := refReach(g, p, fixes, false)
	for _, id := range sortedKeys(allIDs(res)) {
		path := res.Paths[id]
		if path.From != p || path.To != id {
			return fmt.Errorf("%s: path to %s is labeled %s -> %s", p, id, path.From, path.To)
		}
		hs := path.Hops
		if len(hs) == 0 || hs[0].From != p || hs[len(hs)-1].To != id {
			return fmt.Errorf("%s: path to %s does not run from %s to %s: %+v", p, id, p, id, hs)
		}
		// Reference evidence order: live > inferred > audit > supplied > not_visible.
		ev, unverified, supplied, stale := Live, false, false, false
		for i, h := range hs {
			if i+1 < len(hs) && h.To != hs[i+1].From {
				return fmt.Errorf("%s: path to %s breaks at hop %d: %s then %s", p, id, i, h.To, hs[i+1].From)
			}
			cis, ok := ctl[hopKey{h.From, h.To, h.Kind, h.Evidence, h.SourceAPI, h.Reverse, h.Stale}]
			if !ok {
				return fmt.Errorf("%s: path to %s hop %d %+v matches no control edge", p, id, i, h)
			}
			nonCI := false
			for _, ci := range cis {
				nonCI = nonCI || !ci
			}
			if !nonCI && i+1 < len(hs) {
				return fmt.Errorf("%s: path to %s expands through CI-only hop %d %s -> %s", p, id, i, h.From, h.To)
			}
			supplied = supplied || h.Evidence == Supplied || strings.HasPrefix(h.SourceAPI, "supplied:")
			stale = stale || h.Stale
			switch {
			case !refVerified(h.Evidence):
				unverified = true
				ev = NotVisible
			case h.Evidence == Supplied && ev != NotVisible:
				ev = Supplied
			case h.Evidence == Audit && (ev == Live || ev == Inferred):
				ev = Audit
			case h.Evidence == Inferred && ev == Live:
				ev = Inferred
			}
		}
		if path.Stale != stale {
			return fmt.Errorf("%s: path to %s has stale=%v, hops say %v", p, id, path.Stale, stale)
		}
		if path.Evidence != ev || path.Unverified != unverified {
			return fmt.Errorf("%s: path to %s has evidence %s/unverified=%v, hops say %s/%v", p, id, path.Evidence, path.Unverified, ev, unverified)
		}
		if path.Supplied != supplied {
			return fmt.Errorf("%s: path to %s has supplied=%v, hops say %v", p, id, path.Supplied, supplied)
		}
		want := allDist[id]
		if !unverified {
			want = confDist[id]
		}
		if len(hs) != want {
			return fmt.Errorf("%s: path to %s has %d hops, shortest is %d", p, id, len(hs), want)
		}
	}
	return nil
}

func propPathValidity(g *Graph, _ *rand.Rand) error {
	ix := NewIndex(g)
	for _, p := range ix.Principals() {
		if err := checkPaths(g, p, ix.Reach(p, Options{}), nil); err != nil {
			return err
		}
	}
	return nil
}

func totalsNotAbove(a, b Totals) error {
	type pair struct {
		name string
		a, b float64
	}
	for _, x := range []pair{
		{"principals", float64(a.Principals), float64(b.Principals)},
		{"confirmed.repos", float64(a.Confirmed.Repos), float64(b.Confirmed.Repos)},
		{"confirmed.orgs", float64(a.Confirmed.Orgs), float64(b.Confirmed.Orgs)},
		{"confirmed.workflows", float64(a.Confirmed.Workflows), float64(b.Confirmed.Workflows)},
		{"confirmed.secrets", float64(a.Confirmed.Secrets), float64(b.Confirmed.Secrets)},
		{"confirmed.oidc", float64(a.Confirmed.OIDC), float64(b.Confirmed.OIDC)},
		{"confirmed.runners", float64(a.Confirmed.Runners), float64(b.Confirmed.Runners)},
		{"confirmed.cloud_targets", float64(a.Confirmed.CloudTargets), float64(b.Confirmed.CloudTargets)},
		{"confirmed_pairs", float64(a.ConfirmedPairs), float64(b.ConfirmedPairs)},
		{"score", a.Score, b.Score},
	} {
		if x.a > x.b+1e-9 {
			return fmt.Errorf("after %s = %v > before %v", x.name, x.a, x.b)
		}
	}
	// Possible counts may grow when a fix turns confirmed reach into possible
	// reach, so only confirmed+possible is bounded.
	for _, x := range []pair{
		{"repos", float64(a.Confirmed.Repos + a.Possible.Repos), float64(b.Confirmed.Repos + b.Possible.Repos)},
		{"workflows", float64(a.Confirmed.Workflows + a.Possible.Workflows), float64(b.Confirmed.Workflows + b.Possible.Workflows)},
		{"secrets", float64(a.Confirmed.Secrets + a.Possible.Secrets), float64(b.Confirmed.Secrets + b.Possible.Secrets)},
		{"oidc", float64(a.Confirmed.OIDC + a.Possible.OIDC), float64(b.Confirmed.OIDC + b.Possible.OIDC)},
		{"runners", float64(a.Confirmed.Runners + a.Possible.Runners), float64(b.Confirmed.Runners + b.Possible.Runners)},
		{"cloud_targets", float64(a.Confirmed.CloudTargets + a.Possible.CloudTargets), float64(b.Confirmed.CloudTargets + b.Possible.CloudTargets)},
		{"pairs", float64(a.ConfirmedPairs + a.PossiblePairs), float64(b.ConfirmedPairs + b.PossiblePairs)},
	} {
		if x.a > x.b {
			return fmt.Errorf("after confirmed+possible %s = %v > before %v", x.name, x.a, x.b)
		}
	}
	return nil
}

// fixSets returns every singleton candidate plus 20 random subsets.
func fixSets(cands []Fix, r *rand.Rand) [][]Fix {
	var out [][]Fix
	for _, c := range cands {
		out = append(out, []Fix{c})
	}
	if len(cands) == 0 {
		return out
	}
	for i := 0; i < 20; i++ {
		var s []Fix
		for _, c := range cands {
			if r.IntN(2) == 0 {
				s = append(s, c)
			}
		}
		out = append(out, s)
	}
	return out
}

// extraFixSample bounds the non-candidate workflow fixes P6 adds per graph.
const extraFixSample = 6

// extraWorkflowFixes returns up to extraFixSample RestrictToken and
// HardenTrigger fixes on workflows that Candidates does not propose: ones
// whose token_write or CAN_TRIGGER edges are all not_visible, or that have
// none (a no-op). Candidates already covers the verified ones; these check
// that a fix on an unconfirmed or absent edge never grows reach either.
func extraWorkflowFixes(g *Graph, cands []Fix, r *rand.Rand) []Fix {
	have := map[string]bool{}
	for _, c := range cands {
		have[c.ID()] = true
	}
	seen := map[string]bool{}
	var extra []Fix
	for _, e := range g.Edges {
		for _, w := range []string{e.From, e.To} {
			if KindFromID(w) != KindWorkflow || seen[w] {
				continue
			}
			seen[w] = true
			for _, f := range []Fix{RestrictToken{Workflow: w}, HardenTrigger{Workflow: w}} {
				if !have[f.ID()] {
					extra = append(extra, f)
				}
			}
		}
	}
	var out []Fix
	for _, i := range sampleIdx(r, len(extra), extraFixSample) {
		out = append(out, extra[i])
	}
	return out
}

func fixIDs(fs []Fix) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID())
	}
	return out
}

func propFixMonotonic(g *Graph, r *rand.Rand) error {
	ix := NewIndex(g)
	principals := ix.Principals()
	base := map[string]Result{}
	for _, p := range principals {
		base[p] = ix.Reach(p, Options{})
	}
	cands := append(ix.Candidates(), extraWorkflowFixes(g, ix.Candidates(), r)...)
	for n, fs := range fixSets(cands, r) {
		cg := ix.buildControl(fs, ix.MaxAuditAge(0))
		for _, p := range principals {
			after := ix.reach(cg, p)
			// The random subsets are also checked against the reference model
			// with the same fixes applied (singletons are covered by the subsets).
			if n >= len(cands) {
				if err := sameKeys(confirmedIDs(after), refReach(g, p, fs, true)); err != nil {
					return fmt.Errorf("fixes %v: %s confirmed reach != reference: %v", fixIDs(fs), p, err)
				}
			}
			if extra := notSubset(confirmedIDs(after), confirmedIDs(base[p])); len(extra) > 0 {
				return fmt.Errorf("fixes %v grow %s confirmed reach by %v", fixIDs(fs), p, extra)
			}
			if extra := notSubset(allIDs(after), allIDs(base[p])); len(extra) > 0 {
				return fmt.Errorf("fixes %v grow %s confirmed+possible reach by %v", fixIDs(fs), p, extra)
			}
		}
		d := ix.WhatIf(fs)
		if err := totalsNotAbove(d.After, d.Before); err != nil {
			return fmt.Errorf("WhatIf(%v): %v", fixIDs(fs), err)
		}
	}
	return nil
}

// sampleIdx returns up to n distinct indices out of [0, total).
func sampleIdx(r *rand.Rand, total, n int) []int {
	idx := r.Perm(total)
	if len(idx) > n {
		idx = idx[:n]
	}
	sort.Ints(idx)
	return idx
}

// edgeSample bounds the per-graph cost of P7 and P8.
const edgeSample = 8

func propEdgeRemovalMonotonic(g *Graph, r *rand.Rand) error {
	ix := NewIndex(g)
	principals := ix.Principals()
	base := map[string]Result{}
	for _, p := range principals {
		base[p] = ix.Reach(p, Options{})
	}
	for _, i := range sampleIdx(r, len(g.Edges), edgeSample) {
		h := cloneGraph(g)
		e := h.Edges[i]
		h.Edges = append(h.Edges[:i:i], h.Edges[i+1:]...)
		hx := NewIndex(h)
		for _, p := range principals {
			after := hx.Reach(p, Options{})
			if extra := notSubset(confirmedIDs(after), confirmedIDs(base[p])); len(extra) > 0 {
				return fmt.Errorf("removing %s -%s-> %s grows %s confirmed reach by %v", e.From, e.Kind, e.To, p, extra)
			}
			if extra := notSubset(allIDs(after), allIDs(base[p])); len(extra) > 0 {
				return fmt.Errorf("removing %s -%s-> %s grows %s confirmed+possible reach by %v", e.From, e.Kind, e.To, p, extra)
			}
		}
	}
	return nil
}

func propEvidenceMonotonic(g *Graph, r *rand.Rand) error {
	ix := NewIndex(g)
	principals := ix.Principals()
	var nv []int
	for i, e := range g.Edges {
		if e.Evidence == NotVisible {
			nv = append(nv, i)
		}
	}
	for _, j := range sampleIdx(r, len(nv), edgeSample) {
		i := nv[j]
		h := cloneGraph(g)
		h.Edges[i].Evidence = Live
		hx := NewIndex(h)
		for _, p := range principals {
			if lost := notSubset(confirmedIDs(ix.Reach(p, Options{})), confirmedIDs(hx.Reach(p, Options{}))); len(lost) > 0 {
				e := g.Edges[i]
				return fmt.Errorf("upgrading %s -%s-> %s to live shrinks %s confirmed reach by %v", e.From, e.Kind, e.To, p, lost)
			}
		}
	}
	return nil
}

func propSuggestFixesConsistent(g *Graph, _ *rand.Rand) error {
	ix := NewIndex(g)
	picks := ix.SuggestFixes(5)
	var prefix []Fix
	prev := 0
	for i, s := range picks {
		if s.Removed <= 0 {
			return fmt.Errorf("pick %d %s removes %d pairs", i, s.FixID, s.Removed)
		}
		if s.CumulativeRemoved < prev {
			return fmt.Errorf("pick %d %s: cumulative_removed %d < previous %d", i, s.FixID, s.CumulativeRemoved, prev)
		}
		prev = s.CumulativeRemoved
		prefix = append(prefix, s.Fix)
		if got := ix.WhatIf(prefix).After.ConfirmedPairs; s.Remaining != got {
			return fmt.Errorf("pick %d %s: remaining %d, WhatIf(prefix) says %d", i, s.FixID, s.Remaining, got)
		}
	}
	return nil
}

// whoCanReachSample bounds the number of WhoCanReach targets checked in P10.
const whoCanReachSample = 5

func propDeterministic(g *Graph, r *rand.Rand) error {
	h := cloneGraph(g)
	r.Shuffle(len(h.Nodes), func(i, j int) { h.Nodes[i], h.Nodes[j] = h.Nodes[j], h.Nodes[i] })
	r.Shuffle(len(h.Edges), func(i, j int) { h.Edges[i], h.Edges[j] = h.Edges[j], h.Edges[i] })
	a, b := NewIndex(g), NewIndex(h)
	same := func(what string, x, y any) error {
		jx, err := json.Marshal(x)
		if err != nil {
			return err
		}
		jy, err := json.Marshal(y)
		if err != nil {
			return err
		}
		if !bytes.Equal(jx, jy) {
			return fmt.Errorf("%s differs after shuffling nodes and edges:\n%s\n%s", what, jx, jy)
		}
		return nil
	}
	if err := same("Principals", a.Principals(), b.Principals()); err != nil {
		return err
	}
	for _, p := range a.Principals() {
		if err := same("Reach("+p+")", a.Reach(p, Options{}), b.Reach(p, Options{})); err != nil {
			return err
		}
	}
	var targets []string
	for _, n := range g.Nodes {
		targets = append(targets, n.ID)
	}
	for _, e := range g.Edges {
		targets = append(targets, e.To)
	}
	sort.Strings(targets)
	for _, i := range sampleIdx(r, len(targets), whoCanReachSample) {
		if err := same("WhoCanReach("+targets[i]+")", a.WhoCanReach(targets[i]), b.WhoCanReach(targets[i])); err != nil {
			return err
		}
	}
	if err := same("TopPaths(0)", a.TopPaths(0), b.TopPaths(0)); err != nil {
		return err
	}
	return same("SuggestFixes(5)", a.SuggestFixes(5), b.SuggestFixes(5))
}

// TestPropertyReferenceAgreesOnFixture pins the reference BFS to the
// hand-checked acme fixture, so a bug in refReach cannot hide an engine bug.
func TestPropertyReferenceAgreesOnFixture(t *testing.T) {
	g := loadAcme(t)
	for _, p := range properties {
		if err := p.check(g, propRand(1)); err != nil {
			t.Errorf("%s on testdata/acme: %v", p.name, err)
		}
	}
	ref := refReach(g, "identity:alice", nil, true)
	if _, ok := ref["repo:acme-app/infra"]; !ok {
		t.Errorf("reference misses repo:acme-app/infra for identity:alice: %v", sortedIntKeys(ref))
	}
}

// refVerified is the reference reading of evidence: live, inferred and audit
// facts, and facts from a user-supplied file, are confirmed; not_visible (and
// anything unknown) is not. Kept separate from Verified so a broken Verified
// fails P2. Stale audit hops are already not_visible in refControl.
func refVerified(e Evidence) bool {
	return e == Live || e == "inferred" || e == Audit || e == "supplied"
}

// TestParallelEdgeTieBreak is the case P10 found: two parallel evidence edges
// with the same evidence used to collapse to whichever came first in g.Edges,
// so the reported hop's source_api changed with input order.
func TestParallelEdgeTieBreak(t *testing.T) {
	a := Edge{From: "members:acme", To: "repo:acme/web", Kind: CanPush, Evidence: Live, SourceAPI: "rest:b"}
	b := a
	b.SourceAPI = "rest:a"
	for _, edges := range [][]Edge{{a, b}, {b, a}} {
		g := &Graph{Schema: SchemaVersion, Edges: edges}
		hops := Reach(g, "members:acme", Options{}).Paths["repo:acme/web"].Hops
		if len(hops) != 1 || hops[0].SourceAPI != "rest:a" {
			t.Errorf("edges %v: hops = %+v, want one hop with source_api rest:a", edges, hops)
		}
	}
}
