package graph

import (
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
)

// fastIndex is the base control graph (no fixes) with node IDs interned to
// int32 and edges in flat slices, built once per Index on first use. Node
// numbers follow sorted ID order, so comparing two numbers compares their IDs
// and a traversal over numbers visits nodes in the same order as the
// map-based bfs. It also carries the fix overlay that SuggestFixes uses: for
// each control edge, which fixes can remove it.
type fastIndex struct {
	ids    []string
	num    map[string]int32
	isRepo []bool
	isPop  []bool // an org_members population (see Index.pairReach)

	// All base control edges, grouped by source in the order of
	// controlGraph.out (target ID, then control before CI).
	start []int32 // edges of node u are start[u]:start[u+1]
	to    []int32
	ci    []bool
	ok    []bool // Verified(hop evidence)
	hop   []Hop

	// Reverse adjacency: redge[rstart[v]:rstart[v+1]] are the edges into v.
	rstart []int32
	redge  []int32

	// The verified-only control graph used to count confirmed pairs, with
	// the fix overlay: vtags[vtagStart[e]:vtagStart[e+1]] are the fix tags
	// that remove edge e. An edge with no tags is never removed. An edge
	// with tags is removed once every one of them is applied (each tag is
	// one way the edge exists).
	vstart    []int32
	vto       []int32
	vci       []bool
	vtagStart []int32
	vtags     []int32
	tagNum    map[string]int32
}

func (ix *Index) fast() *fastIndex {
	ix.fastOnce.Do(func() { ix.fastIx = ix.buildFast() })
	return ix.fastIx
}

// overlayTag names the fix that removes a candidate control edge, or ""
// when no fix can remove it. It mirrors buildControl: fixSet.removesPush and
// removesTrigger drop CAN_PUSH and CAN_TRIGGER edges, and a pinned action
// drops every hop addResolves derives from its RESOLVES_TO edges (the
// reversed host -> action hop, and the ref_bypass principal -> action hops).
func overlayTag(ce cedge, e Edge) string {
	switch e.Kind {
	case CanPush:
		if ce.hop.To != e.To {
			return tagPin(ce.hop.To) // ref_bypass hop into the action
		}
		switch e.Attrs[AttrVia] {
		case ViaDefaultPerm:
			if KindFromID(e.From) == KindOrgMembers {
				return tagLower(OrgOf(e.From))
			}
		case ViaTokenWrite:
			return tagRestrict(e.From)
		case ViaOrgOwner:
			return tagOwner(ownerKey(e.From, OrgOf(e.To)))
		}
	case CanTrigger:
		return tagHarden(e.To)
	case ResolvesTo:
		return tagPin(e.From)
	}
	return ""
}

func tagPin(action string) string  { return "pin\x00" + action }
func tagLower(org string) string   { return "lower\x00" + org }
func tagRestrict(wf string) string { return "restrict\x00" + wf }
func tagHarden(wf string) string   { return "harden\x00" + wf }
func tagOwner(key string) string   { return "owner\x00" + key }

func setTags(m map[string]bool, f func(string) string, out []string) []string {
	for _, k := range sortedKeys(m) {
		out = append(out, f(k))
	}
	return out
}

// fixTags lists the overlay tags a fix applies.
func fixTags(f Fix) []string {
	var fs fixSet
	f.apply(&fs)
	var out []string
	out = setTags(fs.pinned, tagPin, out)
	out = setTags(fs.lowered, tagLower, out)
	out = setTags(fs.restricted, tagRestrict, out)
	out = setTags(fs.hardened, tagHarden, out)
	return setTags(fs.unowned, tagOwner, out)
}

func (ix *Index) buildFast() *fastIndex {
	// Record, for every control edge key, whether some verified evidence
	// edge that no fix removes backs it (then no fix set removes it), and
	// otherwise the tags of the verified edges that do.
	type ckey struct {
		from, to string
		ci       bool
	}
	type overlay struct {
		fixed bool
		tags  []string
	}
	ov := map[ckey]*overlay{}
	ix.buildControlRec(nil, ix.MaxAuditAge(0), func(ce cedge, e Edge) {
		if !Verified(ce.hop.Evidence) {
			return
		}
		k := ckey{ce.hop.From, ce.to, ce.ci}
		o := ov[k]
		if o == nil {
			o = &overlay{}
			ov[k] = o
		}
		if t := overlayTag(ce, e); t == "" {
			o.fixed = true
		} else {
			o.tags = append(o.tags, t)
		}
	})

	set := map[string]bool{}
	for _, n := range ix.g.Nodes {
		set[n.ID] = true
	}
	for _, e := range ix.g.Edges {
		set[e.From], set[e.To] = true, true
	}
	for from, es := range ix.base.out {
		set[from] = true
		for _, ce := range es {
			set[ce.to] = true
		}
	}
	for _, p := range ix.Principals() {
		set[p] = true
	}
	fx := &fastIndex{ids: sortedKeys(set), num: map[string]int32{}, tagNum: map[string]int32{}}
	n := len(fx.ids)
	fx.isRepo = make([]bool, n)
	fx.isPop = make([]bool, n)
	for i, id := range fx.ids {
		fx.num[id] = int32(i)
		fx.isRepo[i] = ix.Kind(id) == KindRepo
		fx.isPop[i] = ix.Kind(id) == KindOrgMembers
	}
	fx.start = make([]int32, n+1)
	fx.vstart = make([]int32, n+1)
	fx.vtagStart = []int32{0}
	indeg := make([]int32, n+1)
	for u, id := range fx.ids {
		fx.start[u] = int32(len(fx.to))
		fx.vstart[u] = int32(len(fx.vto))
		for _, ce := range ix.base.out[id] {
			v := fx.num[ce.to]
			ok := Verified(ce.hop.Evidence)
			fx.to = append(fx.to, v)
			fx.ci = append(fx.ci, ce.ci)
			fx.ok = append(fx.ok, ok)
			fx.hop = append(fx.hop, ce.hop)
			indeg[v+1]++
			if !ok {
				continue
			}
			fx.vto = append(fx.vto, v)
			fx.vci = append(fx.vci, ce.ci)
			if o := ov[ckey{id, ce.to, ce.ci}]; o != nil && !o.fixed {
				seen := map[string]bool{}
				for _, t := range o.tags {
					if !seen[t] {
						seen[t] = true
						fx.vtags = append(fx.vtags, fx.tag(t))
					}
				}
			}
			fx.vtagStart = append(fx.vtagStart, int32(len(fx.vtags)))
		}
	}
	fx.start[n] = int32(len(fx.to))
	fx.vstart[n] = int32(len(fx.vto))

	fx.rstart = make([]int32, n+1)
	for v := 0; v < n; v++ {
		fx.rstart[v+1] = fx.rstart[v] + indeg[v+1]
	}
	fx.redge = make([]int32, len(fx.to))
	fill := append([]int32(nil), fx.rstart[:n]...)
	for e, v := range fx.to {
		fx.redge[fill[v]] = int32(e)
		fill[v]++
	}
	return fx
}

func (fx *fastIndex) tag(t string) int32 {
	if i, ok := fx.tagNum[t]; ok {
		return i
	}
	i := int32(len(fx.tagNum))
	fx.tagNum[t] = i
	return i
}

// parallelFor runs work(w, i) for i in [0, n) on up to GOMAXPROCS workers; w
// is the worker number, for per-worker scratch. Each i runs exactly once,
// and callers write results by i, so the outcome does not depend on
// scheduling.
func parallelFor(n, workers int, work func(w, i int)) {
	if workers > n {
		workers = n
	}
	if workers <= 1 {
		for i := 0; i < n; i++ {
			work(0, i)
		}
		return
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				work(w, i)
			}
		}(w)
	}
	wg.Wait()
}

func workers() int { return max(1, runtime.GOMAXPROCS(0)) }

// --- WhoCanReach ---------------------------------------------------------

// whoCanReach finds the principals that can reach target with one reverse
// walk over the control graph, then runs the forward traversal only from
// those, stopping once target is found. The paths are the ones reach
// reports (see pathScratch.pathTo).
func (ix *Index) whoCanReach(target string) []Path {
	fx := ix.fast()
	t, ok := fx.num[target]
	if !ok {
		return nil
	}
	// can[x]: controlling x reaches target. Target is reached from a node
	// with any edge into it (a CI hop records its target), and control
	// spreads backwards over control (non-CI) edges only.
	can := make([]bool, len(fx.ids))
	can[t] = true
	queue := []int32{t}
	for len(queue) > 0 {
		x := queue[0]
		queue = queue[1:]
		for _, e := range fx.redge[fx.rstart[x]:fx.rstart[x+1]] {
			if fx.ci[e] && x != t {
				continue
			}
			if u := fx.from(e); !can[u] {
				can[u] = true
				queue = append(queue, u)
			}
		}
	}
	var cands []string
	for _, p := range ix.Principals() {
		if p != target && can[fx.num[p]] {
			cands = append(cands, p)
		}
	}
	out := make([]Path, len(cands))
	found := make([]bool, len(cands))
	nw := workers()
	scratch := make([]*pathScratch, nw)
	parallelFor(len(cands), nw, func(w, i int) {
		if scratch[w] == nil {
			scratch[w] = newPathScratch(len(fx.ids))
		}
		out[i], found[i] = scratch[w].pathTo(fx, fx.num[cands[i]], t)
	})
	paths := out[:0]
	for i, p := range out {
		if found[i] {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil // as the naive loop returned
	}
	sortWho(paths)
	return paths
}

// sortWho orders WhoCanReach output: confirmed first, then fewer hops, then
// principal ID.
func sortWho(out []Path) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Unverified != out[j].Unverified {
			return !out[i].Unverified
		}
		if len(out[i].Hops) != len(out[j].Hops) {
			return len(out[i].Hops) < len(out[j].Hops)
		}
		return out[i].From < out[j].From
	})
}

// from returns the source node of edge e (binary search over start).
func (fx *fastIndex) from(e int32) int32 {
	return int32(sort.Search(len(fx.ids), func(u int) bool { return fx.start[u+1] > e }))
}

// pathScratch is one worker's buffers for pathTo. Stamps avoid clearing
// per-node arrays between traversals.
type pathScratch struct {
	stamp      uint32
	seen       []uint32
	ctrl       []uint32
	firstEdge  []int32 // edge that first reached the node (its reported path)
	ctrlEdge   []int32 // edge of the node's control path; -1 at the start
	ctrlEv     []Evidence
	candStamp  []uint32
	candEdge   []int32
	candCtrl   []bool
	candEv     []Evidence
	frontier   []int32
	touched    []int32
	nextFront  []int32
	sourceNode []int32 // source node of candEdge, kept to avoid a search
	firstFrom  []int32
	ctrlFrom   []int32
}

func newPathScratch(n int) *pathScratch {
	return &pathScratch{
		seen: make([]uint32, n), ctrl: make([]uint32, n),
		firstEdge: make([]int32, n), ctrlEdge: make([]int32, n), ctrlEv: make([]Evidence, n),
		candStamp: make([]uint32, n), candEdge: make([]int32, n), candCtrl: make([]bool, n), candEv: make([]Evidence, n),
		sourceNode: make([]int32, n), firstFrom: make([]int32, n), ctrlFrom: make([]int32, n),
	}
}

// pathTo returns the path reach(base, from).Paths[to] would report: the
// confirmed traversal's path when to is confirmed, else the full one's.
func (s *pathScratch) pathTo(fx *fastIndex, from, to int32) (Path, bool) {
	if hops, ok := s.bfsTo(fx, from, to, true); ok {
		return pathOf(fx.ids[from], fx.ids[to], hops), true
	}
	if hops, ok := s.bfsTo(fx, from, to, false); ok {
		return pathOf(fx.ids[from], fx.ids[to], hops), true
	}
	return Path{}, false
}

// bfsTo is controlGraph.bfs over the interned graph, stopped as soon as
// target is seen. It makes the same choices: layer by layer, among
// candidates for a node in one layer a control hop beats a CI hop, then the
// stronger path evidence wins, then the first found (frontier in ID order,
// edges in controlGraph.out order). A node is expanded only once
// controlled, along its control path. The first path that reaches a node
// is the one reported.
func (s *pathScratch) bfsTo(fx *fastIndex, from, target int32, verifiedOnly bool) ([]Hop, bool) {
	s.stamp += 2
	seenMark, candMark := s.stamp, s.stamp+1
	s.seen[from], s.ctrl[from] = seenMark, seenMark
	s.ctrlEdge[from], s.ctrlEv[from] = -1, Live
	s.frontier = append(s.frontier[:0], from)
	for len(s.frontier) > 0 {
		s.touched = s.touched[:0]
		for _, u := range s.frontier {
			base := s.ctrlEv[u]
			for e := fx.start[u]; e < fx.start[u+1]; e++ {
				if verifiedOnly && !fx.ok[e] {
					continue
				}
				v := fx.to[e]
				if s.seen[v] == seenMark && (s.ctrl[v] == seenMark || fx.ci[e]) {
					continue
				}
				ctrl := !fx.ci[e]
				ev := weakest(base, fx.hop[e].Evidence)
				if s.candStamp[v] != candMark {
					s.candStamp[v] = candMark
					s.touched = append(s.touched, v)
				} else if better := (ctrl && !s.candCtrl[v]) || (ctrl == s.candCtrl[v] && evRank(ev) > evRank(s.candEv[v])); !better {
					continue
				}
				s.candEdge[v], s.candCtrl[v], s.candEv[v], s.sourceNode[v] = e, ctrl, ev, u
			}
		}
		sort.Slice(s.touched, func(i, j int) bool { return s.touched[i] < s.touched[j] })
		s.nextFront = s.nextFront[:0]
		for _, v := range s.touched {
			s.candStamp[v] = 0
			if s.seen[v] != seenMark {
				s.seen[v] = seenMark
				s.firstEdge[v], s.firstFrom[v] = s.candEdge[v], s.sourceNode[v]
			}
			if s.candCtrl[v] {
				s.ctrl[v] = seenMark
				s.ctrlEdge[v], s.ctrlFrom[v], s.ctrlEv[v] = s.candEdge[v], s.sourceNode[v], s.candEv[v]
				s.nextFront = append(s.nextFront, v)
			}
		}
		s.frontier, s.nextFront = s.nextFront, s.frontier
		if s.seen[target] == seenMark {
			// The reported path: the control path of the node that first
			// reached target, plus that hop.
			var rev []Hop
			rev = append(rev, fx.hop[s.firstEdge[target]])
			for u := s.firstFrom[target]; s.ctrlEdge[u] >= 0; u = s.ctrlFrom[u] {
				rev = append(rev, fx.hop[s.ctrlEdge[u]])
			}
			hops := make([]Hop, len(rev))
			for i, h := range rev {
				hops[len(rev)-1-i] = h
			}
			return hops, true
		}
	}
	return nil, false
}
