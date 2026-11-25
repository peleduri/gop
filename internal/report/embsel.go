package report

import (
	"container/heap"
	"math"
	"runtime"
	"sort"
	"sync"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// pathCand is one reach path that may be embedded: its target org's
// truncation keys, not the path itself (selectPaths walks the kept ones
// again). pi is the principal's index in the scores; within a principal,
// targets come in ID order, so (pi, to) is the order the paths are listed in.
type pathCand struct {
	conf bool
	term int8
	hops int16
	pi   int32
	to   string
	tk   string
	org  string
	path graph.Path // set for kept candidates only, after the second walk
}

// candLess is the truncation order: confirmed first, then terminal impact
// (OIDC and cloud, secrets, runners, repos), then fewer hops, then listing
// order.
func candLess(a, b *pathCand) bool {
	if a.conf != b.conf {
		return a.conf
	}
	if a.term != b.term {
		return a.term < b.term
	}
	if a.hops != b.hops {
		return a.hops < b.hops
	}
	if a.pi != b.pi {
		return a.pi < b.pi
	}
	return a.to < b.to
}

// worstFirst is a heap of the best cap candidates seen, the worst on top.
type worstFirst []*pathCand

func (h worstFirst) Len() int           { return len(h) }
func (h worstFirst) Less(i, j int) bool { return candLess(h[j], h[i]) }
func (h worstFirst) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *worstFirst) Push(x any)        { *h = append(*h, x.(*pathCand)) }
func (h *worstFirst) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// orgTop keeps the best cap candidates of one target org and counts all.
type orgTop struct {
	total int
	h     worstFirst
}

func (o *orgTop) add(c *pathCand, cap int) {
	o.total++
	if len(o.h) < cap {
		heap.Push(&o.h, c)
		return
	}
	if candLess(c, o.h[0]) {
		o.h[0] = c
		heap.Fix(&o.h, 0)
	}
}

type orgSel struct {
	org   string
	total int
	kept  []*pathCand // in truncation order
}

type pathSel struct {
	perOrg int
	orgs   []orgSel   // by org name
	porgs  [][]string // principalOrgs per score index
}

// selectPaths walks every scored principal once, on a worker pool, and keeps
// for each target org the best perOrg paths in candLess order (perOrg is
// maxPerOrg, lowered so that all orgs together stay near maxEmbeddedPaths),
// counting every path. Only the kept paths are ever turned into embedded
// paths, so memory stays bounded by the cap, not by principals x targets.
func selectPaths(ix *graph.Index, scores []graph.Score, maxPerOrg int) pathSel {
	sel := pathSel{porgs: make([][]string, len(scores))}
	nw := max(1, min(len(scores), runtime.GOMAXPROCS(0)))
	local := make([]map[string]*orgTop, nw)
	jobs := make(chan int)
	done := make(chan int)
	for w := 0; w < nw; w++ {
		local[w] = map[string]*orgTop{}
		go func(w int) {
			for i := range jobs {
				p := scores[i].Principal
				sel.porgs[i] = principalOrgs(ix, p)
				r := ix.Reach(p, graph.Options{})
				for _, to := range sortedPathKeys(r.Paths) {
					tk := targetKind(ix.Kind(to))
					if tk == "" {
						continue
					}
					path := r.Paths[to]
					org := orgName(graph.OrgOf(to))
					if tk == "cloud" && len(path.Hops) > 0 {
						// A cloud role has no org: file it under the org of the workflow that assumes it.
						org = orgName(graph.OrgOf(path.Hops[len(path.Hops)-1].From))
					}
					o := local[w][org]
					if o == nil {
						o = &orgTop{}
						local[w][org] = o
					}
					o.add(&pathCand{conf: !path.Unverified, term: int8(termRank(tk)), hops: int16(min(len(path.Hops), math.MaxInt16)), pi: int32(i), to: to, tk: tk, org: org}, maxPerOrg)
				}
			}
			done <- w
		}(w)
	}
	for i := range scores {
		jobs <- i
	}
	close(jobs)
	for range nw {
		<-done
	}

	merged := map[string]*orgSel{}
	for _, m := range local {
		for org, o := range m {
			s := merged[org]
			if s == nil {
				s = &orgSel{org: org}
				merged[org] = s
			}
			s.total += o.total
			s.kept = append(s.kept, o.h...)
		}
	}
	sel.perOrg = maxPerOrg
	if n := len(merged); n > 0 {
		sel.perOrg = min(maxPerOrg, max(minPathsPerOrg, maxEmbeddedPaths/n))
	}
	for _, s := range merged {
		sort.Slice(s.kept, func(i, j int) bool { return candLess(s.kept[i], s.kept[j]) })
		if len(s.kept) > sel.perOrg {
			s.kept = s.kept[:sel.perOrg]
		}
		sel.orgs = append(sel.orgs, *s)
	}
	sort.Slice(sel.orgs, func(i, j int) bool { return sel.orgs[i].org < sel.orgs[j].org })

	// Walk the principals of the kept paths again and take their paths:
	// holding every candidate's hops would cost principals x targets.
	byP := map[int32][]*pathCand{}
	for _, o := range sel.orgs {
		for _, c := range o.kept {
			byP[c.pi] = append(byP[c.pi], c)
		}
	}
	pis := make([]int32, 0, len(byP))
	for pi := range byP {
		pis = append(pis, pi)
	}
	parallelEach(len(pis), func(k int) {
		pi := pis[k]
		r := ix.Reach(scores[pi].Principal, graph.Options{})
		for _, c := range byP[pi] {
			c.path = r.Paths[c.to]
		}
	})
	return sel
}

// parallelEach runs fn(i) for i in [0, n) on GOMAXPROCS workers.
func parallelEach(n int, fn func(i int)) {
	nw := max(1, min(n, runtime.GOMAXPROCS(0)))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range nw {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

// embPathOf turns a kept candidate into its embedded path.
func embPathOf(ix *graph.Index, c *pathCand, porgs []string) embPath {
	path := c.path
	ep := embPath{From: path.From, FromOrgs: porgs, To: c.to, ToKind: c.tk, ToOrg: c.org,
		Ev: "confirmed", Refs: []string{}, Note: path.SuppliedNote()}
	if path.Unverified {
		ep.Ev = "possible"
	}
	refs := map[string]bool{}
	for _, h := range ix.Annotate(path).Hops {
		ep.Hops = append(ep.Hops, embHop{From: h.From, To: h.To, Kind: string(h.Kind),
			Ev: mcpserver.HopEvidenceLabel(h), API: h.SourceAPI, Rev: h.Reverse, Why: h.Reason, Note: h.Note, raw: h.Evidence, stale: h.Stale})
		for _, id := range []string{h.From, h.To} {
			if ix.Kind(id) == graph.KindActionRef {
				refs[refKind(ix, id)] = true
			}
		}
	}
	ep.Refs = sortedSet(refs)
	return ep
}
