package graph

import (
	"slices"
	"strings"
)

// suggestFixes is SuggestFixes without rebuilding anything per candidate. It
// returns exactly what the plain greedy returns (each round, the candidate
// with the largest marginal drop in confirmed pairs, ties by fix ID), using:
//
//   - the fix overlay: the control graph is built once, and a set of fixes is
//     a set of applied tags; the traversal skips an edge once every tag that
//     backs it is applied (fastIndex.vtags);
//   - confirmed-only counting: only the verified traversal runs, and it
//     counts repos without building paths;
//   - affected-principal pruning: a candidate can change a principal's count
//     only if it removes a control edge leaving a node the principal
//     controls. Each principal keeps its count and its per-candidate drops
//     across rounds; after a pick only the principals that pick touched are
//     recomputed;
//   - a bounded worker pool over principals, each worker with its own
//     scratch. Results are written by principal and summed in order, and the
//     pick is chosen after all of them are in, so the outcome never depends
//     on scheduling.
func (ix *Index) suggestFixes(budget int, cands []Fix) []FixSuggestion {
	if budget <= 0 {
		return nil
	}
	fx := ix.fast()
	candTags := make([][]int32, len(cands))
	tagCands := make([][]int32, len(fx.tagNum))
	for c, f := range cands {
		for _, t := range fixTags(f) {
			if n, ok := fx.tagNum[t]; ok {
				candTags[c] = append(candTags[c], n)
				tagCands[n] = append(tagCands[n], int32(c))
			}
		}
	}
	sps := ix.ScoringPrincipals()
	ps := make([]int32, len(sps))
	for i, p := range sps {
		ps[i] = fx.num[p]
	}

	applied := make([]bool, len(fx.tagNum))
	states := make([]principalState, len(ps))
	nw := workers()
	scratch := make([]*countScratch, nw)
	round := 0
	eval := func(idx []int) {
		round++
		parallelFor(len(idx), nw, func(w, i int) {
			if scratch[w] == nil {
				scratch[w] = newCountScratch(len(fx.ids), len(fx.tagNum), len(cands))
			}
			s := scratch[w]
			if s.round != round {
				copy(s.off, applied)
				s.round = round
			}
			p := idx[i]
			states[p] = s.evalPrincipal(fx, ps[p], candTags, tagCands)
		})
	}
	gain := make([]int, len(cands))
	addGains := func(st principalState, sign int) {
		for i, c := range st.touch {
			gain[c] += sign * int(st.drop[i])
		}
	}

	all := make([]int, len(ps))
	for i := range all {
		all[i] = i
	}
	eval(all)
	baseline := 0
	for _, st := range states {
		baseline += st.count
		addGains(st, 1)
	}

	var out []FixSuggestion
	current := baseline
	for len(out) < budget && current > 0 {
		best := -1
		for c := range cands {
			if gain[c] > 0 && (best < 0 || gain[c] > gain[best]) {
				best = c
			}
		}
		if best < 0 {
			break
		}
		after := current - gain[best]
		var affected []int
		for p, st := range states {
			for _, c := range st.touch {
				if int(c) == best {
					affected = append(affected, p)
					break
				}
			}
		}
		for _, t := range candTags[best] {
			applied[t] = true
		}
		for _, p := range affected {
			addGains(states[p], -1)
		}
		eval(affected)
		for _, p := range affected {
			addGains(states[p], 1)
		}
		f := cands[best]
		var es []string
		for _, e := range f.edges(ix) {
			es = append(es, strings.Join([]string{e.From, string(e.Kind), e.To}, " "))
		}
		removedTotal := baseline - after
		out = append(out, FixSuggestion{
			Fix: f, FixID: f.ID(), Edges: es,
			Removed: current - after, CumulativeRemoved: removedTotal, Remaining: after,
			CumulativePct: 100 * float64(removedTotal) / float64(baseline),
			Caveat:        fixCaveat(ix, f),
		})
		current = after
	}
	return out
}

// principalState is one principal's confirmed repo count under the applied
// fixes, the candidates that touch it (remove a live edge out of a node it
// controls, alone or together with other candidates), and for each the drop
// in its count if that candidate alone were added.
type principalState struct {
	count int
	touch []int32
	drop  []int32
}

// countScratch is one worker's buffers for evalPrincipal.
type countScratch struct {
	round    int    // the eval round off was last copied in
	off      []bool // applied tags, plus the candidate under test
	stamp    uint32
	ctrl     []uint32
	reached  []uint32
	queue    []int32
	ctrlList []int32
	cstamp   uint32
	cmark    []uint32 // candidate seen in this evaluation
	cneed    []uint32 // candidate can remove an edge alone: needs a count
	live     []int32
}

func newCountScratch(nodes, tags, cands int) *countScratch {
	return &countScratch{off: make([]bool, tags), ctrl: make([]uint32, nodes), reached: make([]uint32, nodes),
		cmark: make([]uint32, cands), cneed: make([]uint32, cands)}
}

// removed reports whether verified edge e is skipped under s.off: it has
// tags and every one is applied.
func (s *countScratch) removed(fx *fastIndex, e int32) bool {
	lo, hi := fx.vtagStart[e], fx.vtagStart[e+1]
	if lo == hi {
		return false
	}
	for _, t := range fx.vtags[lo:hi] {
		if !s.off[t] {
			return false
		}
	}
	return true
}

// count is the number of repos in p's confirmed pair reach under s.off (p
// itself excluded): the nodes p controls over verified control edges, plus
// the CI targets of those nodes, never entering an org_members population
// other than p (see Index.pairReach). After it returns, s.ctrlList holds the
// controlled nodes when keep is set.
func (s *countScratch) count(fx *fastIndex, p int32, keep bool) int {
	s.stamp++
	mark := s.stamp
	s.ctrl[p], s.reached[p] = mark, mark
	s.queue = append(s.queue[:0], p)
	n := 0
	for i := 0; i < len(s.queue); i++ {
		u := s.queue[i]
		for e := fx.vstart[u]; e < fx.vstart[u+1]; e++ {
			v := fx.vto[e]
			if s.ctrl[v] == mark || (fx.vci[e] && s.reached[v] == mark) || fx.isPop[v] || s.removed(fx, e) {
				continue
			}
			if s.reached[v] != mark {
				s.reached[v] = mark
				if fx.isRepo[v] {
					n++
				}
			}
			if !fx.vci[e] {
				s.ctrl[v] = mark
				s.queue = append(s.queue, v)
			}
		}
	}
	if keep {
		s.ctrlList = append(s.ctrlList[:0], s.queue...)
	}
	return n
}

// evalPrincipal computes p's state under s.off (the applied tags).
func (s *countScratch) evalPrincipal(fx *fastIndex, p int32, candTags, tagCands [][]int32) principalState {
	st := principalState{count: s.count(fx, p, true)}
	s.cstamp++
	mark := s.cstamp
	for _, u := range s.ctrlList {
		for e := fx.vstart[u]; e < fx.vstart[u+1]; e++ {
			lo, hi := fx.vtagStart[e], fx.vtagStart[e+1]
			if lo == hi {
				continue
			}
			s.live = s.live[:0]
			for _, t := range fx.vtags[lo:hi] {
				if !s.off[t] {
					s.live = append(s.live, t)
				}
			}
			for _, t := range s.live {
				for _, c := range tagCands[t] {
					if s.cmark[c] != mark {
						s.cmark[c] = mark
						st.touch = append(st.touch, c)
					}
					if s.cneed[c] != mark && covers(candTags[c], s.live) {
						s.cneed[c] = mark
					}
				}
			}
		}
	}
	slices.Sort(st.touch)
	st.drop = make([]int32, len(st.touch))
	for i, c := range st.touch {
		if s.cneed[c] != mark {
			continue
		}
		var set []int32
		for _, t := range candTags[c] {
			if !s.off[t] {
				s.off[t] = true
				set = append(set, t)
			}
		}
		st.drop[i] = int32(st.count - s.count(fx, p, false))
		for _, t := range set {
			s.off[t] = false
		}
	}
	return st
}

// covers reports whether every tag in live is one of tags.
func covers(tags, live []int32) bool {
	for _, t := range live {
		found := false
		for _, x := range tags {
			if x == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// confirmedPairs is WhatIf(fixes).Before.ConfirmedPairs and
// .After.ConfirmedPairs without building paths or a control graph per fix
// set: the fast index's counting walk over the fix overlay, on a worker pool.
// Every fix must have overlay tags (fixTags); a fix with none changes
// nothing here.
func (ix *Index) confirmedPairs(fixes []Fix) (before, after int) {
	fx := ix.fast()
	sps := ix.ScoringPrincipals()
	applied := make([]bool, len(fx.tagNum))
	for _, f := range fixes {
		for _, t := range fixTags(f) {
			if n, ok := fx.tagNum[t]; ok {
				applied[n] = true
			}
		}
	}
	nw := workers()
	scratch := make([]*countScratch, nw)
	b, a := make([]int, len(sps)), make([]int, len(sps))
	parallelFor(len(sps), nw, func(w, i int) {
		if scratch[w] == nil {
			scratch[w] = newCountScratch(len(fx.ids), len(fx.tagNum), 0)
		}
		s := scratch[w]
		p := fx.num[sps[i]]
		clear(s.off)
		b[i] = s.count(fx, p, false)
		copy(s.off, applied)
		a[i] = s.count(fx, p, false)
	})
	for i := range sps {
		before += b[i]
		after += a[i]
	}
	return before, after
}
