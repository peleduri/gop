package graph

// Upstream returns every node with a control path to target in the control
// graph with no fixes, confirmed or possible (not_visible hops are followed),
// sorted and without target itself. It is the reverse of Reach: v is in
// Upstream(t) exactly when Reach(v) has a path to t. A CI-only hop (a workflow
// running in its repo's CI) counts only as the last hop into target, as in
// Reach.
func (ix *Index) Upstream(target string) []string {
	type in struct {
		from string
		ci   bool
	}
	rev := map[string][]in{}
	for from, es := range ix.base.out {
		for _, e := range es {
			rev[e.to] = append(rev[e.to], in{from, e.ci})
		}
	}
	seen := map[string]bool{target: true}
	frontier := []string{target}
	for len(frontier) > 0 {
		v := frontier[0]
		frontier = frontier[1:]
		for _, u := range rev[v] {
			if seen[u.from] || (u.ci && v != target) {
				continue
			}
			seen[u.from] = true
			frontier = append(frontier, u.from)
		}
	}
	delete(seen, target)
	return sortedKeys(seen)
}
