package graph

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// genEnterprise builds a synthetic enterprise with a realistic shape for the
// engine benchmarks: one shared-actions org (acme-o0) whose repos host the
// action refs, and orgs-1 consumer orgs (acme-o1, ...) holding the repos.
//
//   - About 70% of workflows use 1 to 5 shared actions, picked with a skewed
//     (Zipf) popularity, so a few actions are used everywhere.
//   - About 30% of action refs are mutable (branch or tag), the rest SHA pins;
//     some branch refs are protected, with ref_bypass pushes into their host.
//   - About 10% of actions are composites that USES another action (nested
//     USES, cycles allowed).
//   - About 20% of workflows have a write GITHUB_TOKEN (via=token_write), most
//     carry a secret, some an OIDC token or a self-hosted runner.
//   - Half the consumer orgs have default_perm write, so their members push
//     to every repo of the org (via=default_perm).
//   - principals is the number of identities and teams: 60% identities with
//     direct pushes, 20% teams with team pushes, 20% plain org members (not
//     scoring principals). external:anyone and some org members can cause a
//     risky trigger in a few workflows.
//   - About 1% of edges are not_visible, 10% audit (a fifth of those older
//     than the 90-day maximum audit age, so stale) and 10% inferred; the rest
//     are live.
//
// popularRepo (repo:acme-o1/r0) always runs the most popular action, which is
// mutable, with a write token, so many principals reach it.
func genEnterprise(seed uint64, orgs, repos, actions, principals int) *Graph {
	r := rand.New(rand.NewPCG(seed, 0x656e74))
	orgs = max(orgs, 2)
	repos = max(repos, 1)
	actions = max(actions, 1)
	g := &Graph{Schema: SchemaVersion, Enterprise: "acme", CollectedAt: genTime}
	node := func(id string, kind NodeKind, attrs map[string]string) {
		g.Nodes = append(g.Nodes, Node{ID: id, Kind: kind, Name: id, Attrs: attrs, Evidence: Live})
	}
	ev := func() Evidence {
		switch x := r.IntN(100); {
		case x == 0:
			return NotVisible
		case x < 11:
			return Audit
		case x < 21:
			return Inferred
		}
		return Live
	}
	edge := func(from, to string, kind EdgeKind, attrs map[string]string) {
		e := Edge{From: from, To: to, Kind: kind, Evidence: ev(),
			SourceAPI: "bench:" + string(kind), ObservedAt: genTime, Attrs: attrs}
		if e.Evidence == Audit && r.IntN(5) == 0 {
			e.ObservedAt = genTime.Add(-120 * 24 * time.Hour)
		}
		g.Edges = append(g.Edges, e)
	}
	org := func(i int) string { return fmt.Sprintf("acme-o%d", i) }
	consumer := func(i int) string { return org(1 + i%(orgs-1)) }

	for i := 0; i < orgs; i++ {
		perm := "read"
		if i > 0 && i%2 == 1 {
			perm = "write"
		}
		node("org:"+org(i), KindOrg, map[string]string{AttrDefaultPerm: perm, AttrTwoFactor: "required", AttrSSO: "enforced"})
		node("members:"+org(i), KindOrgMembers, nil)
	}

	// Shared actions: two refs per host repo on average.
	hosts := max(1, actions/2)
	for h := 0; h < hosts; h++ {
		node(fmt.Sprintf("repo:%s/a%d", org(0), h), KindRepo, nil)
	}
	actionIDs := make([]string, actions)
	refKind := map[string]map[string]string{} // USES attrs per action
	for i := 0; i < actions; i++ {
		h := i % hosts
		host := fmt.Sprintf("repo:%s/a%d", org(0), h)
		attrs := map[string]string{}
		var ref string
		switch x := r.IntN(10); {
		case i == 0 || x < 2:
			ref, attrs[AttrRefKind] = fmt.Sprintf("main%d", i), "branch"
			if i != 0 && r.IntN(4) == 0 {
				attrs[AttrRefProtected] = "true"
				attrs[AttrBypass] = "none"
			}
		case x < 3:
			ref, attrs[AttrRefKind] = fmt.Sprintf("v%d", i), "tag"
		default:
			ref, attrs[AttrRefKind] = fmt.Sprintf("%040x", r.Uint64()<<8|uint64(i)), "sha"
		}
		id := fmt.Sprintf("action:%s/a%d@%s", org(0), h, ref)
		actionIDs[i] = id
		refKind[id] = map[string]string{AttrRefKind: attrs[AttrRefKind]}
		node(id, KindActionRef, attrs)
		edge(id, host, ResolvesTo, nil)
	}
	// Nested USES: composites.
	for i, a := range actionIDs {
		if i > 0 && r.IntN(10) == 0 {
			b := actionIDs[r.IntN(actions)]
			edge(a, b, Uses, refKind[b])
		}
	}

	zipf := rand.NewZipf(r, 1.2, 4, uint64(actions-1))
	var workflows []string
	repoIDs := make([]string, repos)
	repoOrg := make([]int, repos)
	for i := 0; i < repos; i++ {
		o := consumer(i)
		repoOrg[i] = 1 + i%(orgs-1)
		repo := fmt.Sprintf("repo:%s/r%d", o, i)
		repoIDs[i] = repo
		node(repo, KindRepo, nil)
		nwf := 1 + r.IntN(2)
		for w := 0; w < nwf; w++ {
			wf := fmt.Sprintf("workflow:%s/r%d/.github/workflows/w%d.yml", o, i, w)
			workflows = append(workflows, wf)
			node(wf, KindWorkflow, nil)
			edge(wf, repo, DefinedIn, nil)
			popular := i == 0 && w == 0
			if popular || r.IntN(10) < 7 {
				seen := map[int]bool{}
				if popular {
					seen[0] = true
					edge(wf, actionIDs[0], Uses, refKind[actionIDs[0]])
				}
				for k := 1 + r.IntN(5); k > 0; k-- {
					a := int(zipf.Uint64())
					if !seen[a] {
						seen[a] = true
						edge(wf, actionIDs[a], Uses, refKind[actionIDs[a]])
					}
				}
			}
			if popular || r.IntN(5) == 0 {
				edge(wf, repo, CanPush, map[string]string{AttrVia: ViaTokenWrite, AttrJobs: "build"})
			}
			if r.IntN(4) != 0 {
				s := fmt.Sprintf("secret:%s/r%d/DEPLOY_KEY", o, i)
				if w == 0 {
					node(s, KindSecret, nil)
				}
				edge(wf, s, ExecutesWith, nil)
			}
			if r.IntN(10) == 0 {
				oi := fmt.Sprintf("oidc:%s/r%d/w%d", o, i, w)
				node(oi, KindOIDC, nil)
				edge(wf, oi, ExecutesWith, nil)
			}
			if r.IntN(20) == 0 {
				run := fmt.Sprintf("runner:%s/self-hosted-%d", o, i%7)
				edge(wf, run, ExecutesWith, nil)
			}
		}
		if repoOrg[i]%2 == 1 {
			edge("members:"+o, repo, CanPush, map[string]string{AttrVia: ViaDefaultPerm})
		}
	}
	for i := 0; i < 7*(orgs-1); i++ {
		node(fmt.Sprintf("runner:%s/self-hosted-%d", consumer(i/7), i%7), KindRunner, nil)
	}

	pickRepo := func() string {
		if r.IntN(10) == 0 {
			return fmt.Sprintf("repo:%s/a%d", org(0), r.IntN(hosts))
		}
		return repoIDs[r.IntN(repos)]
	}
	for i := 0; i < principals; i++ {
		o := 1 + r.IntN(orgs-1)
		switch x := r.IntN(10); {
		case x < 6:
			id := fmt.Sprintf("identity:u%d", i)
			node(id, KindIdentity, nil)
			edge(id, "org:"+org(o), MemberOf, nil)
			for k := 1 + r.IntN(3); k > 0; k-- {
				edge(id, pickRepo(), CanPush, map[string]string{AttrVia: ViaDirect})
			}
			if r.IntN(20) == 0 {
				h := r.IntN(hosts)
				edge(id, fmt.Sprintf("repo:%s/a%d", org(0), h), CanPush,
					map[string]string{AttrVia: ViaRefBypass, AttrRef: actionRef(Node{ID: actionIDs[h]})})
			}
		case x < 8:
			id := fmt.Sprintf("team:%s/t%d", org(o), i)
			node(id, KindIdentity, nil)
			for k := 5 + r.IntN(45); k > 0; k-- {
				j := r.IntN(repos)
				edge(id, repoIDs[j], CanPush, map[string]string{AttrVia: ViaTeam})
			}
		default:
			id := fmt.Sprintf("identity:u%d", i)
			node(id, KindIdentity, nil)
			edge(id, "org:"+org(o), MemberOf, nil)
		}
	}
	node("external:anyone", KindExternal, nil)
	for _, wf := range workflows {
		switch r.IntN(100) {
		case 0, 1:
			edge("external:anyone", wf, CanTrigger, map[string]string{"trigger": "pull_request_target", "exec": "checkout"})
		case 2:
			edge("members:"+consumer(r.IntN(orgs-1)), wf, CanTrigger, map[string]string{"trigger": "issue_comment", "exec": "injection"})
		}
	}
	return g
}

const popularRepo = "repo:acme-o1/r0"

// bench10k is the 10k-repo enterprise of the benchmarks: 10 orgs, 10,000
// consumer repos, 2,000 action refs and 2,000 identities and teams.
func bench10k() *Graph { return genEnterprise(1, 10, 10000, 2000, 2000) }

var benchSink any

func BenchmarkNewIndex(b *testing.B) {
	g := bench10k()
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = NewIndex(g)
		}
	})
}

func BenchmarkReach(b *testing.B) {
	ix := NewIndex(bench10k())
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = ix.Reach("members:acme-o1", Options{})
		}
	})
}

func BenchmarkWhoCanReach(b *testing.B) {
	ix := NewIndex(bench10k())
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = ix.WhoCanReach(popularRepo)
		}
	})
}

func BenchmarkTopPaths(b *testing.B) {
	ix := NewIndex(bench10k())
	b.Run("10k", func(b *testing.B) {
		for b.Loop() {
			benchSink = ix.TopPaths(10)
		}
	})
}

func BenchmarkSuggestFixes(b *testing.B) {
	g := bench10k()
	b.Run("10k_budget10", func(b *testing.B) {
		for b.Loop() {
			// A fresh index each time: the fix overlay is built lazily, and
			// an MCP call pays for it once per loaded graph.
			benchSink = NewIndex(g).SuggestFixes(10)
		}
	})
}

// TestGenEnterpriseShape keeps the benchmark generator honest: its graph is
// valid input, deterministic, and has the shape the doc comment promises.
func TestGenEnterpriseShape(t *testing.T) {
	g := genEnterprise(7, 4, 200, 40, 60)
	h := genEnterprise(7, 4, 200, 40, 60)
	if len(g.Edges) != len(h.Edges) || len(g.Nodes) != len(h.Nodes) {
		t.Fatalf("genEnterprise is not deterministic: %d/%d edges, %d/%d nodes", len(g.Edges), len(h.Edges), len(g.Nodes), len(h.Nodes))
	}
	kinds := map[EdgeKind]int{}
	evs := map[Evidence]int{}
	for _, e := range g.Edges {
		kinds[e.Kind]++
		evs[e.Evidence]++
	}
	for _, k := range []EdgeKind{CanPush, MemberOf, DefinedIn, ResolvesTo, Uses, CanTrigger, ExecutesWith} {
		if kinds[k] == 0 {
			t.Errorf("no %s edges", k)
		}
	}
	if evs[Live] == 0 || evs[Audit] == 0 {
		t.Errorf("evidence mix %v: want live and audit edges", evs)
	}
	ix := NewIndex(g)
	if len(ix.WhoCanReach(popularRepo)) == 0 {
		t.Errorf("nobody reaches %s", popularRepo)
	}
	if len(ix.Candidates()) == 0 {
		t.Error("no fix candidates")
	}
}
