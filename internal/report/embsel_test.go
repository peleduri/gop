package report

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
)

// embeddedNaive is the original embedded path pick: every path of every
// scored principal built, then each target org's list stably sorted by
// (confirmed, terminal kind, hops) and cut to perOrg.
func embeddedNaive(ix *graph.Index, scores []graph.Score, perOrg int) (paths []embPath, trunc []embTrunc) {
	byOrg := map[string][]embPath{}
	for _, s := range scores {
		porgs := principalOrgs(ix, s.Principal)
		r := ix.Reach(s.Principal, graph.Options{})
		for _, to := range sortedPathKeys(r.Paths) {
			tk := targetKind(ix.Kind(to))
			if tk == "" {
				continue
			}
			path := r.Paths[to]
			org := orgName(graph.OrgOf(to))
			if tk == "cloud" && len(path.Hops) > 0 {
				org = orgName(graph.OrgOf(path.Hops[len(path.Hops)-1].From))
			}
			c := &pathCand{to: to, tk: tk, org: org, path: path}
			byOrg[org] = append(byOrg[org], embPathOf(ix, c, porgs))
		}
	}
	orgs := make([]string, 0, len(byOrg))
	for o := range byOrg {
		orgs = append(orgs, o)
	}
	sort.Strings(orgs)
	for _, o := range orgs {
		ps := byOrg[o]
		if len(ps) > perOrg {
			sort.SliceStable(ps, func(i, j int) bool {
				a, b := ps[i], ps[j]
				if a.Ev != b.Ev {
					return a.Ev == "confirmed"
				}
				if termRank(a.ToKind) != termRank(b.ToKind) {
					return termRank(a.ToKind) < termRank(b.ToKind)
				}
				return len(a.Hops) < len(b.Hops)
			})
			trunc = append(trunc, embTrunc{Org: o, Total: len(ps)})
			ps = ps[:perOrg]
		}
		paths = append(paths, ps...)
	}
	return paths, trunc
}

func pathKeys(ps []embPath) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = fmt.Sprintf("%s>%s %s %d", p.From, p.To, p.Ev, len(p.Hops))
	}
	sort.Strings(out)
	return out
}

// TestSelectPathsMatchesNaive: the bounded pick embeds exactly the paths the
// build-everything-then-cut pick embeds, at every cap, and reports the same
// truncated orgs and totals.
func TestSelectPathsMatchesNaive(t *testing.T) {
	graphs := map[string]*graph.Graph{
		"acme":  loadAcme(t),
		"demo":  demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}),
		"large": graph.SyntheticLarge(3, graph.LargeSpec{Orgs: 5, Repos: 80, Actions: 20, Principals: 120, Agents: 8, Owners: 4, OwnedOrgs: 2, ExtraMemberships: 1}),
	}
	for name, g := range graphs {
		ix := graph.NewIndex(g)
		scores := ix.Scores()
		for _, cap := range []int{1, 2, 7, maxPathsPerOrg} {
			t.Run(fmt.Sprintf("%s/cap=%d", name, cap), func(t *testing.T) {
				e := buildEmbedded(ix, g, scores, nil, cap)
				wantPaths, wantTrunc := embeddedNaive(ix, scores, e.MaxPerOrg)
				if got, want := pathKeys(e.Paths), pathKeys(wantPaths); !reflect.DeepEqual(got, want) {
					t.Errorf("embedded paths differ\n got: %s\nwant: %s", strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
				if !reflect.DeepEqual(e.Truncated, append([]embTrunc{}, wantTrunc...)) {
					t.Errorf("truncated = %+v, want %+v", e.Truncated, wantTrunc)
				}
				byKey := map[string]embPath{}
				for _, p := range wantPaths {
					byKey[p.From+">"+p.To] = p
				}
				for _, p := range e.Paths {
					if w := byKey[p.From+">"+p.To]; !reflect.DeepEqual(p, w) {
						t.Errorf("path %s>%s differs\n got: %+v\nwant: %+v", p.From, p.To, p, w)
					}
				}
			})
		}
	}
}

// TestEmbeddedBudget: with many target orgs the per-org cap drops so the
// embedded paths stay near maxEmbeddedPaths, and the note says how many
// paths there are in all.
func TestEmbeddedBudget(t *testing.T) {
	g := graph.SyntheticLarge(1, graph.LargeSpec{Orgs: 41, Repos: 1200, Actions: 100, Principals: 1500, Agents: 10, Owners: 20, OwnedOrgs: 8})
	d := build(g, Options{Top: 10, FixBudget: 5})
	if err := addEmbedded(&d, g); err != nil {
		t.Fatal(err)
	}
	ix := graph.NewIndex(g)
	e := buildEmbedded(ix, g, ix.Scores(), nil, maxPathsPerOrg)
	orgs := map[string]bool{}
	for _, p := range e.Paths {
		orgs[p.ToOrg] = true
	}
	if want := maxEmbeddedPaths / len(orgs); len(orgs) < 40 || e.MaxPerOrg != want || len(e.Paths) > maxEmbeddedPaths {
		t.Errorf("per-org cap %d with %d paths into %d orgs; want %d per org, at most %d", e.MaxPerOrg, len(e.Paths), len(orgs), want, maxEmbeddedPaths)
	}
	if !strings.Contains(d.Truncated, fmt.Sprintf("top %d paths per target org (%d of ", e.MaxPerOrg, len(e.Paths))) {
		t.Errorf("truncation note: %s", d.Truncated)
	}
	if e.PrincipalsTotal != len(ix.Scores()) || len(e.Principals) == 0 || len(e.Principals) > len(e.Paths) {
		t.Errorf("principals: %d embedded of %d", len(e.Principals), e.PrincipalsTotal)
	}
}
