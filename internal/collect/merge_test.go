package collect

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

func TestOwnerOrg(t *testing.T) {
	for _, tc := range []struct {
		kind     graph.EdgeKind
		from, to string
		want     string
	}{
		{graph.CanPush, "members:acme-actions", "repo:acme-actions/deploy", "acme-actions"},
		{graph.CanPush, "identity:alice", "repo:acme-app/web", "acme-app"},
		{graph.CanPush, "team:acme-actions/platform", "repo:acme-actions/deploy", "acme-actions"},
		{graph.CanPush, "workflow:acme-app/web/.github/workflows/ci.yml", "repo:acme-app/web", "acme-app"},
		{graph.MemberOf, "identity:alice", "org:acme-app", "acme-app"},
		{graph.MemberOf, "identity:bob", "team:acme-actions/platform", "acme-actions"},
		{graph.MemberOf, "team:acme-actions/platform-oncall", "team:acme-actions/platform", "acme-actions"},
		{graph.CanTrigger, "external:anyone", "workflow:acme-app/web/.github/workflows/pr.yml", "acme-app"},
		{graph.CanTrigger, "members:acme-app", "workflow:acme-app/web/.github/workflows/pr.yml", "acme-app"},
		{graph.Uses, "workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main", "acme-app"},
		{graph.Uses, "action:acme-actions/deploy@main", "action:acme-actions/setup@v2-dev", "acme-actions"},
		{graph.Uses, "action:acme-actions/deploy@main", "action:actions/checkout@v4", "acme-actions"},
		{graph.DefinedIn, "workflow:acme-app/web/.github/workflows/ci.yml", "repo:acme-app/web", "acme-app"},
		{graph.ExecutesWith, "workflow:acme-app/web/.github/workflows/ci.yml", "oidc:acme-app/web", "acme-app"},
		{graph.ExecutesWith, "workflow:acme-app/web/.github/workflows/ci.yml", "secret:acme-app/web", "acme-app"},
		{graph.ExecutesWith, "workflow:acme-app/web/.github/workflows/ci.yml", "runner:acme-app/web", "acme-app"},
		{graph.ResolvesTo, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", ""},
		{graph.CanAssume, "workflow:acme-app/web/.github/workflows/ci.yml", "cloud:aws:role/deploy", ""},
		{"FUTURE_KIND", "workflow:Acme-App/web/.github/workflows/ci.yml", "repo:acme-app/web", "acme-app"},
	} {
		e := graph.Edge{From: tc.from, To: tc.to, Kind: tc.kind}
		if got := ownerOrg(e); got != tc.want {
			t.Errorf("ownerOrg(%s -%s-> %s) = %q, want %q", tc.from, tc.kind, tc.to, got, tc.want)
		}
	}
	for id, want := range map[string]string{
		"org:Acme-Actions":                "acme-actions",
		"members:acme-actions":            "acme-actions",
		"repo:acme-app/web":               "acme-app",
		"action:acme-actions/deploy@main": "acme-actions",
		"team:acme-app/release":           "acme-app",
		"identity:alice":                  "",
		"external:anyone":                 "",
		"enterprise:acme":                 "",
		"cloud:aws:role/deploy":           "",
	} {
		if got := nodeOrg(id); got != want {
			t.Errorf("nodeOrg(%s) = %q, want %q", id, got, want)
		}
	}
}

// collectFixture collects the shared fixture from its own fake, changed by mod
// before the first request.
func collectFixture(t *testing.T, mod func(*fakeGitHub), cfg Config) *graph.Graph {
	t.Helper()
	f := newFakeGitHub(t)
	if mod != nil {
		mod(f)
	}
	cfg.Enterprise = "acme"
	cfg.Client = f.client(t)
	g, err := Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return g
}

// readOnlyActions lowers acme-actions' default repository permission to read.
func readOnlyActions(f *fakeGitHub) {
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login == "acme-actions" {
			f.fx.Orgs[i].Settings["defaultRepositoryPermissionSettingOrganizations"] = "READ"
			f.fx.Orgs[i].OrgREST["default_repository_permission"] = "read"
		}
	}
}

// comparableJSON is stableGraphJSON with coverage sorted, so a merged graph
// and a collection compare byte for byte.
func comparableJSON(t *testing.T, g *graph.Graph) string {
	t.Helper()
	cp := *g
	cp.Coverage = slices.Clone(g.Coverage)
	sort.Slice(cp.Coverage, func(i, j int) bool {
		return coverageKey(cp.Coverage[i]) < coverageKey(cp.Coverage[j])
	})
	return string(stableGraphJSON(t, &cp))
}

func TestMergeRecollectOrg(t *testing.T) {
	base := collectFixture(t, nil, Config{})
	baseCopy := comparableJSON(t, base)
	time.Sleep(2 * time.Millisecond) // fresh's collected_at must differ from base's
	merged := collectFixture(t, readOnlyActions, Config{Orgs: []string{"acme-actions"}, MergeInto: base})
	full := collectFixture(t, readOnlyActions, Config{})
	if comparableJSON(t, base) != baseCopy {
		t.Fatal("MergeInto must not modify the base graph")
	}

	t.Run("equals a full collection", func(t *testing.T) {
		if got, want := comparableJSON(t, merged), comparableJSON(t, full); got != want {
			t.Errorf("merged graph differs from a full collection:\n%s", lineDiff(want, got))
		}
	})

	t.Run("default permission edges are gone", func(t *testing.T) {
		had := 0
		for _, e := range base.Edges {
			if e.From == "members:acme-actions" && e.Kind == graph.CanPush && e.Attrs[graph.AttrVia] == graph.ViaDefaultPerm {
				had++
			}
		}
		if had == 0 {
			t.Fatal("fixture: base should have default_perm edges from members:acme-actions")
		}
		for _, e := range merged.Edges {
			if e.From == "members:acme-actions" && e.Kind == graph.CanPush && e.Attrs[graph.AttrVia] == graph.ViaDefaultPerm {
				t.Errorf("default_perm edge survived: %s -> %s", e.From, e.To)
			}
		}
	})

	t.Run("acme-app is unchanged", func(t *testing.T) {
		pick := func(g *graph.Graph) ([]graph.Node, []graph.Edge) {
			var ns []graph.Node
			var es []graph.Edge
			for _, n := range g.Nodes {
				if nodeOrg(n.ID) == "acme-app" {
					ns = append(ns, n)
				}
			}
			for _, e := range g.Edges {
				if ownerOrg(e) == "acme-app" {
					es = append(es, e)
				}
			}
			return ns, es
		}
		bn, be := pick(base)
		mn, me := pick(merged)
		if len(bn) == 0 || len(be) == 0 {
			t.Fatal("fixture: acme-app should have nodes and edges")
		}
		if !reflect.DeepEqual(bn, mn) {
			t.Errorf("acme-app nodes changed: %d before, %d after", len(bn), len(mn))
		}
		if !reflect.DeepEqual(be, me) {
			t.Errorf("acme-app edges changed: %d before, %d after", len(be), len(me))
		}
	})

	t.Run("cross-org USES edges stay", func(t *testing.T) {
		uses := func(g *graph.Graph) []graph.Edge {
			var out []graph.Edge
			for _, e := range g.Edges {
				if e.Kind == graph.Uses && e.To == "action:acme-actions/deploy@main" && strings.HasPrefix(e.From, "workflow:acme-app/") {
					out = append(out, e)
				}
			}
			return out
		}
		if b, m := uses(base), uses(merged); len(b) == 0 || !reflect.DeepEqual(b, m) {
			t.Errorf("USES from acme-app workflows into acme-actions/deploy@main: base %d, merged %d", len(b), len(m))
		}
		ix := newIndex(merged)
		ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
		if n := ix.node(t, "repo:acme-actions/deploy"); isStub(n) {
			t.Error("RESOLVES_TO target should be the real repo")
		}
	})

	t.Run("org_collected_at", func(t *testing.T) {
		if merged.CollectedAt.Equal(base.CollectedAt) {
			t.Fatal("fresh and base collected_at should differ")
		}
		if got := merged.OrgCollectedAt["acme-actions"]; !got.Equal(merged.CollectedAt) {
			t.Errorf("org_collected_at[acme-actions] = %v, want fresh's %v", got, merged.CollectedAt)
		}
		if got := merged.OrgCollectedAt["acme-app"]; !got.Equal(base.CollectedAt) {
			t.Errorf("org_collected_at[acme-app] = %v, want base's %v", got, base.CollectedAt)
		}
		for o, at := range full.OrgCollectedAt {
			if !at.Equal(full.CollectedAt) {
				t.Errorf("full collection: org_collected_at[%s] = %v, want collected_at", o, at)
			}
		}
		if len(full.OrgCollectedAt) != len(merged.OrgCollectedAt) {
			t.Errorf("org_collected_at keys: full %v, merged %v", full.OrgCollectedAt, merged.OrgCollectedAt)
		}
	})
}

// lineDiff lists the lines only in want (-) or only in got (+).
func lineDiff(want, got string) string {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			m[l]++
		}
		return m
	}
	w, g := count(want), count(got)
	var out []string
	for l, n := range w {
		if g[l] < n {
			out = append(out, "- "+l)
		}
	}
	for l, n := range g {
		if w[l] < n {
			out = append(out, "+ "+l)
		}
	}
	sort.Strings(out)
	if len(out) > 40 {
		out = append(out[:40], "...")
	}
	return strings.Join(out, "\n")
}

func TestMergeWithoutHook(t *testing.T) {
	base := collectFixture(t, nil, Config{})
	fresh := collectFixture(t, readOnlyActions, Config{Orgs: []string{"acme-actions"}})
	merged, err := Merge(base, fresh, []string{"acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	ix := newIndex(merged)
	for _, n := range merged.Nodes {
		if fn, ok := newIndex(fresh).nodes[n.ID]; ok && isStub(n) && !isStub(fn) {
			t.Errorf("stub repo left: %s", n.ID)
		}
	}
	ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
	ix.node(t, "action:acme-actions/deploy@main")
	if got := merged.OrgCollectedAt["acme-actions"]; !got.Equal(fresh.CollectedAt) {
		t.Errorf("org_collected_at[acme-actions] = %v, want %v", got, fresh.CollectedAt)
	}
	if got := merged.OrgCollectedAt["acme-app"]; !got.Equal(base.CollectedAt) {
		t.Errorf("org_collected_at[acme-app] = %v, want %v", got, base.CollectedAt)
	}
	full := collectFixture(t, readOnlyActions, Config{})
	if got, want := comparableJSON(t, merged), comparableJSON(t, full); got != want {
		t.Errorf("merged graph differs from a full collection:\n%s", lineDiff(want, got))
	}
}

func TestMergeReplacesStubs(t *testing.T) {
	appOnly := collectFixture(t, nil, Config{Orgs: []string{"acme-app"}})
	actionsOnly := collectFixture(t, nil, Config{Orgs: []string{"acme-actions"}})
	if n := newIndex(appOnly).node(t, "repo:acme-actions/deploy"); !isStub(n) {
		t.Fatal("fixture: an acme-app-only collection should stub repo:acme-actions/deploy")
	}
	full := collectFixture(t, nil, Config{})
	for name, tc := range map[string]struct {
		base, fresh *graph.Graph
		orgs        []string
	}{
		"stub in base":  {appOnly, actionsOnly, []string{"acme-actions"}},
		"stub in fresh": {actionsOnly, appOnly, []string{"acme-app"}},
	} {
		t.Run(name, func(t *testing.T) {
			merged, err := Merge(tc.base, tc.fresh, tc.orgs)
			if err != nil {
				t.Fatal(err)
			}
			real := map[string]bool{}
			for _, n := range tc.base.Nodes {
				if n.Kind == graph.KindRepo && !isStub(n) {
					real[n.ID] = true
				}
			}
			for _, n := range tc.fresh.Nodes {
				if n.Kind == graph.KindRepo && !isStub(n) {
					real[n.ID] = true
				}
			}
			for _, n := range merged.Nodes {
				if isStub(n) && real[n.ID] {
					t.Errorf("stub %s kept although a real node exists", n.ID)
				}
			}
			for _, e := range merged.Edges {
				if stubArtifact(e) && real[e.To] {
					t.Errorf("stub push edge kept: %s -> %s", e.From, e.To)
				}
			}
			for _, c := range merged.Coverage {
				if c.Fact == "can_push" && real[c.Scope] {
					t.Errorf("stub coverage kept: %s", c.Scope)
				}
			}
			// The two halves rebuild the full graph's edges into the
			// formerly stubbed repos.
			ix, fx := newIndex(merged), newIndex(full)
			for _, e := range full.Edges {
				if e.To == "repo:acme-actions/deploy" && e.Kind != graph.ResolvesTo {
					if _, ok := ix.edge(e.From, e.To, e.Kind); !ok {
						t.Errorf("missing %s -%s-> %s", e.From, e.Kind, e.To)
					}
				}
			}
			for _, e := range merged.Edges {
				if _, ok := fx.edge(e.From, e.To, e.Kind); !ok {
					t.Errorf("edge not in the full collection: %s -%s-> %s", e.From, e.Kind, e.To)
				}
			}
		})
	}
}

func TestCollectMergeIntoChecks(t *testing.T) {
	base := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme"}
	f := newFakeGitHub(t)
	for name, cfg := range map[string]Config{
		"no orgs":          {Enterprise: "acme", MergeInto: base},
		"other enterprise": {Enterprise: "acme", Orgs: []string{"acme-app"}, MergeInto: &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "other"}},
		"other host": {Enterprise: "acme", Orgs: []string{"acme-app"}, MergeInto: synth(
			[]graph.Node{{ID: "enterprise:acme", Kind: graph.KindEnterprise, Attrs: map[string]string{graph.AttrHost: "github.acme.example"}}}, nil),
			Host: "github.com"},
	} {
		cfg.Client = f.client(t)
		if _, err := Collect(context.Background(), cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if n := f.hitCount("/graphql"); n != 0 {
		t.Errorf("refused runs must not call GitHub: %d GraphQL requests", n)
	}
}

// synth builds a small synthetic graph of enterprise acme.
func synth(nodes []graph.Node, edges []graph.Edge, cov ...graph.Coverage) *graph.Graph {
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	for i := range edges {
		if edges[i].Evidence == "" {
			edges[i].Evidence = graph.Live
		}
		if edges[i].SourceAPI == "" {
			edges[i].SourceAPI = "test"
		}
		edges[i].ObservedAt = at
	}
	for i := range nodes {
		if nodes[i].Evidence == "" {
			nodes[i].Evidence = graph.Live
		}
		if nodes[i].Kind == "" {
			nodes[i].Kind = graph.KindFromID(nodes[i].ID)
		}
	}
	if cov == nil {
		cov = []graph.Coverage{}
	}
	return &graph.Graph{Schema: graph.SchemaVersion, CollectedAt: at, Enterprise: "acme", Nodes: nodes, Edges: edges, Coverage: cov}
}

func ent(hidden bool, host string) graph.Node {
	n := graph.Node{ID: "enterprise:acme", Kind: graph.KindEnterprise, Name: "acme", Attrs: map[string]string{"orgs": "2"}}
	if hidden {
		n.Attrs["orgs"] = "unknown"
		n.AttrEvidence = map[string]graph.Evidence{"orgs": graph.NotVisible}
	}
	if host != "" {
		n.Attrs[graph.AttrHost] = host
	}
	return n
}

func TestMergeRefuses(t *testing.T) {
	base := synth([]graph.Node{ent(false, "github.com")}, nil)
	for name, fresh := range map[string]*graph.Graph{
		"enterprise": func() *graph.Graph { g := synth(nil, nil); g.Enterprise = "other"; return g }(),
		"host":       synth([]graph.Node{ent(false, "github.acme.example")}, nil),
		"visibility": synth([]graph.Node{ent(true, "github.com")}, nil),
		"schema":     func() *graph.Graph { g := synth(nil, nil); g.Schema = "gop.graph/v0"; return g }(),
	} {
		if _, err := Merge(base, fresh, []string{"acme-app"}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Merge(base, synth(nil, nil), nil); err == nil {
		t.Error("no orgs: expected an error")
	}
	if _, err := Merge(nil, base, []string{"acme-app"}); err == nil {
		t.Error("nil base: expected an error")
	}
	// Force merges different token modes, keeping base's enterprise facts
	// when fresh could not read the enterprise.
	baseCov := graph.Coverage{Scope: "enterprise:acme", Fact: "members", Reason: "base", NeedsFix: "x"}
	freshCov := graph.Coverage{Scope: "enterprise:acme", Fact: "enterprise", Reason: "fresh", NeedsFix: "y"}
	b := synth([]graph.Node{ent(false, "")}, nil, baseCov)
	f := synth([]graph.Node{ent(true, "github.com")}, nil, freshCov)
	m, err := MergeWith(b, f, []string{"acme-app"}, MergeOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	en, _ := entNode(m)
	if en.Attrs["orgs"] != "2" || en.Attrs[graph.AttrHost] != "github.com" {
		t.Errorf("enterprise node = %+v, want base's with fresh's host", en)
	}
	if len(m.Coverage) != 1 || m.Coverage[0] != baseCov {
		t.Errorf("enterprise coverage = %+v, want base's", m.Coverage)
	}
	// A graph without a host merges with one that has it.
	if _, err := Merge(synth([]graph.Node{ent(false, "")}, nil), synth([]graph.Node{ent(false, "github.com")}, nil), []string{"acme-app"}); err != nil {
		t.Errorf("unrecorded host: %v", err)
	}
}

func TestMergeCarriesUnreadActions(t *testing.T) {
	wf := "workflow:acme-app/web/.github/workflows/ci.yml"
	base := synth([]graph.Node{
		ent(false, ""), {ID: "org:acme-app"}, {ID: "org:acme-actions"},
		{ID: "repo:acme-app/web"}, {ID: wf},
		{ID: "repo:acme-actions/deploy"}, {ID: "repo:acme-actions/setup"},
		{ID: "action:acme-actions/deploy@main", Attrs: map[string]string{"ref": "main", graph.AttrRefKind: "branch"}},
		{ID: "action:acme-actions/setup@v1", Attrs: map[string]string{"ref": "v1"}},
		{ID: "identity:bob"}, {ID: "identity:erin"},
	}, []graph.Edge{
		{From: wf, To: "repo:acme-app/web", Kind: graph.DefinedIn},
		{From: wf, To: "action:acme-actions/deploy@main", Kind: graph.Uses},
		{From: "action:acme-actions/deploy@main", To: "repo:acme-actions/deploy", Kind: graph.ResolvesTo},
		{From: "action:acme-actions/deploy@main", To: "action:acme-actions/setup@v1", Kind: graph.Uses},
		{From: "action:acme-actions/setup@v1", To: "repo:acme-actions/setup", Kind: graph.ResolvesTo},
		{From: "identity:bob", To: "repo:acme-actions/deploy", Kind: graph.CanPush,
			Attrs: map[string]string{graph.AttrVia: graph.ViaRefBypass, graph.AttrRef: "main"}},
		{From: "identity:bob", To: "repo:acme-actions/deploy", Kind: graph.CanPush, Attrs: map[string]string{graph.AttrVia: graph.ViaDirect}},
		{From: "identity:erin", To: "repo:acme-actions/setup", Kind: graph.CanPush, Attrs: map[string]string{graph.AttrVia: graph.ViaOutsideCollaborator}},
		{From: wf, To: "cloud:aws:111111111111:role/deploy", Kind: graph.CanAssume, Evidence: graph.Supplied},
	}, graph.Coverage{Scope: "action:acme-actions/deploy@main", Fact: graph.AttrBypass, Reason: "r", NeedsFix: "f"})
	// fresh re-read acme-actions without MergeInto: the repos, not the actions.
	fresh := synth([]graph.Node{
		ent(false, ""), {ID: "org:acme-actions"}, {ID: "repo:acme-actions/deploy"}, {ID: "repo:acme-actions/setup"},
	}, nil)
	fresh.CollectedAt = base.CollectedAt.Add(time.Hour)
	m, err := Merge(base, fresh, []string{"acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	ix := newIndex(m)
	for _, id := range []string{"action:acme-actions/deploy@main", "action:acme-actions/setup@v1", "identity:bob"} {
		ix.node(t, id)
	}
	ix.mustEdge(t, wf, "action:acme-actions/deploy@main", graph.Uses)
	ix.mustEdge(t, "action:acme-actions/deploy@main", "action:acme-actions/setup@v1", graph.Uses)
	ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
	ix.mustEdge(t, "action:acme-actions/setup@v1", "repo:acme-actions/setup", graph.ResolvesTo)
	ix.mustEdge(t, wf, "cloud:aws:111111111111:role/deploy", graph.CanAssume)
	bypass := 0
	for _, e := range m.Edges {
		if e.Kind == graph.CanPush && e.To == "repo:acme-actions/deploy" {
			if e.Attrs[graph.AttrVia] != graph.ViaRefBypass {
				t.Errorf("re-collected grant %v should come from fresh only", e.Attrs)
			}
			bypass++
		}
	}
	if bypass != 1 {
		t.Errorf("ref_bypass edges of the carried ref: %d, want 1", bypass)
	}
	if _, ok := hasCoverage(m, "action:acme-actions/deploy@main", graph.AttrBypass); !ok {
		t.Error("coverage of the carried action should stay")
	}
	// erin's only fact was a grant in the re-collected org: she is gone.
	if _, ok := ix.nodes["identity:erin"]; ok {
		t.Error("identity:erin should be dropped: nothing references it")
	}
	if got := m.OrgCollectedAt; !got["acme-actions"].Equal(fresh.CollectedAt) || !got["acme-app"].Equal(base.CollectedAt) {
		t.Errorf("org_collected_at = %v", got)
	}
}

func TestMergeDropsUnusedActions(t *testing.T) {
	wf := "workflow:acme-actions/deploy/.github/workflows/ci.yml"
	base := synth([]graph.Node{
		ent(false, ""), {ID: "org:acme-actions"}, {ID: "repo:acme-actions/deploy"}, {ID: wf},
		{ID: "action:actions/checkout@v4"},
		{ID: "repo:acme-legacy/tool", Attrs: map[string]string{attrCollected: "false", "org": "acme-legacy"}},
		{ID: "action:acme-legacy/tool@main"}, {ID: "members:acme-legacy"},
	}, []graph.Edge{
		{From: wf, To: "repo:acme-actions/deploy", Kind: graph.DefinedIn},
		{From: wf, To: "action:actions/checkout@v4", Kind: graph.Uses},
		{From: wf, To: "action:acme-legacy/tool@main", Kind: graph.Uses},
		{From: "action:acme-legacy/tool@main", To: "repo:acme-legacy/tool", Kind: graph.ResolvesTo},
		{From: "members:acme-legacy", To: "repo:acme-legacy/tool", Kind: graph.CanPush, Evidence: graph.NotVisible,
			Attrs: map[string]string{graph.AttrVia: graph.ViaUnknown}},
	}, graph.Coverage{Scope: "repo:acme-legacy/tool", Fact: "can_push", Reason: "r", NeedsFix: "f"})
	// The workflow is gone after re-collection.
	fresh := synth([]graph.Node{ent(false, ""), {ID: "org:acme-actions"}, {ID: "repo:acme-actions/deploy"}}, nil)
	m, err := Merge(base, fresh, []string{"acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, n := range m.Nodes {
		ids = append(ids, n.ID)
	}
	if want := []string{"enterprise:acme", "org:acme-actions", "repo:acme-actions/deploy"}; !slices.Equal(ids, want) {
		t.Errorf("nodes = %v, want %v", ids, want)
	}
	if len(m.Edges) != 0 || len(m.Coverage) != 0 {
		t.Errorf("edges %v, coverage %v: want none", m.Edges, m.Coverage)
	}
}

func TestMergeEvidenceAgnostic(t *testing.T) {
	// Merge copies evidence through untouched, whatever its level.
	base := synth([]graph.Node{ent(false, ""), {ID: "org:acme-app"}, {ID: "repo:acme-app/web"}, {ID: "members:acme-app"}},
		[]graph.Edge{{From: "members:acme-app", To: "repo:acme-app/web", Kind: graph.CanPush, Evidence: graph.Audit,
			Attrs: map[string]string{graph.AttrVia: graph.ViaDefaultPerm}}})
	fresh := synth([]graph.Node{ent(false, ""), {ID: "org:acme-actions"}}, nil)
	m, err := Merge(base, fresh, []string{"acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	if e := newIndex(m).mustEdge(t, "members:acme-app", "repo:acme-app/web", graph.CanPush); e.Evidence != graph.Audit {
		t.Errorf("evidence = %s, want audit", e.Evidence)
	}
}

func TestValidateMerged(t *testing.T) {
	ok := synth([]graph.Node{{ID: "identity:bob"}, {ID: "repo:acme-actions/deploy"}}, []graph.Edge{
		{From: "identity:bob", To: "repo:acme-actions/deploy", Kind: graph.CanPush, Attrs: map[string]string{graph.AttrVia: graph.ViaDirect}},
		{From: "identity:bob", To: "repo:acme-actions/deploy", Kind: graph.CanPush, Attrs: map[string]string{graph.AttrVia: graph.ViaRefBypass, graph.AttrRef: "main"}},
		{From: "identity:bob", To: "repo:acme-actions/deploy", Kind: graph.CanPush, Attrs: map[string]string{graph.AttrVia: graph.ViaRefBypass, graph.AttrRef: "v1"}},
		// Undeclared, but the kind is inferable from the ID.
		{From: "action:acme-actions/deploy@main", To: "repo:acme-actions/deploy", Kind: graph.ResolvesTo},
	})
	if err := validateMerged(ok); err != nil {
		t.Errorf("valid graph: %v", err)
	}
	for name, g := range map[string]*graph.Graph{
		"unknown endpoint": synth([]graph.Node{{ID: "repo:acme-app/web"}},
			[]graph.Edge{{From: "mystery", To: "repo:acme-app/web", Kind: graph.CanPush}}),
		"duplicate edge": synth([]graph.Node{{ID: "identity:bob"}, {ID: "repo:acme-app/web"}}, []graph.Edge{
			{From: "identity:bob", To: "repo:acme-app/web", Kind: graph.CanPush},
			{From: "identity:bob", To: "repo:acme-app/web", Kind: graph.CanPush, Attrs: map[string]string{graph.AttrVia: graph.ViaTeam}},
		}),
		"duplicate node": synth([]graph.Node{{ID: "identity:bob"}, {ID: "identity:bob"}}, nil),
	} {
		err := validateMerged(g)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), "mystery") && name == "unknown endpoint" {
			t.Errorf("%s: error should name the endpoint: %v", name, err)
		}
	}
}

func TestMergeOutputLoads(t *testing.T) {
	base := collectFixture(t, nil, Config{})
	merged := collectFixture(t, readOnlyActions, Config{Orgs: []string{"acme-actions"}, MergeInto: base})
	var buf bytes.Buffer
	if err := WriteGraph(&buf, merged); err != nil {
		t.Fatal(err)
	}
	g, err := graph.Load(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.OrgCollectedAt) == 0 {
		t.Error("org_collected_at should round-trip")
	}
	// Scores of principals outside the re-collected org are unchanged.
	bix, mix := graph.NewIndex(base), graph.NewIndex(g)
	if b, m := bix.BlastRadius("members:acme-app"), mix.BlastRadius("members:acme-app"); b.Score < m.Score {
		t.Errorf("members:acme-app score grew after lowering acme-actions' default permission: %v -> %v", b.Score, m.Score)
	}
}

// TestMergeIntoRereadsUsedActions changes an acme-actions action only acme-app
// uses (deploy@v1 becomes an immutable release): MergeInto reads it again, a
// plain partial collection does not.
func TestMergeIntoRereadsUsedActions(t *testing.T) {
	immutableV1 := func(f *fakeGitHub) {
		readOnlyActions(f)
		f.releases["acme-actions/deploy@v1"] = true
	}
	base := collectFixture(t, nil, Config{})
	if newIndex(base).node(t, "action:acme-actions/deploy@v1").Attrs[graph.AttrRefImmutable] != "false" {
		t.Fatal("fixture: deploy@v1 should start mutable")
	}
	merged := collectFixture(t, immutableV1, Config{Orgs: []string{"acme-actions"}, MergeInto: base})
	full := collectFixture(t, immutableV1, Config{})
	if got, want := comparableJSON(t, merged), comparableJSON(t, full); got != want {
		t.Errorf("merged graph differs from a full collection:\n%s", lineDiff(want, got))
	}
	if v := newIndex(merged).node(t, "action:acme-actions/deploy@v1").Attrs[graph.AttrRefImmutable]; v != "true" {
		t.Errorf("deploy@v1 ref_immutable = %q, want true", v)
	}
	// Without MergeInto the action is not read again: base's view is carried.
	fresh := collectFixture(t, immutableV1, Config{Orgs: []string{"acme-actions"}})
	stale, err := Merge(base, fresh, []string{"acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	if v := newIndex(stale).node(t, "action:acme-actions/deploy@v1").Attrs[graph.AttrRefImmutable]; v != "false" {
		t.Errorf("carried deploy@v1 ref_immutable = %q, want base's false", v)
	}
}

// TestMergeIntoWithCache runs a MergeInto re-collection through the response
// cache a full run filled: the cache revalidates, and the merge still equals
// the full graph.
func TestMergeIntoWithCache(t *testing.T) {
	f := newFakeGitHub(t)
	f.etags = true
	dir := filepath.Join(t.TempDir(), "gop-cache")
	ctx := context.Background()
	base, err := collectCached(t, ctx, f, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	f.resetCounts()
	merged, err := Collect(ctx, Config{Enterprise: "acme", Client: f.client(t), CacheDir: dir,
		DisableGraphQLBatch: true, Orgs: []string{"acme-actions"}, MergeInto: base})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := comparableJSON(t, merged), comparableJSON(t, base); got != want {
		t.Errorf("cached merge differs from the full graph:\n%s", lineDiff(want, got))
	}
	notModified := 0
	for _, n := range f.notModified {
		notModified += n
	}
	if notModified == 0 {
		t.Error("the merge run should revalidate cached responses (no 304 seen)")
	}
	if _, err := os.Stat(filepath.Join(dir, cacheRunFile)); !os.IsNotExist(err) {
		t.Errorf("run.json must be removed after a successful merge run: %v", err)
	}
}

// TestMergeUpgradesV1 merges a v1 base with a current-schema fresh graph: Load
// upgrades the base, and the result has the current schema and keeps
// audit_retention_days.
func TestMergeUpgradesV1(t *testing.T) {
	base := synth([]graph.Node{ent(false, ""), {ID: "org:acme-app"}, {ID: "repo:acme-app/web"}, {ID: "members:acme-app"}},
		[]graph.Edge{{From: "members:acme-app", To: "repo:acme-app/web", Kind: graph.CanPush,
			Attrs: map[string]string{graph.AttrVia: graph.ViaDefaultPerm}}})
	base.Schema = graph.SchemaV1
	base.AuditRetentionDays = 180
	fresh := synth([]graph.Node{ent(false, ""), {ID: "org:acme-actions"}, {ID: "repo:acme-actions/deploy"}, {ID: "members:acme-actions"}},
		[]graph.Edge{{From: "members:acme-actions", To: "repo:acme-actions/deploy", Kind: graph.CanPush, Evidence: graph.Inferred,
			Attrs: map[string]string{graph.AttrVia: graph.ViaDefaultPerm, "rule": graph.ViaDefaultPerm}}})
	m, err := Merge(base, fresh, []string{"acme-actions"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Schema != graph.SchemaVersion || m.AuditRetentionDays != 180 {
		t.Errorf("schema %q, audit_retention_days %d", m.Schema, m.AuditRetentionDays)
	}
	ix := newIndex(m)
	if e := ix.mustEdge(t, "members:acme-actions", "repo:acme-actions/deploy", graph.CanPush); e.Evidence != graph.Inferred {
		t.Errorf("fresh evidence = %s, want inferred", e.Evidence)
	}
	ix.mustEdge(t, "members:acme-app", "repo:acme-app/web", graph.CanPush)
	// A v1 document claiming inferred evidence is rejected by Load, so by Merge.
	bad := synth(nil, []graph.Edge{{From: "members:acme-app", To: "repo:acme-app/web", Kind: graph.CanPush, Evidence: graph.Inferred}})
	bad.Schema = graph.SchemaV1
	if _, err := Merge(bad, fresh, []string{"acme-actions"}); err == nil {
		t.Error("v1 base with inferred evidence: expected an error")
	}
}
