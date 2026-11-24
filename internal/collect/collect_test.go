package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

type index struct {
	g     *graph.Graph
	nodes map[string]graph.Node
}

func newIndex(g *graph.Graph) *index {
	ix := &index{g: g, nodes: map[string]graph.Node{}}
	for _, n := range g.Nodes {
		ix.nodes[n.ID] = n
	}
	return ix
}

func (ix *index) node(t *testing.T, id string) graph.Node {
	t.Helper()
	n, ok := ix.nodes[id]
	if !ok {
		t.Fatalf("missing node %s", id)
	}
	return n
}

func (ix *index) edge(from, to string, kind graph.EdgeKind) (graph.Edge, bool) {
	for _, e := range ix.g.Edges {
		if e.From == from && e.To == to && e.Kind == kind {
			return e, true
		}
	}
	return graph.Edge{}, false
}

func (ix *index) mustEdge(t *testing.T, from, to string, kind graph.EdgeKind) graph.Edge {
	t.Helper()
	e, ok := ix.edge(from, to, kind)
	if !ok {
		t.Fatalf("missing edge %s -%s-> %s", from, kind, to)
	}
	return e
}

func (ix *index) noEdge(t *testing.T, from, to string, kind graph.EdgeKind) {
	t.Helper()
	if _, ok := ix.edge(from, to, kind); ok {
		t.Errorf("unexpected edge %s -%s-> %s", from, kind, to)
	}
}

func hasCoverage(g *graph.Graph, scope, fact string) (graph.Coverage, bool) {
	for _, c := range g.Coverage {
		if c.Scope == scope && c.Fact == fact {
			return c, true
		}
	}
	return graph.Coverage{}, false
}

func collectAcme(t *testing.T, orgs ...string) (*fakeGitHub, *index) {
	t.Helper()
	f := newFakeGitHub(t)
	f.failures["/orgs/acme-app/repos"] = 1 // one 502, then success
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Orgs: orgs, Client: f.client(t)})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return f, newIndex(g)
}

func TestCollectAcme(t *testing.T) {
	f, ix := collectAcme(t)
	g := ix.g

	t.Run("every edge has evidence, source and known endpoints", func(t *testing.T) {
		for _, e := range g.Edges {
			if e.Evidence == "" || e.SourceAPI == "" || e.ObservedAt.IsZero() {
				t.Errorf("edge %s -%s-> %s lacks evidence/source/time", e.From, e.Kind, e.To)
			}
			if _, ok := ix.nodes[e.From]; !ok {
				t.Errorf("edge from unknown node %s", e.From)
			}
			if _, ok := ix.nodes[e.To]; !ok {
				t.Errorf("edge to unknown node %s", e.To)
			}
		}
		for _, n := range g.Nodes {
			if n.Evidence == "" {
				t.Errorf("node %s has no evidence", n.ID)
			}
		}
	})

	t.Run("not_visible facts are never off", func(t *testing.T) {
		for _, n := range g.Nodes {
			for k, ev := range n.AttrEvidence {
				if ev == graph.NotVisible && (n.Attrs[k] == "off" || n.Attrs[k] == "false" || n.Attrs[k] == "none") {
					t.Errorf("%s.%s is not_visible but reads %q", n.ID, k, n.Attrs[k])
				}
			}
		}
		legacy := ix.node(t, "org:acme-legacy")
		if legacy.Attrs[graph.AttrIPAllowList] != "unknown" || legacy.AttrEvidence[graph.AttrIPAllowList] != graph.NotVisible {
			t.Errorf("acme-legacy ip_allow_list = %q (%q), want unknown/not_visible",
				legacy.Attrs[graph.AttrIPAllowList], legacy.AttrEvidence[graph.AttrIPAllowList])
		}
		// A non-owner org records no IP allow list details, only unknown
		// with the ip_allow_list coverage entry.
		for _, k := range []string{graph.AttrIPAllowListEntries, graph.AttrIPAllowListApps} {
			if legacy.Attrs[k] != "unknown" || legacy.AttrEvidence[k] != graph.NotVisible {
				t.Errorf("acme-legacy %s = %q (%q), want unknown/not_visible", k, legacy.Attrs[k], legacy.AttrEvidence[k])
			}
		}
		covered := false
		for _, c := range g.Coverage {
			covered = covered || (c.Scope == "org:acme-legacy" && c.Fact == graph.AttrIPAllowList)
		}
		if !covered {
			t.Error("acme-legacy has no ip_allow_list coverage entry")
		}
		if legacy.AttrEvidence["repositories"] != graph.NotVisible {
			t.Errorf("acme-legacy repositories evidence = %q, want not_visible", legacy.AttrEvidence["repositories"])
		}
		if ix.node(t, "repo:acme-legacy/old-site").ID == "" {
			t.Error("visible acme-legacy repo not recorded")
		}
	})

	t.Run("coverage lists acme-legacy", func(t *testing.T) {
		c, ok := hasCoverage(g, "org:acme-legacy", "ip_allow_list")
		if !ok {
			t.Fatalf("no ip_allow_list coverage for acme-legacy: %+v", g.Coverage)
		}
		if c.Reason != "token is not an org owner" ||
			c.NeedsFix != "org owner on acme-legacy (SSO enforced: join through the identity provider first)" {
			t.Errorf("coverage = %+v", c)
		}
		if _, ok := hasCoverage(g, "org:acme-legacy", "repositories"); !ok {
			t.Error("no repositories coverage for acme-legacy")
		}
		for _, c := range g.Coverage {
			if c.Scope == "org:acme-app" && c.Fact == "team_members:release" {
				continue // the fixture's release team refuses its member list on purpose
			}
			if c.Scope == "org:acme-secure" || c.Scope == "org:acme-app" {
				t.Errorf("unexpected coverage for owned org: %+v", c)
			}
		}
	})

	t.Run("org settings from the enterprise owner view", func(t *testing.T) {
		want := map[string]map[string]string{
			"org:acme-actions": {graph.AttrSSO: "configured", graph.AttrTwoFactor: "not_required", graph.AttrDefaultPerm: "write",
				graph.AttrMembersCreate: "true", graph.AttrChangeVisiblity: "false", graph.AttrPrivateForks: "true",
				graph.AttrIPAllowList: "off", graph.AttrMembers: "1"},
			"org:acme-app": {graph.AttrDefaultPerm: "read", graph.AttrTwoFactor: "required", graph.AttrMembersCreate: "false",
				graph.AttrChangeVisiblity: "true", graph.AttrMembers: "3", "repositories": "10"},
			"org:acme-legacy": {graph.AttrSSO: "enforced", graph.AttrDefaultPerm: "write", graph.AttrDeleteRepos: "true", graph.AttrMembers: "1"},
			"org:acme-secure": {graph.AttrSSO: "enforced", graph.AttrTwoFactor: "required", graph.AttrDefaultPerm: "read",
				graph.AttrIPAllowList: "on", graph.AttrIPAllowEntries: "5", graph.AttrMembers: "1",
				graph.AttrIPAllowListEntries: "4", graph.AttrIPAllowListApps: "on"},
			"org:acme-archive": {graph.AttrArchived: "true", graph.AttrSSO: "none", graph.AttrDefaultPerm: "none"},
		}
		for id, attrs := range want {
			n := ix.node(t, id)
			for k, v := range attrs {
				if n.Attrs[k] != v {
					t.Errorf("%s.%s = %q, want %q", id, k, n.Attrs[k], v)
				}
				if ev, ok := n.AttrEvidence[k]; ok && ev != graph.Live {
					t.Errorf("%s.%s evidence = %q, want live", id, k, ev)
				}
			}
		}
		for _, n := range g.Nodes {
			if n.Kind == graph.KindRepo && strings.HasPrefix(n.ID, "repo:acme-archive/") {
				t.Errorf("archived org should have no repos, got %s", n.ID)
			}
		}
	})

	t.Run("retry and pagination", func(t *testing.T) {
		if got := f.hitCount("/orgs/acme-app/repos?type=all&per_page=100"); got != 2 {
			t.Errorf("acme-app repos first page requested %d times, want 2 (502 then success)", got)
		}
		if got := f.hitCount("/orgs/acme-app/repos?page=4&per_page=100&type=all"); got != 1 {
			t.Errorf("acme-app repos page 4 requested %d times, want 1", got)
		}
		n := 0
		for _, x := range g.Nodes {
			if x.Kind == graph.KindRepo && strings.HasPrefix(x.ID, "repo:acme-app/") {
				n++
			}
		}
		if n != 10 {
			t.Errorf("acme-app repos = %d, want 10", n)
		}
		if got := f.hitCount("/enterprises/acme/consumed-licenses?page=2&per_page=100"); got != 1 {
			t.Errorf("consumed-licenses page 2 requested %d times, want 1", got)
		}
	})

	t.Run("uses edges and ref kinds", func(t *testing.T) {
		cases := []struct{ wf, action, kind string }{
			{"workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main", "branch"},
			{"workflow:acme-app/web/.github/workflows/ci.yml", "action:actions/checkout@v4", "tag"},
			{"workflow:acme-app/api/.github/workflows/deploy.yml", "action:acme-actions/deploy@" + testSHA, "sha"},
			{"workflow:acme-app/worker/.github/workflows/deploy.yml", "action:acme-actions/deploy@v1", "tag"},
			{"workflow:acme-app/search/.github/workflows/index.yaml", "action:acme-actions/setup@main", "branch"},
		}
		for _, c := range cases {
			e := ix.mustEdge(t, c.wf, c.action, graph.Uses)
			if e.Attrs[graph.AttrRefKind] != c.kind {
				t.Errorf("%s -> %s ref_kind = %q, want %q", c.wf, c.action, e.Attrs[graph.AttrRefKind], c.kind)
			}
			ix.mustEdge(t, c.wf, strings.Replace(strings.SplitN(c.wf, "/.github/", 2)[0], "workflow:", "repo:", 1), graph.DefinedIn)
		}
		reusable := ix.mustEdge(t, "workflow:acme-app/docs/.github/workflows/build.yml",
			"action:acme-actions/setup/.github/workflows/build.yml@main", graph.Uses)
		if reusable.Attrs["level"] != LevelJob {
			t.Errorf("reusable workflow level = %q, want job", reusable.Attrs["level"])
		}
		ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
		ix.mustEdge(t, "action:acme-actions/setup/.github/workflows/build.yml@main", "repo:acme-actions/setup", graph.ResolvesTo)
		ix.noEdge(t, "action:actions/checkout@v4", "repo:actions/checkout", graph.ResolvesTo)
		for _, n := range g.Nodes {
			if strings.Contains(n.ID, "./") || strings.Contains(n.ID, "docker:") {
				t.Errorf("local/docker uses should be skipped, got %s", n.ID)
			}
			if strings.HasPrefix(n.ID, "workflow:acme-app/admin/") {
				t.Errorf("archived repo workflow collected: %s", n.ID)
			}
			if strings.HasSuffix(n.ID, "README.md") {
				t.Errorf("non-yaml file treated as workflow: %s", n.ID)
			}
		}
	})

	t.Run("executes with", func(t *testing.T) {
		ix.mustEdge(t, "workflow:acme-app/billing/.github/workflows/deploy.yml", "oidc:acme-app/billing", graph.ExecutesWith)
		ix.mustEdge(t, "workflow:acme-app/search/.github/workflows/index.yaml", "oidc:acme-app/search", graph.ExecutesWith)
		s := ix.mustEdge(t, "workflow:acme-app/mobile/.github/workflows/release.yml", "secret:acme-app/mobile", graph.ExecutesWith)
		if s.Attrs["secrets"] != "DEPLOY_KEY" {
			t.Errorf("secrets attr = %q", s.Attrs["secrets"])
		}
		inh := ix.mustEdge(t, "workflow:acme-app/docs/.github/workflows/build.yml", "secret:acme-app/docs", graph.ExecutesWith)
		if inh.Attrs["inherit"] != "true" {
			t.Errorf("inherit attr = %q", inh.Attrs["inherit"])
		}
		ix.mustEdge(t, "workflow:acme-app/infra/.github/workflows/apply.yml", "runner:acme-app/infra", graph.ExecutesWith)
		ix.noEdge(t, "workflow:acme-app/web/.github/workflows/ci.yml", "secret:acme-app/web", graph.ExecutesWith)
		ix.noEdge(t, "workflow:acme-app/search/.github/workflows/index.yaml", "secret:acme-app/search", graph.ExecutesWith)
	})

	t.Run("can push from default permission", func(t *testing.T) {
		e := ix.mustEdge(t, "members:acme-actions", "repo:acme-actions/deploy", graph.CanPush)
		// Derived from the org's default permission, not read from the
		// repo's permission list: inferred, with the rule named.
		if e.Evidence != graph.Inferred || e.SourceAPI != srcDefaultPerm || e.Attrs[graph.AttrRule] != graph.RuleDefaultPerm {
			t.Errorf("CAN_PUSH evidence/source/rule = %q/%q/%q", e.Evidence, e.SourceAPI, e.Attrs[graph.AttrRule])
		}
		if e.Attrs[graph.AttrVia] != graph.ViaDefaultPerm || e.Attrs[graph.AttrTwoFactor] != "not_required" || e.Attrs[graph.AttrSSO] != "configured" {
			t.Errorf("CAN_PUSH attrs = %v", e.Attrs)
		}
		ix.mustEdge(t, "members:acme-legacy", "repo:acme-legacy/old-site", graph.CanPush)
		ix.noEdge(t, "members:acme-app", "repo:acme-app/web", graph.CanPush)
		ix.noEdge(t, "members:acme-secure", "repo:acme-secure/vault-proxy", graph.CanPush)
	})

	t.Run("inferred edges count as confirmed", func(t *testing.T) {
		// Reading the derived edges as live would not change confirmed reach.
		live := *g
		live.Edges = append([]graph.Edge(nil), g.Edges...)
		n := 0
		for i, e := range live.Edges {
			if e.Evidence == graph.Inferred {
				if e.Attrs[graph.AttrRule] == "" {
					t.Errorf("inferred edge %s -%s-> %s has no rule", e.From, e.Kind, e.To)
				}
				live.Edges[i].Evidence = graph.Live
				n++
			}
		}
		if n == 0 {
			t.Fatal("no inferred edges collected")
		}
		got := graph.Reach(g, "members:acme-actions", graph.Options{}).Confirmed
		want := graph.Reach(&live, "members:acme-actions", graph.Options{}).Confirmed
		if !reflect.DeepEqual(got, want) || len(got.Repos) == 0 {
			t.Errorf("confirmed reach with inferred = %+v, read live = %+v", got, want)
		}
	})

	t.Run("transitive references", func(t *testing.T) {
		pinned := "action:acme-actions/deploy@" + testSHA
		e := ix.mustEdge(t, pinned, "action:acme-actions/setup@main", graph.Uses)
		if e.Attrs[graph.AttrRefKind] != "branch" || e.SourceAPI != srcNested {
			t.Errorf("nested edge = %+v", e)
		}
		// setup@main cycles back to deploy@SHA; visited tracking stops it.
		ix.mustEdge(t, "action:acme-actions/setup@main", pinned, graph.Uses)
		ix.mustEdge(t, "action:acme-actions/setup@main", "action:actions/checkout@v4", graph.Uses)
		// Reusable workflow expands to its own uses.
		ix.mustEdge(t, "action:acme-actions/setup/.github/workflows/build.yml@main", "action:acme-actions/deploy@main", graph.Uses)
		if ix.node(t, pinned).Attrs["runs_using"] != "composite" {
			t.Error("pinned deploy action should be composite")
		}
		f.mu.Lock()
		refs := strings.Join(f.refs, ",")
		f.mu.Unlock()
		if !strings.Contains(refs, testSHA) {
			t.Errorf("contents not fetched at the pinned sha; refs seen: %s", refs)
		}
		hidden := ix.node(t, "action:acme-legacy/hidden-tool@v2")
		if hidden.Attrs["nested"] != "unknown" || hidden.AttrEvidence["nested"] != graph.NotVisible {
			t.Errorf("hidden-tool nested = %q (%q)", hidden.Attrs["nested"], hidden.AttrEvidence["nested"])
		}
		if _, ok := hasCoverage(g, "action:acme-legacy/hidden-tool@v2", "nested_uses"); !ok {
			t.Error("missing nested_uses coverage for hidden-tool")
		}
	})

	t.Run("golden graph", func(t *testing.T) {
		testutil.Golden(t, "collect_acme.json", stableGraphJSON(t, g))
	})

	t.Run("WriteGraph round trip", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteGraph(&buf, g); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "\n  \"schema\"") {
			t.Error("output is not indented")
		}
		if strings.Contains(buf.String(), testToken) {
			t.Error("token leaked into graph output")
		}
		var back graph.Graph
		if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
			t.Fatal(err)
		}
		if back.Schema != graph.SchemaVersion || len(back.Nodes) != len(g.Nodes) || len(back.Edges) != len(g.Edges) {
			t.Errorf("round trip mismatch: %s %d/%d %d/%d", back.Schema, len(back.Nodes), len(g.Nodes), len(back.Edges), len(g.Edges))
		}
	})
}

// stableGraphJSON writes g with every timestamp zeroed, so the output of two
// runs on the same fixture is byte-identical.
func stableGraphJSON(t *testing.T, g *graph.Graph) []byte {
	t.Helper()
	cp := *g
	cp.CollectedAt = time.Time{}
	cp.OrgCollectedAt = nil
	cp.Edges = slices.Clone(g.Edges)
	for i := range cp.Edges {
		cp.Edges[i].ObservedAt = time.Time{}
	}
	var buf bytes.Buffer
	if err := WriteGraph(&buf, &cp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCollectAllowlist(t *testing.T) {
	_, ix := collectAcme(t, "acme-app", "acme-missing")
	for _, n := range ix.g.Nodes {
		if n.Kind == graph.KindOrg && n.ID != "org:acme-app" {
			t.Errorf("org outside allowlist collected: %s", n.ID)
		}
	}
	// Actions in a non-selected enterprise org still resolve, to a stub repo.
	ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
	if ix.node(t, "repo:acme-actions/deploy").Attrs["collected"] != "false" {
		t.Error("stub repo should be marked collected=false")
	}
	if _, ok := hasCoverage(ix.g, "org:acme-missing", "org"); !ok {
		t.Error("missing coverage for unknown allowlisted org")
	}
}

func TestCollectBadToken(t *testing.T) {
	f := newFakeGitHub(t)
	c, err := NewClient(ClientOptions{BaseURL: f.srv.URL, Token: "wrong-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Collect(context.Background(), Config{Enterprise: "acme", Client: c})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "wrong-secret-value") {
		t.Errorf("token leaked in error: %v", err)
	}
}

func TestOwnerFixWithoutSSO(t *testing.T) {
	k := &collector{}
	o := &orgState{login: "acme-app", node: &graph.Node{Attrs: map[string]string{graph.AttrSSO: "configured"}}}
	if got := k.ownerFix(o); got != "org owner on acme-app" {
		t.Errorf("ownerFix = %q", got)
	}
}

func TestCanPushOrgOwners(t *testing.T) {
	_, ix := collectAcme(t)

	e := ix.mustEdge(t, "identity:alice", "repo:acme-app/web", graph.CanPush)
	if e.Attrs[graph.AttrVia] != graph.ViaOrgOwner || e.Attrs["permission"] != "admin" ||
		e.Evidence != graph.Inferred || e.Attrs[graph.AttrRule] != graph.RuleOrgOwner || e.SourceAPI != srcLicenses {
		t.Errorf("owner edge = %+v", e)
	}
	// Owners reach every collected repo of the org, archived ones included.
	ix.mustEdge(t, "identity:alice", "repo:acme-app/admin", graph.CanPush)
	ix.mustEdge(t, "identity:alice", "repo:acme-actions/deploy", graph.CanPush)
	ix.mustEdge(t, "identity:carol", "repo:acme-secure/vault-proxy", graph.CanPush)

	// A direct grant to an owner keeps the more specific via=direct.
	api := ix.mustEdge(t, "identity:alice", "repo:acme-app/api", graph.CanPush)
	if api.Attrs[graph.AttrVia] != graph.ViaDirect || api.Attrs["permission"] != "admin" || api.SourceAPI != srcCollabs {
		t.Errorf("owner with direct grant = %+v, want via=direct from the collaborators API", api)
	}

	m := ix.mustEdge(t, "identity:alice", "org:acme-actions", graph.MemberOf)
	if m.Attrs["role"] != "owner" || m.Evidence != graph.Live || m.SourceAPI != srcLicenses {
		t.Errorf("MEMBER_OF = %+v", m)
	}
	ix.mustEdge(t, "identity:dave", "org:acme-app", graph.MemberOf)
	if n := ix.node(t, "identity:dave"); n.Kind != graph.KindIdentity || n.Evidence != graph.Live {
		t.Errorf("identity node = %+v", n)
	}
	// Members without a grant get no CAN_PUSH from the read default.
	ix.noEdge(t, "identity:dave", "repo:acme-app/web", graph.CanPush)

	// blast_radius on an identity now resolves.
	if s := graph.BlastRadius(ix.g, "identity:alice"); s.Confirmed.Repos == 0 {
		t.Errorf("alice blast radius = %+v", s)
	}
}

func TestCanPushCollaborators(t *testing.T) {
	_, ix := collectAcme(t)

	t.Run("direct collaborator with push", func(t *testing.T) {
		e := ix.mustEdge(t, "identity:bob", "repo:acme-actions/deploy", graph.CanPush)
		if e.Attrs[graph.AttrVia] != graph.ViaDirect || e.Attrs["permission"] != "maintain" ||
			e.Evidence != graph.Live || e.SourceAPI != srcCollabs {
			t.Errorf("bob edge = %+v", e)
		}
		ix.mustEdge(t, "identity:bob", "repo:acme-app/web", graph.CanPush)
	})

	t.Run("outside collaborator with a custom role", func(t *testing.T) {
		e := ix.mustEdge(t, "identity:frank", "repo:acme-app/api", graph.CanPush)
		if e.Attrs[graph.AttrVia] != graph.ViaOutsideCollaborator || e.Attrs["permission"] != "deployer" ||
			e.Attrs["base_role"] != "write" || e.Evidence != graph.Live {
			t.Errorf("frank edge = %+v", e)
		}
		if n := ix.node(t, "identity:frank"); n.Kind != graph.KindIdentity {
			t.Errorf("frank node = %+v", n)
		}
		for _, e := range ix.g.Edges {
			if e.From == "identity:frank" && e.Kind == graph.MemberOf {
				t.Errorf("outside collaborator has MEMBER_OF %s", e.To)
			}
		}
		erin := ix.mustEdge(t, "identity:erin", "repo:acme-actions/deploy", graph.CanPush)
		if erin.Attrs[graph.AttrVia] != graph.ViaOutsideCollaborator || erin.Evidence != graph.Live {
			t.Errorf("erin edge = %+v", erin)
		}
	})

	t.Run("collaborator without push", func(t *testing.T) {
		ix.noEdge(t, "identity:dave", "repo:acme-actions/deploy", graph.CanPush)
	})

	t.Run("non-owner org is coverage, license grants are not_visible", func(t *testing.T) {
		c, ok := hasCoverage(ix.g, "org:acme-legacy", "can_push:collaborators")
		if !ok || c.Reason != "could not list collaborators on 1 repos (needs push access)" {
			t.Errorf("coverage = %+v (found %v)", c, ok)
		}
		if _, ok := hasCoverage(ix.g, "org:acme-legacy", "outside_collaborators"); !ok {
			t.Error("missing outside_collaborators coverage for acme-legacy")
		}
		repo := ix.node(t, "repo:acme-legacy/old-site")
		if repo.Attrs["collaborators"] != "unknown" || repo.AttrEvidence["collaborators"] != graph.NotVisible {
			t.Errorf("old-site collaborators = %q (%q)", repo.Attrs["collaborators"], repo.AttrEvidence["collaborators"])
		}
		e := ix.mustEdge(t, "identity:bob", "repo:acme-legacy/old-site", graph.CanPush)
		if e.Evidence != graph.NotVisible || e.Attrs[graph.AttrVia] != graph.ViaDirect || e.Attrs["permission"] != "unknown" {
			t.Errorf("unconfirmed grant = %+v", e)
		}
		for _, c := range ix.g.Coverage {
			if c.Fact == "can_push:collaborators" && c.Scope != "org:acme-legacy" {
				t.Errorf("unexpected collaborators coverage: %+v", c)
			}
		}
	})

	t.Run("forbidden repo makes the license grant possible, not confirmed", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.forbidCollab["acme-actions/deploy"] = true
		g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
		if err != nil {
			t.Fatal(err)
		}
		fx := newIndex(g)
		e := fx.mustEdge(t, "identity:erin", "repo:acme-actions/deploy", graph.CanPush)
		if e.Evidence != graph.NotVisible || e.Attrs["permission"] != "unknown" || e.Attrs["license_role"] != "Write" {
			t.Errorf("erin edge = %+v", e)
		}
		c, ok := hasCoverage(g, "org:acme-actions", "can_push:collaborators")
		if !ok || c.Reason != "could not list collaborators on 1 repos (needs push access)" {
			t.Errorf("coverage = %+v (found %v)", c, ok)
		}
		// bob's grant on deploy is unseen, and his license lists no role there.
		fx.noEdge(t, "identity:bob", "repo:acme-actions/deploy", graph.CanPush)
		r := graph.Reach(g, "identity:erin", graph.Options{})
		if slices.Contains(r.Confirmed.Repos, "repo:acme-actions/deploy") {
			t.Errorf("unconfirmed grant leaked into confirmed reach: %v", r.Confirmed.Repos)
		}
		if !slices.Contains(r.Possible.Repos, "repo:acme-actions/deploy") {
			t.Errorf("possible = %v, want repo:acme-actions/deploy", r.Possible.Repos)
		}
	})

	t.Run("one request per repo and org, archived repos skipped", func(t *testing.T) {
		f, _ := collectAcme(t)
		if got := f.hitCount("/repos/acme-actions/deploy/collaborators?affiliation=direct&per_page=100"); got != 1 {
			t.Errorf("deploy collaborators requested %d times, want 1", got)
		}
		if got := f.hitCount("/repos/acme-app/admin/collaborators?affiliation=direct&per_page=100"); got != 0 {
			t.Errorf("archived repo collaborators requested %d times, want 0", got)
		}
		if got := f.hitCount("/orgs/acme-app/outside_collaborators?per_page=100"); got != 1 {
			t.Errorf("outside collaborators requested %d times, want 1 per org", got)
		}
	})
}

func TestCollaboratorPagination(t *testing.T) {
	f := newFakeGitHub(t)
	f.pageSize = 1 // deploy's three collaborators span three pages
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
	if err != nil {
		t.Fatal(err)
	}
	ix := newIndex(g)
	ix.mustEdge(t, "identity:bob", "repo:acme-actions/deploy", graph.CanPush)
	ix.mustEdge(t, "identity:erin", "repo:acme-actions/deploy", graph.CanPush)
	if got := f.hitCount("/repos/acme-actions/deploy/collaborators?affiliation=direct&page=3&per_page=100"); got != 1 {
		t.Errorf("deploy collaborators page 3 requested %d times, want 1", got)
	}
}

func TestCanPushTeams(t *testing.T) {
	f, ix := collectAcme(t)
	const (
		platform = "team:acme-actions/platform"
		oncall   = "team:acme-actions/platform-oncall"
		deploy   = "repo:acme-actions/deploy"
	)

	t.Run("team nodes", func(t *testing.T) {
		n := ix.node(t, platform)
		if n.Kind != graph.KindIdentity || n.Evidence != graph.Live || n.Attrs["org"] != "acme-actions" ||
			n.Attrs["slug"] != "platform" || n.Attrs["privacy"] != "closed" {
			t.Errorf("platform node = %+v", n)
		}
		// role=all returns the child team's members too: bob and alice.
		if n.Attrs[graph.AttrMembers] != "2" {
			t.Errorf("platform members = %q, want 2", n.Attrs[graph.AttrMembers])
		}
		if graph.OrgOf(platform) != "org:acme-actions" {
			t.Errorf("OrgOf(%s) = %q", platform, graph.OrgOf(platform))
		}
	})

	t.Run("team grant with push", func(t *testing.T) {
		e := ix.mustEdge(t, platform, deploy, graph.CanPush)
		if e.Attrs[graph.AttrVia] != graph.ViaTeam || e.Attrs["permission"] != "maintain" ||
			e.Evidence != graph.Live || e.SourceAPI != srcTeamRepos {
			t.Errorf("platform edge = %+v", e)
		}
	})

	t.Run("read and triage grants yield no edge", func(t *testing.T) {
		ix.noEdge(t, platform, "repo:acme-actions/setup", graph.CanPush)
		ix.noEdge(t, "team:acme-actions/readers", deploy, graph.CanPush)
		ix.node(t, "team:acme-actions/readers")
	})

	t.Run("nesting and direct members", func(t *testing.T) {
		e := ix.mustEdge(t, oncall, platform, graph.MemberOf)
		if e.Evidence != graph.Live || e.SourceAPI != srcTeams {
			t.Errorf("nesting edge = %+v", e)
		}
		e = ix.mustEdge(t, "identity:bob", platform, graph.MemberOf)
		if e.Evidence != graph.Live || e.SourceAPI != srcTeamMembers {
			t.Errorf("bob membership = %+v", e)
		}
		ix.mustEdge(t, "identity:alice", oncall, graph.MemberOf)
		// alice is listed on platform only through the child team: one fact per edge.
		ix.noEdge(t, "identity:alice", platform, graph.MemberOf)
		ix.noEdge(t, "identity:dave", "team:acme-actions/readers", graph.MemberOf)
	})

	t.Run("reach through the child team", func(t *testing.T) {
		r := graph.Reach(ix.g, oncall, graph.Options{})
		if !slices.Contains(r.Confirmed.Repos, deploy) {
			t.Fatalf("child team repos = %v", r.Confirmed.Repos)
		}
		if n := len(r.Paths[deploy].Hops); n != 2 {
			t.Errorf("child team path = %d hops, want 2", n)
		}
		var who []string
		for _, p := range graph.WhoCanReach(ix.g, deploy) {
			who = append(who, p.From)
		}
		for _, want := range []string{platform, oncall} {
			if !slices.Contains(who, want) {
				t.Errorf("WhoCanReach(%s) = %v, missing %s", deploy, who, want)
			}
		}
	})

	t.Run("members refused keeps the grant", func(t *testing.T) {
		const release = "team:acme-app/release"
		e := ix.mustEdge(t, release, "repo:acme-app/docs", graph.CanPush)
		if e.Evidence != graph.Live || e.Attrs[graph.AttrVia] != graph.ViaTeam || e.Attrs["permission"] != "write" {
			t.Errorf("release edge = %+v", e)
		}
		n := ix.node(t, release)
		if n.Attrs[graph.AttrMembers] != "unknown" || n.AttrEvidence[graph.AttrMembers] != graph.NotVisible {
			t.Errorf("release members = %q (%q)", n.Attrs[graph.AttrMembers], n.AttrEvidence[graph.AttrMembers])
		}
		var covs []graph.Coverage
		for _, c := range ix.g.Coverage {
			if strings.HasPrefix(c.Fact, "team_members:") {
				covs = append(covs, c)
			}
		}
		if len(covs) != 1 || covs[0].Scope != "org:acme-app" || covs[0].Fact != "team_members:release" {
			t.Errorf("team_members coverage = %+v, want one entry for release", covs)
		}
		for _, e := range ix.g.Edges {
			if e.To == release && e.Kind == graph.MemberOf {
				t.Errorf("invented member edge %+v", e)
			}
		}
	})

	t.Run("requests", func(t *testing.T) {
		if got := f.hitCount("/orgs/acme-actions/teams?per_page=100"); got != 1 {
			t.Errorf("teams listed %d times, want 1", got)
		}
		if got := f.hitCount("/orgs/acme-actions/teams/readers/repos?per_page=100"); got != 1 {
			t.Errorf("readers repos requested %d times, want 1", got)
		}
		// readers has no push grant and no parent with one: its members are not needed.
		if got := f.hitCount("/orgs/acme-actions/teams/readers/members?role=all&per_page=100"); got != 0 {
			t.Errorf("readers members requested %d times, want 0", got)
		}
		if got := f.hitCount("/orgs/acme-actions/teams/platform-oncall/members?role=all&per_page=100"); got != 1 {
			t.Errorf("platform-oncall members requested %d times, want 1", got)
		}
	})
}

func TestTeamsNotVisible(t *testing.T) {
	_, ix := collectAcme(t)
	c, ok := hasCoverage(ix.g, "org:acme-legacy", "can_push:teams")
	if !ok || c.Reason != "token is not an org owner: secret teams and their grants are not listed" ||
		c.NeedsFix != "org owner on acme-legacy (SSO enforced: join through the identity provider first)" {
		t.Errorf("coverage = %+v (found %v)", c, ok)
	}
	if n := ix.node(t, "org:acme-legacy"); n.Attrs["teams_partial"] != "true" {
		t.Errorf("acme-legacy teams_partial = %q", n.Attrs["teams_partial"])
	}
	// The closed team is visible and its grant observed; the secret one is not listed.
	e := ix.mustEdge(t, "team:acme-legacy/legacy-devs", "repo:acme-legacy/old-site", graph.CanPush)
	if e.Evidence != graph.Live {
		t.Errorf("legacy-devs edge = %+v", e)
	}
	if _, ok := ix.nodes["team:acme-legacy/legacy-admins"]; ok {
		t.Error("secret team listed for a non-owner token")
	}
	for _, org := range []string{"org:acme-actions", "org:acme-app", "org:acme-secure"} {
		if _, ok := hasCoverage(ix.g, org, "can_push:teams"); ok {
			t.Errorf("unexpected can_push:teams coverage on owned %s", org)
		}
		if n := ix.node(t, org); n.Attrs["teams_partial"] != "" {
			t.Errorf("%s teams_partial = %q", org, n.Attrs["teams_partial"])
		}
	}
}

// refsWorkflow is a workflow in acme-app/notify that uses each of refs on
// acme-actions/<ref>, with a secret so reach shows up as a terminal.
func refsWorkflow(uses ...string) string {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for _, u := range uses {
		b.WriteString("      - uses: " + u + "\n        with:\n          token: ${{ secrets.NOTIFY_TOKEN }}\n")
	}
	return b.String()
}

const refsWF = "workflow:acme-app/notify/.github/workflows/refs.yml"

func TestResolveRefs(t *testing.T) {
	f := newFakeGitHub(t)
	f.tags["acme-actions/deploy"]["both"] = true
	f.branches["acme-actions/deploy"]["both"] = true
	f.extraWorkflows["acme-app/notify/refs.yml"] = refsWorkflow(
		"acme-actions/deploy@release-2026", "acme-actions/setup@v2-dev", "acme-actions/deploy@both",
		"acme-actions/deploy@abc1234", "acme-actions/deploy@v9-missing")
	ix := collectFake(t, f)

	cases := []struct {
		id, kind, source, ambiguous string
	}{
		{"action:acme-actions/deploy@release-2026", "tag", "api", ""}, // the name says branch
		{"action:acme-actions/setup@v2-dev", "branch", "api", ""},     // the name says tag
		{"action:acme-actions/deploy@both", "branch", "api", "true"},
		{"action:acme-actions/deploy@abc1234", "branch", "name", ""}, // abbreviated SHA: not looked up
		{"action:acme-actions/deploy@v9-missing", "tag", "name", ""}, // neither exists: the guess stays
		{"action:acme-actions/deploy@main", "branch", "api", ""},     // shared fixture
		{"action:acme-actions/deploy@v1", "tag", "api", ""},          // shared fixture
		{"action:acme-legacy/hidden-tool@v2", "tag", "name", ""},     // repo not visible
	}
	for _, tc := range cases {
		n := ix.node(t, tc.id)
		if n.Attrs[graph.AttrRefKind] != tc.kind || n.Attrs[graph.AttrRefKindSource] != tc.source || n.Attrs[graph.AttrRefAmbiguous] != tc.ambiguous {
			t.Errorf("%s: ref_kind=%q source=%q ambiguous=%q, want %q %q %q", tc.id, n.Attrs[graph.AttrRefKind],
				n.Attrs[graph.AttrRefKindSource], n.Attrs[graph.AttrRefAmbiguous], tc.kind, tc.source, tc.ambiguous)
		}
		for _, e := range ix.g.Edges {
			if e.Kind == graph.Uses && e.To == tc.id && e.Attrs[graph.AttrRefKind] != tc.kind {
				t.Errorf("USES %s -> %s ref_kind = %q, want %q", e.From, tc.id, e.Attrs[graph.AttrRefKind], tc.kind)
			}
		}
		_, covered := hasCoverage(ix.g, tc.id, graph.AttrRefKind)
		if covered != (tc.source == "name") {
			t.Errorf("%s: ref_kind coverage = %v, want %v", tc.id, covered, tc.source == "name")
		}
	}
	// Only tags from the API get an immutability verdict.
	if v := ix.node(t, "action:acme-actions/deploy@v9-missing").Attrs[graph.AttrRefImmutable]; v != "" {
		t.Errorf("name-guessed tag has ref_immutable=%q", v)
	}
	if v := ix.node(t, "action:acme-actions/deploy@release-2026").Attrs[graph.AttrRefImmutable]; v != "false" {
		t.Errorf("release-2026 ref_immutable = %q, want false (no release, no tag ruleset)", v)
	}
	// The ambiguous ref is mutable even with the tag reading immutable.
	gix := graph.NewIndex(ix.g)
	if !gix.MutableRef("action:acme-actions/deploy@both") {
		t.Error("ambiguous ref is not mutable")
	}
	p, ok := gix.Reach("identity:bob", graph.Options{}).Paths["action:acme-actions/deploy@both"]
	if !ok || p.Unverified || !usesHop(p, deployRepo, "action:acme-actions/deploy@both") {
		t.Errorf("bob (maintain on deploy) does not control the ambiguous ref through its repo: %+v", p)
	}
}

func TestResolveRefsBatches(t *testing.T) {
	f := newFakeGitHub(t)
	var uses []string
	for i := 0; i < 120; i++ {
		uses = append(uses, fmt.Sprintf("acme-actions/deploy@b%d", i))
	}
	f.extraWorkflows["acme-app/notify/refs.yml"] = refsWorkflow(uses...)
	ix := collectFake(t, f)
	distinct := map[string]bool{}
	for _, n := range ix.g.Nodes {
		if n.Kind == graph.KindActionRef && n.Attrs[attrInEnterprise] == "true" && n.Attrs[graph.AttrRefKind] != "sha" {
			distinct[n.Attrs["owner"]+"/"+n.Attrs["repo"]+"@"+n.Attrs["ref"]] = true
		}
	}
	want := (len(distinct) + refBatchSize - 1) / refBatchSize
	if got := f.hitCount("graphql:refs"); len(distinct) < 120 || got != want {
		t.Errorf("%d distinct refs took %d GraphQL queries, want %d", len(distinct), got, want)
	}
	if n := ix.node(t, "action:acme-actions/deploy@b77"); n.Attrs[graph.AttrRefKindSource] != "name" {
		t.Errorf("b77 source = %q, want name", n.Attrs[graph.AttrRefKindSource])
	}
}

// tagRuleset is a tag ruleset on refs/tags/v* with the given rules, bypassed
// by team acme-actions/release (id 42).
func tagRuleset(t *testing.T, id int, rules ...string) json.RawMessage {
	var rs []map[string]any
	for _, r := range rules {
		rs = append(rs, map[string]any{"type": r})
	}
	return raw(t, map[string]any{
		"id": id, "name": "release-tags", "target": "tag", "enforcement": "active",
		"conditions":    map[string]any{"ref_name": map[string]any{"include": []string{"refs/tags/v*"}, "exclude": []string{}}},
		"rules":         rs,
		"bypass_actors": []map[string]any{{"actor_id": 42, "actor_type": "Team", "bypass_mode": "always"}},
	})
}

// deployV3 is a sub-action of acme-actions/deploy at tag v3. Its action.yml
// is not in the fixture, so it has no nested USES: the consumer is reachable
// through the RESOLVES_TO hop only (deploy's root action.yml uses setup@main,
// which would open a nested path whatever the tag does).
const deployV3 = "action:acme-actions/deploy/tools@v3"

func TestImmutableTags(t *testing.T) {
	// reaches reports whether p reaches the @v3 consumer: "c" confirmed, "p" possible, "" not.
	reaches := func(g *graph.Graph, p string) string {
		r := graph.Reach(g, p, graph.Options{})
		switch {
		case slices.Contains(r.Confirmed.Workflows, refsWF):
			return "c"
		case slices.Contains(r.Possible.Workflows, refsWF):
			return "p"
		}
		return ""
	}
	setup := func(t *testing.T, mod func(*fakeGitHub)) *index {
		f := newFakeGitHub(t)
		f.extraWorkflows["acme-app/notify/refs.yml"] = refsWorkflow("acme-actions/deploy/tools@v3")
		if mod != nil {
			mod(f)
		}
		return collectFake(t, f)
	}
	// withoutGate drops the immutability verdict: what reach was before.
	withoutGate := func(g *graph.Graph) *graph.Graph {
		cp := *g
		cp.Nodes = slices.Clone(g.Nodes)
		for i, n := range cp.Nodes {
			if n.ID == deployV3 {
				attrs := map[string]string{}
				for k, v := range n.Attrs {
					attrs[k] = v
				}
				delete(attrs, graph.AttrRefImmutable)
				cp.Nodes[i].Attrs = attrs
			}
		}
		return &cp
	}
	hasPin := func(g *graph.Graph) bool {
		for _, c := range graph.NewIndex(g).Candidates() {
			if c.ID() == "pin:"+deployV3 {
				return true
			}
		}
		return false
	}
	bypassEdge := func(g *graph.Graph) bool {
		for _, e := range g.Edges {
			if e.From == releaseT && e.To == deployRepo && e.Kind == graph.CanPush &&
				e.Attrs[graph.AttrVia] == graph.ViaRefBypass && e.Attrs[graph.AttrRef] == "v3" {
				return true
			}
		}
		return false
	}

	t.Run("immutable release", func(t *testing.T) {
		ix := setup(t, nil)
		n := ix.node(t, deployV3)
		if n.Attrs[graph.AttrRefImmutable] != "true" || n.Attrs[graph.AttrRefImmutableBy] != graph.RefImmutableRelease || n.AttrEvidence[graph.AttrRefImmutable] != "" {
			t.Fatalf("v3 attrs = %v %v", n.Attrs, n.AttrEvidence)
		}
		if got := reaches(withoutGate(ix.g), "members:acme-actions"); got != "c" {
			t.Fatalf("without the gate members:acme-actions reach = %q, want c (the test would prove nothing)", got)
		}
		if got := reaches(ix.g, "members:acme-actions"); got != "" {
			t.Errorf("members:acme-actions still reaches the @v3 consumer: %q", got)
		}
		if hasPin(ix.g) {
			t.Error("Candidates has pin:" + deployV3)
		}
		// The root action at @v3 too: no pin candidate, and no path through
		// its RESOLVES_TO hop (its nested setup@main still opens one).
		f := newFakeGitHub(t)
		f.extraWorkflows["acme-app/notify/refs.yml"] = refsWorkflow("acme-actions/deploy@v3")
		root := collectFake(t, f)
		for _, c := range graph.NewIndex(root.g).Candidates() {
			if c.ID() == "pin:action:acme-actions/deploy@v3" {
				t.Error("Candidates has pin:action:acme-actions/deploy@v3")
			}
		}
		for id, p := range graph.Reach(root.g, "members:acme-actions", graph.Options{}).Paths {
			if usesHop(p, deployRepo, "action:acme-actions/deploy@v3") {
				t.Errorf("path to %s goes through the immutable tag's repo hop", id)
			}
		}
	})

	noRelease := func(f *fakeGitHub) { delete(f.releases, "acme-actions/deploy@v3") }

	t.Run("tag ruleset", func(t *testing.T) {
		ix := setup(t, func(f *fakeGitHub) {
			noRelease(f)
			f.rulesets["acme-actions/deploy#20"] = tagRuleset(t, 20, "update", "deletion")
		})
		n := ix.node(t, deployV3)
		if n.Attrs[graph.AttrRefImmutable] != "true" || n.Attrs[graph.AttrRefImmutableBy] != graph.RefImmutableRuleset || n.Attrs[graph.AttrBypass] != releaseT {
			t.Fatalf("v3 attrs = %v", n.Attrs)
		}
		if !bypassEdge(ix.g) {
			t.Error("missing team:acme-actions/release -CAN_PUSH-> repo:acme-actions/deploy (via=ref_bypass, ref=v3)")
		}
		if got := reaches(ix.g, "members:acme-actions"); got != "" {
			t.Errorf("members:acme-actions reach = %q, want none", got)
		}
		if got := reaches(ix.g, releaseT); got != "c" {
			t.Errorf("bypass team reach = %q, want c", got)
		}
		if !hasPin(ix.g) {
			t.Error("pin of a tag with a bypass team is not a candidate")
		}
	})

	t.Run("split rules across rulesets", func(t *testing.T) {
		ix := setup(t, func(f *fakeGitHub) {
			noRelease(f)
			f.rulesets["acme-actions/deploy#20"] = tagRuleset(t, 20, "update")
			f.rulesets["acme-actions/deploy#21"] = tagRuleset(t, 21, "deletion", "creation")
		})
		if v := ix.node(t, deployV3).Attrs[graph.AttrRefImmutable]; v != "true" {
			t.Errorf("ref_immutable = %q, want true", v)
		}
	})

	for _, tc := range []struct {
		name string
		mod  func(*testing.T, *fakeGitHub)
	}{
		{"deletion only", func(t *testing.T, f *fakeGitHub) {
			f.rulesets["acme-actions/deploy#20"] = tagRuleset(t, 20, "deletion")
		}},
		{"evaluate mode", func(t *testing.T, f *fakeGitHub) {
			var m map[string]any
			_ = json.Unmarshal(tagRuleset(t, 20, "update", "deletion"), &m)
			m["enforcement"] = "evaluate"
			f.rulesets["acme-actions/deploy#20"] = raw(t, m)
		}},
		{"pattern does not match", func(t *testing.T, f *fakeGitHub) {
			var m map[string]any
			_ = json.Unmarshal(tagRuleset(t, 20, "update", "deletion"), &m)
			m["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{"refs/tags/release-*"}}}
			f.rulesets["acme-actions/deploy#20"] = raw(t, m)
		}},
		{"excluded", func(t *testing.T, f *fakeGitHub) {
			var m map[string]any
			_ = json.Unmarshal(tagRuleset(t, 20, "update", "deletion"), &m)
			m["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{"~ALL"}, "exclude": []string{"refs/tags/v3"}}}
			f.rulesets["acme-actions/deploy#20"] = raw(t, m)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := setup(t, func(f *fakeGitHub) {
				noRelease(f)
				tc.mod(t, f)
			})
			if v := ix.node(t, deployV3).Attrs[graph.AttrRefImmutable]; v != "false" {
				t.Errorf("ref_immutable = %q, want false", v)
			}
			if got := reaches(ix.g, "members:acme-actions"); got != "c" {
				t.Errorf("members:acme-actions reach = %q, want c", got)
			}
		})
	}

	for _, tc := range []struct {
		name string
		mod  func(*testing.T, *fakeGitHub)
	}{
		{"rulesets list forbidden", func(t *testing.T, f *fakeGitHub) {
			noRelease(f)
			f.forbidRulesets["acme-actions/deploy"] = true
		}},
		{"release forbidden", func(t *testing.T, f *fakeGitHub) {
			delete(f.releases, "acme-actions/deploy@v3")
			f.forbidReleases["acme-actions/deploy"] = true
		}},
		{"tag ruleset unreadable", func(t *testing.T, f *fakeGitHub) {
			noRelease(f)
			f.rulesets["acme-actions/deploy#20"] = tagRuleset(t, 20, "update", "deletion")
			f.failures["/repos/acme-actions/deploy/rulesets/20"] = 10
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := setup(t, func(f *fakeGitHub) { tc.mod(t, f) })
			n := ix.node(t, deployV3)
			if n.Attrs[graph.AttrRefImmutable] != "unknown" || n.AttrEvidence[graph.AttrRefImmutable] != graph.NotVisible {
				t.Fatalf("v3 ref_immutable = %q (%q), want unknown/not_visible", n.Attrs[graph.AttrRefImmutable], n.AttrEvidence[graph.AttrRefImmutable])
			}
			if _, ok := hasCoverage(ix.g, deployV3, graph.AttrRefImmutable); !ok {
				t.Error("missing ref_immutable coverage")
			}
			if got := reaches(ix.g, "members:acme-actions"); got != "p" {
				t.Errorf("members:acme-actions reach = %q, want p (possible)", got)
			}
		})
	}

	t.Run("bypass actors hidden", func(t *testing.T) {
		ix := setup(t, func(f *fakeGitHub) {
			noRelease(f)
			f.rulesets["acme-actions/deploy#20"] = tagRuleset(t, 20, "update", "deletion")
			f.hideBypass = true
		})
		n := ix.node(t, deployV3)
		if n.Attrs[graph.AttrRefImmutable] != "true" || n.Attrs[graph.AttrBypass] != "unknown" {
			t.Fatalf("v3 attrs = %v", n.Attrs)
		}
		if got := reaches(ix.g, "members:acme-actions"); got != "p" {
			t.Errorf("members:acme-actions reach = %q, want p", got)
		}
	})
}

// attrEvidence is the effective evidence of one attribute: its own entry in
// AttrEvidence, else the node's evidence.
func attrEvidence(n graph.Node, key string) graph.Evidence {
	if ev, ok := n.AttrEvidence[key]; ok {
		return ev
	}
	return n.Evidence
}

// repoOf returns "repo:O/R" for an ID that lives in one repository
// (repo, workflow, secret, oidc, runner, action), else "".
func repoOf(id string) string {
	prefix, rest, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	switch prefix {
	case "repo", "workflow", "secret", "oidc", "runner", "action":
	default:
		return ""
	}
	rest, _, _ = strings.Cut(rest, "@")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "repo:" + parts[0] + "/" + parts[1]
}

// assertCoverageComplete checks that every node, attribute and edge with
// not_visible evidence has a coverage entry whose scope is the node itself,
// its repo or its org (for an edge: either end, its repo or its org).
func assertCoverageComplete(t *testing.T, g *graph.Graph) {
	t.Helper()
	scopes := map[string]bool{}
	for _, c := range g.Coverage {
		scopes[c.Scope] = true
	}
	covered := func(ids ...string) bool {
		for _, id := range ids {
			for _, s := range []string{id, repoOf(id), graph.OrgOf(id)} {
				if s != "" && scopes[s] {
					return true
				}
			}
		}
		return false
	}
	for _, n := range g.Nodes {
		if n.Evidence == graph.NotVisible && !covered(n.ID) {
			t.Errorf("node %s is not_visible without coverage", n.ID)
		}
		for k, ev := range n.AttrEvidence {
			if ev == graph.NotVisible && !covered(n.ID) {
				t.Errorf("attribute %s.%s is not_visible without coverage", n.ID, k)
			}
		}
	}
	for _, e := range g.Edges {
		if e.Evidence == graph.NotVisible && !covered(e.From, e.To) {
			t.Errorf("edge %s -%s-> %s is not_visible without coverage", e.From, e.Kind, e.To)
		}
	}
}

func TestCoverageGaps(t *testing.T) {
	_, ix := collectAcme(t)
	g := ix.g

	t.Run("coverage is complete", func(t *testing.T) { assertCoverageComplete(t, g) })

	t.Run("workflows directory that is not a listing", func(t *testing.T) {
		r := ix.node(t, "repo:acme-secure/vendor-mirror")
		if r.Attrs["workflows"] != "unknown" || attrEvidence(r, "workflows") != graph.NotVisible {
			t.Errorf("workflows = %q (%q), want unknown/not_visible", r.Attrs["workflows"], attrEvidence(r, "workflows"))
		}
		c, ok := hasCoverage(g, "repo:acme-secure/vendor-mirror", "workflows")
		if !ok || c.Reason != "unexpected contents response for .github/workflows" {
			t.Errorf("coverage = %+v, %v", c, ok)
		}
	})

	t.Run("dynamic uses and unknown runner labels", func(t *testing.T) {
		wid := "workflow:acme-app/search/.github/workflows/index.yaml"
		w := ix.node(t, wid)
		if w.Attrs["dynamic_uses"] != "1" {
			t.Errorf("dynamic_uses = %q, want 1", w.Attrs["dynamic_uses"])
		}
		e := ix.mustEdge(t, wid, "runner:acme-app/search", graph.ExecutesWith)
		if e.Evidence != graph.NotVisible || e.Attrs["classification"] != "unknown" || e.Attrs["labels"] != "gpu,linux" {
			t.Errorf("runner edge = %+v", e)
		}
		if e.Attrs[graph.AttrLine] != "14" {
			t.Errorf("runner edge line = %q, want 14 (the embed job's runs-on)", e.Attrs[graph.AttrLine])
		}
		n := 0
		for _, c := range g.Coverage {
			if c.Scope == wid {
				n++
			}
		}
		if _, ok := hasCoverage(g, wid, "dynamic_uses"); !ok || n != 2 {
			t.Errorf("want dynamic_uses and runner_labels coverage on %s, got %d entries", wid, n)
		}
		if _, ok := hasCoverage(g, wid, "runner_labels"); !ok {
			t.Error("missing runner_labels coverage")
		}
		// ubuntu-latest jobs get no runner edge.
		for _, e := range g.Edges {
			if strings.HasPrefix(e.To, "runner:") && e.From != wid && e.From != "workflow:acme-app/infra/.github/workflows/apply.yml" {
				t.Errorf("unexpected runner edge %s -> %s", e.From, e.To)
			}
		}
		// Self-hosted stays live.
		if e := ix.mustEdge(t, "workflow:acme-app/infra/.github/workflows/apply.yml", "runner:acme-app/infra", graph.ExecutesWith); e.Evidence != graph.Live {
			t.Errorf("self-hosted runner edge evidence = %q", e.Evidence)
		}
	})

	t.Run("archived org", func(t *testing.T) {
		c, ok := hasCoverage(g, "org:acme-archive", "repositories")
		if !ok || c.Reason != "organization is archived; not collected" {
			t.Errorf("coverage = %+v, %v", c, ok)
		}
	})

	t.Run("stub repo in a collected org keeps the default permission edge", func(t *testing.T) {
		r := ix.node(t, "repo:acme-legacy/hidden-tool")
		if r.Evidence != graph.NotVisible || r.Attrs["collected"] != "false" || attrEvidence(r, "collected") != graph.Live {
			t.Errorf("hidden-tool = %+v", r)
		}
		if c, ok := hasCoverage(g, "repo:acme-legacy/hidden-tool", "can_push"); !ok || c.Reason != "host repository not listed for the token" {
			t.Errorf("coverage = %+v, %v", c, ok)
		}
		e := ix.mustEdge(t, "members:acme-legacy", "repo:acme-legacy/hidden-tool", graph.CanPush)
		if e.Evidence != graph.Inferred || e.Attrs[graph.AttrVia] != graph.ViaDefaultPerm || e.Attrs[graph.AttrRule] != graph.RuleDefaultPerm {
			t.Errorf("edge = %+v", e)
		}
	})

	t.Run("not_visible default permission", func(t *testing.T) {
		f := newFakeGitHub(t)
		for i := range f.fx.Orgs {
			if f.fx.Orgs[i].Login == "acme-legacy" {
				delete(f.fx.Orgs[i].Settings, "defaultRepositoryPermissionSettingOrganizations")
			}
		}
		g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := hasCoverage(g, "org:acme-legacy", "can_push:default_perm"); !ok {
			t.Error("missing can_push:default_perm coverage")
		}
		ix := newIndex(g)
		ix.noEdge(t, "members:acme-legacy", "repo:acme-legacy/old-site", graph.CanPush)
		e := ix.mustEdge(t, "members:acme-legacy", "repo:acme-legacy/hidden-tool", graph.CanPush)
		if e.Evidence != graph.NotVisible || e.Attrs[graph.AttrVia] != graph.ViaUnknown {
			t.Errorf("edge = %+v", e)
		}
		assertCoverageComplete(t, g)
	})
}

func TestCoverageLog(t *testing.T) {
	f := newFakeGitHub(t)
	var mu sync.Mutex
	var lines []string
	c, err := NewClient(ClientOptions{BaseURL: f.srv.URL, Token: testToken, Logf: func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(context.Background(), Config{Enterprise: "acme", Client: c}); err != nil {
		t.Fatal(err)
	}
	var cov []string
	for _, l := range lines {
		if strings.HasPrefix(l, "collect: coverage ") {
			cov = append(cov, l)
		}
	}
	want := "collect: coverage acme-legacy: 1 not_visible nodes, 2 edges, 8 attrs, 10 entries"
	if !slices.Contains(cov, want) {
		t.Errorf("coverage log lines = %q, want %q", cov, want)
	}
	for _, l := range cov {
		if strings.HasPrefix(l, "collect: coverage acme-actions:") {
			t.Errorf("fully visible org logged: %q", l)
		}
	}
}

func TestCoverageGapsOutsideOrgs(t *testing.T) {
	_, ix := collectAcme(t, "acme-app")
	g := ix.g
	assertCoverageComplete(t, g)
	r := ix.node(t, "repo:acme-actions/deploy")
	if r.Evidence != graph.NotVisible || r.Attrs["collected"] != "false" {
		t.Errorf("stub = %+v", r)
	}
	c, ok := hasCoverage(g, "repo:acme-actions/deploy", "can_push")
	if !ok || c.Reason != "host repository outside the collected orgs (--orgs)" {
		t.Errorf("coverage = %+v, %v", c, ok)
	}
	e := ix.mustEdge(t, "members:acme-actions", "repo:acme-actions/deploy", graph.CanPush)
	if e.Evidence != graph.NotVisible || e.Attrs[graph.AttrVia] != graph.ViaUnknown {
		t.Errorf("edge = %+v", e)
	}
	res := graph.Reach(g, "members:acme-actions", graph.Options{})
	if !slices.Contains(res.Possible.Repos, "repo:acme-app/web") {
		t.Errorf("possible repos = %v, want acme-app/web", res.Possible.Repos)
	}
	if len(res.Confirmed.Repos) != 0 {
		t.Errorf("confirmed repos = %v, want none", res.Confirmed.Repos)
	}
}
