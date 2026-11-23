package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
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
				graph.AttrIPAllowList: "on", graph.AttrIPAllowEntries: "3", graph.AttrMembers: "1"},
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
		if e.Evidence != graph.Live || e.SourceAPI != srcDefaultPerm {
			t.Errorf("CAN_PUSH evidence/source = %q/%q", e.Evidence, e.SourceAPI)
		}
		if e.Attrs[graph.AttrVia] != graph.ViaDefaultPerm || e.Attrs[graph.AttrTwoFactor] != "not_required" || e.Attrs[graph.AttrSSO] != "configured" {
			t.Errorf("CAN_PUSH attrs = %v", e.Attrs)
		}
		ix.mustEdge(t, "members:acme-legacy", "repo:acme-legacy/old-site", graph.CanPush)
		ix.noEdge(t, "members:acme-app", "repo:acme-app/web", graph.CanPush)
		ix.noEdge(t, "members:acme-secure", "repo:acme-secure/vault-proxy", graph.CanPush)
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
		e.Evidence != graph.Live || e.SourceAPI != srcLicenses {
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
