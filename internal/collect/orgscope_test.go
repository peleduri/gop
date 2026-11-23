package collect

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

// collectNoEnterprise runs Collect against a fake whose token cannot read the enterprise.
func collectNoEnterprise(t *testing.T, setup func(f *fakeGitHub), orgs ...string) (*fakeGitHub, *index) {
	t.Helper()
	f := newFakeGitHub(t)
	f.enterpriseForbidden = true
	if setup != nil {
		setup(f)
	}
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Orgs: orgs, Client: f.client(t)})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return f, newIndex(g)
}

func TestCollectWithoutEnterprise(t *testing.T) {
	f, ix := collectNoEnterprise(t, nil, "acme-actions", "acme-app")
	g := ix.g

	t.Run("org nodes from --orgs and enterprise coverage", func(t *testing.T) {
		var orgs []string
		for _, n := range g.Nodes {
			if n.Kind == graph.KindOrg {
				orgs = append(orgs, n.ID)
			}
		}
		if !slices.Equal(orgs, []string{"org:acme-actions", "org:acme-app"}) {
			t.Errorf("orgs = %v", orgs)
		}
		c, ok := hasCoverage(g, "enterprise:acme", "enterprise")
		if !ok {
			t.Fatalf("missing enterprise:acme / enterprise coverage: %+v", g.Coverage)
		}
		if !strings.HasPrefix(c.Reason, "token cannot read enterprise acme") || c.NeedsFix != "enterprise owner token with read:enterprise" {
			t.Errorf("enterprise coverage = %+v", c)
		}
		ent := ix.node(t, "enterprise:acme")
		if ent.Attrs["orgs"] != "unknown" || ent.AttrEvidence["orgs"] != graph.NotVisible {
			t.Errorf("enterprise orgs = %q (%q), want unknown/not_visible", ent.Attrs["orgs"], ent.AttrEvidence["orgs"])
		}
		app := ix.node(t, "org:acme-app")
		if app.Attrs["in_enterprise_source"] != "config" || app.Attrs["source"] != "config:--orgs" {
			t.Errorf("acme-app source attrs = %v", app.Attrs)
		}
		if got := f.hitCount("/orgs/acme-app"); got != 1 {
			t.Errorf("GET /orgs/acme-app requested %d times, want 1", got)
		}
		for _, c := range g.Coverage {
			if c.Fact == "ownerInfo" || strings.Contains(c.Scope, "org:acme-legacy") {
				t.Errorf("unexpected coverage %+v", c)
			}
		}
	})

	t.Run("settings: sso not_visible, default_perm live from GET /orgs", func(t *testing.T) {
		app := ix.node(t, "org:acme-app")
		if app.Attrs[graph.AttrSSO] != "unknown" || app.AttrEvidence[graph.AttrSSO] != graph.NotVisible {
			t.Errorf("acme-app sso = %q (%q), want unknown/not_visible", app.Attrs[graph.AttrSSO], app.AttrEvidence[graph.AttrSSO])
		}
		want := map[string]string{graph.AttrDefaultPerm: "read", graph.AttrTwoFactor: "required",
			graph.AttrMembersCreate: "false", graph.AttrPrivateForks: "false"}
		for k, v := range want {
			if app.Attrs[k] != v || app.AttrEvidence[k] != "" {
				t.Errorf("acme-app %s = %q (%q), want %q live", k, app.Attrs[k], app.AttrEvidence[k], v)
			}
		}
		for _, k := range []string{graph.AttrChangeVisiblity, graph.AttrDeleteRepos} {
			if app.Attrs[k] != "unknown" || app.AttrEvidence[k] != graph.NotVisible {
				t.Errorf("acme-app %s = %q (%q), want unknown/not_visible", k, app.Attrs[k], app.AttrEvidence[k])
			}
		}
		if act := ix.node(t, "org:acme-actions"); act.Attrs[graph.AttrMembersCreate] != "true" {
			t.Errorf("acme-actions members_create = %q, want true", act.Attrs[graph.AttrMembersCreate])
		}
		// One coverage entry per setting at enterprise scope, none per org.
		for _, spec := range settingSpecs {
			if _, ok := hasCoverage(g, "enterprise:acme", spec.attr); !ok {
				t.Errorf("missing enterprise coverage for %s", spec.attr)
			}
			if _, ok := hasCoverage(g, "org:acme-app", spec.attr); ok {
				t.Errorf("per-org coverage for %s, want enterprise scope only", spec.attr)
			}
		}
	})

	t.Run("members from the org members API", func(t *testing.T) {
		app := ix.node(t, "org:acme-app")
		if app.Attrs[graph.AttrMembers] != "3" || app.AttrEvidence[graph.AttrMembers] != "" {
			t.Errorf("acme-app members = %q (%q), want 3 live", app.Attrs[graph.AttrMembers], app.AttrEvidence[graph.AttrMembers])
		}
		if app.Attrs["owners"] != "1" {
			t.Errorf("acme-app owners = %q, want 1", app.Attrs["owners"])
		}
		m := ix.mustEdge(t, "identity:alice", "org:acme-app", graph.MemberOf)
		if m.Attrs["role"] != "owner" || m.SourceAPI != srcOrgAdmins {
			t.Errorf("alice MEMBER_OF = %+v", m)
		}
		d := ix.mustEdge(t, "identity:dave", "org:acme-app", graph.MemberOf)
		if d.Attrs["role"] != "member" || d.SourceAPI != srcOrgMembers {
			t.Errorf("dave MEMBER_OF = %+v", d)
		}
		ix.mustEdge(t, "identity:alice", "repo:acme-app/web", graph.CanPush) // owner push from the admin list
		if _, ok := hasCoverage(g, "enterprise:acme", graph.AttrMembers); !ok {
			t.Error("missing consumed-licenses coverage")
		}
	})

	t.Run("planted cross-org path still exists", func(t *testing.T) {
		e := ix.mustEdge(t, "members:acme-actions", "repo:acme-actions/deploy", graph.CanPush)
		if e.Evidence != graph.Inferred || e.SourceAPI != srcOrgREST || e.Attrs[graph.AttrVia] != graph.ViaDefaultPerm {
			t.Errorf("CAN_PUSH = %+v", e)
		}
		r := ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
		if r.SourceAPI != "derived:workflow.uses+config:--orgs" {
			t.Errorf("RESOLVES_TO source = %q", r.SourceAPI)
		}
		ix.mustEdge(t, "workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main", graph.Uses)
		if v := ix.node(t, "action:acme-actions/deploy@main").Attrs["in_enterprise"]; v != "true" {
			t.Errorf("deploy@main in_enterprise = %q, want true", v)
		}
		ix.noEdge(t, "members:acme-app", "repo:acme-app/web", graph.CanPush) // read default

		eng := graph.NewIndex(g)
		res := eng.Reach("members:acme-actions", graph.Options{})
		if !slices.Contains(res.Confirmed.Repos, "repo:acme-app/web") {
			t.Errorf("members:acme-actions should reach repo:acme-app/web, confirmed = %v", res.Confirmed.Repos)
		}
	})

	t.Run("owners outside --orgs are unknown, not outside", func(t *testing.T) {
		for _, id := range []string{"action:actions/checkout@v4"} {
			n := ix.node(t, id)
			if n.Attrs["in_enterprise"] != "unknown" || n.AttrEvidence["in_enterprise"] != graph.NotVisible {
				t.Errorf("%s in_enterprise = %q (%q), want unknown/not_visible", id, n.Attrs["in_enterprise"], n.AttrEvidence["in_enterprise"])
			}
		}
		ix.noEdge(t, "action:actions/checkout@v4", "repo:actions/checkout", graph.ResolvesTo)
		if f.hitCount("/orgs/actions") != 0 || f.hitCount("/orgs/acme-legacy") != 0 {
			t.Error("collector looked up action owners outside --orgs")
		}
	})

	t.Run("graph validates against the JSON Schema", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteGraph(&buf, g); err != nil {
			t.Fatal(err)
		}
		res, err := schema.Validate(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !res.Valid {
			t.Fatalf("graph does not validate: %v", res.Errors)
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
	})
}

func TestUnknownOwnerCoverage(t *testing.T) {
	_, ix := collectNoEnterprise(t, func(f *fakeGitHub) {
		f.extraWorkflows["acme-app/web/other.yml"] = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme-other/tool@main\n"
	}, "acme-actions", "acme-app")

	n := ix.node(t, "action:acme-other/tool@main")
	if n.Attrs["in_enterprise"] != "unknown" || n.AttrEvidence["in_enterprise"] != graph.NotVisible {
		t.Errorf("acme-other/tool in_enterprise = %q (%q), want unknown/not_visible", n.Attrs["in_enterprise"], n.AttrEvidence["in_enterprise"])
	}
	ix.mustEdge(t, "workflow:acme-app/web/.github/workflows/other.yml", "action:acme-other/tool@main", graph.Uses)
	ix.noEdge(t, "action:acme-other/tool@main", "repo:acme-other/tool", graph.ResolvesTo)

	var entries []graph.Coverage
	for _, c := range ix.g.Coverage {
		if c.Fact == "in_enterprise" {
			entries = append(entries, c)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("in_enterprise coverage entries = %+v, want one aggregated entry", entries)
	}
	c := entries[0]
	if c.Scope != "enterprise:acme" || !strings.Contains(c.Reason, "acme-other") ||
		!strings.Contains(c.Reason, "actions") || !strings.Contains(c.NeedsFix, "--orgs") {
		t.Errorf("aggregated coverage = %+v", c)
	}
}

func TestUnknownOwnerCoverageCap(t *testing.T) {
	k := &collector{enterprise: "acme", covSeen: map[string]bool{}}
	for i := 0; i < maxListedOwners+5; i++ {
		an := &graph.Node{Attrs: map[string]string{}, Evidence: graph.Live}
		k.markUnknownOwner(an, "owner-"+string(rune('a'+i)))
	}
	k.markUnknownOwner(&graph.Node{Attrs: map[string]string{}, Evidence: graph.Live}, "OWNER-A") // case-insensitive duplicate
	k.coverUnknownOwners()
	if len(k.coverage) != 1 {
		t.Fatalf("coverage = %+v", k.coverage)
	}
	r := k.coverage[0].Reason
	if !strings.Contains(r, "25 action owners") || !strings.Contains(r, "(+5 more)") || strings.Contains(r, "owner-y") {
		t.Errorf("reason = %q", r)
	}
}

func TestCollectDiscoversInstallationOrgs(t *testing.T) {
	f, ix := collectNoEnterprise(t, func(f *fakeGitHub) { f.installation = true })
	if f.hitCount("/installation/repositories?per_page=100") != 1 {
		t.Error("installation repositories not requested")
	}
	for _, id := range []string{"org:acme-actions", "org:acme-app", "org:acme-legacy", "org:acme-secure"} {
		n := ix.node(t, id)
		if n.Attrs["in_enterprise_source"] != "installation" || n.Attrs["source"] != srcInstallRepos {
			t.Errorf("%s source attrs = %v", id, n.Attrs)
		}
	}
	if _, ok := ix.nodes["org:acme-archive"]; ok {
		t.Error("org without installation repositories should not be discovered")
	}
	// Discovered orgs resolve cross-org references like --orgs does.
	ix.mustEdge(t, "action:acme-actions/deploy@main", "repo:acme-actions/deploy", graph.ResolvesTo)
	ix.mustEdge(t, "members:acme-actions", "repo:acme-actions/deploy", graph.CanPush)
}

func TestCollectDiscoversUserOrgs(t *testing.T) {
	_, ix := collectNoEnterprise(t, nil)
	n := ix.node(t, "org:acme-archive")
	if n.Attrs[graph.AttrArchived] != "true" || n.Attrs["source"] != srcUserOrgs {
		t.Errorf("acme-archive = %v", n.Attrs)
	}
	legacy := ix.node(t, "org:acme-legacy")
	if legacy.Attrs[graph.AttrDefaultPerm] != "unknown" || legacy.AttrEvidence[graph.AttrDefaultPerm] != graph.NotVisible {
		t.Errorf("acme-legacy default_perm = %q (%q), want unknown/not_visible", legacy.Attrs[graph.AttrDefaultPerm], legacy.AttrEvidence[graph.AttrDefaultPerm])
	}
	// No default-permission edge when GET /orgs did not return the permission.
	ix.noEdge(t, "members:acme-legacy", "repo:acme-legacy/old-site", graph.CanPush)
}

func TestCollectWithoutEnterpriseNoOrgs(t *testing.T) {
	f := newFakeGitHub(t)
	f.enterpriseForbidden = true
	f.noUserOrgs = true
	_, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
	if err == nil || !strings.Contains(err.Error(), "--orgs") {
		t.Fatalf("err = %v, want a hint to pass --orgs", err)
	}
}
