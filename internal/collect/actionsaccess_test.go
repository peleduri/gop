package collect

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// actionsAccess serves /repos/{o}/{r}/actions/permissions/access from the
// repo's actions_access (GitHub's default "none" when absent). It needs repo
// admin: repos flagged actions_access_forbidden and repos in orgs the token
// does not own answer 403; unknown repos 404.
func (f *fakeGitHub) actionsAccess(w http.ResponseWriter, full string) {
	owner, name, _ := strings.Cut(full, "/")
	for _, o := range f.fx.Orgs {
		if o.Login != owner {
			continue
		}
		for _, raw := range o.Repos {
			var m struct {
				Name      string `json:"name"`
				Level     string `json:"actions_access"`
				Forbidden bool   `json:"actions_access_forbidden"`
			}
			_ = json.Unmarshal(raw, &m)
			if m.Name != name {
				continue
			}
			if m.Forbidden || !o.Owner {
				writeJSON(w, http.StatusForbidden, map[string]string{"message": "Must have admin rights to Repository."})
				return
			}
			if m.Level == "" {
				m.Level = "none"
			}
			writeJSON(w, http.StatusOK, map[string]string{"access_level": m.Level})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
}

// setRepoField sets one field of a fixture repo before collecting.
func (f *fakeGitHub) setRepoField(t *testing.T, org, repo, key string, val any) {
	t.Helper()
	for i, o := range f.fx.Orgs {
		if o.Login != org {
			continue
		}
		for j, rr := range o.Repos {
			var m map[string]any
			if err := json.Unmarshal(rr, &m); err != nil {
				t.Fatal(err)
			}
			if m["name"] != repo {
				continue
			}
			m[key] = val
			f.fx.Orgs[i].Repos[j] = raw(t, m)
			return
		}
	}
	t.Fatalf("no fixture repo %s/%s", org, repo)
}

const (
	setupRepo     = "repo:acme-actions/setup"
	accessPath    = "/repos/acme-actions/setup/actions/permissions/access"
	setupAction   = "action:acme-actions/setup@main"
	setupBuild    = "workflow:acme-actions/setup/.github/workflows/build.yml"
	searchIdx     = "workflow:acme-app/search/.github/workflows/index.yaml"
	docsBuild     = "workflow:acme-app/docs/.github/workflows/build.yml"
	billingDeploy = "workflow:acme-app/billing/.github/workflows/deploy.yml"
)

// reachesVia reports whether the path to id runs through hop from -> to.
func reachesVia(r graph.Result, id, from, to string) bool {
	p, ok := r.Paths[id]
	return ok && usesHop(p, from, to)
}

func TestActionsAccess(t *testing.T) {
	t.Run("fixture levels", func(t *testing.T) {
		f, ix := collectAcme(t)
		for id, want := range map[string]string{deployRepo: "enterprise", setupRepo: "organization"} {
			n := ix.node(t, id)
			if n.Attrs[graph.AttrActionsAccess] != want || n.AttrEvidence[graph.AttrActionsAccess] != "" || n.Evidence != graph.Live {
				t.Errorf("%s actions_access = %q (%q), want %q live", id, n.Attrs[graph.AttrActionsAccess], n.AttrEvidence[graph.AttrActionsAccess], want)
			}
		}
		// One request per host repo, whatever the number of refs into it.
		if got := f.hitCount("/repos/acme-actions/deploy/actions/permissions/access"); got != 1 {
			t.Errorf("deploy access read %d times, want 1", got)
		}
		// Only host repos are read.
		if got := f.hitCount("/repos/acme-app/web/actions/permissions/access"); got != 0 {
			t.Errorf("acme-app/web hosts no action but its access was read %d times", got)
		}
		// hidden-tool is not visible (acme-legacy is not owned): unknown + coverage.
		hidden := ix.node(t, "repo:acme-legacy/hidden-tool")
		if hidden.Attrs[graph.AttrActionsAccess] != "unknown" || hidden.AttrEvidence[graph.AttrActionsAccess] != graph.NotVisible {
			t.Errorf("hidden-tool actions_access = %q (%q)", hidden.Attrs[graph.AttrActionsAccess], hidden.AttrEvidence[graph.AttrActionsAccess])
		}
		if c, ok := hasCoverage(ix.g, "repo:acme-legacy/hidden-tool", graph.AttrActionsAccess); !ok || c.NeedsFix != "admin on acme-legacy/hidden-tool (or org owner)" {
			t.Errorf("hidden-tool coverage = %+v, %v", c, ok)
		}
		// consumer_org on USES edges into enterprise actions.
		for _, c := range []struct{ from, to, org string }{
			{webCI, deployMain, "acme-app"},
			{searchIdx, setupAction, "acme-app"},
			{setupBuild, deployMain, "acme-actions"},
			{deployMain, setupAction, "acme-actions"},
			{setupAction, "action:acme-actions/deploy@0123456789abcdef0123456789abcdef01234567", "acme-actions"},
			{"workflow:acme-secure/vault-proxy/.github/workflows/ci.yml", "action:acme-legacy/hidden-tool@v2", "acme-secure"},
		} {
			if e := ix.mustEdge(t, c.from, c.to, graph.Uses); e.Attrs[graph.AttrConsumerOrg] != c.org {
				t.Errorf("%s -> %s consumer_org = %q, want %q", c.from, c.to, e.Attrs[graph.AttrConsumerOrg], c.org)
			}
		}
		if e := ix.mustEdge(t, setupAction, "action:actions/checkout@v4", graph.Uses); e.Attrs[graph.AttrConsumerOrg] != "" {
			t.Errorf("USES into an action outside the enterprise has consumer_org %q", e.Attrs[graph.AttrConsumerOrg])
		}
	})

	t.Run("engine", func(t *testing.T) {
		_, ix := collectAcme(t)
		r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
		// setup is organization: the acme-app and acme-legacy workflows that
		// use setup (or its reusable workflow) are no longer reached at all.
		for _, w := range []string{searchIdx, docsBuild, "workflow:acme-legacy/old-site/.github/workflows/ci.yml"} {
			if _, ok := r.Paths[w]; ok {
				t.Errorf("%s reached: %+v", w, r.Paths[w].Hops)
			}
		}
		if slices.Contains(r.Confirmed.OIDC, "oidc:acme-app/search") || slices.Contains(r.Possible.OIDC, "oidc:acme-app/search") {
			t.Error("oidc:acme-app/search reached through setup")
		}
		// acme-actions consumers of setup still get it: from setup's repo, the
		// composite action deploy@main (same org) is controlled through
		// setup@main, and with it deploy's acme-app consumers.
		rs := graph.Reach(ix.g, setupRepo, graph.Options{})
		if p := rs.Paths[deployMain]; p.Unverified || !usesHop(p, setupAction, deployMain) {
			t.Errorf("path to %s = %+v, want confirmed through %s", deployMain, p.Hops, setupAction)
		}
		if !slices.Contains(rs.Confirmed.Workflows, billingDeploy) {
			t.Errorf("%s not confirmed from %s", billingDeploy, setupRepo)
		}
		// deploy is enterprise: the planted cross-org path is unchanged.
		if !slices.Contains(r.Confirmed.OIDC, "oidc:acme-app/billing") || !reachesVia(r, billingDeploy, deployMain, billingDeploy) {
			t.Errorf("planted path through %s changed: %+v", deployMain, r.Paths[billingDeploy].Hops)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.setRepoField(t, "acme-actions", "deploy", "actions_access_forbidden", true)
		ix := collectFake(t, f)
		n := ix.node(t, deployRepo)
		if n.Attrs[graph.AttrActionsAccess] != "unknown" || n.AttrEvidence[graph.AttrActionsAccess] != graph.NotVisible {
			t.Errorf("deploy actions_access = %q (%q)", n.Attrs[graph.AttrActionsAccess], n.AttrEvidence[graph.AttrActionsAccess])
		}
		c, ok := hasCoverage(ix.g, deployRepo, graph.AttrActionsAccess)
		if !ok || c.NeedsFix != "admin on acme-actions/deploy (or org owner)" || !strings.Contains(c.Reason, "403") {
			t.Errorf("coverage = %+v, %v", c, ok)
		}
		// Cross-org paths through deploy move from confirmed to possible.
		r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
		if slices.Contains(r.Confirmed.OIDC, "oidc:acme-app/billing") || !slices.Contains(r.Possible.OIDC, "oidc:acme-app/billing") {
			t.Errorf("oidc:acme-app/billing confirmed=%v possible=%v, want possible only", r.Confirmed.OIDC, r.Possible.OIDC)
		}
		if p := r.Paths[billingDeploy]; !p.Unverified || !usesHop(p, deployMain, billingDeploy) {
			t.Errorf("path to %s = %+v, want unverified through %s", billingDeploy, p, deployMain)
		}
		// Same-org uses of deploy stay confirmed.
		if p := graph.Reach(ix.g, deployRepo, graph.Options{}).Paths[setupBuild]; p.Unverified || !usesHop(p, deployMain, setupBuild) {
			t.Errorf("path to %s = %+v, want confirmed through %s", setupBuild, p.Hops, deployMain)
		}
	})

	t.Run("public and unrecognized", func(t *testing.T) {
		f := newFakeGitHub(t)
		f.setRepoField(t, "acme-actions", "deploy", "visibility", "public")
		f.setRepoField(t, "acme-actions", "setup", "actions_access", "galaxy")
		ix := collectFake(t, f)
		if got := ix.node(t, deployRepo).Attrs[graph.AttrActionsAccess]; got != "public" {
			t.Errorf("public deploy actions_access = %q", got)
		}
		if got := f.hitCount("/repos/acme-actions/deploy/actions/permissions/access"); got != 0 {
			t.Errorf("public repo access read %d times, want 0", got)
		}
		n := ix.node(t, setupRepo)
		if n.Attrs[graph.AttrActionsAccess] != "unknown" || n.AttrEvidence[graph.AttrActionsAccess] != graph.NotVisible {
			t.Errorf("setup actions_access = %q (%q)", n.Attrs[graph.AttrActionsAccess], n.AttrEvidence[graph.AttrActionsAccess])
		}
		if c, ok := hasCoverage(ix.g, setupRepo, graph.AttrActionsAccess); !ok || !strings.Contains(c.Reason, `"galaxy"`) {
			t.Errorf("setup coverage = %+v, %v", c, ok)
		}
	})
}
