package collect

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestAppInventory: planted case 1 (an AI review App on every repository of
// acme-app with contents and workflows write) becomes an App identity; an
// org the token does not own gets app_installations unknown with coverage.
func TestAppInventory(t *testing.T) {
	f := newFakeGitHub(t)
	ix := collectMode(t, f, false)
	app := ix.node(t, "identity:acme-ai-reviewer[bot]")
	wantAttrs(t, "app", app, map[string]string{
		graph.AttrAppID: "9001", graph.AttrAppSlug: "acme-ai-reviewer", graph.AttrAppOrgs: "acme-app",
		graph.AttrAppWrite: "contents,pull_requests,workflows", graph.AttrAppRepos: "all", graph.AttrAppAI: "name",
	})
	if app.AttrEvidence[graph.AttrAppWrite] == graph.NotVisible {
		t.Error("app_write is not_visible, want live")
	}
	wantAttrs(t, "acme-app", ix.node(t, "org:acme-app"), map[string]string{graph.AttrAppInstallations: "1"})
	legacy := ix.node(t, "org:acme-legacy")
	if legacy.Attrs[graph.AttrAppInstallations] != "unknown" || legacy.AttrEvidence[graph.AttrAppInstallations] != graph.NotVisible {
		t.Errorf("acme-legacy app_installations = %q (%s)", legacy.Attrs[graph.AttrAppInstallations], legacy.AttrEvidence[graph.AttrAppInstallations])
	}
	found := false
	for _, c := range ix.g.Coverage {
		if c.Scope == "org:acme-legacy" && c.Fact == graph.FactAppInstallations {
			found = true
		}
	}
	if !found {
		t.Error("no app_installations coverage entry for acme-legacy")
	}
}

// TestAppInventoryMerge: one App installed in two orgs is one identity with
// the union of its write permissions; all repositories in any org wins.
func TestAppInventoryMerge(t *testing.T) {
	f := newFakeGitHub(t)
	f.installs["acme-actions"] = []map[string]any{{"id": 502, "app_id": 9001, "app_slug": "acme-ai-reviewer", "repository_selection": "selected",
		"permissions": map[string]any{"issues": "write", "contents": "read"}}}
	f.installs["acme-app"] = append(f.installs["acme-app"], map[string]any{"id": 503, "app_id": 42, "app_slug": "acme-deploy", "repository_selection": "selected",
		"permissions": map[string]any{"metadata": "read"}})
	ix := collectMode(t, f, false)
	wantAttrs(t, "merged", ix.node(t, "identity:acme-ai-reviewer[bot]"), map[string]string{
		graph.AttrAppOrgs: "acme-actions,acme-app", graph.AttrAppWrite: "contents,issues,pull_requests,workflows", graph.AttrAppRepos: "all",
	})
	deploy := ix.node(t, "identity:acme-deploy[bot]")
	wantAttrs(t, "read-only", deploy, map[string]string{graph.AttrAppWrite: "none", graph.AttrAppRepos: "selected"})
	if _, ok := deploy.Attrs[graph.AttrAppAI]; ok {
		t.Error("acme-deploy is not an AI name")
	}
}

// TestAppInventoryForbidden: an owner token the endpoint refuses (a missing
// scope) gives unknown with the documented access in the fix.
func TestAppInventoryForbidden(t *testing.T) {
	f := newFakeGitHub(t)
	f.installsDenied["acme-app"] = true
	ix := collectMode(t, f, false)
	org := ix.node(t, "org:acme-app")
	if org.Attrs[graph.AttrAppInstallations] != "unknown" {
		t.Errorf("app_installations = %q", org.Attrs[graph.AttrAppInstallations])
	}
	for _, c := range ix.g.Coverage {
		if c.Scope == "org:acme-app" && c.Fact == graph.FactAppInstallations && c.NeedsFix == appInstallFix {
			return
		}
	}
	t.Error("no coverage entry naming the access")
}

func TestAppNamesAI(t *testing.T) {
	for slug, want := range map[string]bool{"claude": true, "copilot-swe-agent": true, "acme-ai-reviewer": true,
		"renovate": false, "dependabot": false, "acme-deploy": false} {
		if got := graph.AppNamesAI(slug); got != want {
			t.Errorf("AppNamesAI(%q) = %v", slug, got)
		}
	}
}

// reposOf lists the collected repo node IDs of an org.
func reposOf(ix *index, org string) []string {
	var out []string
	for _, n := range ix.g.Nodes {
		if n.Kind == graph.KindRepo && n.Attrs["org"] == org && n.Attrs[attrCollected] != "false" {
			out = append(out, n.ID)
		}
	}
	return out
}

// TestAppPushAll: an App installed on all repositories of acme-app with
// contents: write pushes to every repo of the org (inferred, rule
// app_install), with workflows: write noted, and to no repo of another org.
func TestAppPushAll(t *testing.T) {
	f := newFakeGitHub(t)
	ix := collectMode(t, f, false)
	app := "identity:acme-ai-reviewer[bot]"
	repos := reposOf(ix, "acme-app")
	if len(repos) == 0 {
		t.Fatal("no acme-app repos")
	}
	for _, r := range repos {
		e := ix.mustEdge(t, app, r, graph.CanPush)
		if e.Evidence != graph.Inferred || e.SourceAPI != srcAppInstallations {
			t.Errorf("%s: evidence %s source %s, want inferred from installations", r, e.Evidence, e.SourceAPI)
		}
		wantEdgeAttrs(t, r, e, map[string]string{graph.AttrVia: graph.ViaAppInstall, graph.AttrRule: graph.RuleAppInstall,
			graph.AttrAppRepos: "all", graph.AttrAppWorkflows: "write", attrPermission: "write"})
	}
	for _, r := range reposOf(ix, "acme-actions") {
		ix.noEdge(t, app, r, graph.CanPush)
	}
	if _, ok := hasCoverage(ix.g, "org:acme-app", graph.FactAppPush); ok {
		t.Error("coverage for an all-repositories installation")
	}
}

// TestAppPushSelected: an installation on selected repositories cannot be
// resolved with an org token: every repo of the org gets a not_visible edge
// with a reason (possible reach only) and the org gets one coverage entry.
// An App with contents: read gets no edges.
func TestAppPushSelected(t *testing.T) {
	f := newFakeGitHub(t)
	f.installs["acme-actions"] = []map[string]any{
		{"id": 601, "app_id": 77, "app_slug": "acme-deploy", "repository_selection": "selected",
			"permissions": map[string]any{"contents": "write", "metadata": "read"}},
		{"id": 602, "app_id": 78, "app_slug": "acme-reader", "repository_selection": "all",
			"permissions": map[string]any{"contents": "read", "issues": "write"}},
	}
	ix := collectMode(t, f, false)
	repos := reposOf(ix, "acme-actions")
	if len(repos) == 0 {
		t.Fatal("no acme-actions repos")
	}
	for _, r := range repos {
		e := ix.mustEdge(t, "identity:acme-deploy[bot]", r, graph.CanPush)
		if e.Evidence != graph.NotVisible {
			t.Errorf("%s: evidence %s, want not_visible", r, e.Evidence)
		}
		if e.Attrs[graph.AttrRule] != "" || e.Attrs[graph.AttrAppWorkflows] != "" || e.Attrs[graph.AttrReason] == "" {
			t.Errorf("%s: attrs %v", r, e.Attrs)
		}
		wantEdgeAttrs(t, r, e, map[string]string{graph.AttrVia: graph.ViaAppInstall, graph.AttrAppRepos: "selected"})
		ix.noEdge(t, "identity:acme-reader[bot]", r, graph.CanPush)
	}
	c, ok := hasCoverage(ix.g, "org:acme-actions", graph.FactAppPush)
	if !ok || !strings.Contains(c.Reason, "acme-deploy") || c.NeedsFix != appSelectedFix {
		t.Errorf("coverage = %+v, %v", c, ok)
	}
	// Possible, never confirmed: the App reaches acme-actions repos only as possible.
	gi := graph.NewIndex(ix.g)
	r := gi.Reach("identity:acme-deploy[bot]", graph.Options{})
	if len(r.Confirmed.Repos) != 0 || len(r.Possible.Repos) == 0 {
		t.Errorf("reach confirmed %v possible %v", r.Confirmed.Repos, r.Possible.Repos)
	}
}

func wantEdgeAttrs(t *testing.T, name string, e graph.Edge, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if e.Attrs[k] != v {
			t.Errorf("%s: %s = %q, want %q", name, k, e.Attrs[k], v)
		}
	}
}
