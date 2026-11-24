package collect

import (
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
