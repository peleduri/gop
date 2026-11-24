package collect

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

// collectMode runs Collect against f with GraphQL batching on or off and
// checks the graph validates cleanly.
func collectMode(t *testing.T, f *fakeGitHub, rest bool) *index {
	t.Helper()
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), DisableGraphQLBatch: rest})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteGraph(&buf, g); err != nil {
		t.Fatal(err)
	}
	r, err := schema.Validate(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid || len(r.Warnings) > 0 {
		t.Fatalf("graph does not validate cleanly: errors %v warnings %v", r.Errors, r.Warnings)
	}
	return newIndex(g)
}

func classic(reviews int, codeOwner, dismiss, enforceAdmins, force, signed bool, checks []string, users, apps []string) map[string]any {
	us := []any{}
	for _, u := range users {
		us = append(us, map[string]any{"login": u})
	}
	as := []any{}
	for _, a := range apps {
		as = append(as, map[string]any{"slug": a})
	}
	return map[string]any{
		"required_status_checks": map[string]any{"contexts": checks, "checks": []any{}},
		"enforce_admins":         map[string]any{"enabled": enforceAdmins},
		"required_pull_request_reviews": map[string]any{
			"required_approving_review_count": reviews, "require_code_owner_reviews": codeOwner,
			"dismiss_stale_reviews": dismiss, "require_last_push_approval": false,
			"bypass_pull_request_allowances": map[string]any{"users": us, "teams": []any{}, "apps": as},
		},
		"required_signatures": map[string]any{"enabled": signed},
		"allow_force_pushes":  map[string]any{"enabled": force},
	}
}

func ruleset(id int, actors ...map[string]any) map[string]any {
	if actors == nil {
		actors = []map[string]any{}
	}
	return map[string]any{"id": id, "target": "branch", "enforcement": "active", "bypass_actors": actors}
}

func actor(typ string, id int) map[string]any {
	return map[string]any{"actor_id": id, "actor_type": typ, "bypass_mode": "always"}
}

func typedRule(typ string, id int, src string) map[string]any {
	return map[string]any{"type": typ, "ruleset_id": id, "ruleset_source_type": src, "parameters": map[string]any{}}
}

func wantAttrs(t *testing.T, mode string, n graph.Node, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := n.Attrs[k]; got != v {
			t.Errorf("%s: %s %s = %q, want %q", mode, n.ID, k, got, v)
		}
	}
}

// Both the batched GraphQL path and the REST fallback build the same
// effective default-branch protection.
func TestDefaultBranchProtection(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *fakeGitHub)
		want  map[string]string
	}{
		{"classic only", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = nil
			f.protection["acme-actions/deploy@main"] = raw(t, classic(2, true, true, true, false, true, []string{"build"}, []string{"alice"}, []string{"ci-bot"}))
		}, map[string]string{
			graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "2", graph.AttrBranchCodeOwnerReview: "true",
			graph.AttrBranchDismissStale: "true", graph.AttrBranchLastPush: "false", graph.AttrBranchSignedCommits: "true",
			graph.AttrBranchForcePush: "false", graph.AttrBranchStatusChecks: "1", graph.AttrBranchAdminBypass: "false",
			graph.AttrBranchAppBypass: "true", graph.AttrBranchBypassActors: "2", graph.AttrBranchSources: "classic",
			graph.AttrBranchValueSources: "required_reviews=classic,require_code_owner_review=classic,dismiss_stale_reviews=classic," +
				"require_signed_commits=classic,required_status_checks=classic,allow_force_push=classic,admin_bypass=classic,app_bypass=classic",
		}},
		{"repo and org rulesets with bypass actors", func(t *testing.T, f *fakeGitHub) {
			pr := prRule(7, 1, true, false)
			pr["ruleset_source_type"] = "Repository"
			f.rules["acme-actions/deploy@main"] = raws(t, pr, typedRule("non_fast_forward", 9, "Organization"))
			f.rulesets["acme-actions/deploy#9"] = raw(t, ruleset(9, actor("OrganizationAdmin", 1), actor("Integration", 77)))
		}, map[string]string{
			graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "1", graph.AttrBranchDismissStale: "true",
			graph.AttrBranchForcePush: "false", graph.AttrBranchAdminBypass: "false", graph.AttrBranchAppBypass: "false",
			graph.AttrBranchBypassActors: "3", graph.AttrBranchSources: "ruleset:7,ruleset:9",
			graph.AttrBranchValueSources: "required_reviews=ruleset:7,dismiss_stale_reviews=ruleset:7,allow_force_push=ruleset:9," +
				"admin_bypass=ruleset:7,app_bypass=ruleset:7",
		}},
		{"rulesets that admins and an app bypass", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, typedRule("required_signatures", 9, "Organization"))
			f.rulesets["acme-actions/deploy#9"] = raw(t, ruleset(9, actor("RepositoryRole", 5), actor("Integration", 77)))
		}, map[string]string{
			graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "0", graph.AttrBranchSignedCommits: "true",
			graph.AttrBranchForcePush: "true", graph.AttrBranchAdminBypass: "true", graph.AttrBranchAppBypass: "true",
			graph.AttrBranchBypassActors: "2", graph.AttrBranchSources: "ruleset:9",
		}},
		{"classic and rulesets merged", func(t *testing.T, f *fakeGitHub) {
			pr := prRule(7, 2, false, true)
			f.rules["acme-actions/deploy@main"] = raws(t, pr)
			f.rulesets["acme-actions/deploy#7"] = raw(t, ruleset(7, actor("OrganizationAdmin", 1)))
			f.protection["acme-actions/deploy@main"] = raw(t, classic(1, false, false, false, false, false, nil, nil, nil))
		}, map[string]string{
			graph.AttrBranchProtected: "true", graph.AttrBranchReviews: "2", graph.AttrBranchLastPush: "true",
			graph.AttrBranchForcePush: "false", graph.AttrBranchAdminBypass: "true", graph.AttrBranchBypassActors: "1",
			graph.AttrBranchSources: "classic,ruleset:7",
			graph.AttrBranchValueSources: "required_reviews=ruleset:7,require_last_push_approval=ruleset:7," +
				"allow_force_push=classic,admin_bypass=classic+ruleset:7,app_bypass=classic+ruleset:7",
		}},
		{"no protection", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = nil
		}, map[string]string{
			graph.AttrBranchProtected: "false", graph.AttrBranchReviews: "0", graph.AttrBranchForcePush: "true",
			graph.AttrBranchSources: "none", graph.AttrBranchBypassActors: "0", graph.AttrBranchAdminBypass: "",
		}},
	}
	for _, tc := range cases {
		for _, rest := range []bool{false, true} {
			mode := tc.name + " (graphql)"
			if rest {
				mode = tc.name + " (rest)"
			}
			f := newFakeGitHub(t)
			tc.setup(t, f)
			ix := collectMode(t, f, rest)
			n := ix.node(t, deployRepo)
			wantAttrs(t, mode, n, tc.want)
			if attrEvidence(n, graph.AttrBranchProtected) != graph.Live {
				t.Errorf("%s: branch_protected evidence %q", mode, attrEvidence(n, graph.AttrBranchProtected))
			}
		}
	}
}

// Rules the token cannot read make protection unknown, with coverage that
// names the access needed; unknown never reads as unprotected.
func TestDefaultBranchProtectionForbidden(t *testing.T) {
	for _, rest := range []bool{false, true} {
		f := newFakeGitHub(t)
		f.forbidRule["acme-actions/deploy"] = true
		ix := collectMode(t, f, rest)
		n := ix.node(t, deployRepo)
		wantAttrs(t, "forbidden", n, map[string]string{graph.AttrBranchProtected: "unknown", graph.AttrBranchReviews: "unknown",
			graph.AttrBranchForcePush: "unknown"})
		if attrEvidence(n, graph.AttrBranchProtected) != graph.NotVisible {
			t.Errorf("rest=%v: evidence %q", rest, attrEvidence(n, graph.AttrBranchProtected))
		}
		c, ok := hasCoverage(ix.g, deployRepo, graph.FactBranchProtection)
		if !ok || !strings.Contains(c.Reason, "403") || c.NeedsFix != "read access to acme-actions/deploy" {
			t.Errorf("rest=%v: coverage %+v %v", rest, c, ok)
		}
	}
}

// A token that is not a repo admin sees classic protection only through its
// non-admin view: what only admins see is unknown, with one org coverage
// entry (GraphQL) or a repo entry (REST, where the rules are admin only).
func TestDefaultBranchProtectionNotAdmin(t *testing.T) {
	for _, rest := range []bool{false, true} {
		f := newFakeGitHub(t)
		f.fx.Orgs[0].Owner = false // acme-actions
		f.rules["acme-actions/deploy@main"] = nil
		f.protection["acme-actions/deploy@main"] = raw(t, classic(2, false, true, true, false, false, nil, nil, nil))
		g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t), DisableGraphQLBatch: rest})
		if err != nil {
			t.Fatal(err)
		}
		ix := newIndex(g)
		n := ix.node(t, deployRepo)
		want := map[string]string{graph.AttrBranchProtected: "true", graph.AttrBranchDismissStale: "unknown",
			graph.AttrBranchAdminBypass: "unknown", graph.AttrBranchBypassActors: "unknown"}
		scope := "org:acme-actions"
		if rest {
			want[graph.AttrBranchReviews] = "unknown"
			scope = deployRepo
		} else {
			want[graph.AttrBranchReviews] = "2"
			want[graph.AttrBranchForcePush] = "false"
		}
		wantAttrs(t, "not admin", n, want)
		if c, ok := hasCoverage(g, scope, graph.FactBranchProtection); !ok || !strings.Contains(c.NeedsFix, "admin on") {
			t.Errorf("rest=%v: coverage %+v %v", rest, c, ok)
		}
	}
}

// The batched path costs one GraphQL query per batch of repositories and no
// REST protection request for default branches; an unsupported query falls
// back to REST with the same result.
func TestDefaultBranchProtectionRequests(t *testing.T) {
	f := newFakeGitHub(t)
	f.protection["acme-actions/setup@main"] = raw(t, classic(1, false, true, true, false, false, nil, nil, nil))
	a := collectMode(t, f, false)
	if f.protQueries != 1 {
		t.Errorf("protection queries = %d, want 1", f.protQueries)
	}
	if n := f.hitCount("/repos/acme-actions/setup/branches/main/protection"); n != 1 {
		t.Errorf("classic protection requested %d times, want 1 (action ref protection only)", n)
	}
	g := newFakeGitHub(t)
	g.protection["acme-actions/setup@main"] = f.protection["acme-actions/setup@main"]
	g.protUnsupported = true
	b := collectMode(t, g, false)
	for _, id := range []string{deployRepo, "repo:acme-actions/setup"} {
		na, nb := a.node(t, id), b.node(t, id)
		for _, k := range protectionAttrs {
			if na.Attrs[k] != nb.Attrs[k] {
				t.Errorf("%s %s: batched %q, REST fallback %q", id, k, na.Attrs[k], nb.Attrs[k])
			}
		}
	}
}

func TestCodeowners(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  map[string]string
	}{
		{"missing", nil, map[string]string{graph.AttrCodeowners: "none", graph.AttrCodeownersWorkflows: "false", graph.AttrCodeownersValid: ""}},
		{"covers workflows", map[string]string{".github/CODEOWNERS": "* @acme-actions/platform\n/.github/workflows/ @acme-actions/release\n"},
			map[string]string{graph.AttrCodeowners: ".github/CODEOWNERS", graph.AttrCodeownersValid: "true", graph.AttrCodeownersWorkflows: "true"}},
		{"does not cover workflows", map[string]string{"docs/CODEOWNERS": "/src/ @alice\n"},
			map[string]string{graph.AttrCodeowners: "docs/CODEOWNERS", graph.AttrCodeownersValid: "true", graph.AttrCodeownersWorkflows: "false"}},
		{"first location wins", map[string]string{"CODEOWNERS": "* @bob\n", "docs/CODEOWNERS": "/src/ @alice\n"},
			map[string]string{graph.AttrCodeowners: "CODEOWNERS", graph.AttrCodeownersWorkflows: "true"}},
		{"invalid line", map[string]string{".github/CODEOWNERS": "!*.md @bob\n.github/ @acme-actions/platform\n"},
			map[string]string{graph.AttrCodeowners: ".github/CODEOWNERS", graph.AttrCodeownersValid: "false", graph.AttrCodeownersWorkflows: "true"}},
	}
	for _, tc := range cases {
		for _, rest := range []bool{false, true} {
			f := newFakeGitHub(t)
			for p, body := range tc.files {
				f.extraFiles["acme-actions/deploy/"+p] = body
			}
			ix := collectMode(t, f, rest)
			wantAttrs(t, tc.name, ix.node(t, deployRepo), tc.want)
		}
	}
}

func TestCodeownersUnreadable(t *testing.T) {
	f := newFakeGitHub(t)
	f.extraFiles["acme-actions/deploy/.github/CODEOWNERS"] = "* @bob\n"
	f.truncated["acme-actions/deploy/.github/CODEOWNERS"] = true
	ix := collectMode(t, f, false)
	n := ix.node(t, deployRepo)
	wantAttrs(t, "truncated", n, map[string]string{graph.AttrCodeowners: "unknown", graph.AttrCodeownersWorkflows: "unknown"})
	if _, ok := hasCoverage(ix.g, deployRepo, graph.FactCodeowners); !ok {
		t.Error("no codeowners coverage")
	}
}

func TestParseCodeowners(t *testing.T) {
	cases := []struct {
		text             string
		valid, workflows bool
	}{
		{"", true, false},
		{"# comment\n\n*       @acme-actions/platform # trailing\n", true, true},
		{"*.yml @alice\n", true, false}, // .yaml is not covered
		{"*.yml @alice\n*.yaml @alice\n", true, true},
		{".github/workflows/* @alice\n", true, true},
		{"/.github/ @alice\n", true, true},
		{"**/workflows/** @alice\n", true, true},
		{"workflows/ @alice\n", true, true},
		{"* @alice\n.github/workflows/\n", true, false}, // the last match has no owner
		{"* @alice\n/docs/ @bob\n", true, true},
		{"* not-an-owner\n", false, false},
		{"[ab].yml @alice\n* @bob\n", false, true},
		{"* alice@acme.example\n", true, true},
	}
	for _, tc := range cases {
		co := ParseCodeowners([]byte(tc.text))
		if co.Valid != tc.valid || co.Workflows != tc.workflows {
			t.Errorf("%q: valid=%v workflows=%v, want %v %v", tc.text, co.Valid, co.Workflows, tc.valid, tc.workflows)
		}
	}
}

func TestSecretScanning(t *testing.T) {
	f := newFakeGitHub(t)
	f.secAnalysis["acme-actions/deploy"] = map[string]any{
		"secret_scanning":                 map[string]string{"status": "enabled"},
		"secret_scanning_push_protection": map[string]string{"status": "enabled"},
	}
	f.secAnalysis["acme-actions/setup"] = nil
	ix := collectMode(t, f, false)
	deploy := ix.node(t, deployRepo)
	wantAttrs(t, "on", deploy, map[string]string{graph.AttrSecretScanning: "on", graph.AttrSecretPushProtection: "on",
		graph.AttrSecretValidity: "unknown"})
	if attrEvidence(deploy, graph.AttrSecretValidity) != graph.NotVisible {
		t.Error("validity checks unknown without not_visible evidence")
	}
	setup := ix.node(t, "repo:acme-actions/setup")
	wantAttrs(t, "hidden", setup, map[string]string{graph.AttrSecretScanning: "unknown", graph.AttrSecretPushProtection: "unknown"})
	web := ix.node(t, "repo:acme-app/web")
	wantAttrs(t, "off", web, map[string]string{graph.AttrSecretScanning: "on", graph.AttrSecretPushProtection: "off"})
	if c, ok := hasCoverage(ix.g, "org:acme-actions", graph.FactSecretScanning); !ok || !strings.Contains(c.Reason, "1 of 2") {
		t.Errorf("coverage %+v %v", c, ok)
	}
	if _, ok := hasCoverage(ix.g, "org:acme-actions", graph.AttrSecretValidity); !ok {
		t.Error("no validity checks coverage")
	}
	// Archived repos get no hardening attrs.
	if a := ix.node(t, "repo:acme-app/admin"); a.Attrs[graph.AttrSecretScanning] != "" {
		t.Errorf("archived repo has secret_scanning %q", a.Attrs[graph.AttrSecretScanning])
	}
}
