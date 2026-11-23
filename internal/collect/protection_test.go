package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

const (
	deployMain = "action:acme-actions/deploy@main"
	setupMain  = "action:acme-actions/setup@main"
	deployRepo = "repo:acme-actions/deploy"
	webCI      = "workflow:acme-app/web/.github/workflows/ci.yml"
	releaseT   = "team:acme-actions/release"
	platformT  = "team:acme-actions/platform"
)

func raws(t *testing.T, vs ...any) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, 0, len(vs))
	for _, v := range vs {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func raw(t *testing.T, v any) json.RawMessage { return raws(t, v)[0] }

func prRule(id int, approvals int, dismiss, lastPush bool) map[string]any {
	return map[string]any{"type": "pull_request", "ruleset_id": id, "parameters": map[string]any{
		"required_approving_review_count": approvals, "dismiss_stale_reviews_on_push": dismiss,
		"require_last_push_approval": lastPush, "require_code_owner_review": false,
	}}
}

// collectFake runs Collect against f and checks the result validates against
// the JSON Schema with no warnings (every not_visible fact has coverage).
func collectFake(t *testing.T, f *fakeGitHub) *index {
	t.Helper()
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
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

func usesHop(p graph.Path, from, to string) bool {
	for _, h := range p.Hops {
		if h.From == from && h.To == to {
			return true
		}
	}
	return false
}

func TestRefProtection(t *testing.T) {
	_, base := collectAcme(t)
	baseReach := graph.Reach(base.g, "members:acme-actions", graph.Options{})

	type want struct {
		protected, protection, bypass string
		evidence                      graph.Evidence // of ref_protected
		bypassEdges                   []string       // principals with a via=ref_bypass edge into deploy
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, f *fakeGitHub)
		want  want
	}{
		{"reviews with stale dismissal", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
		}, want{"true", "reviews,dismiss_stale", releaseT, graph.Live, []string{releaseT}}},
		{"reviews without stale dismissal", func(t *testing.T, f *fakeGitHub) {}, // the fixture as checked in
			want{"false", "reviews", "", graph.Live, nil}},
		{"last push approval", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 2, false, true))
		}, want{"true", "reviews,last_push_approval", releaseT, graph.Live, []string{releaseT}}},
		{"zero approvals", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 0, true, true))
		}, want{"false", "", "", graph.Live, nil}},
		{"status checks only", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, map[string]any{"type": "required_status_checks", "ruleset_id": 8,
				"parameters": map[string]any{"required_status_checks": []any{map[string]any{"context": "build"}}}})
		}, want{"false", "status_checks", "", graph.Live, nil}},
		{"update rule", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, map[string]any{"type": "update", "ruleset_id": 7,
				"parameters": map[string]any{"update_allows_fetch_and_merge": false}})
		}, want{"true", "push_restricted", releaseT, graph.Live, []string{releaseT}}},
		{"classic restrictions, admins enforced", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = nil
			f.protection["acme-actions/deploy@main"] = raw(t, map[string]any{
				"required_status_checks": map[string]any{"strict": true, "contexts": []string{"build"}},
				"enforce_admins":         map[string]any{"enabled": true},
				"restrictions": map[string]any{"users": []any{map[string]any{"login": "erin"}},
					"teams": []any{map[string]any{"slug": "platform"}}, "apps": []any{}},
			})
		}, want{"true", "status_checks,push_restricted,admins_enforced", "identity:erin," + platformT, graph.Live,
			[]string{"identity:erin", platformT}}},
		{"classic reviews, admins not enforced", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = nil
			f.protection["acme-actions/deploy@main"] = raw(t, map[string]any{
				"enforce_admins": map[string]any{"enabled": false},
				"required_pull_request_reviews": map[string]any{"required_approving_review_count": 1, "dismiss_stale_reviews": true,
					"bypass_pull_request_allowances": map[string]any{"users": []any{map[string]any{"login": "bob"}}, "teams": []any{}, "apps": []any{}}},
			})
		}, want{"true", "reviews,dismiss_stale", "identity:alice,identity:bob", graph.Live,
			[]string{"identity:alice", "identity:bob"}}},
		{"classic reviews without stale dismissal", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = nil
			f.protection["acme-actions/deploy@main"] = raw(t, map[string]any{
				"enforce_admins":                map[string]any{"enabled": true},
				"required_pull_request_reviews": map[string]any{"required_approving_review_count": 1, "dismiss_stale_reviews": false},
			})
		}, want{"false", "reviews,admins_enforced", "", graph.Live, nil}},
		{"rules forbidden", func(t *testing.T, f *fakeGitHub) {
			f.forbidRule["acme-actions/deploy"] = true
		}, want{"unknown", "", "", graph.NotVisible, nil}},
		{"bypass actors hidden", func(t *testing.T, f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
			f.hideBypass = true
		}, want{"true", "reviews,dismiss_stale", "unknown", graph.Live, nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			tc.setup(t, f)
			ix := collectFake(t, f)
			n := ix.node(t, deployMain)
			w := tc.want
			if n.Attrs[graph.AttrRefProtected] != w.protected || n.Attrs[graph.AttrRefProtection] != w.protection ||
				n.Attrs[graph.AttrBypass] != w.bypass {
				t.Errorf("ref_protected=%q ref_protection=%q bypass=%q, want %q %q %q", n.Attrs[graph.AttrRefProtected],
					n.Attrs[graph.AttrRefProtection], n.Attrs[graph.AttrBypass], w.protected, w.protection, w.bypass)
			}
			ev := n.AttrEvidence[graph.AttrRefProtected]
			if ev == "" {
				ev = n.Evidence
			}
			if ev != w.evidence {
				t.Errorf("ref_protected evidence = %q, want %q", ev, w.evidence)
			}
			var got []string
			for _, e := range ix.g.Edges {
				if e.Kind == graph.CanPush && e.Attrs[graph.AttrVia] == graph.ViaRefBypass {
					if e.To != deployRepo || e.Attrs[graph.AttrRef] != "main" || e.Evidence != graph.Live {
						t.Errorf("bypass edge %+v", e)
					}
					got = append(got, e.From)
				}
			}
			if !slices.Equal(got, w.bypassEdges) {
				t.Errorf("bypass edges from %v, want %v", got, w.bypassEdges)
			}
			if w.protected == "false" {
				r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
				if !slices.Equal(r.Confirmed.Repos, baseReach.Confirmed.Repos) || !slices.Equal(r.Confirmed.Workflows, baseReach.Confirmed.Workflows) {
					t.Errorf("unprotected ref changed reach: %v, want %v", r.Confirmed.Repos, baseReach.Confirmed.Repos)
				}
			}
		})
	}
}

func TestRefProtectionReach(t *testing.T) {
	f := newFakeGitHub(t)
	f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
	ix := collectFake(t, f)

	// The bypass team's edge, as collected.
	var e graph.Edge
	for _, x := range ix.g.Edges {
		if x.From == releaseT && x.To == deployRepo && x.Kind == graph.CanPush {
			e = x
		}
	}
	if e.Attrs[graph.AttrVia] != graph.ViaRefBypass || e.Attrs[graph.AttrRef] != "main" || e.SourceAPI != srcRuleset ||
		e.Attrs["rule_source"] != "ruleset:7" || e.Attrs["bypass_mode"] != "always" {
		t.Fatalf("release bypass edge = %+v", e)
	}

	// members:acme-actions can push to deploy, but no longer changes deploy@main
	// that way. (It still reaches deploy@main's consumers through the nested,
	// unprotected setup@main, which deploy@main itself uses.)
	r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
	for id, p := range r.Paths {
		if usesHop(p, deployRepo, deployMain) {
			t.Errorf("path to %s still uses %s -> %s", id, deployRepo, deployMain)
		}
	}
	rel := graph.Reach(ix.g, releaseT, graph.Options{})
	if !slices.Contains(rel.Confirmed.Workflows, webCI) {
		t.Fatalf("release team should reach %s: %v", webCI, rel.Confirmed.Workflows)
	}
	if p := rel.Paths[deployMain]; len(p.Hops) != 1 || p.Hops[0].Kind != graph.CanPush || p.Hops[0].From != releaseT {
		t.Errorf("release -> deploy@main path = %+v, want one CAN_PUSH hop", p.Hops)
	}

	// With setup@main protected too (no bypass), members:acme-actions no longer
	// reaches the acme-app workflows that use deploy@main; the release team does.
	f2 := newFakeGitHub(t)
	f2.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
	f2.rules["acme-actions/setup@main"] = raws(t, prRule(8, 1, true, false))
	ix2 := collectFake(t, f2)
	if n := ix2.node(t, setupMain); n.Attrs[graph.AttrBypass] != "none" {
		t.Errorf("setup@main bypass = %q, want none", n.Attrs[graph.AttrBypass])
	}
	m := graph.Reach(ix2.g, "members:acme-actions", graph.Options{})
	for _, wf := range []string{webCI, "workflow:acme-app/billing/.github/workflows/deploy.yml"} {
		if slices.Contains(m.Confirmed.Workflows, wf) || slices.Contains(m.Possible.Workflows, wf) {
			t.Errorf("members:acme-actions still reaches %s", wf)
		}
	}
	if rel := graph.Reach(ix2.g, releaseT, graph.Options{}); !slices.Contains(rel.Confirmed.Workflows, webCI) {
		t.Errorf("release team lost %s", webCI)
	}
}

func TestRefProtectionNotVisible(t *testing.T) {
	_, base := collectAcme(t)
	if p, ok := graph.Reach(base.g, platformT, graph.Options{}).Paths[webCI]; !ok || p.Unverified {
		t.Fatalf("baseline: platform should reach %s confirmed", webCI)
	}
	for name, setup := range map[string]func(f *fakeGitHub){
		"rules forbidden": func(f *fakeGitHub) { f.forbidRule["acme-actions/deploy"] = true },
		"bypass hidden": func(f *fakeGitHub) {
			f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
			f.hideBypass = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGitHub(t)
			setup(f)
			ix := collectFake(t, f)
			fact := graph.AttrRefProtection
			if name == "bypass hidden" {
				fact = graph.AttrBypass
			}
			if _, ok := hasCoverage(ix.g, deployMain, fact); !ok {
				t.Errorf("no %s coverage for %s: %+v", fact, deployMain, ix.g.Coverage)
			}
			r := graph.Reach(ix.g, platformT, graph.Options{})
			if slices.Contains(r.Confirmed.Workflows, webCI) || !slices.Contains(r.Possible.Workflows, webCI) {
				t.Errorf("%s should move from confirmed to possible: confirmed %v possible %v", webCI, r.Confirmed.Workflows, r.Possible.Workflows)
			}
		})
	}
}

func TestRefProtectionActors(t *testing.T) {
	f := newFakeGitHub(t)
	f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
	f.rulesets["acme-actions/deploy#7"] = raw(t, map[string]any{"id": 7, "bypass_actors": []any{
		map[string]any{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"},
		map[string]any{"actor_id": 2, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"},
		map[string]any{"actor_id": 900, "actor_type": "User", "bypass_mode": "always"},
		map[string]any{"actor_id": 31, "actor_type": "Integration", "bypass_mode": "always"},
		map[string]any{"actor_id": 77, "actor_type": "RepositoryRole", "bypass_mode": "always"},
	}})
	f.userIDs[900] = "frank"
	ix := collectFake(t, f)
	// alice: org owner; bob and platform: maintain on deploy; frank: user actor.
	want := "identity:alice,identity:bob,identity:frank," + platformT
	if got := ix.node(t, deployMain).Attrs[graph.AttrBypass]; got != want {
		t.Errorf("bypass = %q, want %q", got, want)
	}
	c, ok := hasCoverage(ix.g, deployMain, "ref_bypass")
	if !ok || !bytes.Contains([]byte(c.Reason), []byte("integration")) || !bytes.Contains([]byte(c.Reason), []byte("custom repository role 77")) {
		t.Errorf("ref_bypass coverage = %+v (found %v)", c, ok)
	}
	// bob keeps his direct grant next to the bypass edge.
	var vias []string
	for _, e := range ix.g.Edges {
		if e.From == "identity:bob" && e.To == deployRepo && e.Kind == graph.CanPush {
			vias = append(vias, e.Attrs[graph.AttrVia])
		}
	}
	if !slices.Equal(vias, []string{graph.ViaDirect, graph.ViaRefBypass}) {
		t.Errorf("bob -> deploy edges via %v", vias)
	}
}

func TestRefProtectionCache(t *testing.T) {
	f, ix := collectAcme(t)
	// setup@main and the reusable workflow setup/.github/workflows/build.yml@main
	// share one (repo, branch): one request each.
	for _, p := range []string{"/repos/acme-actions/setup/rules/branches/main?per_page=100", "/repos/acme-actions/setup/branches/main"} {
		if got := f.hitCount(p); got != 1 {
			t.Errorf("%s requested %d times, want 1", p, got)
		}
	}
	for _, id := range []string{setupMain, "action:acme-actions/setup/.github/workflows/build.yml@main"} {
		n := ix.node(t, id)
		if n.Attrs[graph.AttrRefProtected] != "false" || n.Attrs[graph.AttrRefProtection] != "status_checks" {
			t.Errorf("%s: ref_protected=%q ref_protection=%q", id, n.Attrs[graph.AttrRefProtected], n.Attrs[graph.AttrRefProtection])
		}
	}
	// Tags and SHAs are not looked at.
	for _, id := range []string{"action:acme-actions/deploy@v1", "action:acme-actions/deploy@" + testSHA} {
		if v, ok := ix.node(t, id).Attrs[graph.AttrRefProtected]; ok {
			t.Errorf("%s has ref_protected=%q", id, v)
		}
	}
	// Classic details are read only for protected branches.
	if got := f.hitCount("/repos/acme-actions/deploy/branches/main/protection"); got != 0 {
		t.Errorf("protection of an unprotected branch requested %d times", got)
	}
}

func TestBranchPath(t *testing.T) {
	for in, want := range map[string]string{
		"main":       "/repos/acme-actions/setup/branches/main",
		"release/v1": "/repos/acme-actions/setup/branches/release/v1",
		"feat#1 x":   "/repos/acme-actions/setup/branches/feat%231%20x",
	} {
		if got := branchPath("acme-actions", "setup", "branches", in); got != want {
			t.Errorf("branchPath(%q) = %q, want %q", in, got, want)
		}
	}
}
