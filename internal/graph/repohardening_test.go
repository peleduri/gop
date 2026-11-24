package graph

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// hardenedGraph: members:o (write via default perm) and identity:alice
// (admin) push to repo:o/app, whose workflow holds secrets; bob bypasses
// via ref_bypass. attrs are the repo's hardening attrs (nil: none).
func hardenedGraph(attrs map[string]string) *Graph {
	a := map[string]string{"default_branch": "main", AttrVisibility: "private"}
	for k, v := range attrs {
		a[k] = v
	}
	return &Graph{Schema: SchemaVersion,
		Nodes: []Node{
			{ID: "repo:o/app", Kind: KindRepo, Name: "o/app", Evidence: Live, Attrs: a},
			{ID: "repo:o/lib", Kind: KindRepo, Name: "o/lib", Evidence: Live},
		},
		Edges: []Edge{
			edge("members:o", "CAN_PUSH", "repo:o/app", AttrVia, ViaDefaultPerm, "permission", "write"),
			edge("members:o", "CAN_PUSH", "repo:o/lib", AttrVia, ViaDefaultPerm, "permission", "write"),
			edge("identity:alice", "CAN_PUSH", "repo:o/app", AttrVia, ViaDirect, "permission", "admin"),
			edge("identity:bob", "CAN_PUSH", "repo:o/app", AttrVia, ViaRefBypass, AttrRef, "main"),
			edge("workflow:o/app/.github/workflows/ci.yml", "DEFINED_IN", "repo:o/app"),
			edge("workflow:o/app/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:o/app"),
		}}
}

func protectedAttrs(reviews string, extra ...string) map[string]string {
	m := map[string]string{AttrBranchProtected: "true", AttrBranchReviews: reviews, AttrBranchForcePush: "false",
		AttrBranchAdminBypass: "false", AttrBranchPushRestricted: "false", AttrBranchSources: "ruleset:7"}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return m
}

func TestHopNote(t *testing.T) {
	cases := []struct {
		name                string
		attrs               map[string]string
		members, alice, bob string
	}{
		{"no attrs", nil, "", "", ""},
		{"unknown", map[string]string{AttrBranchProtected: "unknown", AttrBranchReviews: "unknown"}, "", "", ""},
		{"not protected", map[string]string{AttrBranchProtected: "false", AttrBranchReviews: "0", AttrBranchForcePush: "true"},
			NoteDirect, NoteDirect, ""},
		{"two approvals", protectedAttrs("2"), "push needs 2 approvals to reach `main`", "push needs 2 approvals to reach `main`", ""},
		{"one approval with CODEOWNERS on workflows",
			protectedAttrs("1", AttrBranchCodeOwnerReview, "true", AttrCodeowners, ".github/CODEOWNERS", AttrCodeownersWorkflows, "true"),
			"push needs 1 approval to reach `main` + CODEOWNERS on workflows", "push needs 1 approval to reach `main` + CODEOWNERS on workflows", ""},
		{"code owner review without workflow coverage",
			protectedAttrs("1", AttrBranchCodeOwnerReview, "true", AttrCodeowners, "CODEOWNERS", AttrCodeownersWorkflows, "false"),
			"push needs 1 approval to reach `main`", "push needs 1 approval to reach `main`", ""},
		{"force push allowed", protectedAttrs("2", AttrBranchForcePush, "true"), NoteDirect, NoteDirect, ""},
		{"admin bypass: only the admin goes direct", protectedAttrs("2", AttrBranchAdminBypass, "true"),
			"push needs 2 approvals to reach `main`", NoteDirect, ""},
		{"no approval required", protectedAttrs("0"), NoteDirect, NoteDirect, ""},
		{"no approval but push restricted", protectedAttrs("0", AttrBranchPushRestricted, "true"), "", "", ""},
		{"reviews unknown", protectedAttrs("unknown"), "", "", ""},
	}
	for _, tc := range cases {
		ix := NewIndex(hardenedGraph(tc.attrs))
		for p, want := range map[string]string{"members:o": tc.members, "identity:alice": tc.alice, "identity:bob": tc.bob} {
			r := ix.Reach(p, Options{})
			path := ix.Annotate(r.Paths["secret:o/app"])
			if len(path.Hops) == 0 {
				t.Fatalf("%s: %s has no path to the secret", tc.name, p)
			}
			if got := path.Hops[0].Note; got != want {
				t.Errorf("%s: %s note %q, want %q", tc.name, p, got, want)
			}
			if raw := r.Paths["secret:o/app"]; raw.Hops[0].Note != "" {
				t.Errorf("%s: Annotate changed the cached path", tc.name)
			}
			for _, h := range path.Hops[1:] {
				if h.Note != "" {
					t.Errorf("%s: non-push hop got note %q", tc.name, h.Note)
				}
			}
		}
	}
}

// Hardening attrs are context: evidence, counts, scores and rank order are
// identical with and without them.
func TestRepoHardeningDoesNotChangeScores(t *testing.T) {
	base := NewIndex(hardenedGraph(nil))
	for _, attrs := range []map[string]string{
		protectedAttrs("2", AttrBranchCodeOwnerReview, "true", AttrCodeownersWorkflows, "true", AttrSecretPushProtection, "on"),
		{AttrBranchProtected: "false", AttrBranchReviews: "0", AttrSecretScanning: "off"},
		{AttrBranchProtected: "unknown"},
	} {
		ix := NewIndex(hardenedGraph(attrs))
		if !reflect.DeepEqual(base.Scores(), ix.Scores()) {
			t.Errorf("%v: scores differ:\n%+v\n%+v", attrs, base.Scores(), ix.Scores())
		}
		if !reflect.DeepEqual(base.TopPaths(10), ix.TopPaths(10)) {
			t.Errorf("%v: rank order differs", attrs)
		}
		for _, p := range []string{"members:o", "identity:alice"} {
			a, b := base.Reach(p, Options{}), ix.Reach(p, Options{})
			if !reflect.DeepEqual(a.Confirmed, b.Confirmed) || !reflect.DeepEqual(a.Possible, b.Possible) {
				t.Errorf("%v: reach of %s differs", attrs, p)
			}
		}
		if !reflect.DeepEqual(base.SuggestFixes(5), ix.SuggestFixes(5)) {
			t.Errorf("%v: suggested fixes differ", attrs)
		}
	}
}

func TestHardeningRollups(t *testing.T) {
	g := hardenedGraph(protectedAttrs("2", AttrCodeowners, ".github/CODEOWNERS", AttrCodeownersWorkflows, "true",
		AttrSecretScanning, "on", AttrSecretPushProtection, "off"))
	g.Nodes[1].Attrs = map[string]string{AttrBranchProtected: "unknown", AttrBranchReviews: "unknown", AttrCodeowners: "none",
		AttrSecretScanning: "unknown", AttrSecretPushProtection: "unknown"}
	g.Nodes = append(g.Nodes,
		Node{ID: "repo:o/site", Kind: KindRepo, Name: "o/site", Evidence: Live, Attrs: map[string]string{AttrBranchProtected: "false",
			AttrBranchReviews: "0", AttrCodeowners: "CODEOWNERS", AttrCodeownersWorkflows: "false", AttrSecretScanning: "on", AttrSecretPushProtection: "on"}},
		Node{ID: "repo:o/old", Kind: KindRepo, Name: "o/old", Evidence: Live, Attrs: map[string]string{AttrArchived: "true", AttrBranchProtected: "false"}},
	)
	rs := NewIndex(g).HardeningRollups()
	if len(rs) != 1 {
		t.Fatalf("rollups %+v", rs)
	}
	r := rs[0]
	want := HardeningRollup{Org: "org:o", Repos: 3,
		Protected:      Share{Yes: 1, No: 1, Unknown: 1},
		Reviews:        Share{Yes: 1, No: 1, Unknown: 1},
		CodeownersWF:   Share{Yes: 1, No: 2},
		SecretScanning: Share{Yes: 2, Unknown: 1},
		PushProtection: Share{Yes: 1, No: 1, Unknown: 1}}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("rollup\n got %+v\nwant %+v", r, want)
	}
	if s := r.Protected.String(); s != "1/3 (1 unknown)" {
		t.Errorf("share string %q", s)
	}
}

func TestSuggestHardening(t *testing.T) {
	g := hardenedGraph(map[string]string{AttrBranchProtected: "false", AttrBranchReviews: "0", AttrSecretPushProtection: "off"})
	g.Nodes[1].Attrs = map[string]string{AttrBranchProtected: "unknown", AttrSecretPushProtection: "unknown"}
	ix := NewIndex(g)
	got := ix.SuggestHardening(10, 10)
	var ids []string
	for _, s := range got {
		ids = append(ids, s.FixID)
		if !HardeningOnly(s.Fix) || len(FixEdges(ix, s.Fix)) != 0 {
			t.Errorf("%s is not advisory", s.FixID)
		}
	}
	want := []string{"require_reviews:repo:o/app", "push_protection:repo:o/app"}
	if !slices.Equal(ids, want) {
		t.Errorf("suggestions %v, want %v (unknown repos are never suggested)", ids, want)
	}
	d := ix.WhatIf([]Fix{got[0].Fix, got[1].Fix})
	if d.Before != d.After {
		t.Errorf("advisory fixes changed reach: %+v -> %+v", d.Before, d.After)
	}
	if n := len(ix.SuggestHardening(10, 1)); n != 1 {
		t.Errorf("limit 1 gave %d", n)
	}
}

func TestHardeningSummary(t *testing.T) {
	h, ok := RepoHardening(Node{ID: "repo:o/app", Attrs: protectedAttrs("2", AttrBranchCodeOwnerReview, "true",
		AttrCodeowners, ".github/CODEOWNERS", AttrCodeownersWorkflows, "true", AttrSecretScanning, "on", AttrSecretPushProtection, "off",
		"default_branch", "main")})
	if !ok {
		t.Fatal("no hardening")
	}
	got := h.Summary()
	for _, want := range []string{"default branch `main`: protected (ruleset:7)", "2 approvals", "CODEOWNERS review",
		"force push blocked", "CODEOWNERS covers workflows", "secret scanning on, push protection off"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q lacks %q", got, want)
		}
	}
	if _, ok := RepoHardening(Node{ID: "repo:o/x"}); ok {
		t.Error("a repo without attrs reports hardening")
	}
}
