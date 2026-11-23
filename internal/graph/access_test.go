package graph

import (
	"slices"
	"testing"
)

func TestActionsAccessAllows(t *testing.T) {
	const (
		host     = "repo:acme-actions/setup"
		sameRepo = "repo:Acme-Actions/Setup" // GitHub names are case-insensitive
		sameOrg  = "repo:acme-actions/deploy"
		otherOrg = "repo:acme-app/web"
	)
	type verdict struct {
		ok bool
		ev Evidence
	}
	open, hidden, closed := verdict{true, Live}, verdict{true, NotVisible}, verdict{false, Live}
	cases := []struct {
		level                        string
		repo, org, cross, noConsumer verdict
	}{
		{"", open, open, open, open},
		{AccessPublic, open, open, open, open},
		{AccessEnterprise, open, open, open, open},
		{AccessOrganization, open, open, closed, hidden},
		{AccessUser, open, open, closed, hidden},
		{AccessNone, open, closed, closed, hidden},
		{AccessUnknown, open, open, hidden, hidden},
		{"some-future-level", open, open, hidden, hidden},
	}
	for _, tc := range cases {
		for consumer, want := range map[string]verdict{sameRepo: tc.repo, sameOrg: tc.org, otherOrg: tc.cross, "": tc.noConsumer} {
			ok, ev := actionsAccessAllows(tc.level, host, consumer)
			if got := (verdict{ok, ev}); got != want {
				t.Errorf("actionsAccessAllows(%q, %s, %q) = %v, want %v", tc.level, host, consumer, got, want)
			}
		}
	}
}

func TestRepoFromID(t *testing.T) {
	for id, want := range map[string]string{
		"action:acme-actions/setup@main":                         "repo:acme-actions/setup",
		"action:acme-actions/setup/sub/dir@v1":                   "repo:acme-actions/setup",
		"action:acme-actions/setup/.github/workflows/b.yml@main": "repo:acme-actions/setup",
		"workflow:acme-app/web/.github/workflows/ci.yml":         "repo:acme-app/web",
		"action:./local":         "repo:./local",
		"action:docker":          "",
		"repo:acme-app/web":      "",
		"secret:acme-app/web":    "",
		"workflow:acme-app":      "",
		"action:/setup@main":     "",
		"no-prefix/acme-app/web": "",
	} {
		if got := repoFromID(id); got != want {
			t.Errorf("repoFromID(%q) = %q, want %q", id, got, want)
		}
	}
}

// accessGraph: members:acme-actions push to acme-actions/setup, which hosts
// action:acme-actions/setup@main. It is used by a workflow in the same org
// (acme-actions/deploy), by a workflow in another org (acme-app/web), and by a
// composite action hosted in acme-app/tool that acme-app/api uses. Each
// workflow holds secrets. level "" leaves actions_access unset.
func accessGraph(level string) *Graph {
	var attrs map[string]string
	if level != "" {
		attrs = map[string]string{AttrActionsAccess: level}
	}
	const setup = "action:acme-actions/setup@main"
	return &Graph{Schema: SchemaVersion,
		Nodes: []Node{{ID: "repo:acme-actions/setup", Kind: KindRepo, Name: "acme-actions/setup", Evidence: Live, Attrs: attrs}},
		Edges: []Edge{
			edge("members:acme-actions", "CAN_PUSH", "repo:acme-actions/setup", AttrVia, ViaDirect),
			edge(setup, "RESOLVES_TO", "repo:acme-actions/setup"),
			edge("workflow:acme-actions/deploy/.github/workflows/ci.yml", "DEFINED_IN", "repo:acme-actions/deploy"),
			edge("workflow:acme-actions/deploy/.github/workflows/ci.yml", "USES", setup, AttrRefKind, "branch", AttrConsumerOrg, "acme-actions"),
			edge("workflow:acme-actions/deploy/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:acme-actions/deploy"),
			edge("workflow:acme-app/web/.github/workflows/ci.yml", "DEFINED_IN", "repo:acme-app/web"),
			edge("workflow:acme-app/web/.github/workflows/ci.yml", "USES", setup, AttrRefKind, "branch", AttrConsumerOrg, "acme-app"),
			edge("workflow:acme-app/web/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:acme-app/web"),
			edge("action:acme-app/tool@v1", "RESOLVES_TO", "repo:acme-app/tool"),
			edge("action:acme-app/tool@v1", "USES", setup, AttrRefKind, "branch", AttrConsumerOrg, "acme-app"),
			edge("workflow:acme-app/api/.github/workflows/ci.yml", "DEFINED_IN", "repo:acme-app/api"),
			edge("workflow:acme-app/api/.github/workflows/ci.yml", "USES", "action:acme-app/tool@v1", AttrRefKind, "tag", AttrConsumerOrg, "acme-app"),
			edge("workflow:acme-app/api/.github/workflows/ci.yml", "EXECUTES_WITH", "secret:acme-app/api"),
		}}
}

func TestActionsAccessGatesUses(t *testing.T) {
	// For each secret: "c" confirmed, "p" possible, "" not reached.
	cases := []struct {
		level            string
		deploy, web, api string
	}{
		{"", "c", "c", "c"},
		{AccessPublic, "c", "c", "c"},
		{AccessEnterprise, "c", "c", "c"},
		{AccessOrganization, "c", "", ""},
		{AccessUser, "c", "", ""},
		{AccessNone, "", "", ""},
		{AccessUnknown, "c", "p", "p"},
	}
	for _, tc := range cases {
		t.Run("level="+tc.level, func(t *testing.T) {
			r := Reach(accessGraph(tc.level), "members:acme-actions", Options{})
			for secret, want := range map[string]string{"secret:acme-actions/deploy": tc.deploy, "secret:acme-app/web": tc.web, "secret:acme-app/api": tc.api} {
				got := ""
				switch {
				case slices.Contains(r.Confirmed.Secrets, secret):
					got = "c"
				case slices.Contains(r.Possible.Secrets, secret):
					got = "p"
				}
				if got != want {
					t.Errorf("%s = %q, want %q", secret, got, want)
				}
			}
			// The action itself stays reachable: pushing to its repo changes it.
			if !slices.Contains(r.Confirmed.Actions, "action:acme-actions/setup@main") {
				t.Errorf("action not confirmed: %+v", r.Confirmed.Actions)
			}
		})
	}
}

func TestActionsAccessNoAttrMatchesToday(t *testing.T) {
	g := loadAcme(t)
	ix := NewIndex(g)
	if ix.gates != nil {
		t.Fatal("acme fixture has no actions_access, gates should be nil")
	}
	// Setting an access level that allows everything changes nothing either.
	h := cloneGraph(g)
	for i, n := range h.Nodes {
		if n.Kind == KindRepo {
			attrs := map[string]string{}
			for k, v := range n.Attrs {
				attrs[k] = v
			}
			attrs[AttrActionsAccess] = AccessEnterprise
			h.Nodes[i].Attrs = attrs
		}
	}
	hx := NewIndex(h)
	if hx.gates == nil {
		t.Fatal("gates should be computed when a repo has actions_access")
	}
	for _, p := range ix.Principals() {
		a, b := ix.Reach(p, Options{}), hx.Reach(p, Options{})
		if !slices.Equal(sortedKeys(pathSet(a)), sortedKeys(pathSet(b))) {
			t.Errorf("%s: reach differs with actions_access=enterprise everywhere", p)
		}
	}
}

func pathSet(r Result) map[string]bool {
	out := map[string]bool{}
	for id, p := range r.Paths {
		out[id+"|"+string(p.Evidence)] = true
	}
	return out
}

func TestActionsAccessDroppedPinIsNotSuggested(t *testing.T) {
	pin := "pin:action:acme-actions/setup@main"
	has := func(level string) bool {
		for _, s := range SuggestFixes(accessGraph(level), 5) {
			if s.FixID == pin {
				return true
			}
		}
		return false
	}
	if !has("") {
		t.Fatalf("without actions_access, %s should be suggested", pin)
	}
	// With none every consumer hop is dropped: pinning removes no pair.
	if has(AccessNone) {
		t.Errorf("with actions_access=none, %s should not be suggested", pin)
	}
	if !slices.ContainsFunc(NewIndex(accessGraph(AccessNone)).Candidates(), func(f Fix) bool { return f.ID() == pin }) {
		t.Errorf("%s should still be a candidate (it is only never picked)", pin)
	}
}
