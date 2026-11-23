package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

// TestEndToEndAcme runs the whole pipeline on the synthetic acme enterprise:
// fake GitHub API -> Collect -> graph.json round-trip -> reachability engine.
func TestEndToEndAcme(t *testing.T) {
	_, ix := collectAcme(t)

	var buf bytes.Buffer
	if err := WriteGraph(&buf, ix.g); err != nil {
		t.Fatalf("WriteGraph: %v", err)
	}
	vres, err := schema.Validate(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !vres.Valid {
		t.Fatalf("collected graph does not validate: %v", vres.Errors)
	}
	for _, w := range vres.Warnings {
		t.Logf("validate warning: %s", w)
	}
	g, err := graph.Load(&buf)
	if err != nil {
		t.Fatalf("graph.Load of collected graph: %v", err)
	}
	eng := graph.NewIndex(g)

	res := eng.Reach("members:acme-actions", graph.Options{})
	repos := res.Confirmed.Repos
	t.Logf("members:acme-actions confirmed repos: %v", repos)
	t.Logf("possible repos: %v", res.Possible.Repos)

	// Branch and tag consumers of acme-actions/deploy are reachable.
	for _, want := range []string{"repo:acme-app/web", "repo:acme-app/billing", "repo:acme-app/worker"} {
		if !slices.Contains(repos, want) {
			t.Errorf("expected %s in confirmed reach", want)
		}
	}
	// acme-app/api pins deploy by SHA, but that composite action itself uses
	// acme-actions/setup@main, so the path stays open through the nested ref.
	if !slices.Contains(repos, "repo:acme-app/api") {
		t.Errorf("SHA-pinned composite with a mutable nested ref must stay reachable")
	}
	// acme-secure never runs acme-actions code on a mutable ref at top level and
	// its default permission is read: members of acme-secure reach nothing outside.
	sec := eng.Reach("members:acme-secure", graph.Options{})
	for _, r := range sec.Confirmed.Repos {
		if graph.OrgOf(r) != "org:acme-secure" {
			t.Errorf("acme-secure members should not reach %s", r)
		}
	}

	// Pinning deploy@main alone removes nothing for acme-actions members: the
	// deploy action itself calls acme-actions/setup@main, so whoever controls
	// setup still controls every deploy@main consumer. This is the
	// nested-reference trap gop exists to show. (Direct collaborators on deploy
	// alone, such as bob and erin, do lose reach: they cannot push to setup.)
	pinDeploy := graph.PinRef{Action: "action:acme-actions/deploy@main"}
	d := eng.WhatIf([]graph.Fix{pinDeploy})
	for _, pd := range d.PerPrincipal {
		if pd.Principal == "members:acme-actions" && pd.After.Confirmed.Repos != pd.Before.Confirmed.Repos {
			t.Errorf("pinning only deploy@main should not change members:acme-actions reach (nested setup@main): before %d after %d",
				pd.Before.Confirmed.Repos, pd.After.Confirmed.Repos)
		}
	}
	after := eng.Reach("members:acme-actions", graph.Options{Fixes: []graph.Fix{pinDeploy}})
	if !slices.Contains(after.Confirmed.Repos, "repo:acme-app/api") {
		t.Errorf("api stays reachable through setup@main after pinning deploy@main")
	}
	// Pinning both mutable refs does cut reach.
	both := eng.WhatIf([]graph.Fix{pinDeploy, graph.PinRef{Action: "action:acme-actions/setup@main"}})
	if both.After.ConfirmedPairs >= both.Before.ConfirmedPairs {
		t.Errorf("pinning deploy@main and setup@main should lower reach: before %d after %d", both.Before.ConfirmedPairs, both.After.ConfirmedPairs)
	}

	// The greedy fix list covers both chokepoints: pinning deploy@main first,
	// because besides acme-actions members two teams (platform and its child
	// platform-oncall) and two collaborators can push to deploy, then the root
	// cause for members, acme-actions' Write default.
	sug := eng.SuggestFixes(3)
	if len(sug) < 2 {
		t.Fatalf("expected at least two fix suggestions, got %+v", sug)
	}
	if sug[0].FixID != "pin:action:acme-actions/deploy@main" || sug[1].FixID != "default_perm:org:acme-actions->read" {
		t.Errorf("first fixes = %s, %s; want pinning deploy@main, then lowering acme-actions default permission", sug[0].FixID, sug[1].FixID)
	}
	for _, s := range sug {
		t.Logf("fix %s removes %d (cumulative %.0f%%)", s.FixID, s.Removed, s.CumulativePct)
	}

	// Every edge the engine walks came from the collector with evidence attached,
	// and anything the token could not see shows up in coverage, never as "off".
	if len(g.Coverage) == 0 {
		t.Errorf("expected coverage entries for acme-legacy")
	}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindOrg && n.AttrEvidence[graph.AttrIPAllowList] == graph.NotVisible && n.Attrs[graph.AttrIPAllowList] == "off" {
			t.Errorf("%s: not visible IP allow list rendered as off", n.ID)
		}
	}
}

// TestEdgePositions checks that every USES edge points at its uses: value in
// the testdata file the fake API served, and that OIDC and runner edges carry
// the id-token and runs-on lines.
func TestEdgePositions(t *testing.T) {
	_, ix := collectAcme(t)
	uses := 0
	for _, e := range ix.g.Edges {
		if e.Kind != graph.Uses {
			continue
		}
		uses++
		file, ref := e.Attrs[graph.AttrFile], e.Attrs[graph.AttrFileRef]
		line, lerr := strconv.Atoi(e.Attrs[graph.AttrLine])
		col, cerr := strconv.Atoi(e.Attrs[graph.AttrCol])
		if file == "" || lerr != nil || cerr != nil {
			t.Errorf("%s -> %s: missing position attrs %v", e.From, e.To, e.Attrs)
			continue
		}
		var path string
		switch {
		case strings.HasPrefix(e.From, "workflow:"):
			// workflow:{org}/{repo}/.github/workflows/{name}
			rest := strings.TrimPrefix(e.From, "workflow:")
			parts := strings.SplitN(rest, "/", 3)
			path = filepath.Join("testdata", "workflows", parts[0], parts[1], filepath.Base(file))
		case strings.HasPrefix(e.From, "action:"):
			// action:{owner}/{repo}[/path]@{ref}; nested files were read at that ref.
			target, at, _ := strings.Cut(strings.TrimPrefix(e.From, "action:"), "@")
			if ref != at {
				t.Errorf("%s -> %s: file_ref %q, want %q", e.From, e.To, ref, at)
			}
			parts := strings.SplitN(target, "/", 3)
			if strings.HasPrefix(file, ".github/workflows/") {
				path = filepath.Join("testdata", "workflows", parts[0], parts[1], filepath.Base(file))
			} else {
				path = filepath.Join("testdata", "actions", parts[0], parts[1], filepath.FromSlash(file))
			}
		default:
			t.Errorf("unexpected USES source %s", e.From)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", e.From, err)
			continue
		}
		lines := strings.Split(string(data), "\n")
		raw := strings.TrimPrefix(e.To, "action:")
		if line < 1 || line > len(lines) || col < 1 || !strings.HasPrefix(lines[line-1][col-1:], raw) {
			t.Errorf("%s -> %s: %s:%d:%d does not start the uses: value", e.From, e.To, path, line, col)
		}
	}
	if uses == 0 {
		t.Fatal("no USES edges collected")
	}

	want := map[string]map[string]string{
		// job-level reusable workflow call
		"workflow:acme-app/docs/.github/workflows/build.yml\x00action:acme-actions/setup/.github/workflows/build.yml@main": {
			graph.AttrFile: ".github/workflows/build.yml", graph.AttrLine: "5", graph.AttrCol: "11", "level": LevelJob},
		// step-level action
		"workflow:acme-app/web/.github/workflows/ci.yml\x00action:acme-actions/deploy@main": {
			graph.AttrFile: ".github/workflows/ci.yml", graph.AttrLine: "8", graph.AttrCol: "15", "level": LevelStep},
		// composite action step, read at the parent's ref
		"action:acme-actions/deploy@main\x00action:acme-actions/setup@main": {
			graph.AttrFile: "action.yml", graph.AttrFileRef: "main", graph.AttrLine: "6", graph.AttrCol: "13"},
		// workflow-level id-token: write
		"workflow:acme-app/billing/.github/workflows/deploy.yml\x00oidc:acme-app/billing": {
			graph.AttrFile: ".github/workflows/deploy.yml", graph.AttrLine: "5"},
		// job-level id-token: write
		"workflow:acme-app/search/.github/workflows/index.yaml\x00oidc:acme-app/search": {
			graph.AttrFile: ".github/workflows/index.yaml", graph.AttrLine: "8"},
		// self-hosted runs-on
		"workflow:acme-app/infra/.github/workflows/apply.yml\x00runner:acme-app/infra": {
			graph.AttrFile: ".github/workflows/apply.yml", graph.AttrLine: "5"},
	}
	for _, e := range ix.g.Edges {
		w, ok := want[e.From+"\x00"+e.To]
		if !ok {
			continue
		}
		delete(want, e.From+"\x00"+e.To)
		for k, v := range w {
			if e.Attrs[k] != v {
				t.Errorf("%s -%s-> %s: attr %s = %q, want %q", e.From, e.Kind, e.To, k, e.Attrs[k], v)
			}
		}
	}
	for k := range want {
		t.Errorf("edge not collected: %q", k)
	}
}
