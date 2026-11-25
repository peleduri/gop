package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/schema"
)

func nodeIDs(g *graph.Graph) map[string]bool {
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	return ids
}

// TestCollectMergeIntoCLI collects two orgs, then re-collects one of them
// into that graph from the CLI: the re-collected org's facts are replaced,
// the other org's are kept, cross-org USES edges survive and the result
// validates.
func TestCollectMergeIntoCLI(t *testing.T) {
	f := newAppGitHub(t, map[string]int64{"acme-actions": 101, "acme-app": 102})
	keyFile := writeKey(t, 0o600)
	dir := t.TempDir()
	basePath := filepath.Join(dir, "graph.json")
	r := runAppEnv(t, nil, f.srv.URL, nil, "collect", "--enterprise", "acme", "--out", basePath,
		"--app-id", "4242", "--app-key-file", keyFile)
	if r.code != exitOK {
		t.Fatalf("base collect: %+v", r)
	}
	base, err := graph.LoadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	// Plant one stale repo in each org: the re-collected org's goes, the
	// other org's stays.
	for _, id := range []string{"repo:acme-actions/gone", "repo:acme-app/kept"} {
		base.Nodes = append(base.Nodes, graph.Node{ID: id, Kind: graph.KindRepo, Name: strings.TrimPrefix(id, "repo:"), Evidence: graph.Live})
	}
	writeGraphFile(t, basePath, base)

	out := filepath.Join(dir, "graph2.json")
	var got collect.Config
	r = runAppEnv(t, nil, f.srv.URL, &got, "collect", "--enterprise", "acme", "--orgs", "acme-actions",
		"--merge-into", basePath, "--out", out, "--app-id", "4242", "--app-key-file", keyFile)
	if r.code != exitOK {
		t.Fatalf("merge collect: %+v", r)
	}
	if got.MergeInto == nil || got.MergeForce || len(got.Orgs) != 1 || got.Orgs[0] != "acme-actions" {
		t.Errorf("config: MergeInto set %v, MergeForce %v, Orgs %q", got.MergeInto != nil, got.MergeForce, got.Orgs)
	}
	if !strings.Contains(r.stderr, "merged acme-actions into "+basePath+", wrote "+out) {
		t.Errorf("stderr lacks the merge line: %s", r.stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, f, r.stdout, r.stderr, string(data))
	if res, err := schema.Validate(data); err != nil || !res.Valid {
		t.Fatalf("merged graph does not validate: %v %+v", err, res)
	}
	merged, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	ids := nodeIDs(merged)
	if ids["repo:acme-actions/gone"] {
		t.Error("a stale repo of the re-collected org survived the merge")
	}
	for _, id := range []string{"repo:acme-app/kept", "org:acme-app", "repo:acme-app/web", "repo:acme-actions/deploy"} {
		if !ids[id] {
			t.Errorf("merged graph lacks %s", id)
		}
	}
	uses := false
	for _, e := range merged.Edges {
		uses = uses || (e.Kind == graph.Uses && e.To == "action:acme-actions/deploy@main")
	}
	if !uses {
		t.Error("merged graph lost the cross-org USES edge into acme-actions/deploy@main")
	}
	if !merged.OrgCollectedAt["acme-app"].Equal(base.CollectedAt) || !merged.OrgCollectedAt["acme-actions"].Equal(merged.CollectedAt) {
		t.Errorf("org_collected_at = %v, want acme-app at the base time %v and acme-actions at %v",
			merged.OrgCollectedAt, base.CollectedAt, merged.CollectedAt)
	}
	if again, _ := graph.LoadFile(basePath); len(again.Nodes) != len(base.Nodes) {
		t.Error("--merge-into modified the base graph")
	}
}

func writeGraphFile(t *testing.T, path string, g *graph.Graph) {
	t.Helper()
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := collect.WriteGraph(fh, g); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectMergeIntoUsageErrors(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "test-token-value-123"}
	other := filepath.Join(t.TempDir(), "other.json")
	g, err := graph.LoadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	g.Enterprise = "other"
	writeGraphFile(t, other, g)
	for name, tc := range map[string]struct {
		args []string
		code int
		msg  string
	}{
		"no orgs":       {[]string{"--merge-into", fixture}, exitUsage, "--merge-into needs --orgs"},
		"force alone":   {[]string{"--merge-force", "--orgs", "acme-app"}, exitUsage, "--merge-force needs --merge-into"},
		"stdin":         {[]string{"--merge-into", "-", "--orgs", "acme-app"}, exitUsage, "needs a file"},
		"other ent":     {[]string{"--merge-into", other, "--orgs", "acme-app"}, exitUsage, `enterprise "other", not "acme"`},
		"missing graph": {[]string{"--merge-into", filepath.Join(t.TempDir(), "none.json"), "--orgs", "acme-app"}, exitRuntime, "--merge-into"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json")}, tc.args...)
			r := runApp(t, env, nil, args...)
			if r.code != tc.code || !strings.Contains(r.stderr, tc.msg) {
				t.Errorf("code %d, want %d with %q: %s", r.code, tc.code, tc.msg, r.stderr)
			}
		})
	}
}

// TestCollectMergeIntoForceAndPartial passes --merge-force through, and
// writes the partial merged graph of a stopped run with exit 3.
func TestCollectMergeIntoForceAndPartial(t *testing.T) {
	var got collect.Config
	stopped := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		fresh, err := graph.LoadFile(fixture)
		if err != nil {
			return nil, err
		}
		fresh.Partial, fresh.PartialReason = true, graph.PartialMaxRequests
		merged, err := collect.MergeWith(cfg.MergeInto, fresh, cfg.Orgs, collect.MergeOptions{Force: cfg.MergeForce})
		if err != nil {
			return nil, err
		}
		return merged, &collect.PartialError{Reason: graph.PartialMaxRequests, Err: context.Canceled}
	}
	out := filepath.Join(t.TempDir(), "g.json")
	r := runApp(t, map[string]string{"GITHUB_TOKEN": "test-token-value-123"}, stopped, "collect", "--enterprise", "acme",
		"--orgs", "acme-app", "--merge-into", fixture, "--merge-force", "--max-requests", "5", "--out", out)
	if r.code != exitPartial || !strings.Contains(r.stderr, "wrote a partial graph to "+out) {
		t.Fatalf("partial merge: %+v", r)
	}
	if !got.MergeForce || got.MergeInto == nil {
		t.Errorf("config: MergeForce %v, MergeInto set %v", got.MergeForce, got.MergeInto != nil)
	}
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Partial || g.PartialReason != graph.PartialMaxRequests {
		t.Errorf("written graph: partial %v reason %q", g.Partial, g.PartialReason)
	}
}

// TestCollectMergeIntoRefusesInvalid writes nothing when the merged graph
// does not validate.
func TestCollectMergeIntoRefusesInvalid(t *testing.T) {
	bad := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		g, err := graph.LoadFile(fixture)
		if err != nil {
			return nil, err
		}
		g.Edges = append(g.Edges, graph.Edge{From: "nowhere", To: "repo:acme-app/web", Kind: graph.CanPush, Evidence: graph.Live})
		return g, nil
	}
	out := filepath.Join(t.TempDir(), "g.json")
	r := runApp(t, map[string]string{"GITHUB_TOKEN": "test-token-value-123"}, bad, "collect", "--enterprise", "acme",
		"--orgs", "acme-app", "--merge-into", fixture, "--out", out)
	if r.code != exitRuntime || !strings.Contains(r.stderr, "the merged graph is invalid") {
		t.Fatalf("invalid merge: %+v", r)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("an invalid merged graph was written: %v", err)
	}
}
