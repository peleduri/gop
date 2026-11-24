package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

func TestCollectBudgetFlags(t *testing.T) {
	var got collect.Config
	fake := func(_ context.Context, cfg collect.Config) (*graph.Graph, error) {
		got = cfg
		return graph.LoadFile(fixture)
	}
	env := map[string]string{"GITHUB_TOKEN": "test-token-value-123"}
	r := runApp(t, env, fake, "collect", "--enterprise", "acme", "--out", filepath.Join(t.TempDir(), "g.json"),
		"--max-requests", "500", "--reserve", "200", "--priority", "acme-secure, acme-app")
	if r.code != 0 {
		t.Fatalf("collect: %+v", r)
	}
	if got.MaxRequests != 500 || got.Reserve != 200 || len(got.Priority) != 2 || got.Priority[0] != "acme-secure" || got.Priority[1] != "acme-app" {
		t.Errorf("config = MaxRequests %d Reserve %d Priority %q", got.MaxRequests, got.Reserve, got.Priority)
	}
	for _, args := range [][]string{{"--max-requests", "-1"}, {"--reserve", "-5"}} {
		r := runApp(t, env, nil, append([]string{"collect", "--enterprise", "acme", "--out", "g.json"}, args...)...)
		if r.code != exitUsage {
			t.Errorf("%v: code %d, want %d", args, r.code, exitUsage)
		}
	}
}

func TestCollectPartialWritesGraph(t *testing.T) {
	const tok = "test-token-value-123"
	stopped := func(context.Context, collect.Config) (*graph.Graph, error) {
		g, err := graph.LoadFile(fixture)
		if err != nil {
			return nil, err
		}
		g.Partial, g.PartialReason = true, graph.PartialInterrupted
		g.Coverage = append(g.Coverage, graph.Coverage{Scope: "org:acme-app", Fact: "phase:workflows",
			Reason: graph.CoverageNotCollected + " (interrupted) before the workflows phase", NeedsFix: "re-run"})
		return g, &collect.PartialError{Reason: graph.PartialInterrupted, Err: context.Canceled}
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "g.json")
	r := runApp(t, map[string]string{"GITHUB_TOKEN": tok}, stopped, "collect", "--enterprise", "acme", "--out", out,
		"--cache-dir", filepath.Join(dir, "cache"))
	if r.code != exitPartial || !strings.Contains(r.stderr, "wrote a partial graph to "+out) || !strings.Contains(r.stderr, "--resume") {
		t.Fatalf("partial collect: %+v", r)
	}
	if strings.Contains(r.stderr, tok) {
		t.Fatal("token in output")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Partial       bool   `json:"partial"`
		PartialReason string `json:"partial_reason"`
	}
	if err := json.Unmarshal(data, &top); err != nil || !top.Partial || top.PartialReason != graph.PartialInterrupted {
		t.Fatalf("written graph: partial %v reason %q (%v)", top.Partial, top.PartialReason, err)
	}

	v := runApp(t, nil, nil, "validate", "--graph", out)
	if v.code != exitOK || !strings.Contains(v.stdout, "warning /partial: Partial graph: the run was interrupted") {
		t.Errorf("validate: %+v", v)
	}
	rep := runApp(t, nil, nil, "report", "--graph", out, "--out", "-", "--format", "md")
	if rep.code != exitOK || !strings.Contains(rep.stdout, "> **Warning:** Partial graph: the run was interrupted") {
		t.Errorf("report: %+v", rep)
	}
	g, err := graph.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := mcpserver.NewEngine(g).Summary(g.CollectedAt)
	if !s.Partial || s.PartialReason != graph.PartialInterrupted || !strings.HasPrefix(s.Note, "Partial graph:") {
		t.Errorf("MCP summary: partial %v reason %q note %q", s.Partial, s.PartialReason, s.Note)
	}
	w := runApp(t, nil, nil, "who", "--graph", out, "--target", "repo:acme-app/web")
	if w.code != exitOK || !strings.HasPrefix(w.stdout, mcpserver.PartialMarker+" ") {
		t.Errorf("who on a partial graph: %+v", w)
	}

	// Without --cache-dir there is nothing to resume from.
	r = runApp(t, map[string]string{"GITHUB_TOKEN": tok}, stopped, "collect", "--enterprise", "acme", "--out", out)
	if r.code != exitPartial || !strings.Contains(r.stderr, "add --cache-dir") {
		t.Errorf("partial collect without a cache: %+v", r)
	}
}
