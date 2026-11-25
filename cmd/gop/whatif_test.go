package main

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/testutil"
)

func TestGoldenWhatIfCLI(t *testing.T) {
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"whatif_demo.txt", []string{"what-if", "--demo", "--reduce-owners", "5", "--pin", "action:acme-actions/deploy@main"}},
		{"whatif_demo.md", []string{"what-if", "--demo", "--lower-default-perm", "org:acme-actions", "--format", "md", "--top", "3", "--limit", "10"}},
		{"whatif_demo.json", []string{"what-if", "--demo", "--pin", "action:acme-actions/deploy@main", "--pin", "action:acme-actions/deploy@v1", "--format", "json", "--limit", "5"}},
		{"whatif_acme.txt", []string{"what-if", "--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--lower-default-perm", "org:acme-actions", "--limit", "0"}},
		{"whatif_acme.md", []string{"what-if", "--graph", fixture, "--restrict-token", "workflow:acme-app/web/.github/workflows/ci.yml", "--format", "markdown"}},
		{"whatif_acme.json", []string{"what-if", "--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--format", "json"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			r := runApp(t, nil, nil, tc.args...)
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%v: %+v", tc.args, r)
			}
			testutil.Golden(t, tc.golden, []byte(r.stdout))
		})
	}
}

// TestWhatIfJSONSchemaStable pins the JSON keys of gop what-if --format json:
// renaming or dropping one breaks scripts that read it.
func TestWhatIfJSONSchemaStable(t *testing.T) {
	r := runApp(t, nil, nil, "what-if", "--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--format", "json")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.stdout), &top); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]json.RawMessage) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if got, want := keys(top), []string{"after", "before", "caveats", "fixes", "remaining_top", "removed_paths", "removed_paths_total", "summary"}; !reflect.DeepEqual(got, want) {
		t.Errorf("top-level keys %v, want %v", got, want)
	}
	sub := func(raw json.RawMessage) map[string]json.RawMessage {
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
			t.Fatalf("%s: %v", raw, err)
		}
		return arr[0]
	}
	if got, want := keys(sub(top["fixes"])), []string{"description", "fix", "fix_id"}; !reflect.DeepEqual(got, want) {
		t.Errorf("fixes[0] keys %v, want %v", got, want)
	}
	if got, want := keys(sub(top["removed_paths"])), []string{"after", "before", "hops", "principal", "target"}; !reflect.DeepEqual(got, want) {
		t.Errorf("removed_paths[0] keys %v, want %v", got, want)
	}
	if got, want := keys(sub(top["remaining_top"])), []string{"after", "before", "path", "principal"}; !reflect.DeepEqual(got, want) {
		t.Errorf("remaining_top[0] keys %v, want %v", got, want)
	}
	var totals map[string]json.RawMessage
	if err := json.Unmarshal(top["before"], &totals); err != nil {
		t.Fatal(err)
	}
	if got, want := keys(totals), []string{"confirmed", "confirmed_pairs", "possible", "possible_pairs", "possible_score", "principals", "score"}; !reflect.DeepEqual(got, want) {
		t.Errorf("before keys %v, want %v", got, want)
	}
}

func TestWhatIfCLIErrors(t *testing.T) {
	const pin = "action:acme-actions/deploy@main"
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"what-if", "--graph", fixture}, exitUsage, "at least one of --pin"},
		{[]string{"what-if", "--demo"}, exitUsage, "at least one of --pin"},
		{[]string{"what-if", "--pin", pin}, exitUsage, "--graph is required"},
		{[]string{"what-if", "--graph", fixture, "--demo", "--pin", pin}, exitUsage, "use --graph or --demo, not both"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "--pin", pin}, exitUsage, "given twice"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "--to", "none"}, exitUsage, "--to needs --lower-default-perm"},
		{[]string{"what-if", "--graph", fixture, "--lower-default-perm", "org:acme-actions", "--to", "write"}, exitUsage, "--to must be read or none"},
		{[]string{"what-if", "--graph", fixture, "--reduce-owners", "-1"}, exitUsage, "--reduce-owners must be positive"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "--top", "0"}, exitUsage, "--top must be at least 1"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "--limit", "-1"}, exitUsage, "--limit must be"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "--format", "html"}, exitUsage, "--format"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "--bogus"}, exitUsage, "flag provided but not defined"},
		{[]string{"what-if", "--graph", fixture, "--pin", pin, "extra"}, exitUsage, ""},
		{[]string{"what-if", "--graph", fixture, "--pin", "repo:acme-app/web"}, exitRuntime, "not an action ref"},
		{[]string{"what-if", "--graph", fixture, "--restrict-token", "workflow:acme-app/web/.github/workflows/nope.yml"}, exitRuntime, "unknown fixes[0].workflow"},
	} {
		r := runApp(t, nil, nil, tc.args...)
		if r.code != tc.code || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v: code %d stderr %q, want %d and %q", tc.args, r.code, r.stderr, tc.code, tc.want)
		}
	}
}

// TestWhatIfCLIMatchesMCP checks gop what-if and the MCP what_if tool report
// the same numbers for the same fixes.
func TestWhatIfCLIMatchesMCP(t *testing.T) {
	acme, err := graph.LoadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		g     *graph.Graph
		args  []string
		specs []mcpserver.FixSpec
	}{
		{"acme pin", acme, []string{"--graph", fixture, "--pin", "action:acme-actions/deploy@main"},
			[]mcpserver.FixSpec{{Type: "pin_ref", Action: "action:acme-actions/deploy@main"}}},
		{"acme pin+lower", acme, []string{"--graph", fixture, "--pin", "action:acme-actions/deploy@main", "--lower-default-perm", "org:acme-actions", "--to", "none"},
			[]mcpserver.FixSpec{{Type: "pin_ref", Action: "action:acme-actions/deploy@main"}, {Type: "lower_default_perm", Org: "org:acme-actions", To: "none"}}},
		{"demo owners", demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}), []string{"--demo", "--reduce-owners", "5"},
			[]mcpserver.FixSpec{{Type: "reduce_owners", Threshold: 5}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runApp(t, nil, nil, append(append([]string{"what-if"}, tc.args...), "--format", "json")...)
			if r.code != exitOK {
				t.Fatalf("%+v", r)
			}
			var cli struct {
				Summary string       `json:"summary"`
				Before  graph.Totals `json:"before"`
				After   graph.Totals `json:"after"`
				Fixes   []struct {
					FixID string `json:"fix_id"`
				} `json:"fixes"`
			}
			if err := json.Unmarshal([]byte(r.stdout), &cli); err != nil {
				t.Fatal(err)
			}
			mcp, err := mcpserver.NewEngine(tc.g).WhatIf(mcpserver.WhatIfInput{Fixes: tc.specs})
			if err != nil {
				t.Fatal(err)
			}
			if cli.Summary != mcp.Summary {
				t.Errorf("summary: cli %q, mcp %q", cli.Summary, mcp.Summary)
			}
			if !reflect.DeepEqual(cli.Before, mcp.Delta.Before) || !reflect.DeepEqual(cli.After, mcp.Delta.After) {
				t.Errorf("totals differ:\ncli %+v -> %+v\nmcp %+v -> %+v", cli.Before, cli.After, mcp.Delta.Before, mcp.Delta.After)
			}
			var ids []string
			for _, f := range cli.Fixes {
				ids = append(ids, f.FixID)
			}
			if !reflect.DeepEqual(ids, mcp.Delta.Fixes) {
				t.Errorf("fix ids: cli %v, mcp %v", ids, mcp.Delta.Fixes)
			}
		})
	}
}
