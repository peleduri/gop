package summary

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sanitize"
	"github.com/peleduri/gop/internal/sarif"
	"github.com/peleduri/gop/internal/schema"
	"github.com/peleduri/gop/internal/testutil"
)

const acme = "../../testdata/acme/graph.json"

func loadFile(t *testing.T, path string, swap func([]byte) []byte) *graph.Graph {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if swap != nil {
		raw = swap(raw)
	}
	g, err := graph.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func demoGraph() *graph.Graph { return demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}) }

func build(t *testing.T, g *graph.Graph, opts Options) (*Summary, []byte) {
	t.Helper()
	s, err := Build(g, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

func validate(t *testing.T, b []byte) {
	t.Helper()
	ps, err := schema.ValidateSummary(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) > 0 {
		t.Fatalf("summary does not match schema/gop.summary.v1.schema.json: %v\n%s", ps, b)
	}
}

// strings collects every string value of a JSON document.
func stringValues(t *testing.T, b []byte) []string {
	t.Helper()
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, x := range v {
				walk(x)
			}
		case map[string]any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(doc)
	return out
}

func TestSchemaValidates(t *testing.T) {
	for name, g := range map[string]*graph.Graph{"demo": demoGraph(), "acme": loadFile(t, acme, nil)} {
		for _, names := range []bool{false, true} {
			s, b := build(t, g, Options{Version: "vTEST", Names: names})
			validate(t, b)
			if s.Schema != Version || s.Names != names || len(s.Rules) != len(sarif.Rules()) {
				t.Errorf("%s names=%v: %+v", name, names, s)
			}
			if len(b) > MaxBytes {
				t.Errorf("%s: %d bytes", name, len(b))
			}
		}
	}
}

func TestSchemaRejectsUnknownFields(t *testing.T) {
	_, b := build(t, demoGraph(), Options{Version: "vTEST"})
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["token"] = "x" },
		func(d map[string]any) { d["coverage"].(map[string]any)["ip_allow_list"] = []any{"10.0.0.1"} },
		func(d map[string]any) { d["top"].([]any)[0].(map[string]any)["login"] = "alice" },
		func(d map[string]any) { d["top"].([]any)[0].(map[string]any)["id"] = "acme-app/web" },
		func(d map[string]any) { d["schema"] = "gop.summary/v2" },
		func(d map[string]any) { delete(d, "pairs") },
	} {
		var c map[string]any
		_ = json.Unmarshal(b, &c)
		mutate(c)
		mb, _ := json.Marshal(c)
		ps, err := schema.ValidateSummary(mb)
		if err != nil {
			t.Fatal(err)
		}
		if len(ps) == 0 {
			t.Errorf("schema accepted %s", mb)
		}
	}
}

// TestCountsMatchSARIF checks the rule counts are the SARIF results with
// possible ones included, and that the rule IDs are SARIF's.
func TestCountsMatchSARIF(t *testing.T) {
	g := demoGraph()
	log, err := sarif.Build(g, sarif.Options{IncludePossible: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{}
	for _, r := range log.Runs[0].Results {
		want[r.RuleID]++
	}
	s, _ := build(t, g, Options{})
	total := 0
	for i, r := range s.Rules {
		if r.ID != sarif.Rules()[i].ID {
			t.Errorf("rule %d: %s", i, r.ID)
		}
		if r.Confirmed+r.Possible != want[r.ID] {
			t.Errorf("%s: %d+%d, want %d", r.ID, r.Confirmed, r.Possible, want[r.ID])
		}
		total += r.Confirmed + r.Possible
	}
	if total != s.Findings || s.Findings != len(log.Runs[0].Results) {
		t.Errorf("findings %d, rules total %d, sarif %d", s.Findings, total, len(log.Runs[0].Results))
	}
	sev := s.Severities
	if sev.Critical+sev.High+sev.Medium+sev.Low == 0 {
		t.Error("demo should have findings by severity")
	}
	ix := graph.NewIndex(g)
	tot := ix.Totals()
	nh := ix.NonHuman()
	if s.Pairs.Confirmed != tot.ConfirmedPairs || s.Pairs.Possible != tot.PossiblePairs || s.Headline.NonHumanActors != nh.Actors ||
		s.Headline.MergeWithoutHuman != nh.Merge {
		t.Errorf("headline %+v pairs %+v, want %+v %+v", s.Headline, s.Pairs, nh, tot)
	}
	if s.Headline.OutsiderTriggerableAgents == 0 || s.Headline.DangerousModeAgents == 0 {
		t.Errorf("demo plants exposed and unrestricted agents: %+v", s.Headline)
	}
	if !s.RunAt.Equal(g.CollectedAt) || s.Enterprise != g.Enterprise {
		t.Errorf("run_at %v enterprise %q", s.RunAt, s.Enterprise)
	}
}

// TestDefaultHasNoNodeNames proves the default summary holds no node name or
// node ID of the graph: only the enterprise slug identifies it.
func TestDefaultHasNoNodeNames(t *testing.T) {
	for name, g := range map[string]*graph.Graph{"demo": demoGraph(), "acme": loadFile(t, acme, nil)} {
		_, b := build(t, g, Options{Version: "vTEST", Top: MaxTop})
		values := stringValues(t, b)
		for _, n := range g.Nodes {
			if n.Kind == graph.KindEnterprise {
				continue
			}
			_, rest, _ := strings.Cut(n.ID, ":")
			for _, needle := range []string{n.Name, n.ID, rest} {
				if len(needle) < 3 || needle == g.Enterprise {
					continue
				}
				for _, v := range values {
					if strings.Contains(v, needle) {
						t.Errorf("%s: default summary value %q contains node name %q (%s)", name, v, needle, n.ID)
					}
				}
			}
		}
		// --names does add them.
		_, nb := build(t, g, Options{Version: "vTEST", Names: true})
		if !bytes.Contains(nb, []byte(".github/workflows/")) {
			t.Errorf("%s: --names output has no workflow names", name)
		}
	}
}

func TestHostileNames(t *testing.T) {
	g := loadFile(t, acme, testutil.HostileGraphJSON)
	for _, names := range []bool{false, true} {
		s, b := build(t, g, Options{Version: "vTEST", Names: names, Top: MaxTop})
		validate(t, b)
		if r, ok := testutil.RawUnsafe(string(b)); ok {
			t.Errorf("names=%v: raw unsafe rune %U in output", names, r)
		}
		if l := testutil.HostileLineStart(string(b)); l != "" {
			t.Errorf("names=%v: line starts with hostile text: %q", names, l)
		}
		for _, v := range stringValues(t, b) {
			if utf8.RuneCountInString(v) > sanitize.MaxValue {
				t.Errorf("names=%v: value of %d runes", names, utf8.RuneCountInString(v))
			}
			if strings.ContainsAny(v, "\n\r") {
				t.Errorf("names=%v: raw newline in %q", names, v)
			}
		}
		hostile := false
		for _, f := range s.Top {
			if strings.Contains(f.Repository+f.Workflow, "SYSTEM") {
				hostile = true
			}
		}
		if hostile != names {
			t.Errorf("names=%v: hostile name in top findings = %v", names, hostile)
		}
		if !names && (bytes.Contains(b, []byte("SYSTEM")) || bytes.Contains(b, []byte("ignore previous"))) {
			t.Errorf("default output carries a hostile name:\n%s", b)
		}
	}
}

func TestTruncate(t *testing.T) {
	s, _ := build(t, demoGraph(), Options{Version: "vTEST", Names: true})
	long := strings.Repeat("x", sanitize.MaxValue)
	s.Top = nil
	for i := 0; i < MaxTop; i++ {
		s.Top = append(s.Top, TopFinding{ID: FindingID("GOP001", long, string(rune('a'+i%26))), Rule: "GOP001", Severity: "high",
			Repository: long, Workflow: long, Org: long})
	}
	b, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxBytes || !s.Truncated || len(s.Top) == 0 || len(s.Top) == MaxTop {
		t.Fatalf("%d bytes, truncated %v, %d top", len(b), s.Truncated, len(s.Top))
	}
	validate(t, b)
	// One more finding would not fit.
	s.Top = append(s.Top, s.Top[0])
	if more, _ := encode(s); len(more) <= MaxBytes {
		t.Errorf("kept %d findings but %d fit", len(s.Top)-1, len(s.Top))
	}
}

func TestFindingID(t *testing.T) {
	id := FindingID("GOP001", "workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main")
	if len(id) != IDLength || id != FindingID("GOP001", "workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main") {
		t.Fatalf("id %q", id)
	}
	if id == FindingID("GOP003", "workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main") {
		t.Error("rule must change the ID")
	}
	for edge, want := range map[string][2]string{
		"members:acme-actions CAN_PUSH repo:acme-actions/deploy (+9 more)":                    {"members:acme-actions", "repo:acme-actions/deploy"},
		"external:anyone CAN_TRIGGER workflow:acme-app/api/.github/workflows/claude-fix.yml":  {"external:anyone", "workflow:acme-app/api/.github/workflows/claude-fix.yml"},
		"workflow:acme-app/web/.github/workflows/ci.yml USES action:acme-actions/deploy@main": {"workflow:acme-app/web/.github/workflows/ci.yml", "action:acme-actions/deploy@main"},
		"external:anyone CAN_MERGE_VIA_BOT repo:acme-app/api":                                 {"external:anyone", "repo:acme-app/api"},
	} {
		if f, to := endpoints(edge); f != want[0] || to != want[1] {
			t.Errorf("endpoints(%q) = %q, %q", edge, f, to)
		}
	}
}

func TestTopBounds(t *testing.T) {
	for _, n := range []int{-1, MaxTop + 1} {
		if _, err := Build(demoGraph(), Options{Top: n}); err == nil {
			t.Errorf("top %d accepted", n)
		}
	}
	s, _ := build(t, demoGraph(), Options{Top: 3})
	if len(s.Top) != 3 {
		t.Errorf("top 3: %d", len(s.Top))
	}
	s, _ = build(t, &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme"}, Options{})
	if s.Top == nil || len(s.Top) != 0 || s.Findings != 0 {
		t.Errorf("empty graph: %+v", s)
	}
}

func TestPartial(t *testing.T) {
	g := demoGraph()
	g.Partial, g.PartialReason = true, graph.PartialRateLimit
	s, b := build(t, g, Options{})
	validate(t, b)
	if !s.Coverage.Partial || s.Coverage.PartialReason != "rate_limit" {
		t.Errorf("coverage %+v", s.Coverage)
	}
}
