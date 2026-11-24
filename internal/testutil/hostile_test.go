package testutil

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// payloadsFile is the corpus export the agent eval reads.
var payloadsFile = filepath.Join("..", "..", "testdata", "hostile", "payloads.json")

// TestPayloadsFile keeps testdata/hostile/payloads.json equal to Payloads,
// so the Go tests and the eval use the same corpus. With -update it
// rewrites the file.
func TestPayloadsFile(t *testing.T) {
	want := PayloadsJSON()
	if *update {
		if err := os.MkdirAll(filepath.Dir(payloadsFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(payloadsFile, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(payloadsFile)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/testutil -update)", err)
	}
	if !bytes.Equal(Normalize(got), want) {
		t.Errorf("%s is out of date; run go test ./internal/testutil -update\n%s", payloadsFile, UnifiedDiff(string(got), string(want)))
	}
	for _, r := range string(got) {
		if r != '\n' && (r < 0x20 || r >= 0x7f) {
			t.Fatalf("%s has a raw non-ASCII or control character %U", payloadsFile, r)
		}
	}
	var f struct{ Payloads []Payload }
	if err := json.Unmarshal(got, &f); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for i, p := range f.Payloads {
		if p != Payloads[i] {
			t.Errorf("payload %d decodes to %+.80v, want %+.80v", i, p, Payloads[i])
		}
		if ids[p.ID] {
			t.Errorf("duplicate payload id %q", p.ID)
		}
		ids[p.ID] = true
	}
	if len(f.Payloads) != len(Payloads) {
		t.Errorf("%d payloads in the file, want %d", len(f.Payloads), len(Payloads))
	}
}

// TestSemanticGraphJSON checks the semantic graph carries every semantic
// value and keeps the real repo beside its lookalike.
func TestSemanticGraphJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "acme", "graph.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Nodes []struct{ ID string }
		Edges []struct{ From, To string }
	}
	if err := json.Unmarshal(SemanticGraphJSON(raw), &g); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	for _, id := range []string{
		"repo:acme-app/web", "repo:acme-app/" + LookalikeRepo, "repo:acme-app/" + InstructionRepo,
		"repo:acme-app/" + MimicRepo, "identity:" + LinkLogin,
		"workflow:acme-app/billing/.github/workflows/" + FakeResultFile,
		"workflow:acme-app/web/.github/workflows/" + ImageFile,
		"workflow:acme-app/" + LookalikeRepo + "/.github/workflows/ci.yml",
	} {
		if !ids[id] {
			t.Errorf("semantic graph lacks node %q", id)
		}
	}
	for _, e := range g.Edges {
		if !ids[e.From] || !ids[e.To] {
			t.Errorf("edge %q -> %q has a missing end", e.From, e.To)
		}
	}
	if len(SemanticValues()) != 6 {
		t.Errorf("SemanticValues = %d values, want 6", len(SemanticValues()))
	}
}

func TestLiveLink(t *testing.T) {
	for _, tc := range []struct {
		in   string
		live bool
	}{
		{"- [ ] Edit [fix](http://example.invalid)", true},
		{"note: ![x](www.example.invalid).yml", true},
		{"bare http://example.invalid", true},
		{"bare WWW.example.invalid", true},
		{`escaped [fix\](http\://example.invalid)`, false},
		{`escaped \[fix\](http\://example.invalid)`, false},
		{`escaped ![x\](www\.example.invalid).yml`, false},
		{"in a span `[fix](http://example.invalid)` ok", false},
		{"```\n[fix](http://example.invalid)\n```", false},
		{"no payload [a](https://docs.example)", false},
	} {
		if got := LiveLink(tc.in) != ""; got != tc.live {
			t.Errorf("LiveLink(%q) = %v, want %v", tc.in, got, tc.live)
		}
	}
	if !OutsideBackticks("x `a` b", "b") || OutsideBackticks("x `a b` c", "a b") {
		t.Error("OutsideBackticks")
	}
	if LineStart("ok\n  danger here", []string{"danger"}) == "" || !strings.Contains(LineStart("x\ny", []string{"y"}), "y") {
		t.Error("LineStart")
	}
}
