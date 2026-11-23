package graph

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// FuzzLoad: Load never panics on arbitrary bytes, and any graph it accepts can
// be indexed and scored without a panic.
func FuzzLoad(f *testing.F) {
	if b, err := os.ReadFile("../../testdata/acme/graph.json"); err == nil {
		f.Add(b)
	}
	for _, seed := range []uint64{1, 7, 42} {
		if b, err := json.Marshal(genGraph(propRand(seed), 12)); err == nil {
			f.Add(b)
		}
	}
	for _, s := range []string{
		``, `{`, `null`, `[]`, `{"schema":"gop.graph/v1"}`,
		`{"schema":"gop.graph/v1","nodes":null,"edges":null}`,
		`{"schema":"gop.graph/v2","collected_at":"2026-11-20T10:00:00Z","audit_retention_days":180,"edges":[{"from":"members:acme","to":"repo:acme/web","kind":"CAN_PUSH","evidence":"inferred","attrs":{"rule":"default_perm"}},{"from":"identity:bob","to":"repo:acme/web","kind":"CAN_PUSH","evidence":"audit","observed_at":"2026-01-01T00:00:00Z"}]}`,
		`{"schema":"gop.graph/v1","edges":[{"from":"members:acme","to":"repo:acme/web","kind":"CAN_PUSH","evidence":"live"}]}`,
		`{"schema":"gop.graph/v1","edges":[{"from":"a","to":"a","kind":"USES","evidence":"not_visible"},{"from":"a","to":"a","kind":"RESOLVES_TO","evidence":"audit"}]}`,
		`{"schema":"gop.graph/v1","edges":[{"from":"identity:x","to":"org:","kind":"MEMBER_OF","evidence":"live"},{"from":"members:","to":"repo:/","kind":"CAN_PUSH","evidence":"live","attrs":{"via":"default_perm"}}]}`,
		`{"schema":"gop.graph/v1","nodes":[{"id":"org:acme","kind":"org","attrs":{"default_perm":"write","sso":"none","two_factor":"not_required"}},{"id":"org:acme","kind":"repo"}]}`,
		`{"schema":"gop.graph/v1","nodes":[{"id":"repo:x/a","kind":"repo","attrs":{"actions_access":"unknown"}}],"edges":[{"from":"action:x/a@main","to":"repo:x/a","kind":"RESOLVES_TO","evidence":"live"},{"from":"workflow:y/b/w.yml","to":"action:x/a@main","kind":"USES","evidence":"live"},{"from":"action:@","to":"action:x/a@main","kind":"USES","evidence":"live"}]}`,
		"{\"schema\":\"gop.graph/v1\",\"edges\":[{\"from\":\"\xff\",\"to\":\"x\",\"kind\":\"USES\",\"evidence\":\"live\"}]}",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := Load(bytes.NewReader(data))
		if err != nil {
			return
		}
		ix := NewIndex(g)
		ix.TopPaths(0)
		for _, p := range ix.Principals() {
			ix.Reach(p, Options{})
		}
		ix.SuggestFixes(2)
	})
}
