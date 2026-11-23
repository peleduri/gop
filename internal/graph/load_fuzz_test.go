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
		`{"schema":"gop.graph/v1","edges":[{"from":"members:acme","to":"repo:acme/web","kind":"CAN_PUSH","evidence":"live"}]}`,
		`{"schema":"gop.graph/v1","edges":[{"from":"a","to":"a","kind":"USES","evidence":"not_visible"},{"from":"a","to":"a","kind":"RESOLVES_TO","evidence":"audit"}]}`,
		`{"schema":"gop.graph/v1","edges":[{"from":"identity:x","to":"org:","kind":"MEMBER_OF","evidence":"live"},{"from":"members:","to":"repo:/","kind":"CAN_PUSH","evidence":"live","attrs":{"via":"default_perm"}}]}`,
		`{"schema":"gop.graph/v1","nodes":[{"id":"org:acme","kind":"org","attrs":{"default_perm":"write","sso":"none","two_factor":"not_required"}},{"id":"org:acme","kind":"repo"}]}`,
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
