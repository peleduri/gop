package schema

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	pub "github.com/peleduri/gop/schema"
)

func validateFile(t *testing.T, path string) *Result {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Validate(data)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return r
}

func TestEmbeddedSchemaCompiles(t *testing.T) {
	for _, v := range KnownVersions() {
		if _, err := compiledFor(v); err != nil {
			t.Fatal(err)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(pub.GraphV1, &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := doc["$id"], "https://github.com/peleduri/gop/schema/gop.graph.v1.schema.json"; got != want {
		t.Errorf("$id = %v, want %s", got, want)
	}
	if got := doc["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v, want draft 2020-12", got)
	}
	props := doc["properties"].(map[string]any)
	if got := props["schema"].(map[string]any)["const"]; got != graph.SchemaVersion {
		t.Errorf("properties.schema.const = %v, want %s", got, graph.SchemaVersion)
	}
}

func TestValidFixtures(t *testing.T) {
	files, _ := filepath.Glob("testdata/valid/*.json")
	files = append(files, filepath.Join("..", "..", "testdata", "acme", "graph.json"))
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			r := validateFile(t, f)
			if !r.Valid || len(r.Errors) > 0 {
				t.Fatalf("want valid, got errors %v", r.Errors)
			}
			if r.Schema != graph.SchemaVersion {
				t.Errorf("schema = %q", r.Schema)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	for _, f := range []string{"testdata/valid/minimal.json", "testdata/valid/reach.json", "../../testdata/acme/graph.json"} {
		if r := validateFile(t, f); len(r.Warnings) > 0 {
			t.Errorf("%s: unexpected warnings %v", f, r.Warnings)
		}
	}
	r := validateFile(t, "testdata/valid/uncovered.json")
	got := pointers(r.Warnings)
	want := []string{"/edges/0/evidence", "/nodes/1/evidence"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings at %v, want %v (%v)", got, want, r.Warnings)
	}
	if !strings.Contains(r.Warnings[1].Message, `"org:acme-legacy"`) {
		t.Errorf("warning should name the org scope: %s", r.Warnings[1].Message)
	}
}

func TestInvalidFixtures(t *testing.T) {
	// Each invalid fixture must produce an error at this JSON pointer whose
	// message contains the given text.
	want := map[string]struct{ ptr, msg string }{
		"bad-edge-kind.json":           {"/edges/0/kind", `"PUSHES" is not one of`},
		"bad-evidence.json":            {"/edges/0/evidence", `"seen" is not one of "live", "audit", "not_visible"`},
		"bad-node-kind.json":           {"/nodes/0/kind", `"host" is not one of`},
		"bad-observed-at.json":         {"/edges/0/observed_at", "RFC 3339"},
		"bad-repo-id.json":             {"/nodes/0/id", `does not match ^repo:[^/]+/[^/]+$`},
		"coverage-missing-fields.json": {"/coverage/0", `missing required field "needs_fix"`},
		"missing-coverage.json":        {"", `missing required field "coverage"`},
		"missing-node.json":            {"/edges/0/to", `"repo:acme-app/missing" is not a declared node`},
		"missing-schema.json":          {"/schema", `missing required field "schema"`},
		"non-string-attr.json":         {"/nodes/0/attrs/members", "must be of type string, got integer"},
		"not-object.json":              {"", "must be a JSON object"},
		"old-members-id.json":          {"/nodes/0/id", "does not match ^members:"},
		"truncated.json":               {"", "not valid JSON"},
		"wrong-schema.json":            {"/schema", `unknown schema version "gop.graph/v2"`},
	}
	files, _ := filepath.Glob("testdata/invalid/*.json")
	if len(files) != len(want) {
		t.Errorf("%d invalid fixtures, %d expectations: keep them in sync", len(files), len(want))
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			w, ok := want[name]
			if !ok {
				t.Fatalf("no expectation for %s", name)
			}
			r := validateFile(t, f)
			if r.Valid {
				t.Fatal("want invalid")
			}
			for _, p := range r.Errors {
				if p.Pointer == w.ptr && strings.Contains(p.Message, w.msg) {
					return
				}
			}
			t.Fatalf("no error at %q containing %q; got %v", w.ptr, w.msg, r.Errors)
		})
	}
}

func TestEveryNodeKindHasIDPattern(t *testing.T) {
	var doc struct {
		Defs map[string]struct {
			AllOf []struct {
				If struct {
					Properties struct {
						Kind struct {
							Const string `json:"const"`
						} `json:"kind"`
					} `json:"properties"`
				} `json:"if"`
			} `json:"allOf"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(pub.GraphV1, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range doc.Defs["Node"].AllOf {
		got = append(got, a.If.Properties.Kind.Const)
	}
	sort.Strings(got)
	want := goConstants(t)["NodeKind"]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Node id patterns cover kinds %v, want %v", got, want)
	}
}

// TestEnumsMatchGoConstants fails when internal/graph/types.go gains (or
// loses) an Evidence, NodeKind or EdgeKind constant that the schema enums do
// not list.
func TestEnumsMatchGoConstants(t *testing.T) {
	var doc struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(pub.GraphV1, &doc); err != nil {
		t.Fatal(err)
	}
	consts := goConstants(t)
	for _, typ := range []string{"Evidence", "NodeKind", "EdgeKind"} {
		got := append([]string(nil), doc.Defs[typ].Enum...)
		sort.Strings(got)
		if len(consts[typ]) == 0 {
			t.Fatalf("no %s constants found in types.go", typ)
		}
		if !reflect.DeepEqual(got, consts[typ]) {
			t.Errorf("schema $defs.%s.enum = %v, types.go constants = %v", typ, got, consts[typ])
		}
	}
}

// goConstants parses internal/graph/types.go and returns the sorted string
// values of constants declared with an explicit Evidence/NodeKind/EdgeKind type.
func goConstants(t *testing.T) map[string][]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "graph", "types.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			id, ok := vs.Type.(*ast.Ident)
			if !ok {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s constant is not a string literal", id.Name)
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				out[id.Name] = append(out[id.Name], val)
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func TestCompileRejectsUnsupportedKeywords(t *testing.T) {
	for _, doc := range []string{
		`{"type": "object", "patternProperties": {"^x": {}}}`,
		`{"properties": {"a": {"oneOf": [{}]}}}`,
		`{"format": "email"}`,
		`{"$ref": "#/$defs/Missing"}`,
		`{"$ref": "https://example.com/other.json"}`,
		`{"pattern": "("}`,
		`{"items": 3}`,
	} {
		if _, err := compile([]byte(doc)); err == nil {
			t.Errorf("compile(%s) succeeded, want error", doc)
		}
	}
}

func TestValidatorKeywords(t *testing.T) {
	cases := []struct {
		schema, inst string
		wantPtrs     []string
	}{
		{`{"type": ["string", "null"]}`, `null`, nil},
		{`{"type": ["string", "null"]}`, `1`, []string{""}},
		{`{"type": "number"}`, `1`, nil},
		{`{"type": "integer"}`, `1.5`, []string{""}},
		{`{"minLength": 2}`, `"é"`, []string{""}},
		{`{"properties": {"a~b/c": {"const": 1}}}`, `{"a~b/c": 2}`, []string{"/a~0b~1c"}},
		{`{"additionalProperties": false, "properties": {"a": true}}`, `{"a": 1, "b": 2}`, []string{"/b"}},
		{`{"if": {"const": 1}, "then": false, "else": {"type": "string"}}`, `1`, []string{""}},
		{`{"if": {"const": 1}, "then": false, "else": {"type": "string"}}`, `2`, []string{""}},
		{`{"if": {"const": 1}, "then": false, "else": {"type": "string"}}`, `"x"`, nil},
		{`{"items": {"type": "string"}}`, `["a", 1, "b", 2]`, []string{"/1", "/3"}},
	}
	for _, tc := range cases {
		c, err := compile([]byte(tc.schema))
		if err != nil {
			t.Fatalf("compile %s: %v", tc.schema, err)
		}
		var v any
		if err := json.Unmarshal([]byte(tc.inst), &v); err != nil {
			t.Fatal(err)
		}
		if got := pointers(c.validate(c.root, v, "")); !reflect.DeepEqual(got, tc.wantPtrs) {
			t.Errorf("schema %s, instance %s: errors at %v, want %v", tc.schema, tc.inst, got, tc.wantPtrs)
		}
	}
}

func TestLoadUnchanged(t *testing.T) {
	// Validation is opt-in: graph.Load still accepts what it accepted before,
	// including a graph whose edge points at an undeclared node.
	f, err := os.Open("testdata/invalid/missing-node.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := graph.Load(f); err != nil {
		t.Fatalf("graph.Load: %v", err)
	}
}

func pointers(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Pointer)
	}
	return out
}

func TestPointerOrder(t *testing.T) {
	ps := []Problem{{Pointer: "/nodes/0"}, {Pointer: "/edges/10/to"}, {Pointer: "/edges/2/from"}, {Pointer: ""}, {Pointer: "/edges/2"}}
	sortProblems(ps)
	want := []string{"", "/edges/2", "/edges/2/from", "/edges/10/to", "/nodes/0"}
	if got := pointers(ps); !reflect.DeepEqual(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}
