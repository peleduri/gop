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
	for _, c := range []struct {
		doc     []byte
		id, ver string
	}{
		{pub.GraphV2, "https://github.com/peleduri/gop/schema/gop.graph.v2.schema.json", graph.SchemaVersion},
		{pub.GraphV1, "https://github.com/peleduri/gop/schema/gop.graph.v1.schema.json", graph.SchemaV1},
	} {
		var doc map[string]any
		if err := json.Unmarshal(c.doc, &doc); err != nil {
			t.Fatal(err)
		}
		if got := doc["$id"]; got != c.id {
			t.Errorf("$id = %v, want %s", got, c.id)
		}
		if got := doc["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("$schema = %v, want draft 2020-12", got)
		}
		props := doc["properties"].(map[string]any)
		if got := props["schema"].(map[string]any)["const"]; got != c.ver {
			t.Errorf("properties.schema.const = %v, want %s", got, c.ver)
		}
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
			if _, ok := Known[r.Schema]; !ok {
				t.Errorf("schema = %q", r.Schema)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	for _, f := range []string{"testdata/valid/minimal.json", "testdata/valid/reach.json", "testdata/valid/ref-protection.json", "testdata/valid/token-write.json", "testdata/valid/actions-access.json", "testdata/valid/can-trigger.json", "testdata/valid/cloud-target.json", "../../testdata/acme/graph.json"} {
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
		"bad-actions-access.json":      {"/nodes/0/attrs/actions_access", `"everyone" is not one of "none", "user", "organization", "enterprise", "public", "unknown"`},
		"bad-edge-kind.json":           {"/edges/0/kind", `"PUSHES" is not one of`},
		"bad-exec.json":                {"/edges/0/attrs/exec", `"fork" is not one of "checkout", "injection"`},
		"bad-external-id.json":         {"/nodes/0/id", `does not match ^external:.+`},
		"bad-evidence.json":            {"/edges/0/evidence", `"seen" is not one of "live", "audit", "supplied", "not_visible"`},
		"bad-node-kind.json":           {"/nodes/0/kind", `"host" is not one of`},
		"bad-line.json":                {"/edges/0/attrs/line", `"L7" does not match`},
		"bad-observed-at.json":         {"/edges/0/observed_at", "RFC 3339"},
		"bad-ref-protected.json":       {"/nodes/0/attrs/ref_protected", `"yes" is not one of "true", "false", "unknown"`},
		"bad-ref-immutable.json":       {"/nodes/0/attrs/ref_immutable", `"maybe" is not one of "true", "false", "unknown"`},
		"bad-token-write.json":         {"/nodes/0/attrs/token_write", `"default" is not one of "true", "false", "unknown"`},
		"bad-repo-id.json":             {"/nodes/0/id", `does not match ^repo:[^/]+/[^/]+$`},
		"bad-team-id.json":             {"/nodes/0/id", `does not match ^(identity:.+|team:[^/]+/[^/]+)$`},
		"coverage-missing-fields.json": {"/coverage/0", `missing required field "needs_fix"`},
		"missing-coverage.json":        {"", `missing required field "coverage"`},
		"missing-node.json":            {"/edges/0/to", `"repo:acme-app/missing" is not a declared node`},
		"missing-schema.json":          {"/schema", `missing required field "schema"`},
		"non-string-attr.json":         {"/nodes/0/attrs/members", "must be of type string, got integer"},
		"not-object.json":              {"", "must be a JSON object"},
		"old-members-id.json":          {"/nodes/0/id", "does not match ^members:"},
		"supplied-no-file.json":        {"/edges/0/attrs", "supplied edge must name the file"},
		"truncated.json":               {"", "not valid JSON"},
		"wrong-schema.json":            {"/schema", `unknown schema version "gop.graph/v3"`},
		"v1-inferred.json":             {"/edges/0/evidence", `"inferred" is not one of "live", "audit", "supplied", "not_visible"`},
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
	if err := json.Unmarshal(pub.GraphV2, &doc); err != nil {
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
	if err := json.Unmarshal(pub.GraphV2, &doc); err != nil {
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

// TestGoAttrValuesValidate builds a CAN_PUSH edge for every Via* constant and a
// USES edge carrying every source position attribute from types.go, so a new
// provenance value or attribute in Go can't be rejected by the schema.
func TestGoAttrValuesValidate(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "graph", "types.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						named[n.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
		}
	}
	var vias []string
	for name, v := range named {
		if strings.HasPrefix(name, "Via") {
			vias = append(vias, v)
		}
	}
	if len(vias) < 4 {
		t.Fatalf("found only %d Via* constants: %v", len(vias), vias)
	}
	g := graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme", Coverage: []graph.Coverage{}}
	g.Nodes = []graph.Node{
		{ID: "identity:alice", Kind: graph.KindIdentity, Name: "alice", Evidence: graph.Live},
		{ID: "repo:acme-app/web", Kind: graph.KindRepo, Name: "web", Evidence: graph.Live},
		{ID: "workflow:acme-app/web/.github/workflows/ci.yml", Kind: graph.KindWorkflow, Name: "ci.yml", Evidence: graph.Live},
		{ID: "action:acme-actions/setup@v1", Kind: graph.KindActionRef, Name: "setup", Evidence: graph.Live,
			Attrs: map[string]string{graph.AttrRef: "main", graph.AttrRefProtected: "true",
				graph.AttrRefProtection: "reviews,dismiss_stale", graph.AttrBypass: "none"}},
	}
	for _, v := range vias {
		g.Edges = append(g.Edges, graph.Edge{From: "identity:alice", To: "repo:acme-app/web", Kind: graph.CanPush,
			Evidence: graph.Live, SourceAPI: "rest:test", Attrs: map[string]string{graph.AttrVia: v, "permission": "write", graph.AttrRef: "main"}})
	}
	g.Edges = append(g.Edges, graph.Edge{From: g.Nodes[2].ID, To: g.Nodes[3].ID, Kind: graph.Uses, Evidence: graph.Live,
		SourceAPI: "rest:test", Attrs: map[string]string{graph.AttrRefKind: "tag", graph.AttrFile: ".github/workflows/ci.yml",
			graph.AttrFileRef: "main", graph.AttrLine: "3", graph.AttrCol: "9"}})
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Validate(data)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid {
		t.Fatalf("graph using every Via* value and source attr is invalid: %v", r.Errors)
	}
}
