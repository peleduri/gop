package sarif

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This file is a test-only JSON Schema draft-04 validator for exactly the
// keywords the vendored SARIF 2.1.0 schema (testdata/sarif-schema-2.1.0.json,
// from the OASIS sarif-spec repository) uses. Unknown keywords fail the test,
// so the validator never silently skips a constraint.

var draft4Keywords = map[string]bool{
	// annotations
	"$schema": true, "id": true, "title": true, "description": true, "default": true, "definitions": true,
	// assertions
	"$ref": true, "type": true, "properties": true, "additionalProperties": true, "required": true,
	"items": true, "minItems": true, "uniqueItems": true, "minimum": true, "maximum": true,
	"pattern": true, "enum": true, "anyOf": true, "oneOf": true, "format": true,
}

type draft4 struct {
	root map[string]any
}

func loadSARIFSchema(t *testing.T) *draft4 {
	t.Helper()
	data, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	d := &draft4{root: root}
	if err := d.check(root, "#"); err != nil {
		t.Fatal(err)
	}
	return d
}

// check rejects unsupported keywords anywhere in the schema.
func (d *draft4) check(s any, at string) error {
	m, ok := s.(map[string]any)
	if !ok {
		return nil
	}
	for k, v := range m {
		if !draft4Keywords[k] {
			return fmt.Errorf("%s: unsupported keyword %q", at, k)
		}
		switch k {
		case "properties", "definitions":
			for name, sub := range v.(map[string]any) {
				if err := d.check(sub, at+"/"+k+"/"+name); err != nil {
					return err
				}
			}
		case "items", "additionalProperties":
			if err := d.check(v, at+"/"+k); err != nil {
				return err
			}
		case "anyOf", "oneOf":
			for i, sub := range v.([]any) {
				if err := d.check(sub, fmt.Sprintf("%s/%s/%d", at, k, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (d *draft4) resolve(ref string) map[string]any {
	name, ok := strings.CutPrefix(ref, "#/definitions/")
	if !ok {
		panic("unsupported $ref " + ref)
	}
	return d.root["definitions"].(map[string]any)[name].(map[string]any)
}

// Validate returns the problems of instance v, each prefixed with its JSON pointer.
func (d *draft4) Validate(v any) []string {
	var out []string
	d.validate(d.root, v, "", &out)
	sort.Strings(out)
	return out
}

func (d *draft4) validate(s map[string]any, v any, ptr string, out *[]string) {
	fail := func(format string, a ...any) { *out = append(*out, ptr+": "+fmt.Sprintf(format, a...)) }
	if ref, ok := s["$ref"].(string); ok {
		d.validate(d.resolve(ref), v, ptr, out)
		return
	}
	if t, ok := s["type"]; ok && !typeOK(t, v) {
		fail("type %v, got %T", t, v)
		return
	}
	if enum, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if reflect.DeepEqual(e, v) {
				found = true
			}
		}
		if !found {
			fail("%v not in enum %v", v, enum)
		}
	}
	switch x := v.(type) {
	case map[string]any:
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, ok := x[r.(string)]; !ok {
					fail("missing required %q", r)
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, val := range x {
			if ps, ok := props[k].(map[string]any); ok {
				d.validate(ps, val, ptr+"/"+k, out)
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					fail("additional property %q", k)
				}
			case map[string]any:
				d.validate(ap, val, ptr+"/"+k, out)
			}
		}
	case []any:
		if mi, ok := s["minItems"].(float64); ok && float64(len(x)) < mi {
			fail("%d items, want at least %v", len(x), mi)
		}
		if u, ok := s["uniqueItems"].(bool); ok && u {
			for i := range x {
				for j := i + 1; j < len(x); j++ {
					if reflect.DeepEqual(x[i], x[j]) {
						fail("items %d and %d are equal", i, j)
					}
				}
			}
		}
		if is, ok := s["items"].(map[string]any); ok {
			for i, item := range x {
				d.validate(is, item, fmt.Sprintf("%s/%d", ptr, i), out)
			}
		}
	case float64:
		if mn, ok := s["minimum"].(float64); ok && x < mn {
			fail("%v below minimum %v", x, mn)
		}
		if mx, ok := s["maximum"].(float64); ok && x > mx {
			fail("%v above maximum %v", x, mx)
		}
	case string:
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(x) {
			fail("%q does not match %q", x, p)
		}
		if f, ok := s["format"].(string); ok {
			switch f {
			case "uri":
				if u, err := url.Parse(x); err != nil || !u.IsAbs() {
					fail("%q is not an absolute uri", x)
				}
			case "uri-reference":
				if _, err := url.Parse(x); err != nil {
					fail("%q is not a uri-reference", x)
				}
			}
		}
	}
	for _, kw := range []string{"anyOf", "oneOf"} {
		subs, ok := s[kw].([]any)
		if !ok {
			continue
		}
		n := 0
		for _, sub := range subs {
			var probs []string
			d.validate(sub.(map[string]any), v, ptr, &probs)
			if len(probs) == 0 {
				n++
			}
		}
		if (kw == "anyOf" && n == 0) || (kw == "oneOf" && n != 1) {
			fail("%s: %d of %d subschemas match", kw, n, len(subs))
		}
	}
}

func typeOK(t, v any) bool {
	if list, ok := t.([]any); ok {
		for _, x := range list {
			if typeOK(x, v) {
				return true
			}
		}
		return false
	}
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	case "null":
		return v == nil
	}
	panic(fmt.Sprintf("unsupported type %v", t))
}

func TestDraft4ValidatorRejects(t *testing.T) {
	d := loadSARIFSchema(t)
	for name, doc := range map[string]string{
		"no version":     `{"runs": []}`,
		"bad version":    `{"version": "2.0.0", "runs": []}`,
		"extra property": `{"version": "2.1.0", "runs": [], "bogus": 1}`,
		"no tool":        `{"version": "2.1.0", "runs": [{"results": []}]}`,
		"line zero": `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gop"}}, "results": [
			{"message": {"text": "x"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"}, "region": {"startLine": 0}}}]}]}]}`,
		"message without text":    `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gop"}}, "results": [{"message": {}}]}]}`,
		"relative informationUri": `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gop", "informationUri": "gop"}}}]}`,
	} {
		var v any
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			t.Fatal(err)
		}
		if probs := d.Validate(v); len(probs) == 0 {
			t.Errorf("%s: validated, want problems", name)
		}
	}
}
