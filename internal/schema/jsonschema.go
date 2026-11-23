package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// This file implements the subset of JSON Schema draft 2020-12 that the gop
// schema uses. It is deliberately small: gop ships as one static binary with
// few dependencies, and owning the walker lets every error name its JSON
// pointer. compile rejects any keyword it does not implement, so the schema
// can't silently grow a constraint that is never checked.

// annotations carry no assertion and are accepted anywhere.
var annotations = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "title": true, "description": true,
}

// assertions are the keywords this validator enforces.
var assertions = map[string]bool{
	"$ref": true, "type": true, "const": true, "enum": true, "minLength": true,
	"pattern": true, "format": true, "required": true, "properties": true,
	"additionalProperties": true, "items": true, "allOf": true,
	"if": true, "then": true, "else": true,
}

// compiled is a parsed schema document ready to validate instances.
type compiled struct {
	root     any
	patterns map[string]*regexp.Regexp
}

// compile parses a schema and checks that it uses only supported keywords,
// that every pattern compiles and that every $ref resolves.
func compile(doc []byte) (*compiled, error) {
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("schema: parse: %w", err)
	}
	c := &compiled{root: root, patterns: map[string]*regexp.Regexp{}}
	if err := c.check(root, ""); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *compiled) check(s any, at string) error {
	switch s := s.(type) {
	case bool:
		return nil
	case map[string]any:
		for _, k := range sortedKeys(s) {
			v := s[k]
			if !annotations[k] && !assertions[k] {
				return fmt.Errorf("schema: %s: unsupported keyword %q", at, k)
			}
			sub := at + "/" + escape(k)
			switch k {
			case "$defs", "properties":
				m, ok := v.(map[string]any)
				if !ok {
					return fmt.Errorf("schema: %s: must be an object", sub)
				}
				for _, name := range sortedKeys(m) {
					if err := c.check(m[name], sub+"/"+escape(name)); err != nil {
						return err
					}
				}
			case "items", "additionalProperties", "if", "then", "else":
				if err := c.check(v, sub); err != nil {
					return err
				}
			case "allOf":
				list, ok := v.([]any)
				if !ok {
					return fmt.Errorf("schema: %s: must be an array", sub)
				}
				for i, item := range list {
					if err := c.check(item, sub+"/"+strconv.Itoa(i)); err != nil {
						return err
					}
				}
			case "pattern":
				p, ok := v.(string)
				if !ok {
					return fmt.Errorf("schema: %s: must be a string", sub)
				}
				re, err := regexp.Compile(p)
				if err != nil {
					return fmt.Errorf("schema: %s: %w", sub, err)
				}
				c.patterns[p] = re
			case "$ref":
				ref, ok := v.(string)
				if !ok {
					return fmt.Errorf("schema: %s: must be a string", sub)
				}
				if _, err := c.resolve(ref); err != nil {
					return fmt.Errorf("schema: %s: %w", sub, err)
				}
			case "format":
				if v != "date-time" {
					return fmt.Errorf("schema: %s: unsupported format %v", sub, v)
				}
			}
		}
		return nil
	}
	return fmt.Errorf("schema: %s: a schema must be an object or a boolean", at)
}

// resolve follows a local reference such as "#/$defs/Node".
func (c *compiled) resolve(ref string) (any, error) {
	if ref != "#" && !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("only local $ref is supported, got %q", ref)
	}
	cur := c.root
	for _, tok := range strings.Split(strings.TrimPrefix(ref, "#"), "/")[1:] {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("$ref %q does not resolve", ref)
		}
		if cur, ok = m[tok]; !ok {
			return nil, fmt.Errorf("$ref %q does not resolve", ref)
		}
	}
	return cur, nil
}

// validate returns every violation of schema s by instance v at pointer ptr.
func (c *compiled) validate(s, v any, ptr string) []Problem {
	switch s := s.(type) {
	case bool:
		if s {
			return nil
		}
		return []Problem{{Pointer: ptr, Message: "no value is allowed here"}}
	case map[string]any:
		return c.validateObject(s, v, ptr)
	}
	return []Problem{{Pointer: ptr, Message: "invalid schema"}}
}

func (c *compiled) validateObject(s map[string]any, v any, ptr string) []Problem {
	var out []Problem
	add := func(format string, a ...any) {
		out = append(out, Problem{Pointer: ptr, Message: fmt.Sprintf(format, a...)})
	}
	if ref, ok := s["$ref"].(string); ok {
		target, err := c.resolve(ref)
		if err != nil {
			add("%v", err)
		} else {
			out = append(out, c.validate(target, v, ptr)...)
		}
	}
	if t, ok := s["type"]; ok && !typeMatches(t, v) {
		add("must be of type %s, got %s", typeList(t), typeOf(v))
		return out // the remaining keywords assume the right type
	}
	if want, ok := s["const"]; ok && !reflect.DeepEqual(want, v) {
		add("must be %s, got %s", show(want), show(v))
	}
	if enum, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if reflect.DeepEqual(e, v) {
				found = true
				break
			}
		}
		if !found {
			vals := make([]string, len(enum))
			for i, e := range enum {
				vals[i] = show(e)
			}
			add("%s is not one of %s", show(v), strings.Join(vals, ", "))
		}
	}
	if str, ok := v.(string); ok {
		if n, ok := s["minLength"].(float64); ok && float64(utf8.RuneCountInString(str)) < n {
			add("must be at least %d characters", int(n))
		}
		if p, ok := s["pattern"].(string); ok && !c.patterns[p].MatchString(str) {
			add("%s does not match %s", show(str), p)
		}
		if s["format"] == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				add("%s is not an RFC 3339 date-time", show(str))
			}
		}
	}
	if obj, ok := v.(map[string]any); ok {
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if name, _ := r.(string); name != "" {
					if _, ok := obj[name]; !ok {
						add("missing required field %q", name)
					}
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		extra, hasExtra := s["additionalProperties"]
		for _, k := range sortedKeys(obj) {
			sub := ptr + "/" + escape(k)
			if ps, ok := props[k]; ok {
				out = append(out, c.validate(ps, obj[k], sub)...)
			} else if hasExtra {
				out = append(out, c.validate(extra, obj[k], sub)...)
			}
		}
	}
	if arr, ok := v.([]any); ok {
		if items, ok := s["items"]; ok {
			for i, item := range arr {
				out = append(out, c.validate(items, item, ptr+"/"+strconv.Itoa(i))...)
			}
		}
	}
	if all, ok := s["allOf"].([]any); ok {
		for _, sub := range all {
			out = append(out, c.validate(sub, v, ptr)...)
		}
	}
	if cond, ok := s["if"]; ok {
		if len(c.validate(cond, v, ptr)) == 0 {
			if then, ok := s["then"]; ok {
				out = append(out, c.validate(then, v, ptr)...)
			}
		} else if els, ok := s["else"]; ok {
			out = append(out, c.validate(els, v, ptr)...)
		}
	}
	return out
}

func typeMatches(t, v any) bool {
	switch t := t.(type) {
	case string:
		return typeIs(t, v)
	case []any:
		for _, x := range t {
			if name, _ := x.(string); typeIs(name, v) {
				return true
			}
		}
	}
	return false
}

func typeIs(name string, v any) bool {
	got := typeOf(v)
	if name == "number" && got == "integer" {
		return true
	}
	return name == got
}

func typeOf(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if v == float64(int64(v)) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

func typeList(t any) string {
	if list, ok := t.([]any); ok {
		parts := make([]string, len(list))
		for i, x := range list {
			parts[i] = fmt.Sprint(x)
		}
		return strings.Join(parts, " or ")
	}
	return fmt.Sprint(t)
}

// show renders a JSON value compactly for messages.
func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// escape encodes one JSON pointer reference token (RFC 6901).
func escape(tok string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(tok)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
