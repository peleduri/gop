// Package schema validates graph.json against the published JSON Schema
// (schema/gop.graph.v1.schema.json) plus the cross-references a schema can't
// express. Validation is opt-in: graph.Load does not call it.
package schema

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/peleduri/gop/internal/graph"
	pub "github.com/peleduri/gop/schema"
)

// Problem is one finding, located by its JSON pointer (RFC 6901; "" is the
// document root).
type Problem struct {
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

func (p Problem) String() string {
	ptr := p.Pointer
	if ptr == "" {
		ptr = "(root)"
	}
	return ptr + ": " + p.Message
}

// Result is the outcome of Validate. Errors make the graph invalid; warnings
// do not.
type Result struct {
	Schema   string    `json:"schema,omitempty"`
	Valid    bool      `json:"valid"`
	Errors   []Problem `json:"errors"`
	Warnings []Problem `json:"warnings"`
}

// Known maps each schema version gop understands to its JSON Schema document.
var Known = map[string][]byte{
	graph.SchemaVersion: pub.GraphV1,
}

// KnownVersions returns the supported schema versions, sorted.
func KnownVersions() []string { return sortedKeys(Known) }

var (
	compileMu sync.Mutex
	compiledV = map[string]*compiled{}
)

func compiledFor(version string) (*compiled, error) {
	compileMu.Lock()
	defer compileMu.Unlock()
	if c, ok := compiledV[version]; ok {
		return c, nil
	}
	c, err := compile(Known[version])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", version, err)
	}
	compiledV[version] = c
	return c, nil
}

// Validate checks a serialized graph:
//   - the document is JSON and its "schema" field names a known version;
//   - it conforms to that version's JSON Schema;
//   - every edge endpoint is declared as a node;
//   - every not_visible fact has a coverage entry for its scope (warning).
//
// The returned error is only for a broken embedded schema; problems with the
// graph itself are reported in the Result.
func Validate(data []byte) (*Result, error) {
	r := &Result{Errors: []Problem{}, Warnings: []Problem{}}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		r.Errors = append(r.Errors, Problem{Pointer: "", Message: "not valid JSON: " + err.Error()})
		return r, nil
	}
	top, ok := doc.(map[string]any)
	if !ok {
		r.Errors = append(r.Errors, Problem{Pointer: "", Message: "must be a JSON object, got " + typeOf(doc)})
		return r, nil
	}
	version, _ := top["schema"].(string)
	if _, known := Known[version]; !known {
		msg := fmt.Sprintf("unknown schema version %s (known: %v)", show(top["schema"]), KnownVersions())
		if _, present := top["schema"]; !present {
			msg = fmt.Sprintf("missing required field \"schema\" (known versions: %v)", KnownVersions())
		}
		r.Errors = append(r.Errors, Problem{Pointer: "/schema", Message: msg})
		return r, nil
	}
	r.Schema = version
	c, err := compiledFor(version)
	if err != nil {
		return nil, err
	}
	r.Errors = append(r.Errors, c.validate(c.root, doc, "")...)
	r.Errors = append(r.Errors, checkEndpoints(top)...)
	r.Warnings = append(r.Warnings, checkCoverage(top)...)
	sortProblems(r.Errors)
	sortProblems(r.Warnings)
	r.Valid = len(r.Errors) == 0
	return r, nil
}

func objects(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, len(list))
	for i, x := range list {
		out[i], _ = x.(map[string]any)
	}
	return out
}

// checkEndpoints reports edges whose from or to is not a declared node.
func checkEndpoints(top map[string]any) []Problem {
	ids := map[string]bool{}
	for _, n := range objects(top["nodes"]) {
		if id, ok := n["id"].(string); ok {
			ids[id] = true
		}
	}
	var out []Problem
	for i, e := range objects(top["edges"]) {
		for _, end := range []string{"from", "to"} {
			id, ok := e[end].(string)
			if !ok || id == "" || ids[id] {
				continue // missing or mistyped endpoints are schema errors
			}
			out = append(out, Problem{
				Pointer: fmt.Sprintf("/edges/%d/%s", i, end),
				Message: fmt.Sprintf("edge endpoint %q is not a declared node", id),
			})
		}
	}
	return out
}

// checkCoverage warns about not_visible nodes, attributes and edges that have
// no coverage entry for the element itself or its org. Coverage is what tells
// the reader which access would make the fact visible.
func checkCoverage(top map[string]any) []Problem {
	scopes := map[string]bool{}
	for _, c := range objects(top["coverage"]) {
		if s, ok := c["scope"].(string); ok {
			scopes[s] = true
		}
	}
	covered := func(ids ...string) bool {
		for _, id := range ids {
			if id != "" && (scopes[id] || scopes[graph.OrgOf(id)] || scopes[workflowRepo(id)]) {
				return true
			}
		}
		return false
	}
	nv := string(graph.NotVisible)
	var out []Problem
	for i, n := range objects(top["nodes"]) {
		id, _ := n["id"].(string)
		if covered(id) {
			continue
		}
		if n["evidence"] == nv {
			out = append(out, Problem{
				Pointer: fmt.Sprintf("/nodes/%d/evidence", i),
				Message: fmt.Sprintf("node %q is not_visible but no coverage entry has scope %s", id, scopeHint(id)),
			})
		}
		ae, _ := n["attr_evidence"].(map[string]any)
		for _, k := range sortedKeys(ae) {
			if ae[k] == nv {
				out = append(out, Problem{
					Pointer: fmt.Sprintf("/nodes/%d/attr_evidence/%s", i, escape(k)),
					Message: fmt.Sprintf("attribute %q of %q is not_visible but no coverage entry has scope %s", k, id, scopeHint(id)),
				})
			}
		}
	}
	for i, e := range objects(top["edges"]) {
		if e["evidence"] != nv {
			continue
		}
		from, _ := e["from"].(string)
		to, _ := e["to"].(string)
		if !covered(from, to) {
			out = append(out, Problem{
				Pointer: fmt.Sprintf("/edges/%d/evidence", i),
				Message: fmt.Sprintf("edge %s -> %s is not_visible but no coverage entry has a scope for either end or its org", from, to),
			})
		}
	}
	return out
}

// workflowRepo returns "repo:O/R" for "workflow:O/R/<path>": coverage on a
// repo also covers the workflows in it. "" for any other ID.
func workflowRepo(id string) string {
	rest, ok := strings.CutPrefix(id, "workflow:")
	if !ok {
		return ""
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "repo:" + parts[0] + "/" + parts[1]
}

func scopeHint(id string) string {
	if org := graph.OrgOf(id); org != "" && org != id {
		if r := workflowRepo(id); r != "" {
			return fmt.Sprintf("%q, %q or %q", id, r, org)
		}
		return fmt.Sprintf("%q or %q", id, org)
	}
	return fmt.Sprintf("%q", id)
}

// sortProblems orders problems by pointer, comparing array indexes as numbers
// so /edges/2 comes before /edges/10.
func sortProblems(ps []Problem) {
	sort.SliceStable(ps, func(i, j int) bool { return pointerLess(ps[i].Pointer, ps[j].Pointer) })
}

func pointerLess(a, b string) bool {
	at, bt := strings.Split(a, "/"), strings.Split(b, "/")
	for k := 0; k < len(at) && k < len(bt); k++ {
		if at[k] == bt[k] {
			continue
		}
		ai, aerr := strconv.Atoi(at[k])
		bi, berr := strconv.Atoi(bt[k])
		if aerr == nil && berr == nil {
			return ai < bi
		}
		return at[k] < bt[k]
	}
	return len(at) < len(bt)
}
