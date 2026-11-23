// Package cartography reads the rows of docs/cartography/oidc-trusts.cypher,
// run by the user against a Cartography Neo4j database, and turns them into
// oidc.Trust values for oidc.Enrich and into observed role use for Annotate.
//
// It reads a local export only: no Neo4j driver, no credentials, no network.
//
// Two kinds of rows come out of the query:
//
//   - kind "trust": one (:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal)
//     relationship whose principal is a GitHub Actions OIDC provider.
//     Cartography stores has_condition and conditions, a JSON array with the
//     raw Condition block of every Allow statement that grants the trust (in
//     document order; null when one statement grants it unconditionally).
//     Each block becomes one trust, read by the same AWS parser as a trust
//     file, so a row gives the same Trust as the equivalent trust policy.
//   - kind "observed": one (:GitHubRepository)-[:ASSUMED_ROLE_WITH_WEB_IDENTITY]->(:AWSRole)
//     relationship that Cartography builds from CloudTrail
//     AssumeRoleWithWebIdentity events (times_used, last_used).
//
// Accepted shapes: a plain JSON array of row objects, the Neo4j Browser JSON
// export (row objects, or driver records with keys and _fields), the Neo4j
// HTTP API result ({"results":[{"columns","data":[{"row"}]}]}), and
// cypher-shell --format plain output. Rows that do not fit become warnings,
// never errors.
package cartography

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/oidc"
)

// Row kinds.
const (
	KindTrust    = "trust"
	KindObserved = "observed"
)

// MaxBytes bounds an export file.
const MaxBytes = 64 << 20

// ErrFormat is returned (wrapped) when the export is not one of the accepted
// shapes at all. Problems with single rows are warnings, not errors.
var ErrFormat = errors.New("cartography: unrecognized export format")

// Observation is one repo that CloudTrail saw assume a role.
type Observation struct {
	Row       int    // 0-based row index in the export
	Repo      string // owner/repo
	RoleARN   string
	TimesUsed int64 // 0 when the export does not say
	FirstSeen string
	LastUsed  string
}

// Result is what Parse found.
type Result struct {
	File         string // cleaned path with '/', as recorded in Trust.File
	Trusts       []oidc.Trust
	Observations []Observation
	TrustRows    int // rows of kind trust that produced at least one trust
	Warnings     []string
}

// ReadFile parses the export at path.
func ReadFile(path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, MaxBytes)
	}
	return Parse(path, data)
}

// Parse parses an export. name is the file it came from; it is cleaned and
// recorded as Trust.File so oidc.Enrich can replace the edges of an earlier
// run over the same file.
func Parse(name string, data []byte) (*Result, error) {
	file := filepath.ToSlash(filepath.Clean(name))
	rows, err := decodeRows(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	r := &Result{File: file, Trusts: []oidc.Trust{}}
	for i, row := range rows {
		r.row(i, row)
	}
	return r, nil
}

func (r *Result) warnf(row int, format string, a ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf("%s: row %d: ", r.File, row)+fmt.Sprintf(format, a...))
}

func (r *Result) row(i int, row map[string]any) {
	kind := strings.ToLower(str(row["kind"]))
	if kind == "" {
		switch {
		case str(row["repo"]) != "":
			kind = KindObserved
		case str(row["principal_arn"]) != "":
			kind = KindTrust
		}
	}
	roleARN := strings.TrimSpace(str(row["role_arn"]))
	switch kind {
	case KindTrust, KindObserved:
	default:
		r.warnf(i, "skipped: kind %q is neither %s nor %s", str(row["kind"]), KindTrust, KindObserved)
		return
	}
	if !isRoleARN(roleARN) {
		r.warnf(i, "skipped: role_arn %q is not an IAM role ARN", roleARN)
		return
	}
	if kind == KindObserved {
		r.observed(i, row, roleARN)
		return
	}
	r.trust(i, row, roleARN)
}

func (r *Result) observed(i int, row map[string]any, roleARN string) {
	repo := strings.TrimSpace(str(row["repo"]))
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		r.warnf(i, "skipped: repo %q is not owner/repo", repo)
		return
	}
	o := Observation{Row: i, Repo: repo, RoleARN: roleARN, FirstSeen: str(row["first_seen"]), LastUsed: str(row["last_used"])}
	if v, ok := row["times_used"]; ok && v != nil {
		n, ok := integer(v)
		if !ok || n < 0 {
			r.warnf(i, "times_used %v is not a count, ignored", v)
		} else {
			o.TimesUsed = n
		}
	}
	r.Observations = append(r.Observations, o)
}

// Pointer is the oidc.Trust.Pointer for a trust from row i: condition block
// j of the row, or the row itself when the trust is unconditional or its
// conditions are unknown (j < 0).
func Pointer(i, j int) string {
	if j < 0 {
		return fmt.Sprintf("/%d", i)
	}
	return fmt.Sprintf("/%d/conditions/%d", i, j)
}

// warnUnknownConditions marks a trust whose conditions the export does not
// carry. Its sub pattern is an OpCEL placeholder, so every match is possible.
const warnUnknownConditions = "condition not fully understood, treated as possible: the export does not carry the trust's conditions"

func (r *Result) trust(i int, row map[string]any, roleARN string) {
	principal := strings.TrimSpace(str(row["principal_arn"]))
	if principal == "" {
		r.warnf(i, "skipped: no principal_arn")
		return
	}
	roleName := str(row["role_name"])
	hasCond, hasCondKnown := boolean(row["has_condition"])

	var blocks []any
	var unknown string
	switch c := row["conditions"].(type) {
	case nil:
		if hasCondKnown && hasCond {
			unknown = "has_condition is true but conditions is empty"
		}
	case string:
		if strings.TrimSpace(c) == "" || strings.TrimSpace(c) == "null" {
			if hasCondKnown && hasCond {
				unknown = "has_condition is true but conditions is empty"
			}
			break
		}
		var v any
		if err := json.Unmarshal([]byte(c), &v); err != nil {
			unknown = "conditions is not JSON"
			break
		}
		blocks, unknown = conditionBlocks(v)
	default:
		blocks, unknown = conditionBlocks(c)
	}
	if !hasCondKnown && len(blocks) == 0 && unknown == "" {
		unknown = "has_condition and conditions are missing (Cartography older than the trust condition properties?)"
	}
	if hasCondKnown && !hasCond && len(blocks) > 0 {
		r.warnf(i, "has_condition is false but conditions are set; the trust is read as unconditional, as Cartography defines it")
		blocks = nil
	}

	if unknown != "" {
		r.warnf(i, "%s: conditions unknown, every match is possible", unknown)
		t, ok := r.parseStatements(i, roleARN, roleName, principal, []any{nil})
		if !ok {
			return
		}
		for k := range t {
			t[k].Pointer = Pointer(i, -1)
			t[k].Subjects = append(t[k].Subjects, oidc.Pattern{Raw: "conditions not exported", Op: oidc.OpCEL})
			t[k].Warnings = dedupe(append(t[k].Warnings, warnUnknownConditions))
			t[k].Warnings = removeString(removeString(t[k].Warnings, oidc.WarnNoSub), oidc.WarnNoAud)
		}
		r.Trusts = append(r.Trusts, t...)
		r.TrustRows++
		return
	}
	if len(blocks) == 0 {
		blocks = []any{nil} // unconditional
	}
	t, ok := r.parseStatements(i, roleARN, roleName, principal, blocks)
	if !ok {
		return
	}
	r.Trusts = append(r.Trusts, t...)
	if len(t) > 0 {
		r.TrustRows++
	}
}

// conditionBlocks reads Cartography's conditions value: a list of Condition
// blocks, or a single block.
func conditionBlocks(v any) ([]any, string) {
	switch x := v.(type) {
	case nil:
		return nil, ""
	case map[string]any:
		return []any{x}, ""
	case []any:
		for _, b := range x {
			if _, ok := b.(map[string]any); !ok {
				return nil, "a conditions element is not a Condition object"
			}
		}
		return x, ""
	}
	return nil, "conditions is not a list of Condition objects"
}

// parseStatements turns one row into a role trust policy with one Allow
// statement per condition block and reads it with the oidc AWS parser.
func (r *Result) parseStatements(i int, roleARN, roleName, principal string, blocks []any) ([]oidc.Trust, bool) {
	stmts := make([]any, 0, len(blocks))
	for _, b := range blocks {
		st := map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"Federated": principal},
			"Action":    "sts:AssumeRoleWithWebIdentity",
		}
		if b != nil {
			st["Condition"] = b
		}
		stmts = append(stmts, st)
	}
	role := map[string]any{"Arn": roleARN, "AssumeRolePolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": stmts}}
	if roleName != "" {
		role["RoleName"] = roleName
	}
	doc, err := json.Marshal(map[string]any{"Role": role})
	if err != nil {
		r.warnf(i, "skipped: %v", err)
		return nil, false
	}
	res, err := oidc.ParseBytes(r.File, doc, oidc.Options{})
	if err != nil {
		r.warnf(i, "skipped: %v", err)
		return nil, false
	}
	const stmtPtr = "/Role/AssumeRolePolicyDocument/Statement/"
	for _, w := range res.Warnings {
		w = strings.TrimPrefix(w, r.File+": ")
		if rest, ok := strings.CutPrefix(w, stmtPtr); ok {
			w = "condition block " + rest
		}
		r.warnf(i, "%s", w)
	}
	for k := range res.Trusts {
		t := &res.Trusts[k]
		t.File = r.File
		j, err := strconv.Atoi(strings.TrimPrefix(t.Pointer, stmtPtr))
		if err != nil || j < 0 || j >= len(blocks) || blocks[j] == nil {
			j = -1
		}
		t.Pointer = Pointer(i, j)
	}
	return res.Trusts, true
}

func isRoleARN(s string) bool {
	parts := strings.SplitN(s, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && strings.HasPrefix(parts[5], "role/") && len(parts[5]) > len("role/")
}

// decodeRows reads the export into row objects keyed by column name.
func decodeRows(data []byte) ([]map[string]any, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] != '[' && trimmed[0] != '{' && trimmed[0] != '"' {
		return plainRows(string(trimmed))
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: not JSON: %v", ErrFormat, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after the JSON value", ErrFormat)
	}
	return jsonRows(v)
}

func jsonRows(v any) ([]map[string]any, error) {
	switch x := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, e := range x {
			m, _ := e.(map[string]any)
			out = append(out, recordRow(m)) // a non-object becomes an empty row and a warning
		}
		return out, nil
	case map[string]any:
		if res, ok := x["results"].([]any); ok {
			return httpRows(res), nil
		}
		if rows, ok := x["rows"].([]any); ok {
			return jsonRows(rows)
		}
		return []map[string]any{recordRow(x)}, nil
	}
	return nil, fmt.Errorf("%w: top-level value is not a list or an object", ErrFormat)
}

// recordRow unwraps a Neo4j driver record ({"keys":[...],"_fields":[...]})
// as the Neo4j Browser exports it; other objects are rows already.
func recordRow(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	keys, kok := m["keys"].([]any)
	fields, fok := m["_fields"].([]any)
	if !kok || !fok {
		return normalize(m).(map[string]any)
	}
	row := map[string]any{}
	for i, k := range keys {
		ks, ok := k.(string)
		if !ok || i >= len(fields) {
			continue
		}
		row[ks] = normalize(fields[i])
	}
	return row
}

// httpRows reads the Neo4j HTTP API result shape.
func httpRows(results []any) []map[string]any {
	var out []map[string]any
	for _, rv := range results {
		rm, _ := rv.(map[string]any)
		cols, _ := rm["columns"].([]any)
		data, _ := rm["data"].([]any)
		for _, dv := range data {
			dm, _ := dv.(map[string]any)
			vals, _ := dm["row"].([]any)
			row := map[string]any{}
			for i, c := range cols {
				cs, ok := c.(string)
				if ok && i < len(vals) {
					row[cs] = normalize(vals[i])
				}
			}
			out = append(out, row)
		}
	}
	return out
}

// normalize turns Neo4j driver integers ({"low":n,"high":0}) into numbers.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 2 {
			lo, lok := x["low"].(json.Number)
			hi, hok := x["high"].(json.Number)
			if lok && hok {
				l, err1 := lo.Int64()
				h, err2 := hi.Int64()
				if err1 == nil && err2 == nil {
					return json.Number(strconv.FormatInt(h<<32|int64(uint32(l)), 10))
				}
			}
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}

func boolean(v any) (val, ok bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, true
		}
		f, err := x.Float64()
		if err == nil && f == float64(int64(f)) {
			return int64(f), true
		}
	case float64:
		if x == float64(int64(x)) {
			return int64(x), true
		}
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func removeString(in []string, s string) []string {
	out := in[:0:0]
	for _, e := range in {
		if e != s {
			out = append(out, e)
		}
	}
	return out
}
