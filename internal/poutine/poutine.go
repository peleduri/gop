// Package poutine reads a poutine JSON report (poutine analyze_org,
// analyze_repo or analyze_local with --format json, see docs/poutine.md) and
// annotates the gop workflow nodes its findings point to.
//
// gop never runs poutine. It reads a local report only: no network, no
// token. poutine finds flaws inside a pipeline (script injection, untrusted
// checkout, self-hosted runners on public repos); gop finds who can reach the
// pipeline. A finding is cited as a separate source on the workflow node and
// never changes the evidence of any gop fact.
//
// The report shape, from poutine v1.1.6 (formatters/json and
// opa/rego/poutine/format/json.rego), is:
//
//	{"rules":    {"<rule id>": {"id", "title", "description", "level", ...}},
//	 "findings": [{"rule_id", "purl", "meta": {"path", "line", "job", "step", ...}}],
//	 "packages": {...}}
//
// purl is the scanned repository, e.g.
// pkg:github/acme-app/web@main?repository_url=github.acme.example for a
// GitHub Enterprise Server host; meta.path is the repo-relative workflow file.
package poutine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// MaxBytes bounds a report file.
const MaxBytes = 64 << 20

// ErrFormat is returned (wrapped) when the file is not a poutine JSON report.
// Problems with single findings are warnings, not errors.
var ErrFormat = errors.New("poutine: not a poutine JSON report")

// Rule levels, highest first. poutine rules declare one of these in their
// metadata (custom.level), note by default.
const (
	LevelError   = "error"
	LevelWarning = "warning"
	LevelNote    = "note"
)

// levelRank orders levels; an unknown level ranks 0.
var levelRank = map[string]int{LevelNote: 1, LevelWarning: 2, LevelError: 3}

// Finding is one poutine finding.
type Finding struct {
	Index  int    // 0-based index in the report's findings array
	RuleID string // e.g. injection, untrusted_checkout_exec
	Level  string // the rule's level from the report's rules, "" when absent
	Purl   string // as poutine wrote it
	Repo   string // owner/repo from a pkg:github purl, "" otherwise
	Path   string // repo-relative file, e.g. .github/workflows/ci.yml; "" when poutine gives none
	Job    string // job id, "" when poutine gives none
	Line   int    // 1-based, 0 when poutine gives none
	// Problem is why the finding cannot be matched to a workflow by repo and
	// path (not a GitHub repo, no path), "" when it can be tried.
	Problem string
}

// Result is what Parse found.
type Result struct {
	File     string // cleaned path with '/'
	Findings []Finding
	Rules    int // rules the report describes
	Warnings []string
}

// ReadFile parses the report at path.
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

type rawRule struct {
	Level string `json:"level"`
}

type rawFinding struct {
	RuleID string          `json:"rule_id"`
	Purl   string          `json:"purl"`
	Meta   json.RawMessage `json:"meta"`
}

type rawMeta struct {
	Path string          `json:"path"`
	Job  json.RawMessage `json:"job"`
	Line json.RawMessage `json:"line"`
}

// Parse parses a report. name is the file it came from.
func Parse(name string, data []byte) (*Result, error) {
	file := filepath.ToSlash(filepath.Clean(name))
	data = bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf"))
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("%s: %w: %v (run poutine with --format json)", file, ErrFormat, err)
	}
	rawFindings, ok := top["findings"]
	if !ok {
		if _, sarif := top["runs"]; sarif {
			return nil, fmt.Errorf("%s: %w: this is SARIF; gop reads poutine's JSON output (run poutine with --format json)", file, ErrFormat)
		}
		return nil, fmt.Errorf("%s: %w: no \"findings\" key (run poutine with --format json)", file, ErrFormat)
	}
	var findings []json.RawMessage
	if string(rawFindings) != "null" {
		if err := json.Unmarshal(rawFindings, &findings); err != nil {
			return nil, fmt.Errorf("%s: %w: \"findings\" is not an array", file, ErrFormat)
		}
	}
	rules := map[string]rawRule{}
	if rr, ok := top["rules"]; ok && string(rr) != "null" {
		if err := json.Unmarshal(rr, &rules); err != nil {
			return nil, fmt.Errorf("%s: %w: \"rules\" is not an object of rules", file, ErrFormat)
		}
	}
	r := &Result{File: file, Findings: []Finding{}, Rules: len(rules)}
	for i, raw := range findings {
		var rf rawFinding
		if err := json.Unmarshal(raw, &rf); err != nil {
			r.warnf(i, "skipped: not a finding object: %v", err)
			continue
		}
		rf.RuleID = strings.TrimSpace(rf.RuleID)
		if rf.RuleID == "" {
			r.warnf(i, "skipped: no rule_id")
			continue
		}
		var m rawMeta
		if len(rf.Meta) > 0 && string(rf.Meta) != "null" {
			if err := json.Unmarshal(rf.Meta, &m); err != nil {
				r.warnf(i, "rule %s: meta is not an object: %v", rf.RuleID, err)
			}
		}
		f := Finding{Index: i, RuleID: rf.RuleID, Purl: rf.Purl, Path: cleanPath(m.Path),
			Job: scalar(m.Job), Line: line(m.Line)}
		if rule, ok := rules[f.RuleID]; ok {
			f.Level = strings.ToLower(strings.TrimSpace(rule.Level))
		}
		repo, problem := repoOf(rf.Purl)
		f.Repo = repo
		switch {
		case problem != "":
			f.Problem = problem
		case f.Path == "":
			f.Problem = "the finding names no file path (a report written with blob SHAs instead of paths)"
		}
		r.Findings = append(r.Findings, f)
	}
	return r, nil
}

func (r *Result) warnf(i int, format string, a ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf("%s: finding %d: ", r.File, i)+fmt.Sprintf(format, a...))
}

// repoOf reads owner/repo from a pkg:github purl
// (pkg:github/<owner>/<repo>[@ref][?qualifiers][#subpath]). problem says why
// there is none; it never quotes the purl, so coverage stays redactable.
func repoOf(purl string) (repo, problem string) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		if purl == "" {
			return "", "the finding has no purl"
		}
		return "", "the purl is not a package URL"
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, path, _ := strings.Cut(strings.TrimLeft(rest, "/"), "/")
	if !strings.EqualFold(typ, "github") {
		return "", fmt.Sprintf("the purl is not a GitHub repository (type %s)", strings.ToLower(typ))
	}
	if at := strings.LastIndex(path, "@"); at >= 0 {
		path = path[:at]
	}
	owner, name, ok := strings.Cut(strings.Trim(path, "/"), "/")
	if ok {
		var err1, err2 error
		owner, err1 = url.PathUnescape(owner)
		name, err2 = url.PathUnescape(name)
		ok = err1 == nil && err2 == nil
	}
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "the purl does not name an owner/repo"
	}
	return owner + "/" + name, ""
}

// cleanPath makes a repo-relative path: no leading ./ or /, forward slashes.
func cleanPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	for {
		switch {
		case strings.HasPrefix(p, "./"):
			p = p[2:]
		case strings.HasPrefix(p, "/"):
			p = p[1:]
		default:
			return p
		}
	}
}

// scalar reads a JSON string or number as text ("" for anything else).
func scalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func line(raw json.RawMessage) int {
	var n int
	if json.Unmarshal(raw, &n) == nil && n > 0 {
		return n
	}
	return 0
}
