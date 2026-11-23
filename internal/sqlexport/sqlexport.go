// Package sqlexport writes gop graphs, their computed reach and their ranked
// findings as a portable SQL script that sqlite3 and duckdb both load, so
// counting and grouping questions ("repos per org reachable by outside
// collaborators, over the last ten runs") can be asked in SQL, a BI tool or a
// text-to-SQL tool.
//
// Safety: table and column names are fixed in this file. Every value taken
// from a graph is written as a standard SQL string literal through Quote
// (single quotes doubled, no other escapes, which is how SQLite and DuckDB
// read them), or as a number gop computed. gop only writes text; it links no
// database driver.
package sqlexport

import (
	"bufio"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/cypher"
	"github.com/peleduri/gop/internal/graph"
)

// batchSize is the number of rows per INSERT statement.
const batchSize = 500

// column is one column of a table. typ is TEXT, INTEGER or REAL.
type column struct {
	name string
	typ  string
}

// table is one table of the schema, in load order.
type table struct {
	name    string
	cols    []column
	indexes [][]string
}

var (
	runsTable = table{"runs", []column{
		{"run_id", "TEXT NOT NULL"},
		{"enterprise", "TEXT NOT NULL"},
		{"collected_at", "TEXT NOT NULL"},
		{"schema_version", "TEXT NOT NULL"},
	}, nil}
	nodesTable = table{"nodes", []column{
		{"run_id", "TEXT NOT NULL"},
		{"id", "TEXT NOT NULL"},
		{"kind", "TEXT NOT NULL"},
		{"name", "TEXT NOT NULL"},
		{"org", "TEXT"},
		{"repo", "TEXT"},
		{"evidence", "TEXT"},
		{"declared", "INTEGER NOT NULL"},
	}, [][]string{{"run_id", "id"}, {"run_id", "kind"}}}
	nodeAttrsTable = table{"node_attrs", []column{
		{"run_id", "TEXT NOT NULL"},
		{"node_id", "TEXT NOT NULL"},
		{"key", "TEXT NOT NULL"},
		{"value", "TEXT NOT NULL"},
		{"evidence", "TEXT"},
	}, [][]string{{"run_id", "node_id"}, {"run_id", "key"}}}
	edgesTable = table{"edges", []column{
		{"run_id", "TEXT NOT NULL"},
		{"edge_id", "INTEGER NOT NULL"},
		{"src", "TEXT NOT NULL"},
		{"dst", "TEXT NOT NULL"},
		{"label", "TEXT NOT NULL"},
		{"evidence", "TEXT NOT NULL"},
		{"confirmed", "INTEGER NOT NULL"},
		{"source_api", "TEXT NOT NULL"},
		{"observed_at", "TEXT NOT NULL"},
	}, [][]string{{"run_id", "src"}, {"run_id", "dst"}}}
	edgeAttrsTable = table{"edge_attrs", []column{
		{"run_id", "TEXT NOT NULL"},
		{"edge_id", "INTEGER NOT NULL"},
		{"key", "TEXT NOT NULL"},
		{"value", "TEXT NOT NULL"},
	}, [][]string{{"run_id", "edge_id"}}}
	findingsTable = table{"findings", []column{
		{"run_id", "TEXT NOT NULL"},
		{"rule", "TEXT NOT NULL"},
		{"subject", "TEXT NOT NULL"},
		{"severity", "REAL NOT NULL"},
		{"possible", "REAL NOT NULL"},
	}, [][]string{{"run_id", "rule"}}}
	reachTable = table{"reach", []column{
		{"run_id", "TEXT NOT NULL"},
		{"principal", "TEXT NOT NULL"},
		{"target", "TEXT NOT NULL"},
		{"target_kind", "TEXT NOT NULL"},
		{"confirmed", "INTEGER NOT NULL"},
		{"evidence", "TEXT NOT NULL"},
		{"hops", "INTEGER NOT NULL"},
		{"path", "TEXT NOT NULL"},
	}, [][]string{{"run_id", "principal"}, {"run_id", "target"}}}

	tables = []table{runsTable, nodesTable, nodeAttrsTable, edgesTable, edgeAttrsTable, findingsTable, reachTable}
)

// Rule names in the findings table.
const (
	// RuleTopRisk is one row per scoring principal with any reach: severity
	// is its confirmed blast-radius score, possible its possible score.
	RuleTopRisk = "top_risk"
	// RuleFixPrefix starts the rule of a fix candidate ("fix_pin",
	// "fix_default_perm", "fix_restrict_token", "fix_harden_trigger"). The
	// subject is the fix ID; severity is the confirmed (principal, repo)
	// pairs the fix alone removes, possible the possible pairs it removes.
	RuleFixPrefix = "fix_"
)

// row is one table row. Values are string, int, float64 or nil (NULL).
type row []any

// dump is the rows of one run, by table name.
type dump struct {
	runID string
	rows  map[string][]row
}

// Write writes graphs as one SQL script: the schema (CREATE ... IF NOT
// EXISTS), then per run a DELETE of that run's rows and the inserts, all in
// one transaction. Loading it into an existing database adds its runs and
// replaces an earlier load of the same run, so the script is idempotent and
// several exports can go into one database for trends. A graph that appears
// twice (same run ID) is written once. The output is deterministic.
func Write(w io.Writer, graphs []*graph.Graph) error {
	var dumps []dump
	seen := map[string]bool{}
	for _, g := range graphs {
		if g == nil {
			g = &graph.Graph{Schema: graph.SchemaVersion}
		}
		d := build(g)
		if seen[d.runID] {
			continue
		}
		seen[d.runID] = true
		dumps = append(dumps, d)
	}

	bw := bufio.NewWriter(w)
	x := &writer{w: bw}
	x.line("-- gop export --format sql (" + graph.SchemaVersion + ")")
	x.line("-- This file lists attack paths (who can make code run where). Keep it and the database private.")
	x.line("-- Load: sqlite3 gop.db < gop.sql   or   duckdb gop.duckdb < gop.sql")
	x.line("-- Idempotent: loading a run again replaces its rows; other runs are kept.")
	for _, d := range dumps {
		x.line("-- run_id: " + commentSafe(d.runID))
	}
	x.line("BEGIN TRANSACTION;")
	for _, t := range tables {
		defs := make([]string, len(t.cols))
		for i, c := range t.cols {
			defs[i] = c.name + " " + c.typ
		}
		x.line("CREATE TABLE IF NOT EXISTS " + t.name + " (" + strings.Join(defs, ", ") + ");")
		for _, ix := range t.indexes {
			x.line("CREATE INDEX IF NOT EXISTS " + t.name + "_" + strings.Join(ix, "_") + " ON " + t.name + " (" + strings.Join(ix, ", ") + ");")
		}
	}
	for _, d := range dumps {
		for i := len(tables) - 1; i >= 0; i-- {
			x.line("DELETE FROM " + tables[i].name + " WHERE run_id = " + Quote(d.runID) + ";")
		}
		for _, t := range tables {
			x.insert(t, d.rows[t.name])
		}
	}
	x.line("COMMIT;")
	if x.err != nil {
		return x.err
	}
	return bw.Flush()
}

type writer struct {
	w   *bufio.Writer
	err error
}

func (x *writer) line(s string) {
	if x.err == nil {
		_, x.err = x.w.WriteString(s + "\n")
	}
}

func (x *writer) insert(t table, rows []row) {
	names := make([]string, len(t.cols))
	for i, c := range t.cols {
		names[i] = c.name
	}
	head := "INSERT INTO " + t.name + " (" + strings.Join(names, ", ") + ") VALUES"
	for start := 0; start < len(rows); start += batchSize {
		end := min(start+batchSize, len(rows))
		x.line(head)
		for i := start; i < end; i++ {
			sep := ","
			if i == end-1 {
				sep = ";"
			}
			x.line("  " + literalRow(rows[i]) + sep)
		}
	}
}

func literalRow(r row) string {
	vals := make([]string, len(r))
	for i, v := range r {
		vals[i] = literal(v)
	}
	return "(" + strings.Join(vals, ", ") + ")"
}

func literal(v any) string {
	switch v := v.(type) {
	case nil:
		return "NULL"
	case string:
		return Quote(v)
	case int:
		return strconv.Itoa(v)
	case bool:
		if v {
			return "1"
		}
		return "0"
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "NULL"
		}
		s := strconv.FormatFloat(v, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	panic("sqlexport: unsupported value type") // rows are built in this file only
}

// Quote returns s as a standard SQL string literal: single quotes doubled,
// nothing else escaped, which is how SQLite and DuckDB read a '...' literal
// (a backslash is an ordinary character in both). The sqlite3 and duckdb
// shells drop a carriage return at the end of an input line, so each CR LF
// is split across two literals joined with || ('a<CR>' || '<LF>b'), which
// keeps the CR off the line end. Invalid UTF-8 and NUL, which neither shell
// can load inside a literal, become U+FFFD.
func Quote(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.ReplaceAll(s, "\x00", "\uFFFD")
	s = strings.ReplaceAll(s, "'", "''")
	s = strings.ReplaceAll(s, "\r\n", "\r' || '\n")
	return "'" + s + "'"
}

// commentSafe keeps only printable ASCII, so a -- comment cannot end early.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// build computes the rows of one graph.
func build(g *graph.Graph) dump {
	run := cypher.Run(g)
	d := dump{runID: run, rows: map[string][]row{}}
	add := func(t table, r row) { d.rows[t.name] = append(d.rows[t.name], append(row{run}, r...)) }

	schema := g.Schema
	if schema == "" {
		schema = graph.SchemaVersion
	}
	add(runsTable, row{g.Enterprise, g.CollectedAt.UTC().Format(time.RFC3339), schema})

	// Nodes, sorted by ID; the first declaration of an ID wins. Edge
	// endpoints the graph does not declare get a row with declared=0 so
	// joins from edges never lose a row.
	nodes := append([]graph.Node(nil), g.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	declared := map[string]bool{}
	var nodeIDs []string
	byID := map[string]graph.Node{}
	for _, n := range nodes {
		if declared[n.ID] {
			continue
		}
		declared[n.ID] = true
		byID[n.ID] = n
		nodeIDs = append(nodeIDs, n.ID)
	}
	undeclared := map[string]bool{}
	for _, e := range g.Edges {
		for _, id := range []string{e.From, e.To} {
			if !declared[id] && !undeclared[id] {
				undeclared[id] = true
				nodeIDs = append(nodeIDs, id)
			}
		}
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		n, ok := byID[id]
		if !ok {
			add(nodesTable, row{id, string(graph.KindFromID(id)), id, nullable(orgOf(id)), nullable(repoOf(id)), nil, false})
			continue
		}
		add(nodesTable, row{id, string(n.Kind), n.Name, nullable(orgOf(id)), nullable(repoOf(id)), string(n.Evidence), true})
		for _, k := range sortedKeys(n.Attrs) {
			ev := n.Evidence
			if a, ok := n.AttrEvidence[k]; ok {
				ev = a
			}
			add(nodeAttrsTable, row{id, k, n.Attrs[k], string(ev)})
		}
	}

	// Edges in a stable order; edge_id is the position in it.
	edges := append([]graph.Edge(nil), g.Edges...)
	keys := make([]string, len(edges))
	for i, e := range edges {
		keys[i] = edgeSortKey(e)
	}
	idx := make([]int, len(edges))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	for id, i := range idx {
		e := edges[i]
		add(edgesTable, row{id, e.From, e.To, string(e.Kind), string(e.Evidence), graph.Verified(e.Evidence), e.SourceAPI, e.ObservedAt.UTC().Format(time.RFC3339)})
		for _, k := range sortedKeys(e.Attrs) {
			add(edgeAttrsTable, row{id, k, e.Attrs[k]})
		}
	}

	ix := graph.NewIndex(g)
	for _, r := range reachRows(ix) {
		add(reachTable, r)
	}
	for _, r := range findingRows(ix) {
		add(findingsTable, r)
	}
	return d
}

// reachRows is one row per (scoring principal, node it reaches), with the
// shortest path the engine found: (principal, target, target_kind,
// confirmed, evidence, hops, path). confirmed is 1 when every hop is
// verified (Path.Unverified is false). path is a JSON array of node IDs.
func reachRows(ix *graph.Index) []row {
	var out []row
	for _, p := range ix.ScoringPrincipals() {
		res := ix.Reach(p, graph.Options{})
		for _, id := range sortedKeys(res.Paths) {
			path := res.Paths[id]
			ids := []string{path.From}
			for _, h := range path.Hops {
				ids = append(ids, h.To)
			}
			out = append(out, row{p, id, string(ix.Kind(id)), !path.Unverified, string(path.Evidence), len(path.Hops), jsonString(ids)})
		}
	}
	return out
}

// findingRows ranks the scoring principals (top_risk) and evaluates every
// fix candidate on its own (fix_*). See RuleTopRisk and RuleFixPrefix.
func findingRows(ix *graph.Index) []row {
	var out []row
	for _, s := range ix.TopPaths(0) {
		if s.Score == 0 && s.PossibleScore == 0 {
			continue
		}
		out = append(out, row{RuleTopRisk, s.Principal, s.Score, s.PossibleScore})
	}
	for _, f := range ix.Candidates() {
		d := ix.WhatIf([]graph.Fix{f})
		kind, _, _ := strings.Cut(f.ID(), ":")
		out = append(out, row{RuleFixPrefix + kind, f.ID(),
			float64(d.Before.ConfirmedPairs - d.After.ConfirmedPairs),
			float64(d.Before.PossiblePairs - d.After.PossiblePairs)})
	}
	return out
}

// edgeSortKey orders edges by kind, endpoints, evidence, source, time and
// attributes, with NUL separators so no field can run into the next.
func edgeSortKey(e graph.Edge) string {
	parts := []string{string(e.Kind), e.From, e.To, string(e.Evidence), e.SourceAPI, e.ObservedAt.UTC().Format(time.RFC3339Nano)}
	for _, k := range sortedKeys(e.Attrs) {
		parts = append(parts, k, e.Attrs[k])
	}
	return strings.Join(parts, "\x00")
}

// orgOf is the org node ID a node belongs to ("org:acme-app"), or "".
func orgOf(id string) string { return graph.OrgOf(id) }

// repoOf is the repo node ID a node belongs to: itself for a repo, the repo
// of a workflow, secret, oidc or runner scope, the host repo of an action
// ref; "" for anything else.
func repoOf(id string) string {
	prefix, rest, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	switch prefix {
	case "repo", "workflow", "secret", "oidc", "runner":
	case "action":
		if i := strings.LastIndex(rest, "@"); i >= 0 {
			rest = rest[:i]
		}
	default:
		return ""
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "repo:" + parts[0] + "/" + parts[1]
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func jsonString(v any) string {
	data, _ := json.Marshal(v) // slices of strings always marshal
	return string(data)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
