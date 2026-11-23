package main

import (
	"flag"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/cypher"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sqlexport"
)

// cmdExport writes graphs in a format other tools load: an idempotent Cypher
// script for Neo4j (one graph), or a SQL script for SQLite and DuckDB (one or
// more graphs, one run each).
func (a *app) cmdExport(args []string) error {
	fs := a.flags("export")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	format := fs.String("format", "cypher", "cypher (an idempotent Neo4j script) or sql (a SQL script for sqlite3 and duckdb; takes several graphs)")
	out := fs.String("out", "-", `path to write the export ("-" for stdout)`)
	ghURL := fs.String("github-url", cypher.DefaultGitHubURL, "GitHub web root of Cartography's GitHubRepository and GitHubOrganization IDs (your GitHub Enterprise Server URL; cypher only)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	f := strings.ToLower(*format)
	switch f {
	case "cypher", "sql":
	case "sqlite", "duckdb":
		return usagef("export: --format must be cypher or sql, got %q (gop writes SQL text: gop export --format sql graph.json | sqlite3 gop.db)", *format)
	default:
		return usagef("export: --format must be cypher or sql, got %q", *format)
	}
	if len(pos) > 0 && *gp != "" {
		return usagef("export: give the graph as an argument or with --graph, not both")
	}
	if len(pos) > 1 && f == "cypher" {
		return usagef("export: want one graph file, got %d arguments (--format sql takes several)", len(pos))
	}
	if strings.TrimSpace(*out) == "" {
		return usagef("export: --out is required")
	}
	if f == "sql" {
		if flagSet(fs, "github-url") {
			return usagef("export: --github-url applies to --format cypher only")
		}
		paths := pos
		if len(paths) == 0 {
			paths = []string{*gp}
		}
		var gs []*graph.Graph
		for _, p := range paths {
			if *useDemo && len(pos) > 0 {
				return usagef("export: use --graph or --demo, not both")
			}
			g, err := a.loadGraph("export", p, *useDemo)
			if err != nil {
				return err
			}
			gs = append(gs, g)
		}
		return a.writeFile(*out, func(w io.Writer) error { return sqlexport.Write(w, gs) })
	}
	if len(pos) == 1 {
		*gp = pos[0]
	}
	opts := cypher.Options{GitHubURL: *ghURL}
	if err := cypher.CheckGitHubURL(opts.GitHubURL); err != nil {
		return usageError{"export: " + err.Error()}
	}
	g, err := a.loadGraph("export", *gp, *useDemo)
	if err != nil {
		return err
	}
	return a.writeFile(*out, func(w io.Writer) error { return cypher.Write(w, g, opts) })
}

// flagSet reports whether the flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
