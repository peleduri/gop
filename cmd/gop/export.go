package main

import (
	"io"
	"strings"

	"github.com/peleduri/gop/internal/cypher"
)

// cmdExport writes the graph in a format other tools load. Only Cypher today.
func (a *app) cmdExport(args []string) error {
	fs := a.flags("export")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	format := fs.String("format", "cypher", "cypher (an idempotent Neo4j script)")
	out := fs.String("out", "-", `path to write the export ("-" for stdout)`)
	ghURL := fs.String("github-url", cypher.DefaultGitHubURL, "GitHub web root of Cartography's GitHubRepository and GitHubOrganization IDs (your GitHub Enterprise Server URL)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	switch len(pos) {
	case 0:
	case 1:
		if *gp != "" {
			return usagef("export: give the graph as an argument or with --graph, not both")
		}
		*gp = pos[0]
	default:
		return usagef("export: want one graph file, got %d arguments", len(pos))
	}
	if f := strings.ToLower(*format); f != "cypher" {
		return usagef("export: --format must be cypher, got %q", *format)
	}
	if strings.TrimSpace(*out) == "" {
		return usagef("export: --out is required")
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
