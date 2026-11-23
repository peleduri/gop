// Command gop maps who can make code run where in a GitHub Enterprise.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/report"
	"github.com/peleduri/gop/internal/schema"
)

// Set by goreleaser: -X main.version=... -X main.commit=... -X main.date=...
var (
	version = "dev"
	commit  = "dev"
	date    = "dev"
)

// Exit codes.
const (
	exitOK      = 0
	exitRuntime = 1
	exitUsage   = 2
)

const usage = `gop maps who can make code run where in a GitHub Enterprise.

Usage:
  gop collect --enterprise <slug> --out graph.json [--orgs a,b]
  gop doctor  --enterprise <slug> [--github-url URL] [--orgs a,b] [--format text|json]
  gop demo    [--size small|medium|large] [--seed N] [--out graph.json]
  gop serve   --graph graph.json | --demo  [--baseline old.json]
  gop report  --graph graph.json | --demo  --out report.html [--format html|md] [--top N]
  gop paths   --graph graph.json --from <principal> [--to <node>]
  gop who     --graph graph.json --target <node>
  gop validate --graph graph.json [--format text|json]
  gop diff    OLD.json NEW.json [--format text|json|markdown] [--only paths,settings,edges,scores,coverage]
              [--fail-on confirmed-increase|any-new-path] [--force]
  gop fix-plan --graph graph.json | --demo  --pin <action> | --lower-default-perm <org> [--to read|none]
              [--format text|markdown|json]
  gop mcp-config --client claude|cursor|vscode --graph graph.json
  gop version

collect reads the token from GITHUB_TOKEN (or GH_TOKEN). It only reads.
When the token cannot read the enterprise (an org-scoped App installation
token, a non-owner token, or no read:enterprise), collect builds the graph
per org: from --orgs, or else the token's own orgs. Enterprise-level facts
are then not_visible and listed in coverage.
doctor is a read-only preflight for collect: token mode, scopes, SSO
authorization gaps, rate limit, a time estimate and what will come out
not_visible. Exit 0 all pass, 1 any fail, 3 warnings only.
demo writes a synthetic enterprise graph (no token, no network) to try gop on.
serve runs an MCP server over stdio. --baseline loads an older snapshot for the diff tool.
validate checks graph.json against the published JSON Schema and that every
edge endpoint is a node. Exit 0 valid, 1 invalid, 2 usage error.
diff exits 0 when no --fail-on condition matched, 1 when one did, 2 on usage or load errors.
--graph - reads the graph from stdin (report, paths, who): gop demo | gop report --graph - --out -
fix-plan prints the change steps for one fix (workflow lines with diffs, settings
with their REST call as text). gop never runs them or calls write APIs.
mcp-config prints the MCP client config for serve; it never writes files.
Confirmed reach: every hop live or audit. Possible reach: at least one hop not visible.
`

// collector is the seam to internal/collect, replaced in tests.
type collector func(ctx context.Context, cfg collect.Config) (*graph.Graph, error)

type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	collect        collector
	serve          func(ctx context.Context, g *graph.Graph, version string, opts mcpserver.ServerOptions) error
	now            func() time.Time // nil means time.Now
}

func main() {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv, collect: collect.Collect, serve: mcpserver.ServeWith}
	os.Exit(a.run(os.Args[1:]))
}

// usageError marks errors that exit 2.
type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// codeError carries a specific exit code (used by diff: 1 for --fail-on, 2 for load errors).
type codeError struct {
	code int
	err  error
}

func (c codeError) Error() string { return c.err.Error() }

func (a *app) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "collect":
		err = a.cmdCollect(rest)
	case "doctor":
		err = a.cmdDoctor(rest)
	case "demo":
		err = a.cmdDemo(rest)
	case "serve":
		err = a.cmdServe(rest)
	case "report":
		err = a.cmdReport(rest)
	case "paths":
		err = a.cmdPaths(rest)
	case "who":
		err = a.cmdWho(rest)
	case "validate":
		err = a.cmdValidate(rest)
	case "diff":
		err = a.cmdDiff(rest)
	case "mcp-config":
		err = a.cmdMCPConfig(rest)
	case "fix-plan":
		err = a.cmdFixPlan(rest)
	case "version", "--version", "-version":
		fmt.Fprintf(a.stdout, "gop %s (commit %s, built %s)\n", version, commit, date)
	case "help", "-h", "--help", "-help":
		fmt.Fprint(a.stdout, usage)
	default:
		err = usagef("unknown command %q", cmd)
	}
	var (
		ue usageError
		ce codeError
	)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.As(err, &ce):
		fmt.Fprintf(a.stderr, "gop %s: %v\n", cmd, ce.err)
		return ce.code
	case errors.As(err, &ue):
		fmt.Fprintf(a.stderr, "gop: %s\n\n%s", ue.msg, usage)
		return exitUsage
	default:
		fmt.Fprintf(a.stderr, "gop %s: %v\n", cmd, err)
		return exitRuntime
	}
}

func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("gop "+name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	return fs
}

// parse parses flags and rejects positional arguments.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usagef("%s: unexpected argument %q", fs.Name(), fs.Arg(0))
	}
	return nil
}

// required takes flag name/value pairs and reports the first empty one.
func required(name string, pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if strings.TrimSpace(pairs[i+1]) == "" {
			return usagef("%s: --%s is required", name, pairs[i])
		}
	}
	return nil
}

func (a *app) cmdCollect(args []string) error {
	fs := a.flags("collect")
	ent := fs.String("enterprise", "", "enterprise slug, e.g. acme")
	out := fs.String("out", "", "path to write graph.json")
	orgs := fs.String("orgs", "", "comma-separated org logins to limit collection to (default: all). "+
		"When the token cannot read the enterprise, these orgs are collected and count as enterprise orgs")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("collect", "enterprise", *ent, "out", *out); err != nil {
		return err
	}
	token := a.getenv("GITHUB_TOKEN")
	if token == "" {
		token = a.getenv("GH_TOKEN")
	}
	if token == "" {
		return usagef("collect: set GITHUB_TOKEN (or GH_TOKEN) to a read-only token; gop never takes a token as a flag")
	}
	cfg := collect.Config{
		Enterprise: *ent,
		Token:      token,
		Orgs:       splitList(*orgs),
		Logf:       func(format string, args ...any) { fmt.Fprintf(a.stderr, "gop collect: "+format+"\n", args...) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, err := a.collect(ctx, cfg)
	if err != nil {
		return errors.New(scrub(err.Error(), token))
	}
	return a.writeFile(*out, func(w io.Writer) error { return collect.WriteGraph(w, g) })
}

// scrub removes the token from a message, defensively.
func scrub(msg, token string) string {
	if token == "" {
		return msg
	}
	return strings.ReplaceAll(msg, token, "[redacted]")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeFile writes atomically with 0600 permissions: graph.json and reports are
// attack maps. "-" writes to stdout.
func (a *app) writeFile(path string, write func(io.Writer) error) error {
	if path == "-" {
		return write(a.stdout)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".gop-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if err := write(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func graphFlag(fs *flag.FlagSet) *string {
	return fs.String("graph", "", `path to graph.json written by gop collect or gop demo ("-" for stdin)`)
}

func demoFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("demo", false, "use the small synthetic demo graph (same as gop demo --size small --seed 1)")
}

// loadGraph reads --graph ("-" is stdin), or generates the small demo graph
// when useDemo is set. Exactly one of the two is required.
func (a *app) loadGraph(cmd, path string, useDemo bool) (*graph.Graph, error) {
	switch {
	case useDemo && path != "":
		return nil, usagef("%s: use --graph or --demo, not both", cmd)
	case useDemo:
		return demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}), nil
	case strings.TrimSpace(path) == "":
		return nil, usagef("%s: --graph is required", cmd)
	case path == "-":
		return graph.Load(a.stdin)
	}
	return graph.LoadFile(path)
}

func (a *app) cmdDemo(args []string) error {
	fs := a.flags("demo")
	size := fs.String("size", demo.SizeSmall, "small (5 orgs, ~60 repos), medium (20 orgs, ~1,000 repos) or large (60 orgs, ~10,000 repos)")
	seed := fs.Int64("seed", 1, "seed for the generated filler; the planted paths are the same for every seed")
	out := fs.String("out", "-", `path to write graph.json ("-" for stdout)`)
	if err := parse(fs, args); err != nil {
		return err
	}
	if _, _, ok := demo.Preset(*size); !ok || *size == "" {
		return usagef("demo: --size must be small, medium or large, got %q", *size)
	}
	if strings.TrimSpace(*out) == "" {
		return usagef("demo: --out is required")
	}
	g := demo.Generate(demo.Options{Seed: *seed, Size: *size})
	if err := a.writeFile(*out, func(w io.Writer) error { return collect.WriteGraph(w, g) }); err != nil {
		return err
	}
	next := *out
	if next == "-" {
		next = "graph.json"
	}
	fmt.Fprintf(a.stderr, "next: gop serve --graph %s\n", next)
	return nil
}

func (a *app) cmdServe(args []string) error {
	fs := a.flags("serve")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	baseline := fs.String("baseline", "", "older graph.json for the diff tool to compare the served graph with")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *gp == "-" {
		return usagef("serve: --graph - is not supported: stdin carries the MCP protocol")
	}
	if *baseline == "-" {
		return usagef("serve: --baseline - is not supported: stdin carries the MCP protocol")
	}
	g, err := a.loadGraph("serve", *gp, *useDemo)
	if err != nil {
		return err
	}
	var opts mcpserver.ServerOptions
	if *baseline != "" {
		if opts.Baseline, err = graph.LoadFile(*baseline); err != nil {
			return codeError{exitUsage, fmt.Errorf("load --baseline %s: %w", *baseline, err)}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.serve(ctx, g, version, opts)
}

func (a *app) cmdReport(args []string) error {
	fs := a.flags("report")
	gp := graphFlag(fs)
	out := fs.String("out", "", `path to write the report ("-" for stdout)`)
	format := fs.String("format", "", "html or md (default html, or md when --out ends in .md)")
	top := fs.Int("top", 10, "principals in the risks table and paths section")
	useDemo := demoFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("report", "out", *out); err != nil {
		return err
	}
	f := strings.ToLower(*format)
	if f == "" {
		f = "html"
		if strings.HasSuffix(strings.ToLower(*out), ".md") {
			f = "md"
		}
	}
	if f != "html" && f != "md" {
		return usagef("report: --format must be html or md, got %q", *format)
	}
	if *top <= 0 {
		return usagef("report: --top must be positive, got %d", *top)
	}
	g, err := a.loadGraph("report", *gp, *useDemo)
	if err != nil {
		return err
	}
	return a.writeFile(*out, func(w io.Writer) error {
		return report.Render(w, g, report.Options{Format: f, Top: *top, Version: version})
	})
}

func (a *app) cmdPaths(args []string) error {
	fs := a.flags("paths")
	gp := graphFlag(fs)
	from := fs.String("from", "", "principal node ID, e.g. members:acme-actions")
	to := fs.String("to", "", "optional target node ID")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("paths", "graph", *gp, "from", *from); err != nil {
		return err
	}
	g, err := a.loadGraph("paths", *gp, false)
	if err != nil {
		return err
	}
	out, err := mcpserver.NewEngine(g).Paths(mcpserver.PathsInput{From: *from, To: *to})
	if err != nil {
		return err
	}
	mcpserver.WritePaths(a.stdout, out)
	return nil
}

func (a *app) cmdWho(args []string) error {
	fs := a.flags("who")
	gp := graphFlag(fs)
	target := fs.String("target", "", "target node ID, e.g. repo:acme-app/web")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("who", "graph", *gp, "target", *target); err != nil {
		return err
	}
	g, err := a.loadGraph("who", *gp, false)
	if err != nil {
		return err
	}
	out, err := mcpserver.NewEngine(g).WhoCanReach(mcpserver.WhoCanReachInput{Target: *target})
	if err != nil {
		return err
	}
	mcpserver.WriteWho(a.stdout, out)
	return nil
}

func (a *app) cmdValidate(args []string) error {
	fs := a.flags("validate")
	gp := graphFlag(fs)
	format := fs.String("format", "text", "text or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("validate", "graph", *gp); err != nil {
		return err
	}
	f := strings.ToLower(*format)
	if f != "text" && f != "json" {
		return usagef("validate: --format must be text or json, got %q", *format)
	}
	data, err := os.ReadFile(*gp)
	if err != nil {
		return err
	}
	res, err := schema.Validate(data)
	if err != nil {
		return err
	}
	if f == "json" {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		writeValidation(a.stdout, *gp, res)
	}
	if !res.Valid {
		return fmt.Errorf("%s is invalid (%d errors)", *gp, len(res.Errors))
	}
	return nil
}

func writeValidation(w io.Writer, path string, res *schema.Result) {
	state := "valid"
	if !res.Valid {
		state = "invalid"
	}
	version := res.Schema
	if version == "" {
		version = "unknown schema"
	}
	fmt.Fprintf(w, "%s: %s (%s, %d errors, %d warnings)\n", path, state, version, len(res.Errors), len(res.Warnings))
	for _, p := range res.Errors {
		fmt.Fprintf(w, "error   %s\n", p)
	}
	for _, p := range res.Warnings {
		fmt.Fprintf(w, "warning %s\n", p)
	}
}
