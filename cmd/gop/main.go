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

	"github.com/peleduri/gop/internal/collect"
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
  gop serve   --graph graph.json
  gop report  --graph graph.json --out report.html [--format html|md] [--top N]
  gop paths   --graph graph.json --from <principal> [--to <node>]
  gop who     --graph graph.json --target <node>
  gop validate --graph graph.json [--format text|json]
  gop version

collect reads the token from GITHUB_TOKEN (or GH_TOKEN). It only reads.
serve runs an MCP server over stdio.
validate checks graph.json against the published JSON Schema and that every
edge endpoint is a node. Exit 0 valid, 1 invalid, 2 usage error.
Confirmed reach: every hop live or audit. Possible reach: at least one hop not visible.
`

// collector is the seam to internal/collect, replaced in tests.
type collector func(ctx context.Context, cfg collect.Config) (*graph.Graph, error)

type app struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	collect        collector
	serve          func(ctx context.Context, g *graph.Graph, version string) error
}

func main() {
	a := &app{stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv, collect: collect.Collect, serve: mcpserver.Serve}
	os.Exit(a.run(os.Args[1:]))
}

// usageError marks errors that exit 2.
type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

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
	case "version", "--version", "-version":
		fmt.Fprintf(a.stdout, "gop %s (commit %s, built %s)\n", version, commit, date)
	case "help", "-h", "--help", "-help":
		fmt.Fprint(a.stdout, usage)
	default:
		err = usagef("unknown command %q", cmd)
	}
	var ue usageError
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, flag.ErrHelp):
		return exitOK
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
	orgs := fs.String("orgs", "", "comma-separated org logins to limit collection to (default: all)")
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
	return fs.String("graph", "", "path to graph.json written by gop collect")
}

func (a *app) cmdServe(args []string) error {
	fs := a.flags("serve")
	gp := graphFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("serve", "graph", *gp); err != nil {
		return err
	}
	g, err := graph.LoadFile(*gp)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.serve(ctx, g, version)
}

func (a *app) cmdReport(args []string) error {
	fs := a.flags("report")
	gp := graphFlag(fs)
	out := fs.String("out", "", `path to write the report ("-" for stdout)`)
	format := fs.String("format", "", "html or md (default html, or md when --out ends in .md)")
	top := fs.Int("top", 10, "principals in the risks table and paths section")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("report", "graph", *gp, "out", *out); err != nil {
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
	g, err := graph.LoadFile(*gp)
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
	g, err := graph.LoadFile(*gp)
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
	g, err := graph.LoadFile(*gp)
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
