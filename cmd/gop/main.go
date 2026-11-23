// Command gop maps who can make code run where in a GitHub Enterprise.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/oidc"
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
  gop collect --enterprise <slug> --out graph.json [--orgs a,b] [--app-id N --app-key-file PATH] [--oidc-trust <files>]
              [--github-url URL]
  gop enrich  --graph graph.json [--oidc-trust <file|dir>[,...]] [--cartography export.json] --out graph2.json
  gop doctor  --enterprise <slug> [--github-url URL] [--orgs a,b] [--format text|json]
              [--app-id N --app-key-file PATH]
  gop demo    [--size small|medium|large] [--seed N] [--out graph.json]
  gop serve   --graph graph.json | --demo  [--baseline old.json]
  gop report  --graph graph.json | --demo  --out report.html [--format html|md] [--top N]
              [--previous old.json]
  gop paths   --graph graph.json --from <principal> [--to <node>]
  gop who     --graph graph.json --target <node>
  gop validate --graph graph.json [--format text|json]
  gop redact  --graph graph.json --out shareable.json [--salt-file key] [--keep-attr k1,k2]
              [--map-out mapping.json]
  gop diff    OLD.json NEW.json [--format text|json|markdown] [--only paths,settings,edges,scores,coverage]
              [--fail-on confirmed-increase|any-new-path] [--force]
  gop fix-plan --graph graph.json | --demo  --pin <action> | --lower-default-perm <org> [--to read|none]
              | --restrict-token <workflow> | --harden-trigger <workflow> [--format text|markdown|json]
  gop sarif   --graph graph.json | --demo  --out gop.sarif | --split-by-repo DIR [--top N]
              [--min-severity low|medium|high|critical] [--include-possible]
  gop pin     --action <owner/repo@ref> [--graph graph.json [--repo owner/repo] [--offline]]
              [--github-url URL] [--format diff|text|json]
  gop export  --format cypher graph.json | --graph graph.json | --demo  [--out gop.cypher] [--github-url URL]
  gop mcp-config --client claude|cursor|vscode --graph graph.json
  gop version

collect reads the token from GITHUB_TOKEN (or GH_TOKEN). It only reads.
When the token cannot read the enterprise (an org-scoped App installation
token, a non-owner token, or no read:enterprise), collect builds the graph
per org: from --orgs, or else the token's own orgs. Enterprise-level facts
are then not_visible and listed in coverage.
GitHub App mode (--app-id and --app-key-file, or GOP_APP_ID and
GOP_APP_PRIVATE_KEY with the PEM contents) mints a read-only installation
token per org instead; it excludes GITHUB_TOKEN. The key stays in memory and
is never printed.
doctor is a read-only preflight for collect: token mode, scopes, SSO
authorization gaps, rate limit, a time estimate and what will come out
not_visible. In App mode it lists installations, the --orgs without one and
any granted permission that is not read. Exit 0 all pass, 1 any fail, 3 warnings only.
enrich reads cloud OIDC trust files you export (AWS, GCP, Azure), or a
Cartography export (--cartography, AWS; one or both), and adds the cloud roles each
workflow's token can assume (CAN_ASSUME). Offline: no token, no cloud API. Those hops have evidence "supplied" and every path through them
says it comes from a supplied file, not from the cloud.
demo writes a synthetic enterprise graph (no token, no network) to try gop on.
serve runs an MCP server over stdio. --baseline loads an older snapshot for the diff tool.
validate checks graph.json against the published JSON Schema and that every
edge endpoint is a node. Exit 0 valid, 1 invalid, 2 usage error.
redact writes a copy of the graph with every org, repo, user, team, action,
workflow file, secret name, runner label and environment replaced by a stable
synthetic name, keeping the structure, evidence and reach. Attach its output
to a bug report, never a raw graph. It fails, writing nothing, when an
original name of 3+ characters is still in the output.
diff exits 0 when no --fail-on condition matched, 1 when one did, 2 on usage or load errors.
--graph - reads the graph from stdin (report, paths, who): gop demo | gop report --graph - --out -
fix-plan prints the change steps for one fix (workflow lines with diffs, settings
with their REST call as text). gop never runs them or calls write APIs.
sarif writes one SARIF 2.1.0 result per fixable edge (GOP001 mutable action
ref, GOP002 default permission). It lists attack paths: uploading it to code
scanning shows them to everyone with alert access. gop never uploads it.
pin resolves an action ref to a commit SHA with read-only GET requests (token
from GITHUB_TOKEN or GH_TOKEN) and, with --graph, prints a git apply diff for
every consuming workflow. It writes to stdout only.
export --format cypher writes an idempotent Neo4j Cypher script (MERGE only)
that loads gop's nodes, edges and computed reach next to Cartography's data and
links them to Cartography's GitHub and AWS nodes. It writes text only.
mcp-config prints the MCP client config for serve; it never writes files.
--github-url (or GOP_GITHUB_URL) on collect, doctor and pin names a GitHub
Enterprise Server instance (https://HOST): gop reads https://HOST/api/v3 and
https://HOST/api/graphql, records host and ghes_version on the enterprise
node and leaves APIs the version lacks not_visible. --api-url and
--graphql-url override the endpoints for a proxy; http:// needs --insecure-http.
Confirmed reach: every hop live, inferred, audit or supplied. Possible reach: at least one hop not visible.
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
	// apiURL (the default of gop pin --github-url) and transport are the
	// GitHub REST root and HTTP transport gop pin uses (defaults:
	// api.github.com, http.DefaultTransport); tests point them at an httptest
	// server.
	apiURL    string
	transport http.RoundTripper
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
	case "enrich":
		err = a.cmdEnrich(rest)
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
	case "redact":
		err = a.cmdRedact(rest)
	case "diff":
		err = a.cmdDiff(rest)
	case "mcp-config":
		err = a.cmdMCPConfig(rest)
	case "fix-plan":
		err = a.cmdFixPlan(rest)
	case "pin":
		err = a.cmdPin(rest)
	case "sarif":
		err = a.cmdSARIF(rest)
	case "export":
		err = a.cmdExport(rest)
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
		"When the token cannot read the enterprise, or in GitHub App mode, these orgs are collected and count as enterprise orgs")
	af := addAppFlags(fs)
	uf := addURLFlags(fs, "collect")
	cacheDir := fs.String("cache-dir", "", "directory for an on-disk REST response cache (off by default): re-runs send conditional "+
		"requests and unchanged responses do not count against the rate limit. It holds API responses as sensitive as graph.json: "+
		"gop creates it 0700; delete it after use and never commit it")
	resume := fs.Bool("resume", false, "with --cache-dir, resume an interrupted collection of the same enterprise and orgs "+
		"without re-requesting what it already fetched")
	var trusts trustFlag
	fs.Var(&trusts, "oidc-trust", trustUsage+" (runs gop enrich after collection)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("collect", "enterprise", *ent, "out", *out); err != nil {
		return err
	}
	if *resume && *cacheDir == "" {
		return usagef("collect: --resume needs --cache-dir")
	}
	ep, err := uf.resolve(a.getenv)
	if err != nil {
		return err
	}
	if len(trusts) > 0 {
		// Fail on unreadable trust files before spending the API budget.
		if _, err := oidc.Parse(oidc.Options{}, trusts...); err != nil {
			return usagef("collect: --oidc-trust: %v", err)
		}
	}
	cr, err := a.resolveCreds("collect", af)
	if err != nil {
		return err
	}
	cfg := collect.Config{
		Enterprise:       *ent,
		Token:            cr.token,
		AppID:            cr.appID,
		AppPrivateKeyPEM: cr.appKey,
		Orgs:             splitList(*orgs),
		Host:             ep.host,
		BaseURL:          ep.rest,
		GraphQLURL:       ep.graphql,
		CacheDir:         *cacheDir,
		Resume:           *resume,
		Logf:             func(format string, args ...any) { fmt.Fprintf(a.stderr, "gop collect: "+format+"\n", args...) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, err := a.collect(ctx, cfg)
	if err != nil {
		return errors.New(cr.redact(err.Error()))
	}
	if len(trusts) > 0 {
		if err := a.enrich(g, trusts, ""); err != nil {
			return err
		}
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
	prev := fs.String("previous", "", "older graph.json: open the report with what changed since it (gop diff)")
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
	opts := report.Options{Format: f, Top: *top, Version: version}
	if strings.TrimSpace(*prev) != "" {
		old, err := graph.LoadFile(*prev)
		if err != nil {
			return codeError{exitUsage, fmt.Errorf("report: load %s: %w", *prev, err)}
		}
		rep, err := diff.Compare(old, g)
		if err != nil {
			return codeError{exitUsage, fmt.Errorf("report: --previous: %w", err)}
		}
		opts.Changes = &rep
	}
	return a.writeFile(*out, func(w io.Writer) error {
		return report.Render(w, g, opts)
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
