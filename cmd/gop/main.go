// Command gop maps who can make code run where in a GitHub Enterprise.
package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/peleduri/gop/internal/advisory"
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
	// exitPartial: collect stopped early and wrote a partial graph.
	exitPartial = 3
)

const usage = `gop maps who can make code run where in a GitHub Enterprise.

Usage:
  gop collect --enterprise <slug> --out graph.json [--orgs a,b] [--app-id N --app-key-file PATH [--parallel N]]
              [--oidc-trust <files>] [--github-url URL] [--verbose] [--advisories <zip|dir> | --advisories-live]
              [--cache-dir DIR [--resume] [--incremental [--full-every DAYS]]] [--max-requests N] [--reserve N] [--priority a,b]
              [--merge-into graph.json --orgs a,b [--merge-force]]
  gop enrich  --graph graph.json [--oidc-trust <file|dir>[,...]] [--cartography export.json] [--poutine report.json]
              [--advisories <zip|dir> | --advisories-live] --out graph2.json
  gop advisories update [--out PATH]
  gop doctor  --enterprise <slug> [--github-url URL] [--orgs a,b] [--format text|json]
              [--app-id N --app-key-file PATH [--parallel N]]
  gop demo    [--size small|medium|large] [--seed N] [--out graph.json]
  gop serve   --graph graph.json | --demo  [--baseline old.json]
  gop report  --graph graph.json | --demo  --out report.html [--format html|md] [--top N]
              [--previous old.json] [--owner-threshold N]
  gop paths   --graph graph.json --from <principal> [--to <node>]
  gop who     --graph graph.json --target <node>
  gop validate --graph graph.json [--format text|json]
  gop redact  --graph graph.json --out shareable.json [--salt-file key] [--keep-attr k1,k2]
              [--map-out mapping.json]
  gop diff    OLD.json NEW.json [--format text|json|markdown] [--only paths,settings,edges,scores,coverage]
              [--fail-on confirmed-increase|any-new-path] [--force]
  gop fix-plan --graph graph.json | --demo  --pin <action> | --lower-default-perm <org> [--to read|none]
              | --restrict-token <workflow> | --harden-trigger <workflow> | --reduce-owners N
              [--format text|markdown|json]
  gop what-if --graph graph.json | --demo  [--pin <action>]... [--lower-default-perm <org>]... [--to read|none]
              [--restrict-token <workflow>]... [--harden-trigger <workflow>]... [--reduce-owners N]
              [--top N] [--limit N] [--format text|markdown|json]
  gop sarif   --graph graph.json | --demo  --out gop.sarif | --split-by-repo DIR [--top N]
              [--min-severity low|medium|high|critical] [--include-possible]
  gop summary --graph graph.json | --demo  --out summary.json [--names] [--top N]
  gop pin     --action <owner/repo@ref> [--graph graph.json [--repo owner/repo] [--offline]]
              [--github-url URL] [--format diff|text|json]
  gop export  --format cypher graph.json | --graph graph.json | --demo  [--out gop.cypher] [--github-url URL]
  gop export  --format sql graph.json [graph2.json ...] | --graph graph.json | --demo  [--out gop.sql]
  gop mcp-config --client claude|codex|cursor|cursor-link|vscode --graph graph.json
  gop version

collect reads the token from GITHUB_TOKEN (or GH_TOKEN). It only reads.
--use-gh-auth (collect, doctor, pin) takes the token of the gh login instead
(gh auth token, for --github-url's host or GH_HOST). Run as a gh extension
(gh gop ...), gop falls back to the gh login when neither variable is set.
When the token cannot read the enterprise (an org-scoped App installation
token, a non-owner token, or no read:enterprise), collect builds the graph
per org: from --orgs, or else the token's own orgs. Enterprise-level facts
are then not_visible and listed in coverage.
A collect that stops early (Ctrl-C, SIGTERM, --max-requests spent, the rate
limit exhausted, or --reserve reached with no reset to wait for) still writes
the graph it has, marked "partial": true, with what it did not read
not_visible and listed in coverage by org and phase, and exits 3. With
--cache-dir, --resume then completes it. --priority orgs are collected
first, then orgs by member count, largest first. --reserve N keeps N
requests of the hourly rate limit unspent for other jobs on the same token
(collect waits for the reset instead).
--merge-into graph.json with --orgs re-collects only those orgs and merges
them into the earlier graph of the same enterprise: their facts are replaced,
every other org's are kept with their coverage, and cross-org paths survive.
The earlier graph is only read (--out may name the same file). The merged
graph is validated before it is written; a stopped run writes a partial
merged graph. --merge-force merges across token modes (one token could read
the enterprise and the other could not).
GitHub App mode (--app-id and --app-key-file, or GOP_APP_ID and
GOP_APP_PRIVATE_KEY with the PEM contents) mints a read-only installation
token per org instead; it excludes GITHUB_TOKEN. The key stays in memory and
is never printed. Each installation has its own rate-limit budget, so App mode
reads --parallel orgs at once (default 4, at most 16; 1 is sequential). The
graph is the same at any --parallel.
collect logs per-repository not-visible errors (for example collaborators the
token cannot list) as one line per org with counts by HTTP status; the
details are in coverage. --verbose (or GOP_VERBOSE=1) logs every repository.
doctor is a read-only preflight for collect: token mode, scopes, SSO
authorization gaps, rate limit, a time estimate and what will come out
not_visible. In App mode it lists installations, the --orgs without one and
any granted permission that is not read. When a token-mode collect would take
more than 3 hours or wait for more than 2 rate-limit resets, doctor recommends
App mode and estimates its time. Exit 0 all pass, 1 any fail, 3 warnings only.
enrich reads cloud OIDC trust files you export (AWS, GCP, Azure), or a
Cartography export (--cartography, AWS; one or both), and adds the cloud roles each
workflow's token can assume (CAN_ASSUME). Offline: no token, no cloud API. Those hops have evidence "supplied" and every path through them
says it comes from a supplied file, not from the cloud. --poutine reads a poutine
JSON report and marks the workflows its findings name (poutine_rules,
poutine_severity); reach into a workflow with an injection finding ranks first.
gop never runs poutine; unmatched findings are listed in coverage.
advisories update downloads the OSV GitHub Actions advisories (all.zip) into
the user cache dir. collect and enrich match every action ref against that copy
(or --advisories, or the OSV API with --advisories-live) and mark affected refs
(attrs advisories, advisory_severity); with no data the check is skipped and
coverage says so. Paths through an affected action rank first.
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
what-if re-scores the graph with the fixes applied together (any mix of the
fix-plan flags; the repeatable ones more than once) and prints the confirmed and
possible (principal, repo) pairs before and after, the paths that disappear and
the top paths that remain: the numbers the MCP what_if tool reports. It changes
nothing.
sarif writes one SARIF 2.1.0 result per fixable edge (GOP001 mutable action
ref, GOP002 default permission). It lists attack paths: uploading it to code
scanning shows them to everyone with alert access. gop never uploads it.
summary writes gop.summary/v1: a small JSON (at most 64 KB) of coverage,
headline numbers, counts per SARIF rule and severity, pair totals and the top
findings as stable hash IDs (--names adds repo, workflow and org names). It
never holds tokens, emails, secret values, member logins or IP lists. It is
what the Action's optional cloud upload sends (docs/cloud.md).
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
	// gh reads the token of the GitHub CLI login (--use-gh-auth, or gop run
	// as `gh gop`); nil means running gh. Tests set a fake.
	gh ghTokener
	// advisoryPath is the default local copy of the OSV advisories
	// (advisory.DefaultPath); nil means none, so tests never read the
	// user's cache. osvZipURL and osvAPIURL override the OSV endpoints.
	advisoryPath         func() (string, error)
	osvZipURL, osvAPIURL string
}

func main() {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv, collect: collect.Collect, serve: mcpserver.ServeWith,
		advisoryPath: advisory.DefaultPath}
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
	case "what-if":
		err = a.cmdWhatIf(rest)
	case "pin":
		err = a.cmdPin(rest)
	case "sarif":
		err = a.cmdSARIF(rest)
	case "summary":
		err = a.cmdSummary(rest)
	case "export":
		err = a.cmdExport(rest)
	case "advisories":
		err = a.cmdAdvisories(rest)
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
	maxReq := fs.Int("max-requests", 0, "stop after this many API requests (0: no limit) and write a partial graph; "+
		"with --cache-dir, --resume continues from there")
	reserve := fs.Int("reserve", 0, "keep this many requests of the hourly rate limit unspent for other jobs on the same token: "+
		"wait for the reset instead of dipping below it, and stop with a partial graph when the reset cannot be waited for")
	priority := fs.String("priority", "", "comma-separated org logins to collect first, in this order "+
		"(the rest follow by member count, largest first), so a stopped or budgeted run covers them")
	incremental := fs.Bool("incremental", false, "with --cache-dir, re-read only what changed since the previous incremental run "+
		"with the same directory: repositories whose pushed_at and updated_at did not move are answered from that run's "+
		"records; org-level reads are always repeated")
	fullEvery := fs.Int("full-every", 7, "with --incremental, do a full run when the last one is at least this many days old")
	parallel := addParallelFlag(fs)
	mergeInto := fs.String("merge-into", "", "earlier graph.json of the same enterprise: re-collect only --orgs and merge them into it "+
		"(their facts are replaced, every other org's are kept); the file is only read")
	mergeForce := fs.Bool("merge-force", false, "with --merge-into, merge graphs collected in different token modes "+
		"(one token could read the enterprise and the other could not); not supported")
	verbose := fs.Bool("verbose", false, "log every per-repository not-visible error (for example collaborators the token "+
		"cannot list) instead of one summary line per org (or set GOP_VERBOSE=1)")
	var trusts trustFlag
	fs.Var(&trusts, "oidc-trust", trustUsage+" (runs gop enrich after collection)")
	adv := addAdvisoryFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("collect", "enterprise", *ent, "out", *out); err != nil {
		return err
	}
	if err := adv.check("collect"); err != nil {
		return err
	}
	if *resume && *cacheDir == "" {
		return usagef("collect: --resume needs --cache-dir")
	}
	if *maxReq < 0 {
		return usagef("collect: --max-requests must not be negative, got %d", *maxReq)
	}
	if *reserve < 0 {
		return usagef("collect: --reserve must not be negative, got %d", *reserve)
	}
	if *incremental && *cacheDir == "" {
		return usagef("collect: --incremental needs --cache-dir")
	}
	if *fullEvery < 1 {
		return usagef("collect: --full-every must be at least 1 (days)")
	}
	if err := checkParallel("collect", *parallel); err != nil {
		return err
	}
	base, err := loadMergeBase(*mergeInto, *mergeForce, *ent, splitList(*orgs))
	if err != nil {
		return err
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
	cr, err := a.resolveCreds("collect", af, *uf.useGH, ghHost(ep, a.getenv))
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
		MaxRequests:      *maxReq,
		Reserve:          *reserve,
		Priority:         splitList(*priority),
		Incremental:      *incremental,
		FullEvery:        time.Duration(*fullEvery) * 24 * time.Hour,
		Parallel:         *parallel,
		MergeInto:        base,
		MergeForce:       *mergeForce,
		Verbose:          *verbose || envTrue(a.getenv("GOP_VERBOSE")),
		Logf:             func(format string, args ...any) { fmt.Fprintf(a.stderr, "gop collect: "+format+"\n", args...) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, err := a.collect(ctx, cfg)
	var partial *collect.PartialError
	if err != nil && (!errors.As(err, &partial) || g == nil) {
		return errors.New(cr.redact(err.Error()))
	}
	if partial != nil && partial.Reason == graph.PartialInterrupted {
		// Writing the partial graph is quick; a second Ctrl-C now ends the
		// process at once.
		stop()
	}
	if len(trusts) > 0 {
		if err := a.enrich(g, trusts, ""); err != nil {
			return err
		}
	}
	a.applyAdvisories(ctx, "collect", g, adv)
	write := func(w io.Writer) error { return collect.WriteGraph(w, g) }
	if base != nil {
		data, err := validMerged(g)
		if err != nil {
			return err
		}
		write = func(w io.Writer) error { _, err := w.Write(data); return err }
	}
	if err := a.writeFile(*out, write); err != nil {
		return err
	}
	if base != nil {
		fmt.Fprintf(a.stderr, "gop collect: merged %s into %s, wrote %s\n", strings.Join(splitList(*orgs), ", "), *mergeInto, *out)
	}
	if partial == nil {
		return nil
	}
	next := "re-run to complete it (add --cache-dir DIR so a later stop can resume)"
	if *cacheDir != "" {
		next = "re-run the same command with --resume to complete it"
	}
	return codeError{exitPartial, errors.New(cr.redact(fmt.Sprintf("stopped early (%s): wrote a partial graph to %s; %s: %v",
		partial.Reason, *out, next, partial.Err)))}
}

// loadMergeBase reads the --merge-into graph, or returns nil when path is
// empty. It refuses, before any request, a merge that cannot work: no --orgs,
// --merge-force alone, an unreadable graph or one of another enterprise.
func loadMergeBase(path string, force bool, ent string, orgs []string) (*graph.Graph, error) {
	if strings.TrimSpace(path) == "" {
		if force {
			return nil, usagef("collect: --merge-force needs --merge-into")
		}
		return nil, nil
	}
	if len(orgs) == 0 {
		return nil, usagef("collect: --merge-into needs --orgs, the orgs to re-collect")
	}
	if path == "-" {
		return nil, usagef("collect: --merge-into needs a file, not stdin")
	}
	base, err := graph.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("collect: --merge-into: %w", err)
	}
	if !strings.EqualFold(base.Enterprise, ent) {
		return nil, usagef("collect: --merge-into %s is a graph of enterprise %q, not %q", path, base.Enterprise, ent)
	}
	return base, nil
}

// validMerged encodes a merged graph and checks it against the published
// JSON Schema (and that every edge endpoint is a node), so a merge never
// writes a graph gop validate would reject.
func validMerged(g *graph.Graph) ([]byte, error) {
	var buf bytes.Buffer
	if err := collect.WriteGraph(&buf, g); err != nil {
		return nil, err
	}
	res, err := schema.Validate(buf.Bytes())
	if err != nil {
		return nil, err
	}
	if !res.Valid {
		return nil, fmt.Errorf("collect: the merged graph is invalid (%d errors, first: %s); nothing was written", len(res.Errors), res.Errors[0])
	}
	return buf.Bytes(), nil
}

// envTrue reports whether an environment value turns a switch on: "1",
// "true", "t" and other strconv.ParseBool true values, in any case.
func envTrue(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
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
	size := fs.String("size", demo.SizeSmall, "small (7 orgs, ~65 repos), medium (20 orgs, ~1,000 repos) or large (60 orgs, ~10,000 repos)")
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
	ownerT := fs.Int("owner-threshold", graph.DefaultOwnerThreshold, "the suggested reduce_owners fix removes standing ownership from accounts that own this many orgs or more")
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
	if *ownerT <= 0 {
		return usagef("report: --owner-threshold must be positive, got %d", *ownerT)
	}
	g, err := a.loadGraph("report", *gp, *useDemo)
	if err != nil {
		return err
	}
	opts := report.Options{Format: f, Top: *top, Version: version, OwnerThreshold: *ownerT}
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
