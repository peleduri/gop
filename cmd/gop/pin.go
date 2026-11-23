package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/graph"
)

const pinHelp = `gop pin resolves an action ref to a commit SHA and prints the edits that pin it.

It makes read-only GET requests only: the commit SHA of the ref, whether the
ref is a tag or a branch, and (with --graph, unless --offline) each consuming
workflow file so the diff has exact context lines. It writes to stdout only:
it never writes files, calls a write endpoint or opens pull requests. Apply the
diff yourself, in a checkout of each repo: gop pin ... --repo acme-app/web | git apply

To keep pins current after this, use Dependabot
(https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot)
or Renovate (https://docs.renovatebot.com/modules/manager/github-actions/).

`

var hexSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// readOnlyTransport refuses every request that is not a GET or HEAD, so gop
// pin cannot write to GitHub even through a bug.
type readOnlyTransport struct{ next http.RoundTripper }

func (t readOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, fmt.Errorf("gop pin is read-only: refusing %s %s", r.Method, r.URL.Path)
	}
	return t.next.RoundTrip(r)
}

// pinResult is what gop pin prints, also as --format json.
type pinResult struct {
	Action   string    `json:"action"`
	Ref      string    `json:"ref"`
	SHA      string    `json:"sha"`
	RefKind  string    `json:"ref_kind"`
	Replace  string    `json:"replace"`
	With     string    `json:"with"`
	Graph    bool      `json:"graph"`
	Offline  bool      `json:"offline,omitempty"`
	Files    []pinFile `json:"files"`
	Skipped  []pinSkip `json:"skipped"`
	Warnings []string  `json:"warnings"`
}

type pinFile struct {
	Repo    string `json:"repo"`
	File    string `json:"file"`
	FileRef string `json:"file_ref,omitempty"`
	Lines   []int  `json:"lines"`
	Diff    string `json:"diff"`
}

type pinSkip struct {
	Repo   string `json:"repo"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

func (a *app) cmdPin(args []string) error {
	fs := a.flags("pin")
	action := fs.String("action", "", "action ref to pin, e.g. acme-actions/deploy@main (action: prefix optional)")
	gp := graphFlag(fs)
	format := fs.String("format", "diff", "diff, text or json")
	repo := fs.String("repo", "", "with --graph: only the workflows of this repo, e.g. acme-app/web (one repo per git apply)")
	ghURL := fs.String("github-url", "", "REST API root (default https://api.github.com; GHES: https://HOST/api/v3)")
	offline := fs.Bool("offline", false, "with --graph: do not fetch workflow files; print one-line hunks from the graph's line attributes (not git apply-able)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), pinHelp)
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("pin", "action", *action); err != nil {
		return err
	}
	uses := strings.TrimPrefix(strings.TrimSpace(*action), "action:")
	u, ok := collect.ParseUses(uses)
	if !ok {
		return usagef("pin: --action must look like owner/repo[/path]@ref, got %q", *action)
	}
	f := strings.ToLower(*format)
	if f != "diff" && f != "text" && f != "json" {
		return usagef("pin: --format must be diff, text or json, got %q", *format)
	}
	if *gp == "" && (*repo != "" || *offline) {
		return usagef("pin: --repo and --offline need --graph")
	}
	token := a.getenv("GITHUB_TOKEN")
	if token == "" {
		token = a.getenv("GH_TOKEN")
	}
	if token == "" {
		return usagef("pin: set GITHUB_TOKEN (or GH_TOKEN) to a read-only token; gop never takes a token as a flag")
	}
	var g *graph.Graph
	if *gp != "" {
		var err error
		if g, err = a.loadGraph("pin", *gp, false); err != nil {
			return err
		}
	}
	next := a.transport
	if next == nil {
		next = http.DefaultTransport
	}
	baseURL := *ghURL
	if baseURL == "" {
		baseURL = a.apiURL
	}
	client, err := collect.NewClient(collect.ClientOptions{
		BaseURL:     baseURL,
		Token:       token,
		HTTPClient:  &http.Client{Transport: readOnlyTransport{next}, Timeout: 60 * time.Second},
		MaxAttempts: 3,
		Logf: func(format string, args ...any) {
			fmt.Fprintln(a.stderr, scrub(fmt.Sprintf("gop pin: "+format, args...), token))
		},
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := pin(ctx, client, u, g, *repo, *offline)
	if err != nil {
		return errors.New(scrub(err.Error(), token))
	}
	for i := range res.Warnings {
		res.Warnings[i] = scrub(res.Warnings[i], token)
	}
	for i := range res.Skipped {
		res.Skipped[i].Reason = scrub(res.Skipped[i].Reason, token)
	}
	switch f {
	case "json":
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(res)
	case "text":
		writePinText(a.stdout, res, "")
	default:
		writePinDiff(a.stdout, res)
	}
	return nil
}

// escapePath escapes each segment of a slash-separated path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func pin(ctx context.Context, c *collect.Client, u collect.ActionUse, g *graph.Graph, onlyRepo string, offline bool) (*pinResult, error) {
	uses := u.Raw
	res := &pinResult{Action: uses, Ref: u.Ref, Graph: g != nil, Offline: offline, Files: []pinFile{}, Skipped: []pinSkip{}, Warnings: []string{}}
	host := u.Owner + "/" + u.Repo
	if u.RefKind == "sha" {
		res.SHA, res.RefKind = strings.ToLower(u.Ref), "sha"
		res.Replace, res.With = "uses: "+uses, "uses: "+uses
		res.Warnings = append(res.Warnings, uses+" is already pinned to a commit SHA: there is nothing to change")
		return res, nil
	}

	repoPath := "/repos/" + escapePath(host)
	body, err := c.GetRaw(ctx, repoPath+"/commits/"+escapePath(u.Ref), "application/vnd.github.sha")
	if err != nil {
		if s := collect.StatusOf(err); s == http.StatusNotFound || s == http.StatusUnprocessableEntity {
			return nil, fmt.Errorf("ref not found: %s (no commit for %q in %s, or the token cannot read %s)", uses, u.Ref, host, host)
		}
		return nil, err
	}
	sha := strings.ToLower(strings.TrimSpace(string(body)))
	if !hexSHA.MatchString(sha) {
		return nil, fmt.Errorf("resolving %s: the API did not return a commit SHA", uses)
	}
	res.SHA = sha
	value, comment := fixplan.PinnedUses(uses, sha)
	res.Replace, res.With = "uses: "+uses, "uses: "+value+" "+comment

	res.RefKind = "unknown"
	if l, err := collect.LookupRef(ctx, c, u.Owner, u.Repo, u.Ref); err != nil {
		res.Warnings = append(res.Warnings, "could not tell whether "+u.Ref+" is a tag or a branch: "+err.Error())
	} else if kind, ambiguous, found := l.Kind(); found {
		res.RefKind = kind
		if ambiguous {
			res.Warnings = append(res.Warnings, u.Ref+" is both a tag and a branch in "+host+": gop reads it as the branch, the more mutable of the two")
		}
	}
	if res.RefKind == "tag" {
		res.Warnings = append(res.Warnings, "tag "+u.Ref+" can be moved to another commit by anyone who can push tags to "+host+": the SHA pins what it points at now")
	}
	if g == nil {
		return res, nil
	}

	ix := graph.NewIndex(g)
	id := "action:" + uses
	if _, ok := ix.Node(id); !ok {
		res.Warnings = append(res.Warnings, "no workflow or action in this graph uses "+uses)
		return res, nil
	}
	plan := fixplan.Build(ix, graph.PinRef{Action: id})
	type key struct{ repo, file, ref string }
	lines := map[key][]int{}
	var order []key
	for _, s := range plan.Steps {
		if s.Kind != fixplan.KindEditWorkflow || (onlyRepo != "" && s.Repo != onlyRepo) {
			continue
		}
		if s.File == "" || s.Line <= 0 {
			res.Skipped = append(res.Skipped, pinSkip{Repo: s.Repo, File: s.File, Reason: "line not recorded in this graph: edit by hand"})
			continue
		}
		if from, _, _ := strings.Cut(s.Edge, " "); strings.HasPrefix(from, "action:") {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s %s is inside %s: its callers pick up the pin only when that ref points at the new commit (a SHA or tag pin needs a new pin)",
				s.Repo, s.File, strings.TrimPrefix(from, "action:")))
		}
		if s.Unconfirmed {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s %s:%d is not visible to the collecting token: confirm it exists first", s.Repo, s.File, s.Line))
		}
		k := key{s.Repo, s.File, s.FileRef}
		if _, ok := lines[k]; !ok {
			order = append(order, k)
		}
		lines[k] = append(lines[k], s.Line)
	}
	if onlyRepo != "" && len(order) == 0 && len(res.Skipped) == 0 {
		res.Warnings = append(res.Warnings, "no workflow in "+onlyRepo+" uses "+uses+" in this graph")
	}
	for _, k := range order {
		ls := lines[k]
		sort.Ints(ls)
		pf := pinFile{Repo: k.repo, File: k.file, FileRef: k.ref, Lines: ls}
		if offline {
			var b strings.Builder
			for _, l := range ls {
				b.WriteString(fixplan.PinDiff(k.file, l, uses, sha))
			}
			pf.Diff = b.String()
			res.Files = append(res.Files, pf)
			continue
		}
		path := "/repos/" + escapePath(k.repo) + "/contents/" + escapePath(k.file)
		if k.ref != "" {
			path += "?ref=" + url.QueryEscape(k.ref)
		}
		content, err := c.GetRaw(ctx, path, "application/vnd.github.raw")
		if err != nil {
			reason := "could not read the file: " + err.Error()
			if collect.IsNotFound(err) {
				reason = "file not found (moved or deleted since the graph was collected)"
			}
			res.Skipped = append(res.Skipped, pinSkip{Repo: k.repo, File: k.file, Reason: reason})
			continue
		}
		diff, missing := fixplan.PinFileDiff(k.file, content, ls, uses, sha)
		for _, l := range missing {
			res.Skipped = append(res.Skipped, pinSkip{Repo: k.repo, File: k.file, Line: l,
				Reason: "the line no longer reads uses: " + uses + " (the file changed since the graph was collected)"})
		}
		if diff == "" {
			continue
		}
		pf.Diff = diff
		res.Files = append(res.Files, pf)
	}
	if offline && len(res.Files) > 0 {
		res.Warnings = append(res.Warnings, "--offline hunks show the uses: entry without its indentation or list marker and carry no context: they do not apply with git apply; drop --offline for exact diffs")
	}
	if repos := filesRepos(res.Files); len(repos) > 1 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the diffs span %d repos: apply each repo's part in its own checkout, or use --repo", len(repos)))
	}
	if ids, labels := fixplan.NestedMutable(ix, id); len(labels) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("pinning %s alone does not close paths through the mutable refs it uses itself: %s. Pin those too (for example gop pin --action %s)",
			uses, strings.Join(labels, ", "), strings.TrimPrefix(ids[0], "action:")))
	}
	return res, nil
}

func filesRepos(files []pinFile) []string {
	var out []string
	for i, f := range files {
		if i == 0 || f.Repo != files[i-1].Repo {
			out = append(out, f.Repo)
		}
	}
	return out
}

// writePinText prints the resolution, the edits and the warnings, each line
// prefixed with prefix.
func writePinText(w io.Writer, r *pinResult, prefix string) {
	p := func(format string, args ...any) { fmt.Fprintf(w, prefix+format+"\n", args...) }
	p("action: %s", r.Action)
	p("sha: %s", r.SHA)
	p("ref kind: %s", r.RefKind)
	p("replace: %s", r.Replace)
	p("with:    %s", r.With)
	if r.Graph && len(r.Files) > 0 {
		p("files (%d):", len(r.Files))
		for _, f := range r.Files {
			ls := make([]string, len(f.Lines))
			for i, l := range f.Lines {
				ls[i] = fmt.Sprint(l)
			}
			p("  %s %s line %s", f.Repo, f.File, strings.Join(ls, ", "))
		}
	}
	for _, s := range r.Skipped {
		loc := s.File
		if s.Line > 0 {
			loc += fmt.Sprintf(":%d", s.Line)
		}
		p("skipped: %s %s: %s", s.Repo, strings.TrimSpace(loc), s.Reason)
	}
	for _, x := range r.Warnings {
		p("warning: %s", x)
	}
}

// writePinDiff prints the diffs, grouped by repo, under a commented header
// that git apply skips. Without a graph it prints the resolution only.
func writePinDiff(w io.Writer, r *pinResult) {
	if !r.Graph {
		writePinText(w, r, "")
		return
	}
	writePinText(w, r, "# ")
	for i, f := range r.Files {
		if i == 0 || f.Repo != r.Files[i-1].Repo {
			fmt.Fprintf(w, "# repo: %s (apply in a checkout of %s)\n", f.Repo, f.Repo)
		}
		fmt.Fprint(w, f.Diff)
	}
}
