// Package redact pseudonymizes a graph so it can be shared in a bug report:
// every org, repo, user, team, action, workflow file, secret name, runner
// label, environment and cloud name is replaced by a stable synthetic name,
// while the structure, evidence and the attrs reach depends on are kept. The
// same salt always gives the same output; a different salt gives different
// names.
//
// Names are assigned per category by sorting the real names on their
// HMAC-SHA256 under the salt and numbering them in that order, so numbers are
// unique, deterministic for a salt and say nothing about the real names or
// their alphabetical order. GitHub compares logins and repo names without
// case, and so does the engine (actions access): names that differ only in
// case get the same synthetic name with a different case pattern, so
// case-insensitive equality is kept and distinct IDs stay distinct.
//
// After rewriting, Redact runs a self-check: no enterprise-internal name of 3
// or more characters may appear anywhere in the output (case-insensitive
// substring scan). Third-party action owners and repos are renamed too but not
// scanned: they are public and collide with GitHub's own vocabulary
// ("actions", "github").
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/peleduri/gop/internal/graph"
)

// Options configure Redact.
type Options struct {
	// Salt keys the pseudonyms and the time offset. Required.
	Salt []byte
	// KeepAttrs lists attr keys to keep beyond gop's own (see DefaultAttrs).
	// Their values are rewritten through the same name map.
	KeepAttrs []string
}

// Result is a redacted graph and the real-to-fake mapping.
type Result struct {
	Graph *graph.Graph
	// Mapping is category -> real name -> synthetic name. It is sensitive:
	// it undoes the redaction.
	Mapping map[string]map[string]string
	// Dropped counts the attr values dropped per key (unknown keys, or
	// values outside a known key's vocabulary).
	Dropped map[string]int
}

// LeakError is returned when the self-check finds an original name in the
// output. It names locations only, never the name.
type LeakError struct {
	Locations []string // first few, e.g. nodes[3].attrs.note
	Count     int
}

func (e *LeakError) Error() string {
	return fmt.Sprintf("self-check failed: an original name still appears in %d places (%s); nothing was written",
		e.Count, strings.Join(e.Locations, ", "))
}

// Mapping categories.
const (
	CatEnterprise = "enterprise"
	CatOrg        = "orgs"
	CatExternal   = "external_owners"
	CatRepo       = "repos"
	CatExtRepo    = "external_repos"
	CatUser       = "users"
	CatTeam       = "teams"
	CatPrincipal  = "external_principals"
	CatWorkflow   = "workflow_files"
	CatPath       = "action_paths"
	CatRef        = "refs"
	CatSecret     = "secrets"
	CatLabel      = "runner_labels"
	CatEnv        = "environments"
	CatJob        = "jobs"
	CatCloud      = "cloud"
	CatFile       = "supplied_files"
)

type mode int

const (
	observe mode = iota // collect real names, output discarded
	record              // names assigned: record the mapping, free text not rewritten
	final               // build the output
)

type redactor struct {
	key  []byte
	keep map[string]bool
	mode mode

	inside  map[string]bool   // lowercased owners inside the enterprise
	refKind map[string]string // ref name -> sha | tag | branch

	orgs, exts, repos, extRepos, users, teams, principals *namer
	wfs, paths, tags, branches, secrets, labels, envs     *namer
	jobs, clouds, accounts, roles, files                  *namer

	offset time.Duration

	mapping map[string]map[string]string
	scan    map[string]bool // lowercased real names the self-check looks for
	words   map[string]string
	pairs   map[string]string
	vocab   map[string]bool // output values that are gop vocabulary (masked by the self-check)
	dropped map[string]int
}

// Redact returns a pseudonymized copy of g. g is not modified.
func Redact(g *graph.Graph, opts Options) (*Result, error) {
	if g == nil {
		return nil, errors.New("redact: nil graph")
	}
	if len(opts.Salt) == 0 {
		return nil, errors.New("redact: empty salt")
	}
	r := newRedactor(opts)
	r.prepare(g)
	r.mode = observe
	r.graph(g)
	for _, n := range r.namers() {
		if err := n.assign(); err != nil {
			return nil, err
		}
	}
	r.mode = record
	r.graph(g)
	r.buildText()
	r.mode = final
	r.dropped = map[string]int{}
	out := r.graph(g)
	if err := r.check(out); err != nil {
		return nil, err
	}
	return &Result{Graph: out, Mapping: r.mapping, Dropped: r.dropped}, nil
}

func newRedactor(opts Options) *redactor {
	r := &redactor{key: opts.Salt, keep: map[string]bool{}, mapping: map[string]map[string]string{}, scan: map[string]bool{},
		vocab: map[string]bool{}, dropped: map[string]int{}}
	for k := range DefaultAttrs {
		r.keep[k] = true
	}
	for _, k := range opts.KeepAttrs {
		if k = strings.TrimSpace(k); k != "" {
			r.keep[k] = true
		}
	}
	num := func(prefix, width string) func(int) string {
		return func(i int) string { return fmt.Sprintf("%s%0"+width+"d", prefix, i) }
	}
	r.orgs = r.newNamer("org", true, num("acme-org-", "2"))
	r.exts = r.newNamer("ext", true, num("ext-", "2"))
	r.repos = r.newNamer("repo", true, num("repo-", "3"))
	r.extRepos = r.newNamer("extrepo", true, num("action-", "3"))
	r.users = r.newNamer("user", true, num("user-", "3"))
	r.teams = r.newNamer("team", true, num("team-", "2"))
	r.principals = r.newNamer("principal", true, num("principal-", "2"))
	r.wfs = r.newNamer("wf", false, num("wf-", "3"))
	r.paths = r.newNamer("path", false, num("sub-", "2"))
	r.tags = r.newNamer("tag", false, num("v1.", "1"))
	r.branches = r.newNamer("branch", false, num("branch-", "1"))
	r.secrets = r.newNamer("secret", false, num("SECRET_", "3"))
	r.labels = r.newNamer("label", true, num("label-", "2"))
	r.envs = r.newNamer("env", true, num("env-", "2"))
	r.jobs = r.newNamer("job", false, num("job-", "2"))
	r.clouds = r.newNamer("cloud", false, num("target-", "2"))
	r.accounts = r.newNamer("account", false, num("account-", "2"))
	r.roles = r.newNamer("role", false, num("role-", "2"))
	r.files = r.newNamer("file", false, num("trust-", "2"))
	sum := r.mac("time-offset")
	day := uint64(24 * time.Hour / time.Second)
	r.offset = -time.Duration(day+binary.BigEndian.Uint64(sum[:8])%(365*day)) * time.Second
	return r
}

func (r *redactor) namers() []*namer {
	return []*namer{r.orgs, r.exts, r.repos, r.extRepos, r.users, r.teams, r.principals, r.wfs, r.paths, r.tags,
		r.branches, r.secrets, r.labels, r.envs, r.jobs, r.clouds, r.accounts, r.roles, r.files}
}

func (r *redactor) mac(s string) []byte {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// prepare decides which owners are inside the enterprise and the kind of
// every ref, before any name is assigned.
func (r *redactor) prepare(g *graph.Graph) {
	r.inside = map[string]bool{}
	ids := make([]string, 0, len(g.Nodes)+2*len(g.Edges))
	for _, n := range g.Nodes {
		ids = append(ids, n.ID)
	}
	for _, e := range g.Edges {
		ids = append(ids, e.From, e.To)
	}
	for _, id := range ids {
		prefix, rest, _ := strings.Cut(id, ":")
		switch prefix {
		case "org", "members", "repo", "workflow", "secret", "oidc", "runner", "team":
			o, _, _ := strings.Cut(rest, "/")
			if o != "" {
				r.inside[strings.ToLower(o)] = true
			}
		}
	}
	r.refKind = map[string]string{}
	set := func(ref, kind string) {
		if ref == "" || kind == "" {
			return
		}
		// A ref seen as a branch anywhere stays a branch: the more mutable reading.
		if r.refKind[ref] != "branch" {
			r.refKind[ref] = kind
		}
	}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindActionRef || strings.HasPrefix(n.ID, "action:") {
			set(refOf(n.ID), n.Attrs[graph.AttrRefKind])
		}
	}
	for _, e := range g.Edges {
		if e.Kind == graph.Uses {
			set(refOf(e.To), e.Attrs[graph.AttrRefKind])
		}
	}
}

func refOf(actionID string) string {
	if i := strings.LastIndex(actionID, "@"); i >= 0 {
		return actionID[i+1:]
	}
	return ""
}

// graph rewrites g in the current mode.
func (r *redactor) graph(g *graph.Graph) *graph.Graph {
	out := &graph.Graph{Schema: g.Schema, Enterprise: r.enterprise(g.Enterprise), CollectedAt: r.time(g.CollectedAt),
		AuditRetentionDays: g.AuditRetentionDays,
		Nodes:              make([]graph.Node, 0, len(g.Nodes)), Edges: make([]graph.Edge, 0, len(g.Edges)), Coverage: make([]graph.Coverage, 0, len(g.Coverage))}
	for _, n := range g.Nodes {
		out.Nodes = append(out.Nodes, r.node(n))
	}
	for _, e := range g.Edges {
		out.Edges = append(out.Edges, r.edge(e))
	}
	for _, c := range g.Coverage {
		out.Coverage = append(out.Coverage, graph.Coverage{Scope: r.scope(c.Scope), Fact: r.text(c.Fact), Reason: r.text(c.Reason), NeedsFix: r.text(c.NeedsFix)})
	}
	// Sort on the synthetic names: the original order follows the real names.
	sort.SliceStable(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	sort.SliceStable(out.Edges, func(i, j int) bool {
		a, b := out.Edges[i], out.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.SourceAPI < b.SourceAPI
	})
	sort.SliceStable(out.Coverage, func(i, j int) bool {
		a, b := out.Coverage[i], out.Coverage[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Fact != b.Fact {
			return a.Fact < b.Fact
		}
		return a.Reason < b.Reason
	})
	return out
}

func (r *redactor) time(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.Add(r.offset).UTC()
}

func (r *redactor) node(n graph.Node) graph.Node {
	id := r.id(n.ID)
	out := graph.Node{ID: id, Kind: n.Kind, Name: r.nodeName(n, id), Evidence: n.Evidence}
	out.Attrs = r.attrs(n.Attrs, attrCtx{node: &n})
	for k, ev := range n.AttrEvidence {
		if _, ok := out.Attrs[k]; !ok {
			continue
		}
		if out.AttrEvidence == nil {
			out.AttrEvidence = map[string]graph.Evidence{}
		}
		out.AttrEvidence[k] = ev
	}
	return out
}

// nodeName rebuilds the display name from the synthetic ID: collectors put
// real names into free-form names ("acme-app/web OIDC token").
func (r *redactor) nodeName(n graph.Node, id string) string {
	_, rest, _ := strings.Cut(id, ":")
	switch {
	case n.ID == "external:anyone":
		return "anyone on the internet"
	case strings.HasPrefix(id, "members:"):
		return "members of " + rest
	}
	return rest
}

func (r *redactor) edge(e graph.Edge) graph.Edge {
	return graph.Edge{From: r.id(e.From), To: r.id(e.To), Kind: e.Kind, Evidence: e.Evidence, SourceAPI: r.sourceAPI(e.SourceAPI),
		ObservedAt: r.time(e.ObservedAt), Attrs: r.attrs(e.Attrs, attrCtx{edge: &e})}
}

func (r *redactor) scope(s string) string {
	if graph.KindFromID(s) != "" {
		return r.id(s)
	}
	return r.text(s)
}

// sourceAPI keeps gop's own API vocabulary and renames supplied file paths.
func (r *redactor) sourceAPI(s string) string {
	if p, ok := strings.CutPrefix(s, graph.SourceSupplied); ok {
		return graph.SourceSupplied + r.file(p)
	}
	return s
}

// id rewrites a node ID through the name map, keeping its convention.
func (r *redactor) id(id string) string {
	prefix, rest, ok := strings.Cut(id, ":")
	if !ok || rest == "" {
		return r.text(id)
	}
	switch prefix {
	case "enterprise":
		return prefix + ":" + r.enterprise(rest)
	case "org", "members":
		return prefix + ":" + r.owner(rest)
	case "identity", "user", "app":
		return prefix + ":" + r.user(rest)
	case "team":
		o, s, ok := strings.Cut(rest, "/")
		if !ok {
			return prefix + ":" + r.owner(rest)
		}
		return prefix + ":" + r.owner(o) + "/" + r.team(o, s)
	case "repo", "secret", "oidc", "runner":
		return prefix + ":" + r.repoPath(rest)
	case "workflow":
		o, tail, ok := strings.Cut(rest, "/")
		if !ok {
			return prefix + ":" + r.owner(rest)
		}
		name, p, ok := strings.Cut(tail, "/")
		if !ok {
			return prefix + ":" + r.owner(o) + "/" + r.repo(o, name)
		}
		return prefix + ":" + r.owner(o) + "/" + r.repo(o, name) + "/" + r.path(p)
	case "action":
		return prefix + ":" + r.action(rest)
	case "cloud":
		provider, target, ok := strings.Cut(rest, ":")
		if !ok {
			return prefix + ":" + r.cloud(rest)
		}
		return prefix + ":" + provider + ":" + r.cloud(target)
	case "external":
		if rest == "anyone" {
			return id
		}
		return prefix + ":" + r.name(r.principals, CatPrincipal, rest, true)
	}
	return r.text(id)
}

// repoPath maps "owner/repo[/more]".
func (r *redactor) repoPath(s string) string {
	o, tail, ok := strings.Cut(s, "/")
	if !ok {
		return r.owner(s)
	}
	name, more, ok := strings.Cut(tail, "/")
	out := r.owner(o) + "/" + r.repo(o, name)
	if ok {
		out += "/" + r.path(more)
	}
	return out
}

// action maps an action ref "owner/repo[/path]@ref".
func (r *redactor) action(raw string) string {
	spec, ref, hasRef := raw, "", false
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		spec, ref, hasRef = raw[:i], raw[i+1:], true
	}
	out := r.repoPath(spec)
	if hasRef {
		out += "@" + r.ref(ref)
	}
	return out
}

func (r *redactor) enterprise(slug string) string {
	if slug == "" {
		return ""
	}
	r.rec(CatEnterprise, slug, "acme-enterprise", true)
	return "acme-enterprise"
}

func (r *redactor) owner(o string) string {
	if o == "" {
		return ""
	}
	if r.inside[strings.ToLower(o)] {
		return r.name(r.orgs, CatOrg, o, true)
	}
	return r.name(r.exts, CatExternal, o, false)
}

func (r *redactor) repo(o, name string) string {
	if name == "" {
		return ""
	}
	key := strings.ToLower(o) + "/" + name
	in := r.inside[strings.ToLower(o)]
	n, cat := r.extRepos, CatExtRepo
	if in {
		n, cat = r.repos, CatRepo
	}
	f := n.name(key)
	if r.mode == record {
		r.rec(cat, o+"/"+name, r.owner(o)+"/"+f, in)
		if in {
			r.scanName(name)
		}
	}
	return f
}

func (r *redactor) user(login string) string { return r.name(r.users, CatUser, login, true) }

func (r *redactor) team(o, slug string) string {
	f := r.teams.name(strings.ToLower(o) + "/" + slug)
	if r.mode == record {
		r.rec(CatTeam, o+"/"+slug, r.owner(o)+"/"+f, true)
		r.scanName(slug)
	}
	return f
}

// path maps a path inside a repo: a workflow file keeps .github/workflows/
// and its extension; anything else becomes sub-NN, keeping a trailing
// action.yml or action.yaml.
func (r *redactor) path(p string) string {
	if p == "" {
		return ""
	}
	if base, ok := strings.CutPrefix(p, ".github/workflows/"); ok && base != "" {
		return ".github/workflows/" + r.wfFile(base)
	}
	dir, base := path.Split(p)
	if dir != "" && (base == "action.yml" || base == "action.yaml") {
		return r.name(r.paths, CatPath, strings.TrimSuffix(dir, "/"), false) + "/" + base
	}
	return r.name(r.paths, CatPath, p, false)
}

func (r *redactor) wfFile(base string) string {
	ext := path.Ext(base)
	if ext != ".yml" && ext != ".yaml" {
		ext = ".yml"
	}
	f := r.wfs.name(base) + ext
	if r.mode == record {
		r.rec(CatWorkflow, base, f, true)
	}
	return f
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// ref maps a git ref: a commit SHA becomes another hex string of the same
// length, a tag v1.N and a branch branch-N. refs/heads/ and refs/tags/
// prefixes are kept.
func (r *redactor) ref(ref string) string {
	if ref == "" {
		return ""
	}
	for _, p := range []string{"refs/heads/", "refs/tags/"} {
		if rest, ok := strings.CutPrefix(ref, p); ok {
			return p + r.ref(rest)
		}
	}
	var f string
	switch {
	case hexRe.MatchString(ref) && (len(ref) == 40 || r.refKind[ref] == "sha"):
		f = hex.EncodeToString(r.mac("sha\x00" + ref))[:len(ref)]
	case r.refKind[ref] == "tag":
		f = r.tags.name(ref)
	default:
		f = r.branches.name(ref)
	}
	if r.mode == record {
		r.rec(CatRef, ref, f, false)
	}
	return f
}

func (r *redactor) cloud(target string) string  { return r.name(r.clouds, CatCloud, target, true) }
func (r *redactor) file(p string) string        { return r.name(r.files, CatFile, p, true) + ".json" }
func (r *redactor) secret(s string) string      { return r.name(r.secrets, CatSecret, s, true) }
func (r *redactor) environment(s string) string { return r.name(r.envs, CatEnv, s, true) }
func (r *redactor) job(s string) string         { return r.name(r.jobs, CatJob, s, false) }

// label keeps GitHub's own runner labels and renames the rest.
func (r *redactor) label(s string) string {
	if githubLabel(s) {
		return s
	}
	return r.name(r.labels, CatLabel, s, true)
}

var hostedLabelRe = regexp.MustCompile(`^(ubuntu|windows|macos)-[a-z0-9.-]+$`)

func githubLabel(s string) bool {
	switch strings.ToLower(s) {
	case "self-hosted", "linux", "windows", "macos", "x64", "arm", "arm64", "gpu":
		return true
	}
	return hostedLabelRe.MatchString(strings.ToLower(s))
}

// name maps real through n and records it in the mapping.
func (r *redactor) name(n *namer, cat, real string, scan bool) string {
	if real == "" {
		return ""
	}
	f := n.name(real)
	if r.mode == record {
		r.rec(cat, real, f, scan)
	}
	return f
}

func (r *redactor) rec(cat, real, fake string, scan bool) {
	if r.mode != record || real == "" {
		return
	}
	m := r.mapping[cat]
	if m == nil {
		m = map[string]string{}
		r.mapping[cat] = m
	}
	m[real] = fake
	if scan {
		r.scanName(real)
	}
}

func (r *redactor) scanName(s string) {
	if len(s) >= minScan {
		r.scan[strings.ToLower(s)] = true
	}
}

// minScan is the shortest original name the self-check looks for.
const minScan = 3

// namer assigns synthetic names in one category.
type namer struct {
	cat    string
	key    []byte
	fold   bool // names that differ only in case share a number
	format func(int) string
	seen   map[string]bool
	fake   map[string]string // nil until assign
}

func (r *redactor) newNamer(cat string, fold bool, format func(int) string) *namer {
	return &namer{cat: cat, key: r.key, fold: fold, format: format, seen: map[string]bool{}}
}

func (n *namer) name(real string) string {
	if n.fake == nil {
		n.seen[real] = true
		return real
	}
	if f, ok := n.fake[real]; ok {
		return f
	}
	// Every structured name is seen while observing; this is a safe fallback.
	return n.cat + "-unmapped"
}

func (n *namer) mac(s string) string {
	m := hmac.New(sha256.New, n.key)
	m.Write([]byte(n.cat + "\x00" + s))
	return hex.EncodeToString(m.Sum(nil))
}

func (n *namer) assign() error {
	groups := map[string][]string{}
	for s := range n.seen {
		k := s
		if n.fold {
			k = strings.ToLower(s)
		}
		groups[k] = append(groups[k], s)
	}
	keys := make([]string, 0, len(groups))
	macs := make(map[string]string, len(groups))
	for k := range groups {
		keys = append(keys, k)
		macs[k] = n.mac(k)
	}
	sort.Slice(keys, func(i, j int) bool { return macs[keys[i]] < macs[keys[j]] })
	n.fake = make(map[string]string, len(n.seen))
	for i, k := range keys {
		base := n.format(i + 1)
		vs := groups[k]
		// The all-lowercase spelling gets the plain name; other spellings
		// get case patterns in HMAC order.
		sort.Slice(vs, func(a, b int) bool {
			la, lb := vs[a] == k, vs[b] == k
			if la != lb {
				return la
			}
			return n.mac(vs[a]) < n.mac(vs[b])
		})
		for v, s := range vs {
			f, err := applyCase(base, v)
			if err != nil {
				return fmt.Errorf("redact: %s: %d spellings of one name differ only in case", n.cat, len(vs))
			}
			n.fake[s] = f
		}
	}
	return nil
}

// applyCase upper-cases the letters of base selected by the bits of v.
func applyCase(base string, v int) (string, error) {
	if v == 0 {
		return base, nil
	}
	b := []rune(base)
	bit := 0
	for i, c := range b {
		if !unicode.IsLetter(c) {
			continue
		}
		if v&(1<<bit) != 0 {
			b[i] = unicode.ToUpper(c)
		}
		bit++
	}
	if v >= 1<<bit {
		return "", errors.New("too many case variants")
	}
	return string(b), nil
}
