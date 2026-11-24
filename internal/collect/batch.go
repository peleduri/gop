package collect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// DefaultBatchSize is how many repositories one batched GraphQL query reads.
// 25 repositories with about 20 tree entries each stays well inside GitHub's
// per-query node and cost limits.
const DefaultBatchSize = 25

// workflowDirExpr reads the default branch's workflow directory, like the
// REST contents call without a ref.
const workflowDirExpr = "HEAD:.github/workflows"

// githubDirExpr lists the default branch's .github directory (names and
// types only). GraphQL answers null both for a missing workflows directory
// and for a submodule there, which REST tells apart; the listing does too.
const githubDirExpr = "HEAD:.github"

// Git tree entry modes of regular files.
const (
	modeFile       = 0o100644
	modeExecutable = 0o100755
)

// errTooLarge is the read error of a blob GraphQL returned without its full
// text. gop never parses partial YAML.
var errTooLarge = errors.New("file too large or binary")

// batchState is the batched GraphQL file reader's state for one run.
type batchState struct {
	off     bool // batching disabled (by config or after an unsupported query)
	size    int  // current batch size; halves on RESOURCE_LIMITS_EXCEEDED
	shrunk  bool // the size change has been logged
	queries int  // batched queries sent
}

func newBatchState(cfg Config) batchState {
	size := cfg.BatchSize
	if size <= 0 {
		size = DefaultBatchSize
	}
	return batchState{off: cfg.DisableGraphQLBatch, size: size}
}

// objReq asks for git objects of one repository by rev:path expressions.
// Every string here may come from attacker-written workflow files: they are
// only ever sent as GraphQL variables.
type objReq struct {
	owner, name string
	exprs       []string
	// shallow[j], when set, asks only for expression j's tree entry names,
	// types and modes, not file contents.
	shallow []bool
}

func (r objReq) isShallow(j int) bool { return j < len(r.shallow) && r.shallow[j] }

// objResult is the answer to one objReq. ok is false when the repository
// alias failed (or batching is off), so the caller falls back to REST. objs
// holds one object per expression; nil means the object does not exist.
type objResult struct {
	ok   bool
	objs []*gqlObject
}

type gqlBlob struct {
	Typename    string  `json:"__typename"`
	Text        *string `json:"text"`
	ByteSize    int     `json:"byteSize"`
	IsBinary    bool    `json:"isBinary"`
	IsTruncated bool    `json:"isTruncated"`
}

// complete reports whether the blob's full text came back.
func (b *gqlBlob) complete() bool {
	return b != nil && b.Text != nil && !b.IsBinary && !b.IsTruncated
}

type gqlTreeEntry struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"` // blob, tree or commit (submodule)
	Mode   int      `json:"mode"`
	Object *gqlBlob `json:"object"`
}

type gqlObject struct {
	gqlBlob
	Entries []gqlTreeEntry `json:"entries"`
}

const objectFragment = `fragment gopObject on GitObject {
  __typename
  ... on Blob { text byteSize isBinary isTruncated }
  ... on Tree { entries { name type mode object { __typename ... on Blob { text byteSize isBinary isTruncated } } } }
}
`

const entriesFragment = `fragment gopEntries on GitObject {
  __typename
  ... on Tree { entries { name type mode } }
}
`

// buildObjectQuery returns one query with an alias per request. Aliases and
// variable names are built from indexes only; owner, name and expression
// values travel in the variables map and never in the query text.
func buildObjectQuery(reqs []objReq) (string, map[string]any) {
	vars := map[string]any{}
	var decl, body strings.Builder
	usesObject, usesEntries := false, false
	for i, r := range reqs {
		is := strconv.Itoa(i)
		decl.WriteString("$o" + is + ": String!, $n" + is + ": String!, ")
		vars["o"+is], vars["n"+is] = r.owner, r.name
		body.WriteString("  r" + is + ": repository(owner: $o" + is + ", name: $n" + is + ") {\n")
		for j, e := range r.exprs {
			v := "e" + is + "_" + strconv.Itoa(j)
			decl.WriteString("$" + v + ": String!, ")
			vars[v] = e
			frag := "gopObject"
			if r.isShallow(j) {
				frag, usesEntries = "gopEntries", true
			} else {
				usesObject = true
			}
			body.WriteString("    f" + strconv.Itoa(j) + ": object(expression: $" + v + ") { ..." + frag + " }\n")
		}
		body.WriteString("  }\n")
	}
	// GraphQL rejects a document with an unused fragment.
	q := "query(" + strings.TrimSuffix(decl.String(), ", ") + ") {\n" + body.String() +
		"  rateLimit { cost remaining resetAt }\n}\n"
	if usesObject {
		q += objectFragment
	}
	if usesEntries {
		q += entriesFragment
	}
	return q, vars
}

// isLimitError reports a query GitHub refused as too expensive or too slow.
func isLimitError(errs GraphQLErrors) bool {
	for _, e := range errs {
		if e.Type == "RESOURCE_LIMITS_EXCEEDED" || e.Type == "MAX_NODE_LIMIT_EXCEEDED" ||
			strings.EqualFold(e.Type, "TIMEOUT") || strings.Contains(strings.ToLower(e.Message), "timeout") {
			return true
		}
	}
	return false
}

// aliasIndex returns N for an error path starting at alias "rN", else -1.
func aliasIndex(path []any) int {
	if len(path) == 0 {
		return -1
	}
	s, ok := path[0].(string)
	if !ok || !strings.HasPrefix(s, "r") {
		return -1
	}
	n, err := strconv.Atoi(s[1:])
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// disableBatch turns batching off for the rest of the run.
func (k *collector) disableBatch(why string) {
	if !k.batch.off {
		k.batch.off = true
		k.logf("collect: batched GraphQL file reads disabled, using REST: %s", why)
	}
}

// fetchObjects runs reqs through c as batched GraphQL queries. A query
// GitHub finds too expensive is split in two and retried (25 -> 13 + 12),
// down to one request, after which that request falls back to REST. The only
// error returned is the context's.
func (k *collector) fetchObjects(ctx context.Context, c *Client, reqs []objReq) ([]objResult, error) {
	out := make([]objResult, len(reqs))
	if k.batch.off || len(reqs) == 0 {
		return out, nil
	}
	q, vars := buildObjectQuery(reqs)
	var data map[string]json.RawMessage
	k.batch.queries++
	gqlErrs, err := c.GraphQL(ctx, q, vars, &data)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if s := StatusOf(err); s == 0 || s >= http.StatusInternalServerError {
			return k.splitFetch(ctx, c, reqs) // timeouts surface as 502/504 or transport errors
		}
		k.disableBatch(err.Error())
		return out, nil
	}
	if isLimitError(gqlErrs) {
		return k.splitFetch(ctx, c, reqs)
	}
	if data == nil {
		// Query-level errors only: an older GHES schema, for example.
		k.disableBatch(gqlErrs.Error())
		return out, nil
	}
	failed := map[int]bool{}
	for _, e := range gqlErrs {
		i := aliasIndex(e.Path)
		if i < 0 {
			return out, nil // an error not tied to one repository: REST for the whole batch
		}
		failed[i] = true
	}
	for i, r := range reqs {
		raw, present := data["r"+strconv.Itoa(i)]
		if failed[i] || !present || string(raw) == "null" {
			continue
		}
		var repo map[string]*gqlObject
		if json.Unmarshal(raw, &repo) != nil {
			continue
		}
		res := objResult{ok: true, objs: make([]*gqlObject, len(r.exprs))}
		for j := range r.exprs {
			obj, present := repo["f"+strconv.Itoa(j)]
			if !present {
				res.ok = false
				break
			}
			res.objs[j] = obj
		}
		out[i] = res
	}
	if raw, ok := data["rateLimit"]; ok {
		var rl struct {
			Remaining *int      `json:"remaining"`
			ResetAt   time.Time `json:"resetAt"`
		}
		if json.Unmarshal(raw, &rl) == nil && rl.Remaining != nil {
			c.noteGraphQLRate(*rl.Remaining, rl.ResetAt)
		}
	}
	return out, nil
}

// splitFetch halves reqs and fetches both halves; a single request that is
// still too expensive falls back to REST.
func (k *collector) splitFetch(ctx context.Context, c *Client, reqs []objReq) ([]objResult, error) {
	if len(reqs) <= 1 {
		return make([]objResult, len(reqs)), nil
	}
	h := (len(reqs) + 1) / 2
	if h < k.batch.size {
		k.batch.size = h
		if !k.batch.shrunk {
			k.batch.shrunk = true
			k.logf("collect: GraphQL query too expensive, reducing the batch size to %d", h)
		}
	}
	a, err := k.fetchObjects(ctx, c, reqs[:h])
	if err != nil {
		return nil, err
	}
	b, err := k.fetchObjects(ctx, c, reqs[h:])
	if err != nil {
		return nil, err
	}
	return append(a, b...), nil
}

// ---- workflows ----

type repoRef struct {
	o    *orgState
	repo *graph.Node
}

// collectAllWorkflows reads the default-branch workflows of every collected,
// non-archived repository, in order. Runs of repositories that share a client
// are read in batched GraphQL queries; a repository whose alias fails is read
// over REST, as is everything when batching is off.
func (k *collector) collectAllWorkflows(ctx context.Context) error {
	var all []repoRef
	for _, o := range k.orgs {
		for _, r := range o.repos {
			if r.Attrs[graph.AttrArchived] == "true" {
				continue // archived repositories cannot run workflows
			}
			all = append(all, repoRef{o, r})
		}
	}
	done := 0
	for len(all) > 0 {
		c := k.cl(all[0].o.login)
		n := 1
		for n < len(all) && n < k.batch.size && k.cl(all[n].o.login) == c {
			n++
		}
		chunk := all[:n]
		all = all[n:]
		reqs := make([]objReq, len(chunk))
		for i, rr := range chunk {
			reqs[i] = objReq{owner: rr.o.login, name: repoName(rr.o, rr.repo),
				exprs: []string{workflowDirExpr, githubDirExpr}, shallow: []bool{false, true}}
		}
		res, err := k.fetchObjects(ctx, c, reqs)
		if err != nil {
			return err
		}
		for i, rr := range chunk {
			handled := false
			if res[i].ok {
				if handled, err = k.applyWorkflowDir(ctx, rr.o, rr.repo, res[i].objs[0], res[i].objs[1]); err != nil {
					return err
				}
			}
			if !handled {
				if err := k.collectWorkflows(ctx, rr.o, rr.repo); err != nil {
					return err
				}
			}
			done++
			k.progress(PhaseWorkflows, done, done+len(chunk)-i-1+len(all))
		}
	}
	return nil
}

func repoName(o *orgState, repo *graph.Node) string {
	return strings.TrimPrefix(repo.ID, "repo:"+o.login+"/")
}

// applyWorkflowDir builds a repository's workflow facts from its batched
// .github/workflows tree. It returns false, having changed nothing, when the
// tree holds something only REST reads the same way (a submodule at
// .github/workflows, or a symlinked or submodule workflow file), so the
// caller falls back to REST. github is the shallow .github listing.
func (k *collector) applyWorkflowDir(ctx context.Context, o *orgState, repo *graph.Node, dir, github *gqlObject) (bool, error) {
	full := o.login + "/" + repoName(o, repo)
	switch {
	case dir == nil && github != nil && entryType(github, "workflows") != "":
		if entryType(github, "workflows") != "commit" {
			return false, nil // listed but not resolvable: let REST decide
		}
		// A submodule: GraphQL resolves it to null, REST to an object.
		fallthrough
	case dir != nil && dir.Typename == "Blob":
		// A file, symlink or submodule at .github/workflows: REST returns an
		// object, not a listing, so the workflows are unknown, not absent.
		setAttr(repo, "workflows", "unknown", graph.NotVisible)
		k.cover(repo.ID, "workflows", "unexpected contents response for .github/workflows",
			"check .github/workflows in "+full+" is a directory")
		return true, nil
	case dir == nil:
		// Missing directory (or empty repository): REST answers 404.
		setAttr(repo, "workflows", "0", graph.Live)
		return true, nil
	case dir.Typename != "Tree":
		return false, nil // a submodule or other shape: let REST decide
	}
	for _, e := range dir.Entries {
		if !isYAMLName(e.Name) {
			continue
		}
		if e.Type == "commit" || (e.Type == "blob" && e.Mode != modeFile && e.Mode != modeExecutable) {
			return false, nil
		}
	}
	for _, e := range dir.Entries {
		if e.Name != actionsLockName {
			continue
		}
		switch {
		case e.Type != "blob" || (e.Mode != modeFile && e.Mode != modeExecutable):
			k.noteActionsLock(repo, nil, errLockNotFile)
		case !e.Object.complete():
			k.noteActionsLock(repo, nil, errTooLarge)
		default:
			k.noteActionsLock(repo, []byte(*e.Object.Text), nil)
		}
		break
	}
	count := 0
	var pending []tokenDefault
	for _, e := range dir.Entries {
		if e.Type != "blob" || !isYAMLName(e.Name) {
			continue
		}
		path := ".github/workflows/" + e.Name
		if !e.Object.complete() {
			k.cover(repo.ID, "workflow:"+path, errTooLarge.Error(),
				"review "+path+" in "+full+" by hand (gop does not parse partial files)")
			continue
		}
		count++
		pending = k.processWorkflowFile(o, repo, path, []byte(*e.Object.Text), pending)
	}
	setAttr(repo, "workflows", strconv.Itoa(count), graph.Live)
	return true, k.resolveTokenDefaults(ctx, o, repo, pending)
}

// entryType returns the type of tree's entry called name, or "".
func entryType(tree *gqlObject, name string) string {
	for _, e := range tree.Entries {
		if e.Name == name {
			return e.Type
		}
	}
	return ""
}

// ---- nested actions and reusable workflows ----

// nestedReq returns the batched read for one queued reference, or false when
// it must be read over REST (no ref, or a ref or path git would parse
// differently from the REST contents API).
func nestedReq(u ActionUse) (objReq, bool) {
	if u.Ref == "" || strings.Contains(u.Ref, ":") {
		return objReq{}, false
	}
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "." || seg == ".." {
			return objReq{}, false
		}
	}
	r := objReq{owner: u.Owner, name: u.Repo}
	if u.IsReusableWorkflow() {
		r.exprs = []string{u.Ref + ":" + strings.Trim(u.Path, "/")}
	} else {
		for _, fname := range []string{"action.yml", "action.yaml"} {
			r.exprs = append(r.exprs, u.Ref+":"+strings.Trim(u.Path+"/"+fname, "/"))
		}
	}
	return r, true
}

// prefetchNested reads the files of one wave of queued references in
// batched queries, grouped by client. Entry i of the result is nil when
// wave[i] must be read over REST.
func (k *collector) prefetchNested(ctx context.Context, wave []queued) ([]*nestedFile, error) {
	pre := make([]*nestedFile, len(wave))
	if k.batch.off {
		return pre, nil
	}
	type group struct {
		c    *Client
		idx  []int
		reqs []objReq
	}
	var groups []*group
	byClient := map[*Client]*group{}
	for i, q := range wave {
		if q.depth > MaxNestedDepth {
			continue
		}
		r, ok := nestedReq(q.use)
		if !ok {
			continue
		}
		c := k.cl(q.use.Owner)
		g := byClient[c]
		if g == nil {
			g = &group{c: c}
			byClient[c] = g
			groups = append(groups, g)
		}
		g.idx = append(g.idx, i)
		g.reqs = append(g.reqs, r)
	}
	for _, g := range groups {
		for start := 0; start < len(g.reqs); {
			end := min(start+k.batch.size, len(g.reqs))
			res, err := k.fetchObjects(ctx, g.c, g.reqs[start:end])
			if err != nil {
				return nil, err
			}
			for j, r := range res {
				if r.ok {
					pre[g.idx[start+j]] = nestedResult(wave[g.idx[start+j]].use, r.objs)
				}
			}
			start = end
		}
	}
	return pre, nil
}

// nestedResult turns the objects of one batched nested read into the file
// the REST path would have read: action.yml first, then action.yaml; a
// missing file is a 404 on the last path tried. It returns nil (REST
// fallback) for anything that is not a plain blob.
func nestedResult(u ActionUse, objs []*gqlObject) *nestedFile {
	paths := []string{strings.Trim(u.Path, "/")}
	if !u.IsReusableWorkflow() {
		paths = []string{strings.Trim(u.Path+"/action.yml", "/"), strings.Trim(u.Path+"/action.yaml", "/")}
	}
	if len(objs) != len(paths) {
		return nil
	}
	for i, obj := range objs {
		if obj == nil {
			continue
		}
		if obj.Typename != "Blob" {
			return nil
		}
		if !obj.complete() {
			return &nestedFile{path: paths[i], err: errTooLarge}
		}
		return &nestedFile{path: paths[i], data: []byte(*obj.Text)}
	}
	last := paths[len(paths)-1]
	return &nestedFile{path: last, err: &APIError{
		Method: http.MethodGet, Path: contentsPath(u.Owner, u.Repo, last, u.Ref), StatusCode: http.StatusNotFound, Message: "Not Found",
	}}
}
