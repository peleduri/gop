package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// refBatchSize is the number of (repo, ref) lookups per GraphQL query.
const refBatchSize = 50

// shortSHARe matches an abbreviated commit SHA. Actions does not accept one as
// a ref, so gop does not look it up.
var shortSHARe = regexp.MustCompile(`^[0-9a-fA-F]{7,39}$`)

// RefLookup says whether a ref name exists as a tag and as a branch of a repo.
type RefLookup struct {
	Tag, Branch bool
}

// Kind classifies the lookup: tag or branch, ambiguous when the name is both
// (then kind is branch, the more mutable reading), found=false when it is
// neither.
func (l RefLookup) Kind() (kind string, ambiguous, found bool) {
	switch {
	case l.Tag && l.Branch:
		return "branch", true, true
	case l.Tag:
		return "tag", false, true
	case l.Branch:
		return "branch", false, true
	}
	return "", false, false
}

// LookupRef asks the REST API whether ref is a tag and whether it is a branch
// of owner/repo: GET /repos/{owner}/{repo}/git/ref/tags/{ref}, then
// .../git/ref/heads/{ref}. A 404 means that kind does not exist; any other
// error is returned. gop pin uses this (GET only); gop collect asks the same
// question for many refs at once through GraphQL (resolveRefs).
func LookupRef(ctx context.Context, c *Client, owner, repo, ref string) (RefLookup, error) {
	var l RefLookup
	for _, k := range []struct {
		kind string
		set  *bool
	}{{"git/ref/tags", &l.Tag}, {"git/ref/heads", &l.Branch}} {
		_, err := c.GetRaw(ctx, branchPath(owner, repo, k.kind, ref), "")
		switch {
		case err == nil:
			*k.set = true
		case !IsNotFound(err):
			return RefLookup{}, err
		}
	}
	return l, nil
}

// refBatchQuery builds a query with n aliased lookups r0..r{n-1}. Every owner,
// repo and ref string goes in as a variable ($oN, $nN, $tN, $hN): they come
// from workflow files, which anyone who can push to any repo writes.
func refBatchQuery(n int) string {
	var b strings.Builder
	b.WriteString("query(")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "$o%d: String!, $n%d: String!, $t%d: String!, $h%d: String!", i, i, i, i)
	}
	b.WriteString(") {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  r%d: repository(owner: $o%d, name: $n%d) { t: ref(qualifiedName: $t%d) { target { oid } } b: ref(qualifiedName: $h%d) { target { oid } } }\n",
			i, i, i, i, i)
	}
	b.WriteString("}")
	return b.String()
}

// refBatchVars returns the variables of refBatchQuery(len(ts)) for ts.
func refBatchVars(ts []*refTarget) map[string]any {
	vars := make(map[string]any, 4*len(ts))
	for i, t := range ts {
		owner, repo, _ := strings.Cut(strings.TrimPrefix(t.repoID, "repo:"), "/")
		vars["o"+strconv.Itoa(i)] = owner
		vars["n"+strconv.Itoa(i)] = repo
		vars["t"+strconv.Itoa(i)] = "refs/tags/" + t.ref
		vars["h"+strconv.Itoa(i)] = "refs/heads/" + t.ref
	}
	return vars
}

type gqlRef struct {
	Target struct {
		OID string `json:"oid"`
	} `json:"target"`
}

type gqlRefAlias struct {
	T *gqlRef `json:"t"`
	B *gqlRef `json:"b"`
}

// refTarget is one distinct (host repo, ref) and the action refs that use it.
type refTarget struct {
	repoID, ref string
	actions     []string
}

// refActions lists the enterprise-internal action refs that resolve to a repo,
// sorted, with their host repo IDs.
func (k *collector) refActions() ([]string, map[string]string) {
	resolves := map[string]string{}
	for _, e := range k.edges {
		if e.Kind == graph.ResolvesTo {
			resolves[e.From] = e.To
		}
	}
	var ids []string
	for id, n := range k.nodes {
		if n.Kind == graph.KindActionRef && n.Attrs[attrInEnterprise] == "true" && resolves[id] != "" && n.Attrs["ref"] != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, resolves
}

// resolveRefs replaces the name heuristic with the API's answer for every
// enterprise-internal action ref that is not a commit SHA: one GraphQL query
// per refBatchSize distinct (repo, ref), asking for refs/tags/<ref> and
// refs/heads/<ref>. Only a tag: ref_kind=tag. Only a branch: ref_kind=branch.
// Both: ref_kind=branch with ref_ambiguous=true. Either way
// ref_kind_source=api, and the incoming USES edges get the same ref_kind.
// Neither, or the repo is not visible: the heuristic stays, with
// ref_kind_source=name and a ref_kind coverage entry. A missing repo in one
// alias does not fail the batch.
func (k *collector) resolveRefs(ctx context.Context) error {
	ids, resolves := k.refActions()
	targets := map[string]*refTarget{}
	var order []string
	for _, id := range ids {
		an := k.nodes[id]
		ref := an.Attrs["ref"]
		if an.Attrs[graph.AttrRefKind] == "sha" {
			continue
		}
		if shortSHARe.MatchString(ref) {
			setAttr(an, graph.AttrRefKindSource, graph.RefKindSourceName, graph.Live)
			k.cover(id, graph.AttrRefKind, "ref "+ref+" looks like an abbreviated commit SHA, which is not a valid action ref; ref_kind is a guess from the name",
				"pin the full 40-character commit SHA")
			continue
		}
		key := strings.ToLower(resolves[id]) + "@" + ref
		t, ok := targets[key]
		if !ok {
			t = &refTarget{repoID: resolves[id], ref: ref}
			targets[key] = t
			order = append(order, key)
		}
		t.actions = append(t.actions, id)
	}
	if len(order) == 0 {
		return nil
	}
	usesInto := map[string][]*graph.Edge{}
	for _, e := range k.edges {
		if e.Kind == graph.Uses {
			usesInto[e.To] = append(usesInto[e.To], e)
		}
	}
	for start := 0; start < len(order); start += refBatchSize {
		chunk := order[start:min(start+refBatchSize, len(order))]
		ts := make([]*refTarget, len(chunk))
		for i, key := range chunk {
			ts[i] = targets[key]
		}
		var data map[string]*gqlRefAlias
		gerrs, err := k.c.GraphQL(withAliasPlan(ctx, refsPlan(ts)), refBatchQuery(len(ts)), refBatchVars(ts), &data)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			for _, key := range chunk {
				k.refByName(targets[key], "could not look up the ref: "+err.Error())
			}
			continue
		}
		for i, key := range chunk {
			t := targets[key]
			alias := "r" + strconv.Itoa(i)
			a := data[alias]
			if a == nil {
				reason := "repository " + strings.TrimPrefix(t.repoID, "repo:") + " not found or not visible to the token"
				if msg := aliasError(gerrs, alias); msg != "" {
					reason += " (" + msg + ")"
				}
				k.refByName(t, reason)
				continue
			}
			kind, ambiguous, found := RefLookup{Tag: a.T != nil, Branch: a.B != nil}.Kind()
			if !found {
				k.refByName(t, "neither refs/tags/"+t.ref+" nor refs/heads/"+t.ref+" exists in "+strings.TrimPrefix(t.repoID, "repo:"))
				continue
			}
			for _, id := range t.actions {
				an := k.nodes[id]
				setAttr(an, graph.AttrRefKind, kind, graph.Live)
				setAttr(an, graph.AttrRefKindSource, graph.RefKindSourceAPI, graph.Live)
				if ambiguous {
					setAttr(an, graph.AttrRefAmbiguous, "true", graph.Live)
				}
				for _, e := range usesInto[id] {
					if e.Attrs == nil {
						e.Attrs = map[string]string{}
					}
					e.Attrs[graph.AttrRefKind] = kind
				}
			}
		}
	}
	return nil
}

// aliasError returns the message of the first GraphQL error under alias.
func aliasError(errs GraphQLErrors, alias string) string {
	for _, e := range errs {
		if len(e.Path) > 0 && e.Path[0] == alias {
			if e.Type != "" {
				return e.Type + ": " + truncate(e.Message, 200)
			}
			return truncate(e.Message, 200)
		}
	}
	return ""
}

// refByName keeps the name heuristic for t's actions and says why.
func (k *collector) refByName(t *refTarget, reason string) {
	for _, id := range t.actions {
		setAttr(k.nodes[id], graph.AttrRefKindSource, graph.RefKindSourceName, graph.Live)
		k.cover(id, graph.AttrRefKind, reason+"; ref_kind is a guess from the name", "read access to "+strings.TrimPrefix(t.repoID, "repo:"))
	}
}

// apiTagRuleset is a ruleset as GET /repos/{owner}/{repo}/rulesets/{id}
// returns it: the bypass actors plus what immutability needs.
type apiTagRuleset struct {
	apiRuleset
	Target      string `json:"target"`
	Enforcement string `json:"enforcement"`
	Conditions  *struct {
		RefName *struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"ref_name"`
	} `json:"conditions"`
	Rules []struct {
		Type string `json:"type"`
	} `json:"rules"`
}

// collectTagImmutability decides, for every enterprise-internal action ref
// whose ref_kind=tag came from the API, whether pushing to the host repo can
// move the tag. It runs once per distinct (repo, tag).
//
// The tag is immutable (ref_immutable=true) when its release is immutable
// (GET /repos/{owner}/{repo}/releases/tags/{tag} says immutable: true; nobody
// can move it), or when the active tag rulesets whose ref_name conditions
// match refs/tags/<tag> hold both an update and a deletion rule. Their bypass
// actors become via=ref_bypass CAN_PUSH edges with ref=<tag>, as for branch
// protection. When the answer can't be read, ref_immutable=unknown: the paths
// through the tag stay, possible instead of confirmed.
func (k *collector) collectTagImmutability(ctx context.Context) error {
	ids, resolves := k.refActions()
	cache := map[string]*refProtection{}
	teamIDs := map[string]map[int64]string{}
	for _, id := range ids {
		an := k.nodes[id]
		if an.Attrs[graph.AttrRefKind] != "tag" || an.Attrs[graph.AttrRefKindSource] != graph.RefKindSourceAPI {
			continue
		}
		repoID, tag := resolves[id], an.Attrs["ref"]
		key := strings.ToLower(repoID) + "@" + tag
		rp, ok := cache[key]
		if !ok {
			var err error
			if rp, err = k.tagImmutability(ctx, repoID, tag, teamIDs); err != nil {
				return err
			}
			cache[key] = rp
			for _, g := range rp.grants {
				k.bypassEdge(g, repoID, tag)
			}
		}
		k.applyImmutability(an, repoID, tag, rp)
	}
	return nil
}

func (k *collector) applyImmutability(an *graph.Node, repoID, tag string, rp *refProtection) {
	full := strings.TrimPrefix(repoID, "repo:")
	if rp.protected == "unknown" {
		setAttr(an, graph.AttrRefImmutable, "unknown", graph.NotVisible)
		k.cover(an.ID, graph.AttrRefImmutable, rp.reason, rp.fix)
		return
	}
	setAttr(an, graph.AttrRefImmutable, rp.protected, graph.Live)
	if rp.protected != "true" {
		return
	}
	setAttr(an, graph.AttrRefImmutableBy, rp.lockedBy, graph.Live)
	k.applyBypass(an, full, tag, rp)
}

func (k *collector) tagImmutability(ctx context.Context, repoID, tag string, teamIDs map[string]map[int64]string) (*refProtection, error) {
	full := strings.TrimPrefix(repoID, "repo:")
	owner, repo, _ := strings.Cut(full, "/")
	var rel struct {
		Immutable bool `json:"immutable"`
	}
	var relErr error
	err := k.c.GetJSON(ctx, branchPath(owner, repo, "releases/tags", tag), &rel)
	switch {
	case err == nil && rel.Immutable:
		return &refProtection{protected: "true", lockedBy: graph.RefImmutableRelease, labels: map[string]bool{}}, nil
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil && !IsNotFound(err):
		// A 404 means no release, which says nothing either way.
		relErr = err
	}
	rp, err := k.tagRuleset(ctx, owner, repoID, tag, teamIDs)
	if err != nil {
		return nil, err
	}
	if rp.protected == "false" && relErr != nil {
		return &refProtection{protected: "unknown", reason: "could not read the release of " + full + "@" + tag + ": " + relErr.Error(),
			fix: "read access to " + full}, nil
	}
	return rp, nil
}

// tagRuleset reads the repo's tag rulesets (repo and org level) and decides
// whether they keep tag from moving.
func (k *collector) tagRuleset(ctx context.Context, owner, repoID, tag string, teamIDs map[string]map[int64]string) (*refProtection, error) {
	full := strings.TrimPrefix(repoID, "repo:")
	_, repo, _ := strings.Cut(full, "/")
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/rulesets"
	unknown := func(reason string) *refProtection {
		return &refProtection{protected: "unknown", reason: reason, fix: "read access to " + full}
	}
	if reason, fix, skip := k.ghesGate(capRulesets); skip {
		return &refProtection{protected: "unknown", reason: reason, fix: fix}, nil
	}
	var listed []struct {
		ID          int64  `json:"id"`
		Target      string `json:"target"`
		Enforcement string `json:"enforcement"`
	}
	err := k.c.GetPages(ctx, base+"?includes_parents=true&per_page=100", func(page []byte) error {
		var batch []struct {
			ID          int64  `json:"id"`
			Target      string `json:"target"`
			Enforcement string `json:"enforcement"`
		}
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding rulesets: %w", err)
		}
		listed = append(listed, batch...)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return unknown("could not list the rulesets of " + full + ": " + err.Error()), nil
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].ID < listed[j].ID })
	ref := "refs/tags/" + tag
	var (
		locking    []*apiTagRuleset
		update     bool
		deletion   bool
		unreadable string
	)
	for _, l := range listed {
		if l.Target != "tag" || l.Enforcement != "active" {
			continue
		}
		rs := &apiTagRuleset{}
		if err := k.c.GetJSON(ctx, base+"/"+strconv.FormatInt(l.ID, 10)+"?includes_parents=true", rs); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			unreadable = fmt.Sprintf("could not read tag ruleset %d on %s: %v", l.ID, full, err)
			continue
		}
		rs.ID = l.ID
		if (rs.Enforcement != "" && rs.Enforcement != "active") || !rulesetMatches(rs, ref) {
			continue
		}
		holds := false
		for _, r := range rs.Rules {
			switch r.Type {
			case "update":
				update, holds = true, true
			case "deletion":
				deletion, holds = true, true
			}
		}
		if holds {
			locking = append(locking, rs)
		}
	}
	if !update || !deletion {
		if unreadable != "" {
			return unknown(unreadable), nil
		}
		return &refProtection{protected: "false", labels: map[string]bool{}}, nil
	}
	// Every ruleset with an update or deletion rule names bypassers: an
	// over-approximation, as for branch protection.
	rp := &refProtection{protected: "true", lockedBy: graph.RefImmutableRuleset, labels: map[string]bool{}}
	for _, rs := range locking {
		gs, err := k.rulesetGrants(ctx, owner, repoID, &rs.apiRuleset, teamIDs, rp)
		if err != nil {
			return nil, err
		}
		rp.grants = append(rp.grants, gs...)
	}
	return rp, nil
}

// rulesetMatches reports whether a ruleset's ref_name condition selects ref
// (a full ref, e.g. refs/tags/v3): some include pattern matches and no exclude
// pattern does. A ruleset without a ref_name condition selects nothing.
func rulesetMatches(rs *apiTagRuleset, ref string) bool {
	if rs.Conditions == nil || rs.Conditions.RefName == nil {
		return false
	}
	in := false
	for _, p := range rs.Conditions.RefName.Include {
		in = in || refPatternMatch(p, ref)
	}
	if !in {
		return false
	}
	for _, p := range rs.Conditions.RefName.Exclude {
		if refPatternMatch(p, ref) {
			return false
		}
	}
	return true
}

// Pattern tokens for refPatternMatch.
const (
	tokLit        = iota // one literal rune
	tokAny               // ?: one rune other than /
	tokStar              // *: any run of runes other than /
	tokDoubleStar        // **: any run of runes
	tokDirs              // **/: empty, or any run of runes that ends in /
	tokClass             // [...]: one rune other than / in (or, negated, not in) the set
)

type patTok struct {
	kind   int
	r      rune
	ranges [][2]rune
	negate bool
}

// refPatternMatch matches a ruleset ref_name pattern (fnmatch style, as GitHub
// rulesets use) against a full ref. ~ALL matches every ref; ~DEFAULT_BRANCH
// matches the default branch only, so never a tag. * and ? stop at /, **
// crosses it, **/ also matches nothing, [...] is a class ([!...] or [^...]
// negated, a-z ranges) and \ escapes the next rune. It runs in
// O(len(pattern) * len(ref)) time whatever the input: ref names come from
// workflow files, which attackers can write.
func refPatternMatch(pattern, ref string) bool {
	switch pattern {
	case "~ALL":
		return true
	case "~DEFAULT_BRANCH":
		return false
	}
	toks := parsePattern(pattern)
	name := []rune(ref)
	// m[i][j]: toks[i:] matches name[j:].
	m := make([][]bool, len(toks)+1)
	for i := range m {
		m[i] = make([]bool, len(name)+1)
	}
	m[len(toks)][len(name)] = true
	for i := len(toks) - 1; i >= 0; i-- {
		t := toks[i]
		for j := len(name); j >= 0; j-- {
			var ok bool
			switch t.kind {
			case tokStar:
				ok = m[i+1][j] || (j < len(name) && name[j] != '/' && m[i][j+1])
			case tokDoubleStar:
				ok = m[i+1][j] || (j < len(name) && m[i][j+1])
			case tokDirs:
				// Empty, or consume runes up to and including some /.
				ok = m[i+1][j]
				for k := j; !ok && k < len(name); k++ {
					ok = name[k] == '/' && m[i+1][k+1]
				}
			default:
				ok = j < len(name) && t.matches(name[j]) && m[i+1][j+1]
			}
			m[i][j] = ok
		}
	}
	return m[0][0]
}

func (t patTok) matches(r rune) bool {
	switch t.kind {
	case tokLit:
		return r == t.r
	case tokAny:
		return r != '/'
	case tokClass:
		if r == '/' {
			return false
		}
		in := false
		for _, rg := range t.ranges {
			in = in || (rg[0] <= r && r <= rg[1])
		}
		return in != t.negate
	}
	return false
}

func parsePattern(p string) []patTok {
	rs := []rune(p)
	var out []patTok
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\\' && i+1 < len(rs):
			i++
			out = append(out, patTok{kind: tokLit, r: rs[i]})
		case c == '*' && i+1 < len(rs) && rs[i+1] == '*':
			i++
			for i+1 < len(rs) && rs[i+1] == '*' {
				i++
			}
			if i+1 < len(rs) && rs[i+1] == '/' {
				i++
				out = append(out, patTok{kind: tokDirs})
			} else {
				out = append(out, patTok{kind: tokDoubleStar})
			}
		case c == '*':
			out = append(out, patTok{kind: tokStar})
		case c == '?':
			out = append(out, patTok{kind: tokAny})
		case c == '[':
			if t, n, ok := parseClass(rs[i:]); ok {
				out = append(out, t)
				i += n - 1
			} else {
				out = append(out, patTok{kind: tokLit, r: c})
			}
		default:
			out = append(out, patTok{kind: tokLit, r: c})
		}
	}
	return out
}

// parseClass parses a [...] class at the start of rs and returns it with the
// number of runes it spans. ok is false for an unterminated class.
func parseClass(rs []rune) (patTok, int, bool) {
	t := patTok{kind: tokClass}
	i := 1
	if i < len(rs) && (rs[i] == '!' || rs[i] == '^') {
		t.negate = true
		i++
	}
	first := true
	for i < len(rs) {
		c := rs[i]
		if c == ']' && !first {
			return t, i + 1, true
		}
		first = false
		if c == '\\' && i+1 < len(rs) {
			i++
			c = rs[i]
		}
		lo, hi := c, c
		if i+2 < len(rs) && rs[i+1] == '-' && rs[i+2] != ']' {
			hi = rs[i+2]
			i += 2
		}
		if lo <= hi {
			t.ranges = append(t.ranges, [2]rune{lo, hi})
		}
		i++
	}
	return patTok{}, 0, false
}
