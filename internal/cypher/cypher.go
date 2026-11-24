// Package cypher writes a gop graph as an idempotent Cypher script for Neo4j,
// so teams that already load their estate with Cartography can join gop's
// control paths and reach with Cartography's GitHub and AWS nodes.
//
// Safety: every value taken from the graph is written as a single-quoted
// string literal through Quote. Labels, relationship types and property keys
// come from fixed allowlists in this file, never from the graph; attribute
// keys are written as properties only when they match a strict identifier
// pattern, else they go into a JSON string property. gop only writes text;
// it never connects to Neo4j.
package cypher

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/peleduri/gop/internal/graph"
)

// DefaultGitHubURL is the web root Cartography's GitHub node IDs start with.
const DefaultGitHubURL = "https://github.com"

// batchSize is the number of rows per UNWIND statement.
const batchSize = 500

// Options tune the export.
type Options struct {
	// GitHubURL is the GitHub web root ("https://github.com", or the GitHub
	// Enterprise Server host) that Cartography's GitHubRepository and
	// GitHubOrganization IDs start with. Empty means DefaultGitHubURL.
	GitHubURL string
}

// nodeLabels is the allowlist of kind labels. A node of any other kind gets
// only :GopNode.
var nodeLabels = map[graph.NodeKind]string{
	graph.KindEnterprise:  "GopEnterprise",
	graph.KindOrg:         "GopOrg",
	graph.KindOrgMembers:  "GopOrgMembers",
	graph.KindIdentity:    "GopIdentity",
	graph.KindRepo:        "GopRepo",
	graph.KindWorkflow:    "GopWorkflow",
	graph.KindActionRef:   "GopActionRef",
	graph.KindSecret:      "GopSecret",
	graph.KindOIDC:        "GopOIDC",
	graph.KindRunner:      "GopRunner",
	graph.KindCloudTarget: "GopCloudRole",
	graph.KindExternal:    "GopExternal",
}

// edgeTypes is the allowlist of relationship types for gop edges. An edge of
// any other kind is written as otherEdge with its kind in the kind property.
var edgeTypes = map[graph.EdgeKind]string{
	graph.CanPush:        "CAN_PUSH",
	graph.Uses:           "USES",
	graph.ResolvesTo:     "RESOLVES_TO",
	graph.DefinedIn:      "DEFINED_IN",
	graph.ExecutesWith:   "EXECUTES_WITH",
	graph.MemberOf:       "MEMBER_OF",
	graph.CanTrigger:     "CAN_TRIGGER",
	graph.CanAssume:      "CAN_ASSUME",
	graph.CanMergeViaBot: "CAN_MERGE_VIA_BOT",
}

// Fixed relationship types gop adds itself.
const (
	otherEdge  = "GOP_EDGE"
	reachEdge  = "GOP_REACHES"
	sameAsEdge = "SAME_AS"
)

// Cartography join targets: label and the property that holds the identity.
var joins = []struct {
	kind  graph.NodeKind
	label string
	prop  string
}{
	{graph.KindOrg, "GitHubOrganization", "id"},
	{graph.KindRepo, "GitHubRepository", "id"},
	{graph.KindCloudTarget, "AWSRole", "arn"},
}

// reachKinds are the targets of GOP_REACHES edges: where code runs with
// something worth stealing.
var reachKinds = map[graph.NodeKind]bool{
	graph.KindSecret:      true,
	graph.KindOIDC:        true,
	graph.KindRunner:      true,
	graph.KindCloudTarget: true,
}

// attrKeyRe is the shape an attribute key must have to become a property
// (attr_<key>). Anything else goes into the attrs_extra JSON string.
var attrKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// awsRoleARN matches an exact IAM role ARN (no wildcards).
var awsRoleARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)

// prop is one key/value of a map literal. key is always a fixed name or a
// key that matched attrKeyRe.
type prop struct {
	key string
	val string // already a Cypher literal
}

type row []prop

func (r row) String() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range r {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.key)
		b.WriteString(": ")
		b.WriteString(p.val)
	}
	b.WriteByte('}')
	return b.String()
}

// Run returns the gop_run stamp of g: its collection time and a hash of its
// sorted content, so exporting the same graph twice gives the same stamp and
// any change gives a new one.
func Run(g *graph.Graph) string {
	c := canonical(g)
	data, _ := json.Marshal(c) // a Graph of strings and maps always marshals
	sum := sha256.Sum256(data)
	return g.CollectedAt.UTC().Format(time.RFC3339) + "/" + hex.EncodeToString(sum[:6])
}

// canonical returns a copy of g with nodes and edges sorted.
func canonical(g *graph.Graph) *graph.Graph {
	c := *g
	c.Nodes = append([]graph.Node(nil), g.Nodes...)
	c.Edges = append([]graph.Edge(nil), g.Edges...)
	c.Coverage = nil
	sort.SliceStable(c.Nodes, func(i, j int) bool { return c.Nodes[i].ID < c.Nodes[j].ID })
	sort.SliceStable(c.Edges, func(i, j int) bool { return edgeLess(c.Edges[i], c.Edges[j]) })
	return &c
}

func edgeLess(a, b graph.Edge) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.From != b.From {
		return a.From < b.From
	}
	if a.To != b.To {
		return a.To < b.To
	}
	if ka, kb := edgeKey(a), edgeKey(b); ka != kb {
		return ka < kb
	}
	if a.Evidence != b.Evidence {
		return a.Evidence < b.Evidence
	}
	return a.SourceAPI < b.SourceAPI
}

// edgeKey identifies an edge across exports: endpoints, kind and attributes.
// Evidence, source and time are properties of the fact, not its identity.
func edgeKey(e graph.Edge) string {
	h := sha256.New()
	for _, s := range []string{e.From, string(e.Kind), e.To} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	for _, k := range sortedKeys(e.Attrs) {
		h.Write([]byte(k))
		h.Write([]byte{1})
		h.Write([]byte(e.Attrs[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Write writes the Cypher script for g to w. The output is deterministic.
func Write(w io.Writer, g *graph.Graph, opts Options) error {
	base, err := webRoot(opts.GitHubURL)
	if err != nil {
		return err
	}
	if g == nil {
		g = &graph.Graph{Schema: graph.SchemaVersion}
	}
	c := canonical(g)
	run := Run(g)
	ent := Quote(c.Enterprise)
	runLit := Quote(run)

	bw := bufio.NewWriter(w)
	x := &writer{w: bw}
	x.line("// gop export --format cypher (" + graph.SchemaVersion + ")")
	x.line("// Idempotent: MERGE only. Loading it replaces every earlier gop run of the same enterprise.")
	x.line("// gop_run: " + commentSafe(run))
	x.line("CREATE INDEX gop_node_key IF NOT EXISTS FOR (n:GopNode) ON (n.gop_enterprise, n.id);")

	// Nodes, grouped by label. Edge endpoints the graph does not declare are
	// added with declared=false so no edge is dropped.
	declared := map[string]bool{}
	for _, n := range c.Nodes {
		declared[n.ID] = true
	}
	nodes := append([]graph.Node(nil), c.Nodes...)
	var undeclared []string
	seenUndeclared := map[string]bool{}
	for _, e := range c.Edges {
		for _, id := range []string{e.From, e.To} {
			if !declared[id] && !seenUndeclared[id] {
				seenUndeclared[id] = true
				undeclared = append(undeclared, id)
			}
		}
	}
	sort.Strings(undeclared)
	for _, id := range undeclared {
		nodes = append(nodes, graph.Node{ID: id, Kind: graph.KindFromID(id), Name: id})
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	byLabel := map[string][]row{}
	for _, n := range nodes {
		label := nodeLabels[n.Kind]
		byLabel[label] = append(byLabel[label], nodeRow(n, ent, runLit, declared[n.ID]))
	}
	for _, label := range sortedKeys(byLabel) {
		set := "SET n = row"
		if label != "" {
			set += ", n:" + label
		}
		x.unwind(byLabel[label], "MERGE (n:GopNode {gop_enterprise: row.gop_enterprise, id: row.id}) "+set)
	}

	// gop edges, grouped by relationship type, deduplicated by gop_key.
	ix := graph.NewIndex(c)
	byType := map[string][]row{}
	seenKey := map[string]bool{}
	for _, e := range c.Edges {
		k := edgeKey(e)
		if seenKey[k] {
			continue
		}
		seenKey[k] = true
		typ, ok := edgeTypes[e.Kind]
		if !ok {
			typ = otherEdge
		}
		byType[typ] = append(byType[typ], edgeRow(ix, e, k, runLit))
	}
	for _, typ := range sortedKeys(byType) {
		x.unwind(byType[typ], matchEnds(ent)+" MERGE (a)-[r:"+typ+" {gop_key: row.props.gop_key}]->(b) SET r = row.props")
	}

	// Computed reach: one GOP_REACHES edge per (principal, impact) with the
	// shortest path, confirmed when every hop is live, inferred, fresh audit
	// or supplied. Reach follows gop's pair model (graph.Index.PairReach),
	// like the SQL reach table: what an identity reaches only through an
	// org_members population is on that population's edges, not repeated
	// for every member.
	var reach []row
	for _, p := range ix.ScoringPrincipals() {
		res := ix.PairReach(p)
		for _, id := range sortedKeys(res.Paths) {
			if !reachKinds[ix.Kind(id)] {
				continue
			}
			reach = append(reach, reachRow(res.Paths[id], runLit))
		}
	}
	x.unwind(reach, matchEnds(ent)+" MERGE (a)-[r:"+reachEdge+"]->(b) SET r = row.props")

	// Joins to Cartography nodes. MATCH on both ends: a no-op when
	// Cartography has not loaded the target.
	for _, j := range joins {
		var rows []row
		for _, n := range nodes {
			if n.Kind != j.kind {
				continue
			}
			if t, ok := joinTarget(n, base); ok {
				rows = append(rows, row{{"id", Quote(n.ID)}, {"target", Quote(t)}})
			}
		}
		x.unwind(rows, "MATCH (g:GopNode {gop_enterprise: "+ent+", id: row.id}) MATCH (c:"+j.label+" {"+j.prop+": row.target}) MERGE (g)-[r:"+sameAsEdge+"]->(c) SET r.gop_run = "+runLit)
	}

	// Cleanup: relationships and nodes of older gop runs of this enterprise.
	x.line("MATCH (:GopNode {gop_enterprise: " + ent + "})-[r]->() WHERE r.gop_run IS NOT NULL AND r.gop_run <> " + runLit + " DELETE r;")
	x.line("MATCH (n:GopNode {gop_enterprise: " + ent + "}) WHERE n.gop_run <> " + runLit + " DETACH DELETE n;")
	if x.err != nil {
		return x.err
	}
	return bw.Flush()
}

func matchEnds(ent string) string {
	return "MATCH (a:GopNode {gop_enterprise: " + ent + ", id: row.from}) MATCH (b:GopNode {gop_enterprise: " + ent + ", id: row.to})"
}

type writer struct {
	w   *bufio.Writer
	err error
}

func (x *writer) line(s string) {
	if x.err == nil {
		_, x.err = x.w.WriteString(s + "\n")
	}
}

// unwind writes rows in batches: UNWIND [rows] AS row <body>;
func (x *writer) unwind(rows []row, body string) {
	for start := 0; start < len(rows); start += batchSize {
		end := min(start+batchSize, len(rows))
		x.line("UNWIND [")
		for i := start; i < end; i++ {
			sep := ","
			if i == end-1 {
				sep = ""
			}
			x.line("  " + rows[i].String() + sep)
		}
		x.line("] AS row " + body + ";")
	}
}

func nodeRow(n graph.Node, ent, run string, declared bool) row {
	r := row{
		{"gop_enterprise", ent},
		{"id", Quote(n.ID)},
		{"kind", Quote(string(n.Kind))},
		{"name", Quote(n.Name)},
	}
	if declared {
		r = append(r, prop{"evidence", Quote(string(n.Evidence))}, prop{"confirmed", strconv.FormatBool(graph.Verified(n.Evidence))})
	} else {
		r = append(r, prop{"declared", "false"})
	}
	r = append(r, prop{"gop_run", run})
	r = append(r, attrProps(n.Attrs)...)
	if len(n.AttrEvidence) > 0 {
		r = append(r, prop{"attr_evidence", Quote(jsonString(n.AttrEvidence))})
	}
	return r
}

// edgeRow is one evidence edge. confirmed is false for not_visible and for a
// stale audit fact, which then also gets stale: true.
func edgeRow(ix *graph.Index, e graph.Edge, key, run string) row {
	props := row{
		{"gop_key", Quote(key)},
		{"kind", Quote(string(e.Kind))},
		{"evidence", Quote(string(e.Evidence))},
		{"confirmed", strconv.FormatBool(ix.EdgeVerified(e))},
	}
	if ix.AuditStale(e, ix.MaxAuditAge(0)) {
		props = append(props, prop{"stale", "true"})
	}
	props = append(props, row{
		{"source_api", Quote(e.SourceAPI)},
		{"observed_at", Quote(e.ObservedAt.UTC().Format(time.RFC3339))},
		{"gop_run", run},
	}...)
	props = append(props, attrProps(e.Attrs)...)
	return row{{"from", Quote(e.From)}, {"to", Quote(e.To)}, {"props", props.String()}}
}

func reachRow(p graph.Path, run string) row {
	nodes := []string{p.From}
	kinds := make([]string, 0, len(p.Hops))
	for _, h := range p.Hops {
		nodes = append(nodes, h.To)
		kinds = append(kinds, string(h.Kind))
	}
	props := row{
		{"confirmed", strconv.FormatBool(!p.Unverified)},
		{"evidence", Quote(string(p.Evidence))},
		{"supplied", strconv.FormatBool(p.Supplied)},
		{"hops", strconv.Itoa(len(p.Hops))},
		{"path", list(nodes)},
		{"path_kinds", list(kinds)},
		{"gop_run", run},
	}
	if p.Stale {
		props = append(props, prop{"stale", "true"})
	}
	return row{{"from", Quote(p.From)}, {"to", Quote(p.To)}, {"props", props.String()}}
}

// attrProps writes valid attribute keys as attr_<key> and the rest as one
// attrs_extra JSON string.
func attrProps(attrs map[string]string) []prop {
	var out []prop
	extra := map[string]string{}
	for _, k := range sortedKeys(attrs) {
		if attrKeyRe.MatchString(k) {
			out = append(out, prop{"attr_" + k, Quote(attrs[k])})
		} else {
			extra[k] = attrs[k]
		}
	}
	if len(extra) > 0 {
		out = append(out, prop{"attrs_extra", Quote(jsonString(extra))})
	}
	return out
}

func jsonString(v any) string {
	data, _ := json.Marshal(v) // maps of strings always marshal
	return string(data)
}

func list(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = Quote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// joinTarget returns the Cartography identity of n when it is unambiguous:
// the org URL, the repo URL, or the exact IAM role ARN.
func joinTarget(n graph.Node, base string) (string, bool) {
	switch n.Kind {
	case graph.KindOrg:
		login, ok := strings.CutPrefix(n.ID, "org:")
		if !ok || !segment(login) {
			return "", false
		}
		return base + "/" + login, true
	case graph.KindRepo:
		full, ok := strings.CutPrefix(n.ID, "repo:")
		if !ok {
			return "", false
		}
		owner, name, ok := strings.Cut(full, "/")
		if !ok || !segment(owner) || !segment(name) {
			return "", false
		}
		return base + "/" + owner + "/" + name, true
	case graph.KindCloudTarget:
		arn, ok := strings.CutPrefix(n.ID, "cloud:aws:")
		if !ok || !awsRoleARN.MatchString(arn) {
			return "", false
		}
		return arn, true
	}
	return "", false
}

// segment reports whether s is one non-empty URL path segment.
func segment(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/?#") && s != "." && s != ".."
}

// CheckGitHubURL reports whether s is a usable Options.GitHubURL.
func CheckGitHubURL(s string) error {
	_, err := webRoot(s)
	return err
}

// webRoot validates and normalizes the GitHub web root.
func webRoot(s string) (string, error) {
	if s == "" {
		return DefaultGitHubURL, nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("--github-url must be an http(s) URL with a host and no query, got %q", s)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// commentSafe keeps only characters that cannot end a // comment early.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// Quote returns s as a single-quoted Cypher string literal. Backslash and
// single quote get backslash escapes; control, format, line separator and
// other non-printable characters, and ';' (so a naive statement splitter
// never splits inside a literal), get \uXXXX or \UXXXXXXXX escapes. Invalid
// UTF-8 becomes U+FFFD. The result never contains a raw newline, quote or
// backslash that is not part of an escape.
func Quote(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\'':
			b.WriteString(`\'`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == ';' || needsEscape(r):
			if r <= 0xFFFF {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				fmt.Fprintf(&b, `\U%08X`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

func needsEscape(r rune) bool {
	if r == ' ' {
		return false
	}
	if r == 0x2028 || r == 0x2029 {
		return true
	}
	return !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r)
}
