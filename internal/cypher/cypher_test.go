package cypher

import (
	"bytes"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/peleduri/gop/internal/graph"
)

// lexed is a Cypher script split into code and string literals.
type lexed struct {
	skeleton string   // the script with every literal replaced by '?' and comment lines dropped
	literals []string // decoded literal values, in order
	comments []string
}

// lex is an independent Cypher lexer for gop's output: it decodes every
// single-quoted literal with Cypher's escape rules and fails on anything gop
// must never emit (raw newlines in literals, double-quoted strings, backticks,
// unknown escapes, unterminated literals).
func lex(t *testing.T, script string) lexed {
	t.Helper()
	var out lexed
	var sk strings.Builder
	lines := strings.SplitAfter(script, "\n")
	for _, ln := range lines {
		if strings.HasPrefix(ln, "//") {
			out.comments = append(out.comments, strings.TrimSuffix(ln, "\n"))
			continue
		}
		rs := []rune(ln)
		for i := 0; i < len(rs); i++ {
			r := rs[i]
			switch r {
			case '`', '"':
				t.Fatalf("raw %q outside a literal in line %q", r, ln)
			case '\'':
				var val strings.Builder
				i++
				for ; ; i++ {
					if i >= len(rs) {
						t.Fatalf("unterminated literal in line %q", ln)
					}
					c := rs[i]
					if c == '\'' {
						break
					}
					if c == '\n' || c == '\r' {
						t.Fatalf("raw line break inside a literal in line %q", ln)
					}
					if c != '\\' {
						val.WriteRune(c)
						continue
					}
					i++
					if i >= len(rs) {
						t.Fatalf("dangling backslash in %q", ln)
					}
					switch rs[i] {
					case '\\':
						val.WriteRune('\\')
					case '\'':
						val.WriteRune('\'')
					case '"':
						val.WriteRune('"')
					case 'n':
						val.WriteRune('\n')
					case 'r':
						val.WriteRune('\r')
					case 't':
						val.WriteRune('\t')
					case 'b':
						val.WriteRune('\b')
					case 'f':
						val.WriteRune('\f')
					case 'u', 'U':
						n := 4
						if rs[i] == 'U' {
							n = 8
						}
						if i+n >= len(rs) {
							t.Fatalf("short unicode escape in %q", ln)
						}
						v, err := strconv.ParseUint(string(rs[i+1:i+1+n]), 16, 32)
						if err != nil {
							t.Fatalf("bad unicode escape in %q: %v", ln, err)
						}
						val.WriteRune(rune(v))
						i += n
					default:
						t.Fatalf("unknown escape \\%c in %q", rs[i], ln)
					}
				}
				out.literals = append(out.literals, val.String())
				sk.WriteString("'?'")
			default:
				sk.WriteRune(r)
			}
		}
	}
	out.skeleton = sk.String()
	return out
}

// vocabulary is every identifier gop may emit outside a literal.
var vocabulary = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`CREATE INDEX IF NOT EXISTS FOR ON UNWIND AS MERGE MATCH SET WHERE IS NULL AND DELETE DETACH
		true false n r a b g c row props from to target id gop_enterprise gop_node_key gop_key gop_run
		kind name evidence confirmed declared attr_evidence attrs_extra source_api observed_at
		supplied hops path path_kinds GopNode`) {
		vocabulary[w] = true
	}
	for _, l := range nodeLabels {
		vocabulary[l] = true
	}
	for _, l := range edgeTypes {
		vocabulary[l] = true
	}
	for _, w := range []string{otherEdge, reachEdge, sameAsEdge} {
		vocabulary[w] = true
	}
	for _, j := range joins {
		vocabulary[j.label] = true
		vocabulary[j.prop] = true
	}
}

var identRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// checkVocabulary fails on any identifier outside the fixed vocabulary
// (attr_<key> properties must match the attribute key pattern).
func checkVocabulary(t *testing.T, skeleton string) {
	t.Helper()
	for _, w := range identRe.FindAllString(skeleton, -1) {
		if vocabulary[w] {
			continue
		}
		if k, ok := strings.CutPrefix(w, "attr_"); ok && attrKeyRe.MatchString(k) {
			continue
		}
		t.Errorf("identifier %q outside the fixed vocabulary", w)
	}
	if strings.ContainsAny(skeleton, "`\"$") {
		t.Errorf("skeleton has a backtick, double quote or parameter: %q", skeleton)
	}
}

var commentRe = regexp.MustCompile(`^// [ -~]*$`)

func export(t *testing.T, g *graph.Graph, opts Options) string {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, g, opts); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// hostile packs quote, backslash, backtick, newline, statement terminator,
// comment, parameter, Cypher-looking text, line/paragraph separators, a
// right-to-left override, NUL, non-ASCII, an emoji, a literal \u0027, a
// pre-escaped quote and invalid UTF-8.
const hostile = "a'b\\c`d\"e\nf\r\ng; MATCH (n) DETACH DELETE n; // x */ /* ${p} $q }) MERGE (z:Pwn {k: 1}) RETURN `x`\u2028\u2029\u202e\x00\t é漢字🙂 \\u0027 \\' \xff end"

// hostileSeg is hostile without the characters that make an ID not
// joinable (path separators), so the SAME_AS rows carry hostile text too.
var hostileSeg = strings.NewReplacer("/", "", "?", "", "#", "").Replace(hostile)

// structured builds a graph with one node per kind and one edge per kind,
// every string field set from s (segment-safe parts from seg).
func structured(s, seg string) *graph.Graph {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	attrs := map[string]string{"via": s, "bad key'`\n": s, "file": s}
	return &graph.Graph{
		Schema: graph.SchemaVersion, CollectedAt: at, Enterprise: s,
		Nodes: []graph.Node{
			{ID: "enterprise:" + s, Kind: graph.KindEnterprise, Name: s, Evidence: graph.Live, Attrs: attrs},
			{ID: "org:" + seg, Kind: graph.KindOrg, Name: s, Evidence: graph.Live, Attrs: attrs, AttrEvidence: map[string]graph.Evidence{s: graph.NotVisible}},
			{ID: "identity:" + s, Kind: graph.KindIdentity, Name: s, Evidence: graph.Live},
			{ID: "repo:" + seg + "/" + seg, Kind: graph.KindRepo, Name: s, Evidence: graph.Live, Attrs: attrs},
			{ID: "workflow:" + s, Kind: graph.KindWorkflow, Name: s, Evidence: graph.Live},
			{ID: "secret:" + s, Kind: graph.KindSecret, Name: s, Evidence: graph.Live},
			{ID: "cloud:aws:" + s, Kind: graph.KindCloudTarget, Name: s, Evidence: graph.Supplied},
			{ID: "zz:" + s, Kind: graph.NodeKind(s), Name: s, Evidence: graph.Evidence(s)},
		},
		Edges: []graph.Edge{
			{From: "identity:" + s, To: "repo:" + seg + "/" + seg, Kind: graph.CanPush, Evidence: graph.Live, SourceAPI: s, ObservedAt: at, Attrs: attrs},
			{From: "workflow:" + s, To: "repo:" + seg + "/" + seg, Kind: graph.DefinedIn, Evidence: graph.Live, SourceAPI: s, ObservedAt: at},
			{From: "workflow:" + s, To: "secret:" + s, Kind: graph.ExecutesWith, Evidence: graph.Live, SourceAPI: s, ObservedAt: at, Attrs: attrs},
			{From: "identity:" + s, To: "team:" + s, Kind: graph.MemberOf, Evidence: graph.Live, SourceAPI: s, ObservedAt: at},
			{From: "zz:" + s, To: "secret:" + s, Kind: graph.EdgeKind(s), Evidence: graph.Evidence(s), SourceAPI: s, ObservedAt: at},
		},
	}
}

// TestHostileNamesNoInjection proves graph text cannot leave its literal:
// the script for hostile names has exactly the code skeleton of the script
// for benign names, every identifier is from the fixed vocabulary, and every
// hostile value decodes back unchanged.
func TestHostileNamesNoInjection(t *testing.T) {
	bad := export(t, structured(hostile, hostileSeg), Options{})
	good := export(t, structured("safe name", "safe-name"), Options{})
	lb, lg := lex(t, bad), lex(t, good)
	if lb.skeleton != lg.skeleton {
		t.Fatalf("hostile names changed the code skeleton:\n%s", diffLines(lg.skeleton, lb.skeleton))
	}
	checkVocabulary(t, lb.skeleton)
	for _, c := range lb.comments {
		if !commentRe.MatchString(c) {
			t.Errorf("comment line carries non-ASCII or control text: %q", c)
		}
	}
	want := strings.ToValidUTF8(hostile, "\uFFFD")
	wantSeg := strings.ToValidUTF8(hostileSeg, "\uFFFD")
	found := map[string]int{}
	for _, l := range lb.literals {
		found[l]++
	}
	for _, v := range []string{
		want,             // names, attr values, source_api, enterprise
		"secret:" + want, // IDs
		"team:" + want,   // undeclared endpoint
		"https://github.com/" + wantSeg + "/" + wantSeg, // SAME_AS target
		"https://github.com/" + wantSeg,
	} {
		if found[v] == 0 {
			t.Errorf("literal %q not found", v)
		}
	}
	// The bad attribute key travels only inside attrs_extra.
	if !strings.Contains(bad, "attrs_extra: ") || strings.Contains(lb.skeleton, "bad key") {
		t.Errorf("bad attribute key not confined to attrs_extra")
	}
	// No line outside comments starts anything but known statement shapes.
	for _, ln := range strings.Split(strings.TrimSuffix(lb.skeleton, "\n"), "\n") {
		shape := false
		for _, pre := range []string{"UNWIND [", "  {", "] AS row ", "MATCH ", "CREATE INDEX "} {
			shape = shape || strings.HasPrefix(ln, pre)
		}
		if !shape {
			t.Errorf("unexpected line shape %q", ln)
		}
	}
	// Every ';' ends a line: a naive splitter cannot split inside a literal.
	if strings.Count(bad, ";") != strings.Count(bad, ";\n") {
		t.Errorf("';' inside a line")
	}
}

func TestHostileARNAndURLsDoNotJoin(t *testing.T) {
	g := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme", Nodes: []graph.Node{
		{ID: "cloud:aws:arn:aws:iam::111111111111:role/deploy", Kind: graph.KindCloudTarget, Evidence: graph.Supplied},
		{ID: "cloud:aws:arn:aws:iam::111111111111:role/*", Kind: graph.KindCloudTarget, Evidence: graph.Supplied},
		{ID: "cloud:aws:arn:aws:iam::111111111111:role/x'}) MATCH (n", Kind: graph.KindCloudTarget, Evidence: graph.Supplied},
		{ID: "cloud:gcp:serviceAccount:deploy@acme.iam.gserviceaccount.com", Kind: graph.KindCloudTarget, Evidence: graph.Supplied},
		{ID: "repo:acme-app/web", Kind: graph.KindRepo, Evidence: graph.Live},
		{ID: "repo:acme-app", Kind: graph.KindRepo, Evidence: graph.Live},
		{ID: "repo:acme-app/../x", Kind: graph.KindRepo, Evidence: graph.Live},
		{ID: "org:acme-app", Kind: graph.KindOrg, Evidence: graph.Live},
		{ID: "org:..", Kind: graph.KindOrg, Evidence: graph.Live},
	}}
	out := export(t, g, Options{GitHubURL: "https://ghe.acme.example/"})
	var targets []string
	for _, ln := range strings.Split(out, "\n") {
		if _, rest, ok := strings.Cut(ln, "target: "); ok {
			targets = append(targets, strings.TrimRight(rest, "},"))
		}
	}
	want := []string{"'https://ghe.acme.example/acme-app'", "'https://ghe.acme.example/acme-app/web'", "'arn:aws:iam::111111111111:role/deploy'"}
	if strings.Join(targets, "|") != strings.Join(want, "|") {
		t.Errorf("join targets %v, want %v", targets, want)
	}
	if !strings.Contains(out, "MATCH (c:AWSRole {arn: row.target})") || !strings.Contains(out, "MATCH (c:GitHubRepository {id: row.target})") ||
		!strings.Contains(out, "MATCH (c:GitHubOrganization {id: row.target})") {
		t.Errorf("join statements missing:\n%s", out)
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":              `''`,
		"repo:acme/web": `'repo:acme/web'`,
		`it's`:          `'it\'s'`,
		`a\b`:           `'a\\b'`,
		"a\nb\r\tc":     `'a\nb\r\tc'`,
		"a;b":           `'a\u003Bb'`,
		"`x`\"":         "'`x`\"'",
		"\x00\x7f":      `'\u0000\u007F'`,
		"\u2028\u202e":  `'\u2028\u202E'`,
		"é🙂":            "'é🙂'",
		"\U000E0041":    `'\U000E0041'`,
		"\xff":          "'\uFFFD'",
		`\u0027`:        `'\\u0027'`,
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

// FuzzQuote: any input decodes back to itself (as valid UTF-8) and the
// literal is one line with no unescaped quote or ';'.
func FuzzQuote(f *testing.F) {
	for _, s := range []string{"", hostile, "'", "\\", "\\'", "\n;", "\u2028", "\xff\xfe", "\\u0027"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := Quote(s)
		if strings.ContainsAny(q, "\n\r;") || strings.ContainsRune(q, '\u2028') {
			t.Fatalf("Quote(%q) = %q has a raw line break or ';'", s, q)
		}
		if !utf8.ValidString(q) {
			t.Fatalf("Quote(%q) is not valid UTF-8", s)
		}
		l := lex(t, q+"\n")
		if len(l.literals) != 1 || l.skeleton != "'?'\n" {
			t.Fatalf("Quote(%q) = %q lexes as %+v", s, q, l)
		}
		if want := strings.ToValidUTF8(s, "\uFFFD"); l.literals[0] != want {
			t.Fatalf("Quote(%q) decodes to %q", s, l.literals[0])
		}
	})
}

func TestDeterministic(t *testing.T) {
	g := structured("acme", "acme")
	g.Nodes = append(g.Nodes, graph.Node{ID: "repo:acme/a", Kind: graph.KindRepo, Evidence: graph.Live}, graph.Node{ID: "repo:acme/b", Kind: graph.KindRepo, Evidence: graph.NotVisible})
	first := export(t, g, Options{})
	rng := rand.New(rand.NewSource(7))
	for i := range 5 {
		s := *g
		s.Nodes = append([]graph.Node(nil), g.Nodes...)
		s.Edges = append([]graph.Edge(nil), g.Edges...)
		rng.Shuffle(len(s.Nodes), func(i, j int) { s.Nodes[i], s.Nodes[j] = s.Nodes[j], s.Nodes[i] })
		rng.Shuffle(len(s.Edges), func(i, j int) { s.Edges[i], s.Edges[j] = s.Edges[j], s.Edges[i] })
		if got := export(t, &s, Options{}); got != first {
			t.Fatalf("shuffle %d changed the output:\n%s", i, diffLines(first, got))
		}
	}
	// Any change gives a new run stamp, so the cleanup removes the old run.
	h := *g
	h.Nodes = append([]graph.Node(nil), g.Nodes[:len(g.Nodes)-1]...)
	if Run(&h) == Run(g) {
		t.Errorf("removing a node kept the run stamp %s", Run(g))
	}
	if !strings.HasPrefix(Run(g), "2026-01-01T00:00:00Z/") {
		t.Errorf("run %q", Run(g))
	}
}

func TestShape(t *testing.T) {
	g := structured("acme", "acme")
	g.Edges = append(g.Edges, g.Edges[0]) // a duplicate collapses on gop_key
	out := export(t, g, Options{})
	for _, want := range []string{
		"CREATE INDEX gop_node_key IF NOT EXISTS FOR (n:GopNode) ON (n.gop_enterprise, n.id);",
		"SET n = row, n:GopRepo;",
		"SET n = row, n:GopCloudRole;",
		// unknown node kind: only :GopNode
		"] AS row MERGE (n:GopNode {gop_enterprise: row.gop_enterprise, id: row.id}) SET n = row;",
		// undeclared endpoint
		"id: 'team:acme', kind: 'identity', name: 'team:acme', declared: false",
		"MERGE (a)-[r:CAN_PUSH {gop_key: row.props.gop_key}]->(b) SET r = row.props;",
		"MERGE (a)-[r:GOP_EDGE {gop_key: row.props.gop_key}]->(b)",
		"MERGE (a)-[r:GOP_REACHES]->(b) SET r = row.props;",
		"{from: 'identity:acme', to: 'secret:acme', props: {confirmed: true, evidence: 'live', supplied: false, hops: 3, path: ['identity:acme', 'repo:acme/acme', 'workflow:acme', 'secret:acme'], path_kinds: ['CAN_PUSH', 'DEFINED_IN', 'EXECUTES_WITH']",
		"attr_evidence: '{\"acme\":\"not_visible\"}'",
		"WHERE r.gop_run IS NOT NULL AND r.gop_run <> '" + Run(g) + "' DELETE r;",
		"WHERE n.gop_run <> '" + Run(g) + "' DETACH DELETE n;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "kind: 'CAN_PUSH'"); n != 1 {
		t.Errorf("CAN_PUSH rows: %d, want 1 (duplicate edge must collapse)", n)
	}
	if strings.Contains(out, "CREATE (") {
		t.Errorf("CREATE of nodes; want MERGE only")
	}
}

func TestBatches(t *testing.T) {
	g := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme"}
	for i := range batchSize + 1 {
		g.Nodes = append(g.Nodes, graph.Node{ID: fmt.Sprintf("secret:acme/r%04d", i), Kind: graph.KindSecret, Evidence: graph.Live})
	}
	out := export(t, g, Options{})
	if n := strings.Count(out, "SET n = row, n:GopSecret;"); n != 2 {
		t.Errorf("statements: %d, want 2", n)
	}
	checkVocabulary(t, lex(t, out).skeleton)
}

func TestGitHubURL(t *testing.T) {
	for _, bad := range []string{"ftp://x", "github.com", "https://", "https://x/?a=1", "https://u:p@x"} {
		if CheckGitHubURL(bad) == nil {
			t.Errorf("CheckGitHubURL(%q) = nil", bad)
		}
	}
	for _, ok := range []string{"", "https://github.com", "http://ghe.acme.example/"} {
		if err := CheckGitHubURL(ok); err != nil {
			t.Errorf("CheckGitHubURL(%q) = %v", ok, err)
		}
	}
	if err := Write(&bytes.Buffer{}, nil, Options{GitHubURL: "nope"}); err == nil {
		t.Errorf("Write with a bad URL succeeded")
	}
	if out := export(t, nil, Options{}); !strings.Contains(out, "DETACH DELETE n;") {
		t.Errorf("nil graph: %q", out)
	}
}

func diffLines(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	var out strings.Builder
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			fmt.Fprintf(&out, "line %d:\n- %s\n+ %s\n", i+1, x, y)
		}
	}
	return out.String()
}

func TestInferredConfirmedStaleAuditNot(t *testing.T) {
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	wf := "workflow:acme/web/.github/workflows/ci.yml"
	g := &graph.Graph{Schema: graph.SchemaVersion, CollectedAt: at, Enterprise: "acme",
		Nodes: []graph.Node{
			{ID: "members:acme", Kind: graph.KindOrgMembers, Name: "acme members", Evidence: graph.Live},
			{ID: "identity:bob", Kind: graph.KindIdentity, Name: "bob", Evidence: graph.Live},
			{ID: "repo:acme/web", Kind: graph.KindRepo, Name: "web", Evidence: graph.Live},
			{ID: wf, Kind: graph.KindWorkflow, Name: "ci.yml", Evidence: graph.Live},
			{ID: "secret:acme/web", Kind: graph.KindSecret, Name: "web", Evidence: graph.Live},
		},
		Edges: []graph.Edge{
			{From: "members:acme", To: "repo:acme/web", Kind: graph.CanPush, Evidence: graph.Inferred, SourceAPI: "rest:/orgs/{org}",
				ObservedAt: at, Attrs: map[string]string{graph.AttrVia: graph.ViaDefaultPerm, graph.AttrRule: graph.RuleDefaultPerm}},
			{From: "identity:bob", To: "repo:acme/web", Kind: graph.CanPush, Evidence: graph.Audit, SourceAPI: "audit:repo.add_member",
				ObservedAt: at.Add(-200 * 24 * time.Hour), Attrs: map[string]string{graph.AttrVia: graph.ViaDirect}},
			{From: wf, To: "repo:acme/web", Kind: graph.DefinedIn, Evidence: graph.Live, SourceAPI: "test", ObservedAt: at},
			{From: wf, To: "secret:acme/web", Kind: graph.ExecutesWith, Evidence: graph.Live, SourceAPI: "test", ObservedAt: at},
		}}
	out := export(t, g, Options{})
	if !regexp.MustCompile(`evidence: 'inferred', confirmed: true,[^\n]*attr_rule: 'default_perm'`).MatchString(out) {
		t.Errorf("inferred edge is not confirmed with its rule:\n%s", out)
	}
	if !regexp.MustCompile(`evidence: 'audit', confirmed: false, stale: true`).MatchString(out) {
		t.Errorf("stale audit edge is not unconfirmed and stale:\n%s", out)
	}
	if !regexp.MustCompile(`\{from: 'identity:bob', to: 'secret:acme/web', props: \{confirmed: false,[^\n]*stale: true`).MatchString(out) {
		t.Errorf("reach through the stale edge is not possible and stale:\n%s", out)
	}
	if !regexp.MustCompile(`\{from: 'members:acme', to: 'secret:acme/web', props: \{confirmed: true, evidence: 'inferred'`).MatchString(out) {
		t.Errorf("reach through the inferred edge is not confirmed:\n%s", out)
	}
}
