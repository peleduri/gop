package sqlexport

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/demo"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// sqlite3 returns the path of the sqlite3 shell. Tests that load the script
// skip without it locally and fail without it in CI, so CI always runs them.
func sqlite3(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sqlite3")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("sqlite3 not on PATH; the SQL export tests need it in CI")
		}
		t.Skip("sqlite3 not on PATH")
	}
	versionOnce.Do(func() {
		out, err := exec.Command(p, "-version").Output()
		t.Logf("sqlite3 -version: %s %v", bytes.TrimSpace(out), err)
	})
	return p
}

var versionOnce sync.Once

// load writes graphs as a script and runs it with sqlite3 into db.
func load(t *testing.T, db string, graphs ...*graph.Graph) {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, graphs); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sqlite3(t), "-bail", db)
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil || len(out) > 0 {
		t.Fatalf("sqlite3 load: %v\n%s", err, out)
	}
}

// query runs q and returns the rows as JSON objects.
func query(t *testing.T, db, q string) []map[string]any {
	t.Helper()
	out, err := exec.Command(sqlite3(t), "-bail", "-json", db, q).Output()
	if err != nil {
		t.Fatalf("sqlite3 %q: %v", q, err)
	}
	var rows []map[string]any
	if len(bytes.TrimSpace(out)) == 0 {
		return nil
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("sqlite3 %q: %v\n%s", q, err, out)
	}
	return rows
}

// headerTable runs q and returns sqlite3's header output (columns split by |).
func headerTable(t *testing.T, db, q string) string {
	t.Helper()
	out, err := exec.Command(sqlite3(t), "-bail", "-header", db, q).CombinedOutput()
	if err != nil {
		t.Fatalf("sqlite3 %q: %v\n%s", q, err, out)
	}
	return string(out)
}

func smallDemo() *graph.Graph { return demo.Generate(demo.Options{Seed: 1, Size: demo.SizeSmall}) }

// laterRun is the demo a week later with acme-actions' default permission
// lowered: its via=default_perm CAN_PUSH edges are gone.
func laterRun() *graph.Graph {
	g := smallDemo()
	g.CollectedAt = g.CollectedAt.Add(7 * 24 * time.Hour)
	var es []graph.Edge
	for _, e := range g.Edges {
		if e.Kind == graph.CanPush && e.From == "members:acme-actions" && e.Attrs[graph.AttrVia] == graph.ViaDefaultPerm {
			continue
		}
		es = append(es, e)
	}
	g.Edges = es
	return g
}

var sqlBlock = regexp.MustCompile("(?s)```sql\n(.*?)```")

// TestDocQueries runs every query in docs/sql.md on two demo runs and
// compares the results with a golden file.
func TestDocQueries(t *testing.T) {
	doc, err := os.ReadFile("../../docs/sql.md")
	if err != nil {
		t.Fatal(err)
	}
	qs := sqlBlock.FindAllStringSubmatch(string(doc), -1)
	if len(qs) != 5 {
		t.Fatalf("docs/sql.md has %d sql blocks, want 5", len(qs))
	}
	db := filepath.Join(t.TempDir(), "gop.db")
	load(t, db, smallDemo())
	load(t, db, laterRun())
	var got strings.Builder
	for i, q := range qs {
		fmt.Fprintf(&got, "-- query %d\n%s\n", i+1, headerTable(t, db, q[1]))
	}
	testutil.Golden(t, "doc_queries.txt", []byte(got.String()))
}

// TestReload: loading the same script again replaces its run; a second
// graph adds a run.
func TestReload(t *testing.T) {
	db := filepath.Join(t.TempDir(), "gop.db")
	counts := func() string {
		return headerTable(t, db, "SELECT (SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM nodes), (SELECT COUNT(*) FROM node_attrs), "+
			"(SELECT COUNT(*) FROM edges), (SELECT COUNT(*) FROM edge_attrs), (SELECT COUNT(*) FROM findings), (SELECT COUNT(*) FROM reach)")
	}
	load(t, db, smallDemo())
	once := counts()
	load(t, db, smallDemo(), smallDemo())
	if again := counts(); again != once {
		t.Errorf("reload changed counts:\n%s\n%s", once, again)
	}
	load(t, db, laterRun())
	if n := query(t, db, "SELECT COUNT(*) AS n FROM runs")[0]["n"]; n != float64(2) {
		t.Errorf("runs after a second graph: %v, want 2", n)
	}
}

func TestDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := Write(&a, []*graph.Graph{smallDemo()}); err != nil {
		t.Fatal(err)
	}
	g := smallDemo()
	r := rand.New(rand.NewPCG(7, 7))
	r.Shuffle(len(g.Nodes), func(i, j int) { g.Nodes[i], g.Nodes[j] = g.Nodes[j], g.Nodes[i] })
	r.Shuffle(len(g.Edges), func(i, j int) { g.Edges[i], g.Edges[j] = g.Edges[j], g.Edges[i] })
	if err := Write(&b, []*graph.Graph{g}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("the same graph in another order gives a different script")
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":           "''",
		"acme":       "'acme'",
		"o'brien":    "'o''brien'",
		"''":         "''''''",
		`a\b`:        `'a\b'`,
		"a\x00b":     "'a\uFFFDb'",
		"bad\xffz":   "'bad\uFFFDz'",
		"x'); --":    "'x''); --'",
		"é \u2028;":  "'é \u2028;'",
		"l1\nl2":     `('"l1\nl2"' ->> '$')`,
		"a\r\nb":     `('"a\r\nb"' ->> '$')`,
		"esc\x1b[0m": `('"esc\u001b[0m"' ->> '$')`,
		"o'b\t\"<>":  `('"o''b\t\"<>"' ->> '$')`,
		"del\x7f":    `('"del\u007f"' ->> '$')`,
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

// hostile strings: SQL breakouts, shell dot-commands after a newline,
// comments, backslashes, control and format characters, NUL.
var hostile = []string{
	"repo:acme-app/x'); DROP TABLE nodes; --",
	"repo:acme-app/y';\n.shell echo pwned\n'",
	"repo:acme-app/z\\'\\\\",
	"repo:acme-app/c /* */ -- \r\n\t\x1b[31m",
	"repo:acme-app/u \u202e\u2028\u200b é \U0001F511",
	"repo:acme-app/n\x00ul",
	"repo:acme-app/semi;\n;",
	"repo:acme-app/'",
}

func TestHostileNamesRoundTrip(t *testing.T) {
	g := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme'; DELETE FROM runs; --", CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	g.Nodes = append(g.Nodes, graph.Node{ID: "members:acme-app", Kind: graph.KindOrgMembers, Name: "members", Evidence: graph.Live})
	for i, h := range hostile {
		g.Nodes = append(g.Nodes, graph.Node{ID: h, Kind: graph.KindRepo, Name: h, Evidence: graph.Live,
			Attrs: map[string]string{h: h, "k": fmt.Sprint(i)}})
		g.Edges = append(g.Edges, graph.Edge{From: "members:acme-app", To: h, Kind: graph.CanPush, Evidence: graph.Live, SourceAPI: h,
			Attrs: map[string]string{graph.AttrVia: graph.ViaDefaultPerm, "note": h}})
	}
	// The script itself holds no control character but LF between
	// statements, so no shell's line handling can change a value.
	var script bytes.Buffer
	if err := Write(&script, []*graph.Graph{g}); err != nil {
		t.Fatal(err)
	}
	for i, c := range script.Bytes() {
		if (c < 0x20 && c != '\n') || c == 0x7f {
			t.Fatalf("script byte %d is control character %#x", i, c)
		}
	}
	db := filepath.Join(t.TempDir(), "gop.db")
	load(t, db, g)

	clean := func(s string) string { return strings.ReplaceAll(s, "\x00", "\uFFFD") }
	if got := query(t, db, "SELECT hex(enterprise) AS e FROM runs"); len(got) != 1 || got[0]["e"] != strings.ToUpper(hex.EncodeToString([]byte(g.Enterprise))) {
		t.Errorf("runs: %v", got)
	}
	// Compare hex(value) so the shell's output formatting of control
	// characters cannot hide or fake a difference.
	want := map[string]bool{}
	for _, h := range hostile {
		want[strings.ToUpper(hex.EncodeToString([]byte(clean(h))))] = true
	}
	for _, c := range []struct{ q, col string }{
		{"SELECT hex(id) AS v FROM nodes WHERE kind = 'repo'", "v"},
		{"SELECT hex(name) AS v FROM nodes WHERE kind = 'repo'", "v"},
		{"SELECT hex(key) AS v FROM node_attrs WHERE key <> 'k'", "v"},
		{"SELECT hex(value) AS v FROM node_attrs WHERE key <> 'k'", "v"},
		{"SELECT hex(dst) AS v FROM edges", "v"},
		{"SELECT hex(source_api) AS v FROM edges", "v"},
		{"SELECT hex(value) AS v FROM edge_attrs WHERE key = 'note'", "v"},
		{"SELECT hex(target) AS v FROM reach WHERE target_kind = 'repo'", "v"},
	} {
		got := map[string]bool{}
		for _, r := range query(t, db, c.q) {
			got[r[c.col].(string)] = true
		}
		if len(got) != len(want) {
			t.Errorf("%s: %d distinct values, want %d: %v", c.q, len(got), len(want), got)
		}
		for v := range want {
			if !got[v] {
				t.Errorf("%s: missing %q (hex of %q)", c.q, v, unhex(v))
			}
		}
	}
	if bad := query(t, db, "SELECT id FROM nodes WHERE typeof(id) <> 'text' OR typeof(name) <> 'text'"); len(bad) > 0 {
		t.Errorf("non-text values: %v", bad)
	}
	// Each node attr row joins back to its node: keys and values went to
	// the right columns.
	if bad := query(t, db, "SELECT node_id FROM node_attrs WHERE key <> 'k' AND (key <> node_id OR value <> node_id)"); len(bad) > 0 {
		t.Errorf("attrs out of place: %v", bad)
	}
	if got := query(t, db, "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table'"); got[0]["n"] != float64(len(tables)) {
		t.Errorf("tables: %v, want %d", got, len(tables))
	}
}

// genGraph is a random graph over every edge kind the reach engine follows,
// with random evidence and a few undeclared endpoints.
func genGraph(r *rand.Rand) *graph.Graph {
	g := &graph.Graph{Schema: graph.SchemaVersion, Enterprise: "acme", CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	evs := []graph.Evidence{graph.Live, graph.Live, graph.Audit, graph.Supplied, graph.NotVisible}
	ev := func() graph.Evidence { return evs[r.IntN(len(evs))] }
	node := func(id string, kind graph.NodeKind, attrs map[string]string) string {
		if r.IntN(15) > 0 {
			g.Nodes = append(g.Nodes, graph.Node{ID: id, Kind: kind, Name: id, Evidence: ev(), Attrs: attrs})
		}
		return id
	}
	edge := func(from, to string, kind graph.EdgeKind, attrs map[string]string) {
		g.Edges = append(g.Edges, graph.Edge{From: from, To: to, Kind: kind, Evidence: ev(), SourceAPI: "test", Attrs: attrs})
	}
	pick := func(ids []string) string { return ids[r.IntN(len(ids))] }
	orgs := []string{"acme-app", "acme-actions"}
	perms := []string{"read", "write"}
	var members, repos, idents, wfs, actions, terms []string
	for _, o := range orgs {
		node("org:"+o, graph.KindOrg, map[string]string{graph.AttrDefaultPerm: perms[r.IntN(2)]})
		members = append(members, node("members:"+o, graph.KindOrgMembers, nil))
	}
	for i := 0; i < 2+r.IntN(8); i++ {
		o := pick(orgs)
		repo := fmt.Sprintf("%s/r%d", o, i)
		repos = append(repos, node("repo:"+repo, graph.KindRepo, nil))
		wfs = append(wfs, node(fmt.Sprintf("workflow:%s/.github/workflows/w.yml", repo), graph.KindWorkflow, nil))
		edge(wfs[len(wfs)-1], repos[len(repos)-1], graph.DefinedIn, nil)
		kinds := []struct {
			prefix string
			kind   graph.NodeKind
		}{{"secret", graph.KindSecret}, {"oidc", graph.KindOIDC}, {"runner", graph.KindRunner}}
		k := kinds[r.IntN(len(kinds))]
		terms = append(terms, node(k.prefix+":"+repo, k.kind, nil))
	}
	for i := 0; i < 1+r.IntN(4); i++ {
		idents = append(idents, node(fmt.Sprintf("identity:user-%03d", i), graph.KindIdentity, nil))
		edge(idents[i], "org:"+pick(orgs), graph.MemberOf, nil)
	}
	refs := []string{"main", "v1", "0123456789abcdef0123456789abcdef01234567"}
	kinds := map[string]string{"main": "branch", "v1": "tag", refs[2]: "sha"}
	for i := 0; i < 1+r.IntN(3); i++ {
		host := pick(repos)
		ref := pick(refs)
		a := node("action:"+strings.TrimPrefix(host, "repo:")+"@"+ref, graph.KindActionRef, nil)
		actions = append(actions, a)
		edge(a, host, graph.ResolvesTo, nil)
	}
	for i := 0; i < 3+r.IntN(12); i++ {
		switch r.IntN(5) {
		case 0:
			edge(pick(members), pick(repos), graph.CanPush, map[string]string{graph.AttrVia: graph.ViaDefaultPerm})
		case 1:
			edge(pick(idents), pick(repos), graph.CanPush, map[string]string{graph.AttrVia: graph.ViaDirect})
		case 2:
			a := pick(actions)
			edge(pick(wfs), a, graph.Uses, map[string]string{graph.AttrRefKind: kinds[a[strings.LastIndex(a, "@")+1:]]})
		case 3:
			edge(pick(wfs), pick(terms), graph.ExecutesWith, nil)
		case 4:
			edge("external:anyone", pick(wfs), graph.CanTrigger, map[string]string{"trigger": "pull_request_target", "exec": "checkout"})
		}
	}
	return g
}

type reachKey struct {
	principal, target string
	confirmed         bool
}

// TestReachMatchesGraph: on random graphs and demo graphs, the reach table
// read back from SQLite equals graph.Index.PairReach for every scoring
// principal, and confirmed agrees with the engine's confirmed/possible sets.
func TestReachMatchesGraph(t *testing.T) {
	var graphs []*graph.Graph
	r := rand.New(rand.NewPCG(88, 1))
	for i := 0; i < 40; i++ {
		graphs = append(graphs, genGraph(r))
	}
	for seed := int64(1); seed <= 3; seed++ {
		graphs = append(graphs, demo.Generate(demo.Options{Seed: seed, Size: demo.SizeSmall}))
	}
	_, haveSQLite := exec.LookPath("sqlite3")
	nonEmpty := 0
	for i, g := range graphs {
		ix := graph.NewIndex(g)
		want := map[reachKey]bool{}
		for _, p := range ix.ScoringPrincipals() {
			res := ix.PairReach(p)
			for id, path := range res.Paths {
				want[reachKey{p, id, !path.Unverified}] = true
			}
			for _, set := range []struct {
				re        graph.Reached
				confirmed bool
			}{{res.Confirmed, true}, {res.Possible, false}} {
				for _, ids := range [][]string{set.re.Repos, set.re.Workflows, set.re.Actions, set.re.Secrets, set.re.OIDC, set.re.Runners, set.re.CloudTargets} {
					for _, id := range ids {
						if !want[reachKey{p, id, set.confirmed}] {
							t.Errorf("graph %d: %s reaches %s (confirmed=%v) but Paths disagree", i, p, id, set.confirmed)
						}
					}
				}
			}
		}
		if len(want) > 0 {
			nonEmpty++
		}
		got := map[reachKey]bool{}
		for _, row := range reachRows(ix) {
			got[reachKey{row[0].(string), row[1].(string), row[3].(bool)}] = true
		}
		if haveSQLite == nil || os.Getenv("CI") != "" {
			db := filepath.Join(t.TempDir(), fmt.Sprintf("g%d.db", i))
			load(t, db, g)
			fromDB := map[reachKey]bool{}
			for _, row := range query(t, db, "SELECT principal, target, confirmed FROM reach") {
				fromDB[reachKey{row["principal"].(string), row["target"].(string), row["confirmed"] == float64(1)}] = true
			}
			got = fromDB
		}
		if !equalKeys(got, want) {
			t.Errorf("graph %d: reach rows differ from the engine:\n got %v\nwant %v", i, sortedReach(got), sortedReach(want))
		}
	}
	if nonEmpty < len(graphs)/2 {
		t.Errorf("only %d of %d graphs have any reach; the generator is too sparse", nonEmpty, len(graphs))
	}
}

func equalKeys(a, b map[reachKey]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedReach(m map[reachKey]bool) []string {
	var out []string
	for k := range m {
		out = append(out, fmt.Sprintf("%s->%s:%v", k.principal, k.target, k.confirmed))
	}
	sort.Strings(out)
	return out
}

func unhex(s string) string {
	b, _ := hex.DecodeString(s)
	return string(b)
}

func TestRepoOf(t *testing.T) {
	for in, want := range map[string]string{
		"repo:acme-app/web":                             "repo:acme-app/web",
		"workflow:acme-app/web/.github/workflows/x.yml": "repo:acme-app/web",
		"secret:acme-app/billing":                       "repo:acme-app/billing",
		"action:acme-actions/deploy@main":               "repo:acme-actions/deploy",
		"action:acme-actions/deploy/sub@v1":             "repo:acme-actions/deploy",
		"org:acme-app":                                  "",
		"identity:alice":                                "",
		"repo:acme-app":                                 "",
		"nope":                                          "",
	} {
		if got := repoOf(in); got != want {
			t.Errorf("repoOf(%q) = %q, want %q", in, got, want)
		}
	}
}
