package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/docs"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/testutil"
)

// acmeNow is 30 hours after testdata/acme/graph.json was collected.
var acmeNow = time.Date(2026, 11, 21, 16, 0, 0, 0, time.UTC)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// connectAt connects to a server over g whose clock reads now.
func connectAt(t *testing.T, g *graph.Graph, now time.Time) *mcp.ClientSession {
	t.Helper()
	return connectServer(t, NewServerWith(g, "test", ServerOptions{Now: fixedClock(now)}))
}

func readResource(t *testing.T, cs *mcp.ClientSession, uri string) *mcp.ResourceContents {
	t.Helper()
	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("read %s: %v", uri, err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("read %s: %d contents", uri, len(res.Contents))
	}
	return res.Contents[0]
}

func TestResourcesListed(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	ctx := context.Background()
	res, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range res.Resources {
		got[r.URI] = r.MIMEType
		if r.Description == "" {
			t.Errorf("%s: no description", r.URI)
		}
	}
	want := map[string]string{SummaryURI: "application/json", CoverageURI: "application/json", SchemaURI: "text/markdown"}
	if !maps.Equal(got, want) {
		t.Errorf("resources = %v, want %v", got, want)
	}
	tr, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.ResourceTemplates) != 1 || tr.ResourceTemplates[0].URITemplate != "gop://node/{+id}" ||
		tr.ResourceTemplates[0].MIMEType != "application/json" {
		t.Errorf("templates = %+v", tr.ResourceTemplates)
	}
}

func TestSummaryResource(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	c := readResource(t, cs, SummaryURI)
	if c.MIMEType != "application/json" || c.URI != SummaryURI {
		t.Errorf("contents uri %q mime %q", c.URI, c.MIMEType)
	}
	var s Summary
	if err := json.Unmarshal([]byte(c.Text), &s); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	// Hand count of testdata/acme/graph.json.
	wantNodes := map[string]int{"repo": 16, "workflow": 17, "org": 4, "org_members": 4, "action_ref": 4,
		"identity": 2, "secret": 2, "oidc": 2, "enterprise": 1, "runner": 1}
	wantEdges := map[string]int{"DEFINED_IN": 17, "USES": 14, "CAN_PUSH": 6, "EXECUTES_WITH": 6,
		"RESOLVES_TO": 4, "MEMBER_OF": 2}
	if !maps.Equal(s.NodesByKind, wantNodes) {
		t.Errorf("nodes_by_kind = %v, want %v", s.NodesByKind, wantNodes)
	}
	if !maps.Equal(s.EdgesByKind, wantEdges) {
		t.Errorf("edges_by_kind = %v, want %v", s.EdgesByKind, wantEdges)
	}
	if s.Nodes != 53 || s.Edges != 49 || s.CoverageGaps != 2 {
		t.Errorf("nodes %d edges %d gaps %d, want 53 49 2", s.Nodes, s.Edges, s.CoverageGaps)
	}
	if s.Evidence["nodes"] != (EvidenceMix{Live: 50, Audit: 2, NotVisible: 1}) ||
		s.Evidence["edges"] != (EvidenceMix{Live: 46, Audit: 2, NotVisible: 1}) {
		t.Errorf("evidence = %+v", s.Evidence)
	}
	if s.Enterprise != "acme" || s.Schema != graph.SchemaVersion || s.AgeHours != 30 || s.Staleness != "" {
		t.Errorf("header = %q %q age %d staleness %q", s.Enterprise, s.Schema, s.AgeHours, s.Staleness)
	}
	if len(s.Orgs) != 4 || s.Orgs[0].ID != "org:acme-actions" || s.Orgs[0].DefaultPerm != "write" ||
		s.Orgs[0].TwoFactor != "not_required" || s.Orgs[0].SSO != "configured" {
		t.Errorf("orgs = %+v", s.Orgs)
	}
	if len(s.TopPrincipals) == 0 || len(s.TopPrincipals) > 5 {
		t.Fatalf("top_principals = %d", len(s.TopPrincipals))
	}
	for i := 1; i < len(s.TopPrincipals); i++ {
		if s.TopPrincipals[i].Score > s.TopPrincipals[i-1].Score {
			t.Errorf("top_principals not ranked by confirmed score: %+v", s.TopPrincipals)
		}
	}
	if !strings.Contains(s.Note, "not_visible") || !strings.Contains(s.Note, "not absent or off") {
		t.Errorf("note = %q", s.Note)
	}
	testutil.Golden(t, "resource_summary.json", []byte(c.Text+"\n"))
}

func TestSummaryStaleness(t *testing.T) {
	g := loadAcme(t)
	if got := Staleness(g.CollectedAt, g.CollectedAt.Add(7*24*time.Hour)); got != "" {
		t.Errorf("exactly 7 days: %q, want no warning", got)
	}
	cs := connectAt(t, g, g.CollectedAt.Add(10*24*time.Hour+5*time.Hour))
	var s Summary
	if err := json.Unmarshal([]byte(readResource(t, cs, SummaryURI).Text), &s); err != nil {
		t.Fatal(err)
	}
	if s.Staleness != "snapshot is 10 days old" || s.AgeHours != 245 {
		t.Errorf("staleness %q age %d", s.Staleness, s.AgeHours)
	}
}

func TestOrgAttrNotVisibleIsNeverOff(t *testing.T) {
	n := graph.Node{ID: "org:acme-legacy", Kind: graph.KindOrg, Evidence: graph.Live,
		Attrs:        map[string]string{graph.AttrSSO: "none", graph.AttrTwoFactor: "not_required"},
		AttrEvidence: map[string]graph.Evidence{graph.AttrSSO: graph.NotVisible}}
	if got := orgAttr(n, graph.AttrSSO); got != "not_visible" {
		t.Errorf("sso = %q, want not_visible", got)
	}
	if got := orgAttr(n, graph.AttrTwoFactor); got != "not_required" {
		t.Errorf("two_factor = %q", got)
	}
	if got := orgAttr(n, graph.AttrDefaultPerm); got != "" {
		t.Errorf("uncollected default_perm = %q, want empty", got)
	}
	n.Evidence, n.AttrEvidence = graph.NotVisible, nil
	if got := orgAttr(n, graph.AttrTwoFactor); got != "not_visible" {
		t.Errorf("not_visible node: two_factor = %q", got)
	}
}

func TestCoverageResourceMatchesTool(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	var fromRes, fromTool CoverageOutput
	if err := json.Unmarshal([]byte(readResource(t, cs, CoverageURI).Text), &fromRes); err != nil {
		t.Fatalf("coverage is not valid JSON: %v", err)
	}
	call(t, cs, "coverage", map[string]any{}, &fromTool)
	a, _ := json.Marshal(fromRes)
	b, _ := json.Marshal(fromTool)
	if string(a) != string(b) || len(fromRes.Entries) != 2 {
		t.Errorf("resource %s\ntool %s", a, b)
	}
}

func TestSchemaResource(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	c := readResource(t, cs, SchemaURI)
	if c.MIMEType != "text/markdown" || c.Text != docs.Schema || !strings.HasPrefix(c.Text, "# Graph schema") {
		t.Errorf("schema resource mime %q, %d bytes", c.MIMEType, len(c.Text))
	}
}

func TestNodeResource(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	raw := readResource(t, cs, "gop://node/action:acme-actions/deploy@main")
	enc := readResource(t, cs, "gop://node/action%3Aacme-actions%2Fdeploy%40main")
	if raw.Text != enc.Text {
		t.Errorf("raw and percent-encoded IDs differ")
	}
	var r NodeResource
	if err := json.Unmarshal([]byte(raw.Text), &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "action:acme-actions/deploy@main" || r.Node == nil || len(r.In) == 0 || len(r.Out) == 0 {
		t.Fatalf("node = %+v", r)
	}
	for _, ed := range append(r.In, r.Out...) {
		if ed.Evidence == "" || ed.SourceAPI == "" {
			t.Errorf("edge %s -> %s missing evidence or source", ed.From, ed.To)
		}
	}
	testutil.Golden(t, "resource_node_action.json", []byte(raw.Text+"\n"))
}

func TestNodeResourceUnknown(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	_, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gop://node/repo:acme-app/webb"})
	var je *jsonrpc.Error
	if !errors.As(err, &je) || je.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("err = %v, want resource not found", err)
	}
	if !strings.Contains(je.Message, "repo:acme-app/web") || !strings.Contains(string(je.Data), "repo:acme-app/web") {
		t.Errorf("error does not suggest repo:acme-app/web: %s %s", je.Message, je.Data)
	}
}
