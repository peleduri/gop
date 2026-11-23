package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/docs"
	"github.com/peleduri/gop/internal/graph"
)

// Resource URIs.
const (
	SummaryURI      = "gop://graph/summary"
	CoverageURI     = "gop://graph/coverage"
	SchemaURI       = "gop://graph/schema"
	NodeURIPrefix   = "gop://node/"
	nodeURITemplate = NodeURIPrefix + "{+id}"
)

// staleAfter is the snapshot age past which the summary and every prompt warn.
const staleAfter = 7 * 24 * time.Hour

// summaryTopN is how many principals the summary resource lists.
const summaryTopN = 5

// clock returns opts.Now, or time.Now when unset.
func (o ServerOptions) clock() func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

// Staleness returns "snapshot is N days old" when collectedAt is more than
// seven days before now, else "".
func Staleness(collectedAt, now time.Time) string {
	age := now.Sub(collectedAt)
	if age <= staleAfter {
		return ""
	}
	return fmt.Sprintf("snapshot is %d days old", int(age/(24*time.Hour)))
}

// EvidenceMix counts facts by evidence level. NotVisible facts are unknown, not absent.
type EvidenceMix struct {
	Live       int `json:"live"`
	Inferred   int `json:"inferred"`
	Audit      int `json:"audit"`
	Supplied   int `json:"supplied,omitempty"` // read from a user-supplied file (cloud trust policies)
	NotVisible int `json:"not_visible"`
}

func (m *EvidenceMix) add(ev graph.Evidence) {
	switch ev {
	case graph.Live:
		m.Live++
	case graph.Inferred:
		m.Inferred++
	case graph.Audit:
		m.Audit++
	case graph.Supplied:
		m.Supplied++
	case graph.NotVisible:
		m.NotVisible++
	}
}

// OrgSummary is one org's key settings. A setting the token could not read is
// "not_visible" (unknown, never off); a setting that was not collected is omitted.
type OrgSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Evidence    string `json:"evidence"`
	DefaultPerm string `json:"default_perm,omitempty"`
	TwoFactor   string `json:"two_factor,omitempty"`
	SSO         string `json:"sso,omitempty"`
}

// Summary is the gop://graph/summary resource.
type Summary struct {
	Enterprise    string                 `json:"enterprise"`
	CollectedAt   time.Time              `json:"collected_at"`
	AgeHours      int                    `json:"age_hours"`
	Staleness     string                 `json:"staleness,omitempty" jsonschema:"set when the snapshot is more than 7 days old"`
	Schema        string                 `json:"schema"`
	Demo          bool                   `json:"demo,omitempty"`
	Nodes         int                    `json:"nodes"`
	Edges         int                    `json:"edges"`
	NodesByKind   map[string]int         `json:"nodes_by_kind"`
	EdgesByKind   map[string]int         `json:"edges_by_kind"`
	Evidence      map[string]EvidenceMix `json:"evidence" jsonschema:"evidence mix of nodes and of edges"`
	CoverageGaps  int                    `json:"coverage_gaps" jsonschema:"facts the token could not see; read gop://graph/coverage"`
	Orgs          []OrgSummary           `json:"orgs"`
	TopPrincipals []graph.Score          `json:"top_principals" jsonschema:"top 5 principals by confirmed score"`
	Note          string                 `json:"note"`
}

// summaryNote travels with the summary so a reader never takes not_visible for off.
const summaryNote = "Confirmed reach means every hop was read live, inferred by a documented rule, or read from a recent audit log entry; possible reach " +
	"has at least one not_visible hop. not_visible means the token could not read the fact: it is " +
	"unknown, not absent or off. top_principals is ranked by confirmed score."

// Summary builds the gop://graph/summary resource as of now.
func (e *Engine) Summary(now time.Time) Summary {
	g := e.ix.Graph()
	s := Summary{
		Enterprise:   g.Enterprise,
		CollectedAt:  g.CollectedAt,
		Staleness:    Staleness(g.CollectedAt, now),
		Schema:       g.Schema,
		Demo:         e.demo,
		Nodes:        len(g.Nodes),
		Edges:        len(g.Edges),
		NodesByKind:  map[string]int{},
		EdgesByKind:  map[string]int{},
		CoverageGaps: len(g.Coverage),
		Orgs:         []OrgSummary{},
		Note:         summaryNote,
	}
	if age := now.Sub(g.CollectedAt); age > 0 {
		s.AgeHours = int(age / time.Hour)
	}
	var nodes, edges EvidenceMix
	for _, n := range g.Nodes {
		s.NodesByKind[string(n.Kind)]++
		nodes.add(n.Evidence)
		if n.Kind == graph.KindOrg {
			s.Orgs = append(s.Orgs, OrgSummary{
				ID: n.ID, Name: n.Name, Evidence: string(n.Evidence),
				DefaultPerm: orgAttr(n, graph.AttrDefaultPerm),
				TwoFactor:   orgAttr(n, graph.AttrTwoFactor),
				SSO:         orgAttr(n, graph.AttrSSO),
			})
		}
	}
	for _, ed := range g.Edges {
		s.EdgesByKind[string(ed.Kind)]++
		edges.add(ed.Evidence)
	}
	s.Evidence = map[string]EvidenceMix{"nodes": nodes, "edges": edges}
	sort.Slice(s.Orgs, func(i, j int) bool { return s.Orgs[i].ID < s.Orgs[j].ID })
	s.TopPrincipals = e.ix.TopPaths(summaryTopN)
	if s.TopPrincipals == nil {
		s.TopPrincipals = []graph.Score{}
	}
	return s
}

// orgAttr returns an org setting, "not_visible" when the token could not read
// it, or "" when it was not collected.
func orgAttr(n graph.Node, key string) string {
	ev, ok := n.AttrEvidence[key]
	if !ok {
		ev = n.Evidence
	}
	if ev == graph.NotVisible {
		return string(graph.NotVisible)
	}
	return n.Attrs[key]
}

// NodeResource is the gop://node/{id} resource: a node with its edges.
type NodeResource struct {
	ID string `json:"id"`
	// Node is nil when the ID only appears as an edge endpoint.
	Node *graph.Node `json:"node"`
	In   []EdgeOut   `json:"in"`
	Out  []EdgeOut   `json:"out"`
}

// NodeResource returns the node id with its in and out edges.
func (e *Engine) NodeResource(id string) (NodeResource, error) {
	id, err := e.resolve("id", id)
	if err != nil {
		return NodeResource{}, err
	}
	r := NodeResource{ID: id, In: []EdgeOut{}, Out: []EdgeOut{}}
	if n, ok := e.ix.Node(id); ok {
		r.Node = &n
	}
	for _, ed := range e.ix.In(id) {
		r.In = append(r.In, edgeOut(e.ix, ed, false))
	}
	for _, ed := range e.ix.Out(id) {
		r.Out = append(r.Out, edgeOut(e.ix, ed, false))
	}
	return r, nil
}

// addResources registers the summary, coverage and schema resources and the
// node template. now is the clock used for snapshot age.
func addResources(s *mcp.Server, e *Engine, now func() time.Time) {
	s.AddResource(&mcp.Resource{
		URI:      SummaryURI,
		Name:     "graph_summary",
		Title:    "Graph summary",
		MIMEType: "application/json",
		Description: "Start here: enterprise, snapshot age, schema, node and edge counts by kind, evidence mix " +
			"(live, inferred, audit, not_visible), orgs with default_perm, two_factor and sso, and the top 5 principals " +
			"by confirmed score. Use the node IDs it lists instead of guessing.",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return jsonContents(req.Params.URI, e.Summary(now()))
	})
	s.AddResource(&mcp.Resource{
		URI:         CoverageURI,
		Name:        "graph_coverage",
		Title:       "Coverage gaps",
		MIMEType:    "application/json",
		Description: "What the token could not see (not_visible facts) and the access that would make each visible. Same data as the coverage tool.",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		out, err := e.Coverage(CoverageInput{})
		if err != nil {
			return nil, err
		}
		return jsonContents(req.Params.URI, out)
	})
	s.AddResource(&mcp.Resource{
		URI:         SchemaURI,
		Name:        "graph_schema",
		Title:       "Graph schema",
		MIMEType:    "text/markdown",
		Description: "Node ID conventions, node kinds, edge kinds and their meaning, and evidence levels of the gop.graph/v2 schema.",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
			{URI: req.Params.URI, MIMEType: "text/markdown", Text: docs.Schema},
		}}, nil
	})
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: nodeURITemplate,
		Name:        "node",
		Title:       "Node with its edges",
		MIMEType:    "application/json",
		Description: "One node (e.g. gop://node/repo:acme-app/web) with its in and out edges, each with evidence, " +
			"source_api and observed_at. The ID may be given raw or percent-encoded.",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		uri := req.Params.URI
		raw, ok := strings.CutPrefix(uri, NodeURIPrefix)
		if !ok {
			return nil, mcp.ResourceNotFoundError(uri)
		}
		id, err := url.PathUnescape(raw)
		if err != nil {
			return nil, mcp.ResourceNotFoundError(uri)
		}
		r, err := e.NodeResource(id)
		if err != nil {
			return nil, nodeNotFound(uri, err)
		}
		return jsonContents(uri, r)
	})
}

// nodeNotFound is a resource-not-found error that names close node IDs.
func nodeNotFound(uri string, err error) error {
	data := map[string]any{"uri": uri}
	var u *UnknownNodeError
	if errors.As(err, &u) && len(u.Suggestions) > 0 {
		data["suggestions"] = u.Suggestions
	}
	b, merr := json.Marshal(data)
	if merr != nil {
		return mcp.ResourceNotFoundError(uri)
	}
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "Resource not found: " + err.Error(), Data: b}
}

func jsonContents(uri string, v any) (*mcp.ReadResourceResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
		{URI: uri, MIMEType: "application/json", Text: string(b)},
	}}, nil
}
