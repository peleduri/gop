package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Load decodes a serialized Graph and checks its schema version.
func Load(r io.Reader) (*Graph, error) {
	var g Graph
	dec := json.NewDecoder(r)
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("graph: decode: %w", err)
	}
	if g.Schema != SchemaVersion {
		return nil, fmt.Errorf("graph: unsupported schema %q (want %q)", g.Schema, SchemaVersion)
	}
	for i, e := range g.Edges {
		if e.From == "" || e.To == "" || e.Kind == "" {
			return nil, fmt.Errorf("graph: edge %d: from, to and kind are required", i)
		}
		switch e.Evidence {
		case Live, Audit, NotVisible:
		default:
			return nil, fmt.Errorf("graph: edge %d (%s %s %s): bad evidence %q", i, e.From, e.Kind, e.To, e.Evidence)
		}
	}
	return &g, nil
}

// LoadFile is Load on a file path.
func LoadFile(path string) (*Graph, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// Index holds adjacency lookups over a Graph. It is read-only after NewIndex
// and safe for concurrent use.
type Index struct {
	g     *Graph
	nodes map[string]Node
	out   map[string][]Edge
	in    map[string][]Edge
	base  *controlGraph // control graph with no fixes applied
	gates []usesGate    // actions access gate per g.Edges index; nil when no repo has actions_access
}

// NewIndex builds adjacency lookups. Edge lists are sorted (kind, to/from, source_api)
// so every traversal is deterministic. A nil graph is treated as empty.
func NewIndex(g *Graph) *Index {
	if g == nil {
		g = &Graph{Schema: SchemaVersion}
	}
	ix := &Index{g: g, nodes: map[string]Node{}, out: map[string][]Edge{}, in: map[string][]Edge{}}
	for _, n := range g.Nodes {
		ix.nodes[n.ID] = n
	}
	for _, e := range g.Edges {
		ix.out[e.From] = append(ix.out[e.From], e)
		ix.in[e.To] = append(ix.in[e.To], e)
	}
	for _, m := range []map[string][]Edge{ix.out, ix.in} {
		for _, es := range m {
			sort.SliceStable(es, func(i, j int) bool { return edgeLess(es[i], es[j]) })
		}
	}
	ix.gates = ix.usesGates()
	ix.base = ix.buildControl(nil)
	return ix
}

func edgeLess(a, b Edge) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.From != b.From {
		return a.From < b.From
	}
	if a.To != b.To {
		return a.To < b.To
	}
	return a.SourceAPI < b.SourceAPI
}

// Graph returns the indexed graph.
func (ix *Index) Graph() *Graph { return ix.g }

// Node returns the node with this ID, if the graph declares it.
func (ix *Index) Node(id string) (Node, bool) { n, ok := ix.nodes[id]; return n, ok }

// Out returns edges whose From is id (sorted).
func (ix *Index) Out(id string) []Edge { return ix.out[id] }

// In returns edges whose To is id (sorted).
func (ix *Index) In(id string) []Edge { return ix.in[id] }

// Kind returns the node's kind, or infers it from the ID prefix when the node is undeclared.
func (ix *Index) Kind(id string) NodeKind {
	if n, ok := ix.nodes[id]; ok && n.Kind != "" {
		return n.Kind
	}
	return KindFromID(id)
}

// KindFromID infers a node kind from the ID convention ("repo:O/R", "members:X", ...).
func KindFromID(id string) NodeKind {
	prefix, _, _ := strings.Cut(id, ":")
	switch prefix {
	case "enterprise":
		return KindEnterprise
	case "org":
		return KindOrg
	case "members":
		return KindOrgMembers
	case "identity", "user", "team", "app":
		return KindIdentity
	case "repo":
		return KindRepo
	case "workflow":
		return KindWorkflow
	case "action":
		return KindActionRef
	case "secret":
		return KindSecret
	case "oidc":
		return KindOIDC
	case "runner":
		return KindRunner
	case "cloud":
		return KindCloudTarget
	}
	return ""
}

// OrgOf returns "org:O" for "repo:O/R", "workflow:O/R/...", "secret:O/R", "team:O/slug"
// style IDs and "members:O"/"org:O"; "" when the ID carries no org.
func OrgOf(id string) string {
	prefix, rest, ok := strings.Cut(id, ":")
	if !ok || rest == "" {
		return ""
	}
	switch prefix {
	case "org", "members":
		return "org:" + rest
	case "repo", "workflow", "secret", "oidc", "runner", "action", "team":
		o, _, _ := strings.Cut(rest, "/")
		return "org:" + o
	}
	return ""
}

// Principals returns every node that can start an attack: org_members and identity
// nodes, plus undeclared sources of MEMBER_OF edges and org_members or identity
// sources of CAN_PUSH edges. A workflow with a write token (workflow -CAN_PUSH->
// repo, via=token_write) is controlled, never a principal. Sorted. This is
// the full set used by WhoCanReach and accepted by Reach and BlastRadius; totals
// use ScoringPrincipals instead.
func (ix *Index) Principals() []string {
	set := map[string]bool{}
	for id, n := range ix.nodes {
		if n.Kind == KindOrgMembers || n.Kind == KindIdentity {
			set[id] = true
		}
	}
	for _, e := range ix.g.Edges {
		switch e.Kind {
		case MemberOf:
			set[e.From] = true
		case CanPush:
			if k := ix.Kind(e.From); k == KindOrgMembers || k == KindIdentity {
				set[e.From] = true
			}
		}
	}
	return sortedKeys(set)
}

// ScoringPrincipals is the subset of Principals that TopPaths, WhatIf and
// SuggestFixes score and sum into (principal, repo) pair totals: every org_members
// principal, plus each identity with at least one CAN_PUSH edge or a MEMBER_OF edge
// to something other than an org (a team). Team principals ("team:O/slug") qualify
// through their CAN_PUSH grants or their MEMBER_OF edge to a parent team; a team
// with neither reaches nothing. An identity whose only edges are org
// MEMBER_OF reaches exactly what members:X reaches, so counting it again would
// multiply the totals by the number of licensed users without adding reach. Sorted.
func (ix *Index) ScoringPrincipals() []string {
	var out []string
	for _, p := range ix.Principals() {
		if ix.Kind(p) == KindOrgMembers {
			out = append(out, p)
			continue
		}
		for _, e := range ix.out[p] {
			if e.Kind == CanPush || (e.Kind == MemberOf && ix.Kind(e.To) != KindOrg) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// evRank orders evidence: not_visible (and unknown) < audit < live.
func evRank(e Evidence) int {
	switch e {
	case Live:
		return 2
	case Audit:
		return 1
	}
	return 0
}

// Verified reports whether a hop with this evidence counts toward confirmed reach.
func Verified(e Evidence) bool { return e == Live || e == Audit }

func weakest(a, b Evidence) Evidence {
	if evRank(a) <= evRank(b) {
		if evRank(a) == 0 {
			return NotVisible
		}
		return a
	}
	return b
}
