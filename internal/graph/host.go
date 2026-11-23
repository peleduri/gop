package graph

import "strings"

// Enterprise node attributes that name the GitHub instance a graph came from.
const (
	// AttrHost is the GitHub host: "github.com", or the GitHub Enterprise
	// Server host name such as "github.acme.example".
	AttrHost = "host"
	// AttrGHESVersion is the GitHub Enterprise Server version from GET /meta
	// (installed_version), e.g. "3.14.2". Absent on github.com.
	AttrGHESVersion = "ghes_version"
)

// GitHubDotCom is the AttrHost value of a graph collected from github.com.
const GitHubDotCom = "github.com"

// Host returns the AttrHost of the graph's enterprise node, or "" when the
// graph does not record it (graphs written before gop recorded the host, and
// synthetic graphs).
func Host(g *Graph) string {
	if g == nil {
		return ""
	}
	id := "enterprise:" + g.Enterprise
	for i := range g.Nodes {
		if n := &g.Nodes[i]; n.ID == id || (g.Enterprise == "" && n.Kind == KindEnterprise) {
			return strings.ToLower(strings.TrimSpace(n.Attrs[AttrHost]))
		}
	}
	return ""
}
