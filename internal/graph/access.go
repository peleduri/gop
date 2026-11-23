package graph

import "strings"

// Actions access levels (repo attr actions_access). GitHub's "Access" setting
// under a private or internal repo's Actions settings decides which other
// repositories may use the actions and reusable workflows it hosts. Public
// repos are open to everyone; unknown means the setting could not be read.
const (
	AccessNone         = "none"
	AccessUser         = "user"
	AccessOrganization = "organization"
	AccessEnterprise   = "enterprise"
	AccessPublic       = "public"
	AccessUnknown      = "unknown"
)

// actionsAccessAllows decides whether a workflow or action in consumerRepo may
// use an action hosted in hostRepo whose actions_access is level. Both are repo
// IDs ("repo:O/R"); consumerRepo is "" when it is not known. Owner and repo
// names compare case-insensitively, as GitHub does.
//
//	"" or public:  allowed (a missing attr keeps today's behavior)
//	enterprise:    allowed: every collected org is in the enterprise
//	organization:  allowed only within the host's org
//	user:          allowed only within the host's owner (never between orgs)
//	none:          allowed only from the host repo itself
//	unknown:       same org allowed; anything else allowed but not_visible,
//	               so the path is possible, never confirmed. Values gop does
//	               not know are read as unknown.
//
// A consumer that is not known gets not_visible under any restricting level.
func actionsAccessAllows(level, hostRepo, consumerRepo string) (bool, Evidence) {
	switch level {
	case "", AccessPublic, AccessEnterprise:
		return true, Live
	}
	if consumerRepo == "" {
		return true, NotVisible
	}
	sameRepo := strings.EqualFold(hostRepo, consumerRepo)
	hostOrg := OrgOf(hostRepo)
	sameOrg := hostOrg != "" && strings.EqualFold(hostOrg, OrgOf(consumerRepo))
	switch level {
	case AccessOrganization, AccessUser:
		return sameOrg, Live
	case AccessNone:
		return sameRepo, Live
	}
	if sameOrg {
		return true, Live
	}
	return true, NotVisible
}

// usesGate is the access verdict for one USES edge.
type usesGate uint8

const (
	gateOpen   usesGate = iota // hop unchanged
	gateHidden                 // hop kept, evidence not_visible
	gateClosed                 // hop dropped
)

// usesGates computes the access gate of every USES edge, aligned with g.Edges,
// once per Index (it does not depend on fixes). It returns nil when no repo
// carries actions_access, so graphs without the attr cost nothing and behave
// exactly as before.
func (ix *Index) usesGates() []usesGate {
	found := false
	for _, n := range ix.g.Nodes {
		if n.Attrs[AttrActionsAccess] != "" {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	gates := make([]usesGate, len(ix.g.Edges))
	for i, e := range ix.g.Edges {
		if e.Kind == Uses {
			gates[i] = ix.usesGate(e)
		}
	}
	return gates
}

// usesGate checks every (host, consumer) pair of a USES edge and keeps the most
// permissive verdict. An action normally has one host and its consumer one repo;
// taking the best pair keeps the rule monotonic when a graph has more.
func (ix *Index) usesGate(e Edge) usesGate {
	hosts := ix.actionHosts(e.To)
	if len(hosts) == 0 {
		return gateOpen
	}
	consumers := ix.consumerRepos(e.From)
	if len(consumers) == 0 {
		consumers = []string{""}
	}
	best := gateClosed
	for _, h := range hosts {
		level := ix.nodes[h].Attrs[AttrActionsAccess]
		for _, c := range consumers {
			ok, ev := actionsAccessAllows(level, h, c)
			switch {
			case ok && Verified(ev):
				return gateOpen
			case ok:
				best = gateHidden
			}
		}
	}
	return best
}

// actionHosts returns the repos an action resolves to (its RESOLVES_TO
// targets). Without such an edge it falls back to the repo named by the action
// ID, so dropping a RESOLVES_TO edge never lifts the gate. A repo that is not
// a node carries no actions_access and so allows every consumer.
func (ix *Index) actionHosts(action string) []string {
	var out []string
	for _, e := range ix.out[action] {
		if e.Kind == ResolvesTo {
			out = append(out, e.To)
		}
	}
	if len(out) == 0 {
		if r := repoFromID(action); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// consumerRepos returns the repos a USES consumer runs in: a workflow's
// DEFINED_IN targets, or an action's hosts. Without an edge it falls back to
// the repo named by the ID.
func (ix *Index) consumerRepos(id string) []string {
	if ix.Kind(id) == KindActionRef {
		return ix.actionHosts(id)
	}
	var out []string
	for _, e := range ix.out[id] {
		if e.Kind == DefinedIn {
			out = append(out, e.To)
		}
	}
	if len(out) == 0 {
		if r := repoFromID(id); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// repoFromID reads "repo:O/R" out of "action:O/R[/path]@ref" or
// "workflow:O/R/path". It returns "" for other IDs.
func repoFromID(id string) string {
	prefix, rest, ok := strings.Cut(id, ":")
	if !ok || (prefix != "action" && prefix != "workflow") {
		return ""
	}
	if prefix == "action" {
		if i := strings.LastIndex(rest, "@"); i >= 0 {
			rest = rest[:i]
		}
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "repo:" + parts[0] + "/" + parts[1]
}
