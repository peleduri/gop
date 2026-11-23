package collect

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// knownAccessLevels are the access_level values GitHub returns. Anything else
// is recorded as unknown, so the graph never carries a level gop can't read.
var knownAccessLevels = map[string]bool{
	graph.AccessNone: true, graph.AccessUser: true, graph.AccessOrganization: true, graph.AccessEnterprise: true,
}

// collectActionsAccess reads (GET /repos/{owner}/{repo}/actions/permissions/access)
// the Actions "Access" setting of every repo that
// hosts a referenced enterprise action (the target of a RESOLVES_TO edge): who
// outside the repo may use its actions and reusable workflows. It runs after
// expandNested, one request per private or internal host repo. Public repos get
// actions_access=public without a request. A refused or failed read sets
// actions_access=unknown (not_visible) with a coverage entry: the engine then
// keeps cross-org paths through the repo's actions as possible, never drops
// them. It also records consumer_org on every USES edge into such an action.
func (k *collector) collectActionsAccess(ctx context.Context) error {
	hosts := map[string]bool{}
	for _, e := range k.edges {
		if e.Kind == graph.ResolvesTo {
			hosts[e.To] = true
		}
	}
	ids := make([]string, 0, len(hosts))
	for id := range hosts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ghesReason, ghesFix, ghesSkip := k.ghesGate(capActionsAccess)
	for _, id := range ids {
		n, ok := k.nodes[id]
		if !ok {
			continue
		}
		if n.Attrs[graph.AttrVisibility] == "public" {
			setAttr(n, graph.AttrActionsAccess, graph.AccessPublic, graph.Live)
			continue
		}
		if ghesSkip {
			setAttr(n, graph.AttrActionsAccess, graph.AccessUnknown, graph.NotVisible)
			k.cover(id, graph.AttrActionsAccess, ghesReason, ghesFix)
			continue
		}
		full := strings.TrimPrefix(id, "repo:")
		owner, repo, _ := strings.Cut(full, "/")
		var resp struct {
			AccessLevel string `json:"access_level"`
		}
		path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/actions/permissions/access"
		err := k.cl(owner).GetJSON(ctx, path, &resp)
		reason := ""
		switch {
		case err != nil && ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			reason = "could not read the Actions access setting of " + full + ": " + err.Error()
		case !knownAccessLevels[resp.AccessLevel]:
			reason = "the Actions access setting of " + full + " has an unrecognized access_level " + strconv.Quote(resp.AccessLevel)
		}
		if reason != "" {
			setAttr(n, graph.AttrActionsAccess, graph.AccessUnknown, graph.NotVisible)
			k.cover(id, graph.AttrActionsAccess, reason, k.fixFor(err, "admin on "+full+" (or org owner)"))
			continue
		}
		setAttr(n, graph.AttrActionsAccess, resp.AccessLevel, graph.Live)
	}
	k.consumerOrgs()
	return nil
}

// consumerOrgs sets consumer_org on each USES edge whose target action resolves
// to an enterprise repo: the org of the using workflow's repo, or of the using
// action's host repo.
func (k *collector) consumerOrgs() {
	repoOf := map[string]string{} // workflow or action ID -> repo ID
	for _, e := range k.edges {
		if e.Kind == graph.ResolvesTo || e.Kind == graph.DefinedIn {
			repoOf[e.From] = e.To
		}
	}
	for _, e := range k.edges {
		if e.Kind != graph.Uses {
			continue
		}
		if host := repoOf[e.To]; host == "" || k.nodes[host] == nil {
			continue
		}
		rn := k.nodes[repoOf[e.From]]
		if rn == nil || rn.Attrs["org"] == "" {
			continue
		}
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs[graph.AttrConsumerOrg] = rn.Attrs["org"]
	}
}
