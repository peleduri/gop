package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Team attribute keys.
const (
	attrOrg          = "org"
	attrSlug         = "slug"
	attrPrivacy      = "privacy"
	attrTeamsPartial = "teams_partial"
)

type apiTeam struct {
	Slug    string `json:"slug"`
	Privacy string `json:"privacy"`
	Parent  *struct {
		Slug string `json:"slug"`
	} `json:"parent"`
}

type apiTeamRepo struct {
	Name        string         `json:"name"`
	FullName    string         `json:"full_name"`
	RoleName    string         `json:"role_name"`
	Permissions apiPermissions `json:"permissions"`
}

// teamState is one team of the org being collected.
type teamState struct {
	slug      string
	parent    string // parent slug, "" for a top-level team
	children  []string
	node      *graph.Node
	grants    bool              // the team holds push on at least one repo
	members   map[string]string // lower login -> login, every member including child teams'
	membersOK bool
}

// collectTeams lists the org's teams, their push grants and their members.
//
// Team nodes are "team:<org>/<slug>" identities. Nesting becomes child
// -MEMBER_OF-> parent, and a repo grant with push becomes team -CAN_PUSH-> repo
// (via=team). Members are fetched only for teams that hold a push grant or sit
// below one, so the cost is 1 + N (repos) + M (members) requests per org.
//
// GET /orgs/{org}/teams/{slug}/members also returns the members of child teams.
// To keep one fact per edge, gop records only direct members: a parent's member
// list minus the members of its direct children. A user who is both a direct
// member of the parent and a member of a child is then recorded on the child
// only, which reaches the same repositories (the child inherits the parent's
// grants). When a child's member list cannot be read, nothing is subtracted for
// it: its members are recorded on the parent, which still reaches only what
// they really reach.
func (k *collector) collectTeams(ctx context.Context, o *orgState) error {
	var listed []apiTeam
	err := k.cl(o.login).GetPages(ctx, "/orgs/"+url.PathEscape(o.login)+"/teams?per_page=100", func(page []byte) error {
		var batch []apiTeam
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding teams: %w", err)
		}
		listed = append(listed, batch...)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		setAttr(o.node, attrTeamsPartial, "true", graph.Live)
		k.cover(o.node.ID, "can_push:teams", "could not list teams: "+err.Error(), k.fixFor(err, k.ownerFix(o)))
		return nil
	}
	if !o.ownerVisible {
		setAttr(o.node, attrTeamsPartial, "true", graph.Live)
		k.cover(o.node.ID, "can_push:teams",
			"token is not an org owner: secret teams and their grants are not listed", k.ownerFix(o))
	}

	teams := map[string]*teamState{}
	var order []string
	for _, t := range listed {
		if t.Slug == "" || teams[t.Slug] != nil {
			continue
		}
		n := k.node(teamID(o, t.Slug), graph.KindIdentity, o.login+"/"+t.Slug)
		setAttr(n, attrOrg, o.login, graph.Live)
		setAttr(n, attrSlug, t.Slug, graph.Live)
		if t.Privacy != "" {
			setAttr(n, attrPrivacy, t.Privacy, graph.Live)
		}
		ts := &teamState{slug: t.Slug, node: n}
		if t.Parent != nil {
			ts.parent = t.Parent.Slug
		}
		teams[t.Slug] = ts
		order = append(order, t.Slug)
	}
	sort.Strings(order)
	for _, slug := range order {
		ts := teams[slug]
		if ts.parent == "" {
			continue
		}
		k.edge(ts.node.ID, teamID(o, ts.parent), graph.MemberOf, graph.Live, srcTeams, nil)
		if p := teams[ts.parent]; p != nil {
			p.children = append(p.children, slug)
		} else {
			// The parent was not listed; declare it so the edge has both endpoints.
			n := k.node(teamID(o, ts.parent), graph.KindIdentity, o.login+"/"+ts.parent)
			setAttr(n, attrOrg, o.login, graph.Live)
			setAttr(n, attrSlug, ts.parent, graph.Live)
		}
	}

	for _, slug := range order {
		if err := k.collectTeamRepos(ctx, o, teams[slug]); err != nil {
			return err
		}
	}

	// Members matter for teams that hold a grant and for every team below one.
	need := map[string]bool{}
	for _, slug := range order {
		seen := map[string]bool{}
		for s := slug; s != "" && !seen[s]; {
			seen[s] = true
			t := teams[s]
			if t == nil {
				break
			}
			if t.grants {
				need[slug] = true
				break
			}
			s = t.parent
		}
	}
	for _, slug := range order {
		if !need[slug] {
			continue
		}
		if err := k.collectTeamMembers(ctx, o, teams[slug]); err != nil {
			return err
		}
	}
	for _, slug := range order {
		ts := teams[slug]
		if !need[slug] || !ts.membersOK {
			continue
		}
		inChild := map[string]bool{}
		for _, c := range ts.children {
			if ct := teams[c]; ct != nil && ct.membersOK {
				for l := range ct.members {
					inChild[l] = true
				}
			}
		}
		for lower, login := range ts.members {
			if inChild[lower] {
				continue
			}
			k.edge(k.identity(login).ID, ts.node.ID, graph.MemberOf, graph.Live, srcTeamMembers, nil)
		}
	}
	k.logf("collect: org %s: %d teams (%d with push or below one)", o.login, len(order), len(need))
	return nil
}

func teamID(o *orgState, slug string) string { return "team:" + o.login + "/" + slug }

// collectTeamRepos adds a CAN_PUSH edge for each repository the team can push to.
// A failure is coverage only: the team's grants are then unknown.
func (k *collector) collectTeamRepos(ctx context.Context, o *orgState, ts *teamState) error {
	var repos []apiTeamRepo
	path := "/orgs/" + url.PathEscape(o.login) + "/teams/" + url.PathEscape(ts.slug) + "/repos?per_page=100"
	err := k.cl(o.login).GetPages(ctx, path, func(page []byte) error {
		var batch []apiTeamRepo
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding team repos: %w", err)
		}
		repos = append(repos, batch...)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		setAttr(ts.node, attrRepositories, "unknown", graph.NotVisible)
		k.cover(o.node.ID, "team_repos:"+ts.slug, "could not list repositories of team "+ts.slug+": "+err.Error(),
			k.fixFor(err, k.ownerFix(o)))
		return nil
	}
	for _, r := range repos {
		if !r.Permissions.canPush() {
			continue
		}
		full := r.FullName
		if full == "" {
			full = o.login + "/" + r.Name
		}
		id, ok := k.repoIDs[strings.ToLower(full)]
		if !ok {
			id = "repo:" + full
		}
		ts.grants = true
		k.edge(ts.node.ID, id, graph.CanPush, graph.Live, srcTeamRepos, map[string]string{
			graph.AttrVia: graph.ViaTeam, attrPermission: pushRole(r.RoleName, r.Permissions),
		})
	}
	return nil
}

// collectTeamMembers reads every member of a team (including child teams'
// members). On 403/404 the team keeps its grants, gets members=unknown and one
// coverage entry; no member edge is invented.
func (k *collector) collectTeamMembers(ctx context.Context, o *orgState, ts *teamState) error {
	ts.members = map[string]string{}
	path := "/orgs/" + url.PathEscape(o.login) + "/teams/" + url.PathEscape(ts.slug) + "/members?role=all&per_page=100"
	err := k.cl(o.login).GetPages(ctx, path, func(page []byte) error {
		var batch []struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding team members: %w", err)
		}
		for _, u := range batch {
			if u.Login != "" {
				ts.members[strings.ToLower(u.Login)] = u.Login
			}
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		setAttr(ts.node, graph.AttrMembers, "unknown", graph.NotVisible)
		k.cover(o.node.ID, "team_members:"+ts.slug, "could not list members of team "+ts.slug+": "+err.Error(),
			k.fixFor(err, k.ownerFix(o)+", or maintainer of team "+ts.slug))
		return nil
	}
	ts.membersOK = true
	setAttr(ts.node, graph.AttrMembers, strconv.Itoa(len(ts.members)), graph.Live)
	return nil
}
