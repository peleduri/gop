package collect

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Batched direct collaborators: one GraphQL query per DefaultBatchSize
// repositories of an org replaces one REST collaborators GET per repository.
// The answer becomes the same []apiCollaborator the REST read decodes, so
// both paths record the same edges. A repository falls back to REST when its
// alias fails (no push access, not found), when it has more collaborators
// than one page holds, or when a collaborator's access may come from a role
// GraphQL does not name the way REST does (a custom or organization role).

// collabPage is the most collaborators one alias reads (the first: argument
// of collabFragment); a repository with more is read over REST, which pages
// through them all.
const collabPage = 100

// collabFragment asks for each direct collaborator's login, effective
// permission and the role names of its permission sources.
const collabFragment = `fragment gopCollaborators on Repository {
  collaborators(affiliation: DIRECT, first: 100) {
    pageInfo { hasNextPage }
    edges { permission permissionSources { roleName } node { login } }
  }
}
`

type gqlCollabRepo struct {
	Collaborators *struct {
		PageInfo struct {
			HasNextPage bool `json:"hasNextPage"`
		} `json:"pageInfo"`
		Edges []*struct {
			Permission        string `json:"permission"`
			PermissionSources *[]struct {
				RoleName *string `json:"roleName"`
			} `json:"permissionSources"`
			Node *struct {
				Login string `json:"login"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"collaborators"`
}

// buildCollabQuery returns one query with an alias per repository. Owner
// and name travel as variables only.
func buildCollabQuery(o *orgState, repos []*graph.Node) (string, map[string]any) {
	vars := map[string]any{}
	var decl, body strings.Builder
	for i, r := range repos {
		is := strconv.Itoa(i)
		decl.WriteString("$o" + is + ": String!, $n" + is + ": String!, ")
		vars["o"+is], vars["n"+is] = o.login, repoName(o, r)
		body.WriteString("  r" + is + ": repository(owner: $o" + is + ", name: $n" + is + ") { ...gopCollaborators }\n")
	}
	q := "query(" + strings.TrimSuffix(decl.String(), ", ") + ") {\n" + body.String() +
		"  rateLimit { cost remaining resetAt }\n}\n" + collabFragment
	return q, vars
}

// prefetchCollaborators reads the direct collaborators of o's non-archived
// repositories in batched queries. A repository missing from the result is
// read over REST. The only error returned is the context's.
func (k *collector) prefetchCollaborators(ctx context.Context, o *orgState) (map[string][]apiCollaborator, error) {
	out := map[string][]apiCollaborator{}
	if k.batch.off || k.collabOff {
		return out, nil
	}
	var repos []*graph.Node
	for _, r := range o.repos {
		if r.Attrs[graph.AttrArchived] != "true" {
			repos = append(repos, r)
		}
	}
	c := k.cl(o.login)
	for start := 0; start < len(repos); {
		end := min(start+k.batch.size, len(repos))
		if err := k.fetchCollaborators(ctx, c, o, repos[start:end], out); err != nil {
			return nil, err
		}
		start = end
	}
	return out, nil
}

// fetchCollaborators runs one batched query and stores each repository it
// fully answered in out. A query GitHub finds too expensive is split in two,
// down to one repository.
func (k *collector) fetchCollaborators(ctx context.Context, c *Client, o *orgState, repos []*graph.Node, out map[string][]apiCollaborator) error {
	if k.batch.off || k.collabOff || len(repos) == 0 {
		return nil
	}
	q, vars := buildCollabQuery(o, repos)
	var data map[string]json.RawMessage
	k.batch.queries++
	gqlErrs, err := c.GraphQL(ctx, q, vars, &data)
	split := func() error {
		if len(repos) <= 1 {
			return nil
		}
		h := (len(repos) + 1) / 2
		if err := k.fetchCollaborators(ctx, c, o, repos[:h], out); err != nil {
			return err
		}
		return k.fetchCollaborators(ctx, c, o, repos[h:], out)
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s := StatusOf(err); s == 0 || s >= http.StatusInternalServerError {
			return split()
		}
		k.disableCollabBatch(err.Error())
		return nil
	}
	if isLimitError(gqlErrs) {
		return split()
	}
	if data == nil {
		k.disableCollabBatch(gqlErrs.Error())
		return nil
	}
	failed := map[int]bool{}
	for _, e := range gqlErrs {
		i := aliasIndex(e.Path)
		if i < 0 {
			return nil // not tied to one repository: REST for the whole batch
		}
		failed[i] = true
	}
	for i, r := range repos {
		raw, present := data["r"+strconv.Itoa(i)]
		if failed[i] || !present || string(raw) == "null" {
			continue
		}
		var gr gqlCollabRepo
		if json.Unmarshal(raw, &gr) != nil {
			continue
		}
		if collabs, ok := gqlCollaborators(&gr); ok {
			out[r.ID] = collabs
		}
	}
	if raw, ok := data["rateLimit"]; ok {
		var rl struct {
			Remaining *int      `json:"remaining"`
			ResetAt   time.Time `json:"resetAt"`
		}
		if json.Unmarshal(raw, &rl) == nil && rl.Remaining != nil {
			c.noteGraphQLRate(*rl.Remaining, rl.ResetAt)
		}
	}
	return nil
}

func (k *collector) disableCollabBatch(why string) {
	if !k.collabOff {
		k.collabOff = true
		k.logf("collect: batched GraphQL collaborator reads disabled, using REST: %s", why)
	}
}

// gqlCollaborators turns one repository's batched answer into what the
// REST read decodes, or reports false (REST fallback) when the answer is
// incomplete or could name a role differently from REST.
//
// REST gives role_name and permissions; GraphQL gives the effective
// permission (ADMIN, MAINTAIN, WRITE, ...) and the role name of each
// permission source. When every source names a built-in role (or none),
// REST's role_name is the effective permission in lower case. A custom or
// organization role REST would name instead, or a pusher whose sources are
// not returned, sends the repository to REST.
func gqlCollaborators(gr *gqlCollabRepo) ([]apiCollaborator, bool) {
	cs := gr.Collaborators
	if cs == nil || cs.PageInfo.HasNextPage || len(cs.Edges) > collabPage {
		return nil, false
	}
	out := make([]apiCollaborator, 0, len(cs.Edges))
	for _, e := range cs.Edges {
		if e == nil || e.Node == nil || e.Node.Login == "" {
			return nil, false
		}
		var p apiPermissions
		role := strings.ToLower(e.Permission)
		switch role {
		case "admin":
			p = apiPermissions{Push: true, Maintain: true, Admin: true}
		case "maintain":
			p = apiPermissions{Push: true, Maintain: true}
		case "write":
			p = apiPermissions{Push: true}
		case "read", "triage", "moderate", "triage_plus":
			// No push: REST records no edge whatever the role is called.
			out = append(out, apiCollaborator{Login: e.Node.Login, RoleName: role})
			continue
		default:
			return nil, false // a permission gop does not know
		}
		if e.PermissionSources == nil {
			return nil, false
		}
		for _, src := range *e.PermissionSources {
			if src.RoleName != nil && *src.RoleName != "" && !builtinRoles[strings.ToLower(*src.RoleName)] {
				return nil, false
			}
		}
		out = append(out, apiCollaborator{Login: e.Node.Login, RoleName: role, Permissions: p})
	}
	return out, true
}
