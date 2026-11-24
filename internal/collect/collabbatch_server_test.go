package collect

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

var collabAliasRe = regexp.MustCompile(`(r\d+): repository\(owner: \$(o\d+), name: \$(n\d+)\) \{ \.\.\.gopCollaborators \}`)

// collabQuery answers a batched repository { ...gopCollaborators } query
// from the same fixture data the REST collaborators endpoint serves. A repo
// REST answers 403 gets collaborators:null and a FORBIDDEN error on
// [alias, collaborators]; 404 gets alias:null and NOT_FOUND; objectErrors
// fail the whole alias. Each collaborator's permission is its built-in
// role_name in upper case, or for a custom role the highest built-in role
// its permissions imply; its one permission source names role_name.
func (f *fakeGitHub) collabQuery(w http.ResponseWriter, q string, vars map[string]any) {
	f.mu.Lock()
	limit := f.limitAbove
	f.collabQueries++
	pageMax := f.collabPageMax
	noSources := f.noPermSources
	f.mu.Unlock()
	if pageMax == 0 {
		pageMax = 100
	}
	ms := collabAliasRe.FindAllStringSubmatch(q, -1)
	if limit != 0 && len(ms) > limit {
		writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"type": "RESOURCE_LIMITS_EXCEEDED", "message": "query too expensive"}}})
		return
	}
	if f.collabUnsupported {
		writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"message": "Field 'permissionSources' doesn't exist on type 'RepositoryCollaboratorEdge'"}}})
		return
	}
	data := map[string]any{"rateLimit": map[string]any{"cost": 1, "remaining": 4900, "resetAt": "2030-01-01T14:05:00Z"}}
	var errs []map[string]any
	for _, m := range ms {
		alias := m[1]
		owner, _ := vars[m[2]].(string)
		repo, _ := vars[m[3]].(string)
		full := owner + "/" + repo
		f.mu.Lock()
		typ := f.objectErrors[full]
		f.mu.Unlock()
		if typ != "" {
			data[alias] = nil
			errs = append(errs, map[string]any{"type": typ, "path": []string{alias}, "message": "refused"})
			continue
		}
		collabs, status := f.collabLookup(full)
		switch status {
		case http.StatusOK:
		case http.StatusForbidden:
			data[alias] = map[string]any{"collaborators": nil}
			errs = append(errs, map[string]any{"type": "FORBIDDEN", "path": []string{alias, "collaborators"},
				"message": "Must have push access to view repository collaborators."})
			continue
		default:
			data[alias] = nil
			errs = append(errs, map[string]any{"type": "NOT_FOUND", "path": []string{alias},
				"message": "Could not resolve to a Repository with the name '" + full + "'."})
			continue
		}
		edges := []map[string]any{}
		for _, raw := range collabs {
			if len(edges) == pageMax {
				break
			}
			var c apiCollaborator
			_ = json.Unmarshal(raw, &c)
			perm := strings.ToUpper(c.RoleName)
			if !builtinRoles[c.RoleName] {
				switch p := c.Permissions; {
				case p.Admin:
					perm = "ADMIN"
				case p.Maintain:
					perm = "MAINTAIN"
				case p.Push:
					perm = "WRITE"
				default:
					perm = "READ"
				}
			}
			e := map[string]any{"permission": perm, "node": map[string]any{"login": c.Login},
				"permissionSources": []map[string]any{{"roleName": c.RoleName}}}
			if noSources {
				e["permissionSources"] = nil
			}
			edges = append(edges, e)
		}
		data[alias] = map[string]any{"collaborators": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": len(collabs) > len(edges)},
			"edges":    edges,
		}}
	}
	resp := map[string]any{"data": data}
	if errs != nil {
		resp["errors"] = errs
	}
	writeJSON(w, 200, resp)
}
