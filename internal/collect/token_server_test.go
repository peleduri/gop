package collect

import (
	"encoding/json"
	"net/http"
	"strings"
)

// workflowPerms serves GET /orgs/{org}/actions/permissions/workflow and
// GET /repos/{o}/{r}/actions/permissions/workflow. The repo value is the
// repo's actions_workflow_permissions, else its org's. Orgs the token does not
// own, repos with actions_workflow_permissions_forbidden and
// forbidWorkflowPerms answer 403.
func (f *fakeGitHub) workflowPerms(w http.ResponseWriter, p string) {
	forbidden := func() { writeJSON(w, 403, map[string]string{"message": "Must have admin rights to Repository."}) }
	if f.forbidWorkflowPerms {
		forbidden()
		return
	}
	rest := strings.TrimSuffix(p, "/actions/permissions/workflow")
	owner, repo := strings.TrimPrefix(rest, "/orgs/"), ""
	if r, ok := strings.CutPrefix(rest, "/repos/"); ok {
		owner, repo, _ = strings.Cut(r, "/")
	}
	for _, o := range f.fx.Orgs {
		if o.Login != owner {
			continue
		}
		if !o.Owner {
			forbidden()
			return
		}
		perm := o.WorkflowPerms
		if repo != "" {
			found := false
			for _, raw := range o.Repos {
				var m struct {
					Name      string `json:"name"`
					Perms     string `json:"actions_workflow_permissions"`
					Forbidden bool   `json:"actions_workflow_permissions_forbidden"`
				}
				_ = json.Unmarshal(raw, &m)
				if m.Name != repo {
					continue
				}
				if m.Forbidden {
					forbidden()
					return
				}
				found = true
				if m.Perms != "" {
					perm = m.Perms
				}
			}
			if !found {
				break
			}
		}
		if perm == "" {
			break
		}
		writeJSON(w, 200, map[string]any{"default_workflow_permissions": perm, "can_approve_pull_request_reviews": false})
		return
	}
	writeJSON(w, 404, map[string]string{"message": "Not Found"})
}
