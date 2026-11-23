package collect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// A workflow whose GITHUB_TOKEN has contents: write can push to its own repo,
// so whoever controls the workflow controls the repo: workflow -CAN_PUSH-> repo
// with via=token_write. The permission comes from the file, or, when a job
// declares no permissions, from the repo's default workflow permissions.

const (
	srcRepoWorkflowPerms = "rest:GET /repos/{owner}/{repo}/actions/permissions/workflow"
	srcOrgWorkflowPerms  = "rest:GET /orgs/{org}/actions/permissions/workflow"
)

// Workflow attribute keys.
const (
	attrTokenWrite  = "token_write"  // true | false | unknown (not_visible)
	attrTokenScopes = "token_scopes" // other write scopes, comma list (display only)
	attrJobs        = "jobs"         // job ids on a via=token_write edge
	factWorkflowDef = "default_workflow_permissions"
)

// tokenDefault is a workflow whose token permission depends on the default.
type tokenDefault struct {
	wid  string
	node *graph.Node
	jobs []string
}

// orgWorkflowDefault caches GET /orgs/{org}/actions/permissions/workflow.
type orgWorkflowDefault struct {
	perm string // read | write | "" when refused
	err  error
}

// addTokenFacts records the workflow's token attrs and edge when the file
// decides them, and returns pending with the workflow appended when the
// repo or org default does.
func (k *collector) addTokenFacts(wid string, wn, repo *graph.Node, f *WorkflowFacts, pending []tokenDefault) []tokenDefault {
	if len(f.TokenScopes) > 0 {
		setAttr(wn, attrTokenScopes, strings.Join(f.TokenScopes, ","), graph.Live)
	}
	switch f.TokenContentsWrite {
	case TokenWrite:
		setAttr(wn, attrTokenWrite, "true", graph.Live)
		k.tokenEdge(wid, repo.ID, graph.Live, srcWorkflow, f.TokenWriteJobs)
	case TokenDefault:
		return append(pending, tokenDefault{wid: wid, node: wn, jobs: f.TokenDefaultJobs})
	default:
		setAttr(wn, attrTokenWrite, "false", graph.Live)
	}
	return pending
}

func (k *collector) tokenEdge(wid, repoID string, ev graph.Evidence, src string, jobs []string) {
	k.edge(wid, repoID, graph.CanPush, ev, src, map[string]string{
		graph.AttrVia:  graph.ViaTokenWrite,
		attrPermission: "contents: write",
		attrJobs:       strings.Join(jobs, ","),
	})
}

// resolveTokenDefaults reads the default workflow permissions once for a repo
// with pending workflows and settles each of them.
func (k *collector) resolveTokenDefaults(ctx context.Context, o *orgState, repo *graph.Node, pending []tokenDefault) error {
	if len(pending) == 0 {
		return nil
	}
	perm, src, reason, err := k.collectWorkflowDefaults(ctx, o, repo)
	if err != nil {
		return err
	}
	for _, p := range pending {
		switch perm {
		case "write":
			setAttr(p.node, attrTokenWrite, "true", graph.Live)
			k.tokenEdge(p.wid, repo.ID, graph.Live, src, p.jobs)
		case "read":
			setAttr(p.node, attrTokenWrite, "false", graph.Live)
		default:
			setAttr(p.node, attrTokenWrite, "unknown", graph.NotVisible)
			k.tokenEdge(p.wid, repo.ID, graph.NotVisible, srcRepoWorkflowPerms, p.jobs)
		}
	}
	if perm == "" {
		k.cover(repo.ID, factWorkflowDef, reason, "admin on "+strings.TrimPrefix(repo.ID, "repo:")+" (or org owner)")
	}
	return nil
}

// collectWorkflowDefaults returns the repo's default GITHUB_TOKEN permission
// (read or write) and its source, or "" with a reason when it is not visible.
// The repo setting is read first. When that is refused the org setting is
// read once per org: the repo can only be more restrictive than its org, so
// an org value of read proves read, while write leaves the repo unknown.
func (k *collector) collectWorkflowDefaults(ctx context.Context, o *orgState, repo *graph.Node) (perm, src, reason string, err error) {
	full := strings.TrimPrefix(repo.ID, "repo:")
	owner, name, _ := strings.Cut(full, "/")
	var body struct {
		Default string `json:"default_workflow_permissions"`
	}
	rerr := k.c.GetJSON(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/actions/permissions/workflow", &body)
	if rerr == nil && (body.Default == "read" || body.Default == "write") {
		return body.Default, srcRepoWorkflowPerms, "", nil
	}
	if ctx.Err() != nil {
		return "", "", "", ctx.Err()
	}
	if rerr == nil {
		rerr = fmt.Errorf("unexpected default_workflow_permissions %q", body.Default)
	}
	if o.workflowDefault == nil {
		od := &orgWorkflowDefault{}
		var ob struct {
			Default string `json:"default_workflow_permissions"`
		}
		od.err = k.c.GetJSON(ctx, "/orgs/"+url.PathEscape(o.login)+"/actions/permissions/workflow", &ob)
		if ctx.Err() != nil {
			return "", "", "", ctx.Err()
		}
		if od.err == nil {
			switch ob.Default {
			case "read", "write":
				od.perm = ob.Default
			default:
				od.err = fmt.Errorf("unexpected default_workflow_permissions %q", ob.Default)
			}
		}
		o.workflowDefault = od
	}
	od := o.workflowDefault
	switch {
	case od.perm == "read":
		return "read", srcOrgWorkflowPerms, "", nil
	case od.perm == "write":
		reason = "could not read the repo's default workflow permissions (" + rerr.Error() + "); the org default is write, which the repo may restrict"
	default:
		reason = "could not read the default workflow permissions: repo: " + rerr.Error() + "; org: " + od.err.Error()
	}
	return "", "", reason, nil
}
