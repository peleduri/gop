package collect

import (
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// oidcEdge is a workflow's OIDC edge whose attrs gain job_workflow_ref once
// the reusable workflows it calls have been read.
type oidcEdge struct {
	attrs map[string]string
	envs  map[string]bool
	calls []string // action ids called by id-token jobs (jobs.<id>.uses)
}

// calledOIDC is what a reusable workflow read during nested expansion says
// about the tokens minted inside it.
type calledOIDC struct {
	ref   string   // job_workflow_ref claim value of this workflow
	runs  bool     // an id-token job of this workflow runs steps itself
	envs  []string // environments of its id-token jobs
	calls []string // reusable workflows its id-token jobs call
}

// oidcCalls splits a workflow's id-token jobs into calls of reusable
// workflows (their action ids) and jobs that run steps themselves.
func oidcCalls(f *WorkflowFacts) (calls []string, runs bool) {
	callOf := map[string]string{}
	for _, u := range f.Uses {
		if u.Level == LevelJob {
			callOf[u.Job] = "action:" + u.Raw
		}
	}
	for _, j := range f.IDTokenJobs {
		if aid, ok := callOf[j.Job]; ok {
			calls = append(calls, aid)
		} else {
			runs = true
		}
	}
	return calls, runs
}

// oidcAttrs returns the claim input attrs of a workflow's OIDC edge.
func oidcAttrs(full string, f *WorkflowFacts) map[string]string {
	attrs := map[string]string{
		"permission":              "id-token: write",
		"scopes":                  strings.Join(f.IDTokenScopes, ","),
		graph.AttrJobs:            strings.Join(f.IDTokenJobIDs(), ","),
		graph.AttrRepository:      full,
		graph.AttrRepositoryOwner: strings.SplitN(full, "/", 2)[0],
	}
	if envs := f.IDTokenEnvironments(); len(envs) > 0 {
		attrs[graph.AttrEnvironments] = strings.Join(envs, ",")
	}
	return attrs
}

// trackOIDCEdge remembers an OIDC edge so linkJobWorkflowRefs can complete it.
func (k *collector) trackOIDCEdge(f *WorkflowFacts, attrs map[string]string) {
	calls, _ := oidcCalls(f)
	if len(calls) == 0 {
		return
	}
	envs := map[string]bool{}
	for _, e := range f.IDTokenEnvironments() {
		envs[e] = true
	}
	k.oidcEdges = append(k.oidcEdges, &oidcEdge{attrs: attrs, envs: envs, calls: calls})
}

// noteCalledOIDC records a reusable workflow (action id aid, called as u)
// whose jobs can mint a token.
func (k *collector) noteCalledOIDC(aid string, u ActionUse, f *WorkflowFacts) {
	if !f.IDTokenWrite {
		return
	}
	calls, runs := oidcCalls(f)
	if k.calledOIDC == nil {
		k.calledOIDC = map[string]*calledOIDC{}
	}
	k.calledOIDC[aid] = &calledOIDC{
		ref:   u.Owner + "/" + u.Repo + "/" + u.Path + "@" + claimRef(u.Ref, u.RefKind),
		runs:  runs,
		envs:  f.IDTokenEnvironments(),
		calls: calls,
	}
}

// claimRef writes a uses: ref the way the job_workflow_ref claim does:
// refs/heads/<branch>, refs/tags/<tag>, or the sha. Branch versus tag
// follows RefKind's naming heuristic.
func claimRef(ref, kind string) string {
	switch {
	case strings.HasPrefix(ref, "refs/") || kind == "sha":
		return ref
	case kind == "tag":
		return "refs/tags/" + ref
	default:
		return "refs/heads/" + ref
	}
}

// linkJobWorkflowRefs sets job_workflow_ref (and adds the called workflows'
// environments) on every OIDC edge whose id-token jobs call an enterprise
// reusable workflow that mints the token. A called workflow can only use
// id-token: write when the calling job grants it, so only id-token jobs are
// followed. Reusable workflows outside the enterprise, or not readable, add
// nothing.
func (k *collector) linkJobWorkflowRefs() {
	for _, e := range k.oidcEdges {
		refs, envs, seen := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for env := range e.envs {
			envs[env] = true
		}
		for _, aid := range e.calls {
			k.calledRefs(aid, refs, envs, seen)
		}
		if len(refs) == 0 {
			continue
		}
		e.attrs[graph.AttrJobWorkflowRef] = strings.Join(sortedSet(refs), ",")
		if len(envs) > 0 {
			e.attrs[graph.AttrEnvironments] = strings.Join(sortedSet(envs), ",")
		}
	}
}

func (k *collector) calledRefs(aid string, refs, envs, seen map[string]bool) {
	if seen[aid] {
		return
	}
	seen[aid] = true
	c := k.calledOIDC[aid]
	if c == nil {
		return
	}
	if c.runs {
		refs[c.ref] = true
		for _, env := range c.envs {
			envs[env] = true
		}
	}
	for _, n := range c.calls {
		k.calledRefs(n, refs, envs, seen)
	}
}
