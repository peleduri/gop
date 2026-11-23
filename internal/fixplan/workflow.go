package fixplan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// CAN_TRIGGER edge attributes (written by the collector, see docs/schema.md).
const (
	attrTrigger = "trigger"
	attrExec    = "exec"
	attrJob     = "job"
	attrDetail  = "detail"
	execInject  = "injection"
	settingsAPI = "/actions/permissions/workflow" // in the source_api of a token edge decided by the default
)

// workflowLoc returns the repo ("O/R") and repo-relative file of a workflow
// node: its repo and path attrs, else the parts of its ID.
func workflowLoc(ix *graph.Index, id string) (repo, file string) {
	if n, ok := ix.Node(id); ok && n.Attrs["repo"] != "" && n.Attrs["path"] != "" {
		return n.Attrs["repo"], n.Attrs["path"]
	}
	parts := strings.SplitN(strings.TrimPrefix(id, "workflow:"), "/", 3)
	if len(parts) >= 2 {
		repo = parts[0] + "/" + parts[1]
	}
	if len(parts) == 3 {
		file = parts[2]
	}
	return repo, file
}

func ownerOf(repo string) string { return strings.SplitN(repo, "/", 2)[0] }

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// buildRestrict plans permissions: contents: read for a workflow's token. The
// level follows how the token got write: when jobs take the repo or org
// default (the edge's source is the settings API), a top-level permissions
// block covers exactly those jobs; when the file grants write, the listed
// jobs (or the top-level block they inherit) change.
func buildRestrict(ix *graph.Index, f graph.RestrictToken, p *Plan) {
	wf := strings.TrimPrefix(f.Workflow, "workflow:")
	repo, file := workflowLoc(ix, f.Workflow)
	edges := graph.FixEdges(ix, f)
	if len(edges) == 0 {
		p.Caveats = append(p.Caveats, "this graph records no write GITHUB_TOKEN for "+wf+": there is nothing to change")
		return
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if a, b := graph.Verified(edges[i].Evidence), graph.Verified(edges[j].Evidence); a != b {
			return a
		}
		if edges[i].SourceAPI != edges[j].SourceAPI {
			return edges[i].SourceAPI < edges[j].SourceAPI
		}
		return edges[i].Attrs[graph.AttrJobs] < edges[j].Attrs[graph.AttrJobs]
	})
	byDefault := false
	seen := map[string]bool{}
	for _, e := range edges {
		jobs := splitList(e.Attrs[graph.AttrJobs])
		fromDefault := strings.Contains(e.SourceAPI, settingsAPI)
		k := fmt.Sprint(fromDefault, jobs)
		if seen[k] {
			continue
		}
		seen[k] = true
		byDefault = byDefault || fromDefault
		s := Step{
			Kind: KindEditWorkflow, Repo: repo, File: file, FileRef: e.Attrs[graph.AttrFileRef],
			Line: atoi(e.Attrs[graph.AttrLine]), Col: atoi(e.Attrs[graph.AttrCol]),
			Owner: ownerOf(repo), Edge: edgeLabel(e), Evidence: e.Evidence,
		}
		jobList, verb := "every job", "declares"
		switch len(jobs) {
		case 0:
		case 1:
			jobList = "job " + jobs[0]
		default:
			jobList, verb = "jobs "+strings.Join(jobs, ", "), "declare"
		}
		var notes []string
		switch {
		case fromDefault:
			s.Change = "add a top-level `permissions:` block with `contents: read` (plus any other scope the jobs need, such as `pull-requests: write`)"
			notes = append(notes, jobList+" "+verb+" no permissions and take the repository's default workflow permissions, which allow write; a top-level block applies to exactly the jobs that declare none")
		case len(jobs) > 0:
			s.Change = "set `contents: read` in the `permissions:` of " + jobList + "; if `contents: write` (or `write-all`) is set in the top-level block they inherit, change it there"
			notes = append(notes, "the file grants contents: write to "+jobList+"; job-level permissions replace the top-level block, so change only the jobs that do not need to push")
		default:
			s.Change = "set `contents: read` in the workflow's `permissions:` block and in any job-level block that grants `contents: write` or `write-all`"
		}
		if s.Line == 0 {
			notes = append(notes, "this graph records no line for the permissions: key")
		}
		if !graph.Verified(e.Evidence) {
			s.Unconfirmed = true
			notes = append(notes, ConfirmFirst)
		}
		s.Note = strings.Join(notes, "; ")
		p.Steps = append(p.Steps, s)
	}
	p.Caveats = append(p.Caveats,
		"jobs that push with the GITHUB_TOKEN (tags, release commits, bot updates) stop working: move them to a workflow only trusted events start, or give them a GitHub App token scoped to that repo",
		"whoever controls "+wf+" still runs code in "+repo+"'s CI with its secrets, OIDC and runners; this fix removes only the push with the token")
	if byDefault {
		p.Caveats = append(p.Caveats, "alternative for every workflow in the repo at once: set Settings > Actions > General > Workflow permissions to \"Read repository contents\" on "+repo+" (or the org); workflows that need write must then declare it")
	}
}

// trigStep groups the CAN_TRIGGER edges of one untrusted execution: same job,
// exec, detail and line, any principal or trigger.
type trigStep struct {
	job, exec, detail, file, fileRef string
	line                             int
	edges                            []graph.Edge
}

// buildHarden plans one edit per untrusted execution (job, exec, detail,
// line) behind a workflow's CAN_TRIGGER edges.
func buildHarden(ix *graph.Index, f graph.HardenTrigger, p *Plan) {
	wf := strings.TrimPrefix(f.Workflow, "workflow:")
	repo, file := workflowLoc(ix, f.Workflow)
	edges := graph.FixEdges(ix, f)
	if len(edges) == 0 {
		p.Caveats = append(p.Caveats, "this graph records no CAN_TRIGGER edge into "+wf+": there is nothing to change")
		return
	}
	groups := map[string]*trigStep{}
	var order []string
	for _, e := range edges {
		g := trigStep{
			job: e.Attrs[attrJob], exec: e.Attrs[attrExec], detail: e.Attrs[attrDetail],
			file: file, fileRef: e.Attrs[graph.AttrFileRef], line: atoi(e.Attrs[graph.AttrLine]),
		}
		if v := e.Attrs[graph.AttrFile]; v != "" {
			g.file = v
		}
		k := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", g.job, g.exec, g.detail, g.file, g.line)
		if groups[k] == nil {
			groups[k] = &g
			order = append(order, k)
		}
		groups[k].edges = append(groups[k].edges, e)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := groups[order[i]], groups[order[j]]
		if a.file != b.file {
			return a.file < b.file
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return order[i] < order[j]
	})
	noLine := 0
	for _, k := range order {
		g := groups[k]
		sort.SliceStable(g.edges, func(i, j int) bool {
			if a, b := graph.Verified(g.edges[i].Evidence), graph.Verified(g.edges[j].Evidence); a != b {
				return a
			}
			return g.edges[i].From < g.edges[j].From
		})
		first := g.edges[0]
		s := Step{
			Kind: KindEditWorkflow, Repo: repo, File: g.file, FileRef: g.fileRef, Line: g.line,
			Owner: ownerOf(repo), Edge: edgeLabel(first), Evidence: first.Evidence,
			Change: hardenChange(g),
		}
		var who, triggers []string
		for _, e := range g.edges {
			w := e.From
			if !graph.Verified(e.Evidence) {
				w += " [not visible]"
			}
			who = append(who, w)
			if t := e.Attrs[attrTrigger]; t != "" {
				triggers = append(triggers, t)
			}
		}
		sort.Strings(who)
		sort.Strings(triggers)
		var notes []string
		if len(triggers) > 0 {
			notes = append(notes, "on "+strings.Join(dedup(triggers), ", "))
		}
		notes = append(notes, "can be triggered by "+strings.Join(dedup(who), ", "))
		if g.line == 0 {
			noLine++
			notes = append(notes, "line not recorded in this graph: look for the step in job "+orDefault(g.job, "(unknown)"))
		}
		if !graph.Verified(first.Evidence) {
			s.Unconfirmed = true
			notes = append(notes, ConfirmFirst)
		}
		s.Note = strings.Join(notes, "; ")
		p.Steps = append(p.Steps, s)
	}
	if len(p.Steps) > 1 {
		p.Caveats = append(p.Caveats, fmt.Sprintf("make all %d edits: gop removes the workflow's trigger edges as a whole, and one untrusted execution left in place keeps it attacker-controlled", len(p.Steps)))
	}
	if noLine > 0 {
		p.Caveats = append(p.Caveats, fmt.Sprintf("%d of %d steps have no line number in this graph (collected before line attributes)", noLine, len(p.Steps)))
	}
	p.Caveats = append(p.Caveats,
		"gop matches a narrow set of patterns: review the whole job, including scripts and local actions it runs, for other uses of the pull request's code or text",
		"if the job must build or test the pull request's code, do it in a separate pull_request workflow with a read-only token and no secrets, and pass results through an artifact")
}

// hardenChange is the suggested edit for one untrusted execution.
func hardenChange(g *trigStep) string {
	job := orDefault(g.job, "(unknown)")
	if g.exec == execInject {
		return fmt.Sprintf("in job %s, move `${{ %s }}` out of the script into `env:` (for example `env: UNTRUSTED: ${{ %s }}`) and read it as \"$UNTRUSTED\", so the text is data, not code", job, g.detail, g.detail)
	}
	switch {
	case strings.HasPrefix(g.detail, "ref:"), strings.HasPrefix(g.detail, "repository:"):
		return fmt.Sprintf("in job %s, remove `%s` from the actions/checkout step so it checks out the base commit, or drop the checkout", job, g.detail)
	case g.detail != "":
		return fmt.Sprintf("in job %s, remove the `%s` command that fetches the pull request's code", job, g.detail)
	}
	return "in job " + job + ", stop checking out or running the pull request's code"
}
