package poutine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Unmatched is a finding that matches no workflow node.
type Unmatched struct {
	Finding Finding
	Reason  string
}

// AnnotateStats summarizes one Annotate call.
type AnnotateStats struct {
	Findings   int // findings read
	Matched    int // findings that matched a workflow node
	Workflows  int // workflow nodes annotated
	Injectable int // of those, workflows with an injection-class finding
	Unmatched  []Unmatched
}

// Annotate maps each finding of r to the workflow node of its repo and file
// ("workflow:<owner>/<repo>/<path>", owner and repo compared without case)
// and sets on it:
//
//   - poutine_rules: sorted comma list of the rule IDs;
//   - poutine_severity: the highest rule level (error, warning, note), when
//     the report gives levels;
//   - poutine_jobs: sorted comma list of the job ids the findings name;
//   - poutine_file: r.File.
//
// A finding that matches no workflow (a repo outside the graph, a composite
// action file, a non-GitHub repo, no file path) is returned in
// AnnotateStats.Unmatched and added as a coverage entry with fact
// poutine_finding: never dropped silently. Edges and evidence are not changed.
//
// Poutine attrs and poutine_finding coverage from earlier runs are cleared
// first, so the latest report replaces them. The graph is modified in place in
// a deterministic order.
func Annotate(g *graph.Graph, r *Result) AnnotateStats {
	st := AnnotateStats{Findings: len(r.Findings)}
	byKey := map[string]int{} // lower(owner/repo)/path -> node index
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != graph.KindWorkflow {
			continue
		}
		for _, k := range []string{graph.AttrPoutineRules, graph.AttrPoutineSeverity, graph.AttrPoutineJobs, graph.AttrPoutineFile} {
			delete(n.Attrs, k)
		}
		if k, ok := workflowKey(n.ID); ok {
			byKey[k] = i
		}
	}
	cov := g.Coverage[:0:0]
	for _, c := range g.Coverage {
		if c.Fact != graph.FactPoutine {
			cov = append(cov, c)
		}
	}
	g.Coverage = cov

	type agg struct {
		rules, jobs map[string]bool
		level       string
	}
	hits := map[int]*agg{}
	for _, f := range r.Findings {
		reason := f.Problem
		idx := -1
		if reason == "" {
			parts := strings.SplitN(f.Repo, "/", 2)
			k := strings.ToLower(parts[0]) + "/" + strings.ToLower(parts[1]) + "/" + f.Path
			if i, ok := byKey[k]; ok {
				idx = i
			} else {
				reason = "the graph has no such workflow (the repo is outside the collected orgs, or the file is not a workflow gop collected, such as a composite action)"
			}
		}
		if idx < 0 {
			st.Unmatched = append(st.Unmatched, Unmatched{Finding: f, Reason: reason})
			g.Coverage = append(g.Coverage, coverageFor(r.File, f, reason))
			continue
		}
		st.Matched++
		a := hits[idx]
		if a == nil {
			a = &agg{rules: map[string]bool{}, jobs: map[string]bool{}}
			hits[idx] = a
		}
		a.rules[f.RuleID] = true
		if f.Job != "" {
			a.jobs[f.Job] = true
		}
		if levelRank[f.Level] > levelRank[a.level] {
			a.level = f.Level
		}
	}

	idxs := make([]int, 0, len(hits))
	for i := range hits {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	for _, i := range idxs {
		n, a := &g.Nodes[i], hits[i]
		if n.Attrs == nil {
			n.Attrs = map[string]string{}
		}
		n.Attrs[graph.AttrPoutineRules] = joinSorted(a.rules)
		if a.level != "" {
			n.Attrs[graph.AttrPoutineSeverity] = a.level
		}
		if len(a.jobs) > 0 {
			n.Attrs[graph.AttrPoutineJobs] = joinSorted(a.jobs)
		}
		n.Attrs[graph.AttrPoutineFile] = r.File
		st.Workflows++
		if graph.PoutineInjectable(*n) {
			st.Injectable++
		}
	}
	return st
}

// workflowKey is lower(owner/repo)/path for "workflow:<owner>/<repo>/<path>".
func workflowKey(id string) (string, bool) {
	rest, ok := strings.CutPrefix(id, "workflow:")
	if !ok {
		return "", false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return strings.ToLower(parts[0]) + "/" + strings.ToLower(parts[1]) + "/" + parts[2], true
}

// coverageFor names the file in the scope, as a workflow node ID
// ("workflow:<owner>/<repo>/<path>"), never in the free-text reason: gop
// redact rewrites IDs reliably, while a path or job id inside a sentence can
// keep an original name. A finding without a GitHub repo or a path gets the
// scope "poutine:<report file>" and only its rule and line.
func coverageFor(file string, f Finding, reason string) graph.Coverage {
	scope := "poutine:" + file
	switch {
	case f.Repo != "" && f.Path != "":
		scope = "workflow:" + f.Repo + "/" + f.Path
	case f.Repo != "":
		scope = "repo:" + f.Repo
	}
	at := ""
	if f.Line > 0 {
		at = " at line " + strconv.Itoa(f.Line)
	}
	level := ""
	if f.Level != "" {
		level = " (" + f.Level + ")"
	}
	return graph.Coverage{
		Scope:  scope,
		Fact:   graph.FactPoutine,
		Reason: fmt.Sprintf("poutine finding %d in %s: rule %s%s%s matches no workflow node: %s", f.Index, file, f.RuleID, level, at, reason),
		NeedsFix: "collect the repo's org (gop collect --orgs) and re-run gop enrich --poutine, or run poutine on the repos in the graph; " +
			"gop only annotates workflows it collected",
	}
}

func joinSorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
