package collect

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// Agent memory poisoning across runs (docs/agents-in-ci.md "Agent memory
// across runs"). An AI agent job that people without push access can start
// saves an actions/cache entry, and a job that holds secrets or a write
// token restores it on a later run: text planted in the untrusted run (agent
// notes, instructions, tools) steers the trusted one.
//
// The rules gop applies come from GitHub's cache documentation
// (https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching):
//
//   - A run restores caches of its own branch or of the default branch, so a
//     cache written in the default branch's scope reaches every later run.
//   - pull_request runs (forks included) write to refs/pull/N/merge, which
//     no other branch reads: they are never the writer here.
//   - pull_request_target, issue_comment, workflow_run and the other events
//     outsiders cause that resolve to the default branch get read-only
//     access to its caches, unless the workflow or job sets cache-mode:
//     write or write-only
//     (https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/,
//     https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode).
//     The changelog does not cover GitHub Enterprise Server: there a save
//     with no cache-mode is possible, not confirmed.
//   - A restore matches the key exactly, then by prefix of the key, then by
//     prefix of each restore-keys entry, newest first; the cache version
//     (the path list and compression) must match too.

// cacheWriteTriggers are the risky triggers whose runs resolve to the
// default branch, so a cache they save lands in the scope every branch
// restores from. pull_request_review and pull_request_review_comment run on
// the pull request's merge ref, whose caches no other branch reads.
var cacheWriteTriggers = map[string]bool{
	"pull_request_target": true,
	"issue_comment":       true,
	"workflow_run":        true,
	"issues":              true,
	"discussion":          true,
	"discussion_comment":  true,
}

// CacheStep is one actions/cache, actions/cache/save or actions/cache/restore step.
type CacheStep struct {
	Job         string
	Save        bool     // the step saves (actions/cache post step, or cache/save)
	Restore     bool     // the step restores (actions/cache without lookup-only, or cache/restore)
	Key         string   // with.key as written
	RestoreKeys []string // with.restore-keys, one per line
	Paths       []string // with.path, one per line, in order (the cache version hashes them)
	Line        int      // 1-based line of the step's uses: key
}

// readCaches records the cache steps of every job and the cache-mode of the
// workflow and its jobs. Lenient like readAgents.
func (f *WorkflowFacts) readCaches(doc *yaml.Node) {
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(doc), "workflow")
	if err != nil {
		return
	}
	f.CacheMode = strings.TrimSpace(scalarOf(w, field(root, "cache-mode")))
	_, jobsNode := root.get("jobs")
	jobs, err := w.mapping(jobsNode, "jobs")
	if err != nil {
		return
	}
	ids := append([]string(nil), jobs.keys...)
	sort.Strings(ids)
	for _, id := range ids {
		_, jv := jobs.get(id)
		job, err := w.mapping(jv, "job")
		if err != nil {
			continue
		}
		if m := strings.TrimSpace(scalarOf(w, field(job, "cache-mode"))); m != "" {
			if f.JobCacheModes == nil {
				f.JobCacheModes = map[string]string{}
			}
			f.JobCacheModes[id] = m
		}
		steps, err := w.sequence(field(job, "steps"), "steps")
		if err != nil {
			continue
		}
		for _, sn := range steps {
			step, err := w.mapping(sn, "step")
			if err != nil {
				continue
			}
			u, ok := ParseUses(scalarOf(w, field(step, "uses")))
			if !ok || !strings.EqualFold(u.Owner+"/"+u.Repo, "actions/cache") {
				continue
			}
			with, _ := w.mapping(field(step, "with"), "with")
			c := CacheStep{Job: id, Key: strings.TrimSpace(scalarOf(w, field(with, "key"))),
				RestoreKeys: lines(scalarOf(w, field(with, "restore-keys"))), Paths: lines(scalarOf(w, field(with, "path")))}
			lookupOnly := strings.EqualFold(strings.TrimSpace(scalarOf(w, field(with, "lookup-only"))), "true")
			switch strings.ToLower(strings.Trim(u.Path, "/")) {
			case "":
				c.Save, c.Restore = true, !lookupOnly
			case "save":
				c.Save = true
			case "restore":
				c.Restore = !lookupOnly
			default:
				continue
			}
			if k, _ := step.get("uses"); k != nil {
				c.Line = k.Line
			}
			if c.Key == "" || len(c.Paths) == 0 {
				continue
			}
			f.Caches = append(f.Caches, c)
		}
	}
}

// lines splits a multi-line input into trimmed, non-empty lines.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// cacheModeOf is a job's effective cache-mode: the job's own, else the workflow's.
func (f *WorkflowFacts) cacheModeOf(job string) string {
	if m, ok := f.JobCacheModes[job]; ok {
		return m
	}
	return f.CacheMode
}

// MemoryDir returns the agent memory store a cached path names ("" when
// none): a known store (graph.AgentMemoryDirs), or "memory" for any
// segment named memory or memories.
func MemoryDir(p string) string {
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		seg = strings.TrimPrefix(seg, "!")
		for _, d := range graph.AgentMemoryDirs {
			if d != "memory" && strings.EqualFold(seg, d) {
				return d
			}
		}
		if l := strings.ToLower(seg); l == "memory" || l == "memories" || l == ".memory" {
			return "memory"
		}
	}
	return ""
}

// runUnique are expressions that differ on every run: a key built from them
// is never matched exactly by another run.
var runUnique = regexp.MustCompile(`github\.run_(id|number|attempt)\b`)

// staticPrefix is a key's text before its first expression, and whether
// the key has one.
func staticPrefix(k string) (string, bool) {
	if i := strings.Index(k, "${{"); i >= 0 {
		return k[:i], true
	}
	return k, false
}

// Cache match kinds, weakest last.
const (
	MatchExact      = "exact"      // the same static key
	MatchPrefix     = "prefix"     // a static restore key (or the key) is a prefix of the saved key's static text
	MatchExpression = "expression" // the keys match only if their expressions evaluate alike: inferred
)

// matchCache reports whether a restore step can restore what a save step
// saved, how, and with what evidence (live for static keys and paths,
// inferred when an expression decides it).
func matchCache(save, restore CacheStep) (how string, ev graph.Evidence, ok bool) {
	if strings.Join(save.Paths, "\n") != strings.Join(restore.Paths, "\n") {
		return "", "", false // a different cache version
	}
	pathExpr := strings.Contains(strings.Join(save.Paths, "\n"), "${{")
	ws, wExpr := staticPrefix(save.Key)
	unique := runUnique.MatchString(save.Key)
	result := func(h string, e graph.Evidence) (string, graph.Evidence, bool) {
		if pathExpr {
			e = graph.Inferred
			if h != MatchExpression {
				h = MatchExpression
			}
		}
		return h, e, true
	}
	if save.Key == restore.Key && !unique {
		if !wExpr {
			return result(MatchExact, graph.Live)
		}
		return result(MatchExpression, graph.Inferred)
	}
	best := ""
	for _, rk := range append([]string{restore.Key}, restore.RestoreKeys...) {
		rs, rExpr := staticPrefix(rk)
		switch {
		case !rExpr && rs != "" && strings.HasPrefix(ws, rs):
			return result(MatchPrefix, graph.Live)
		case !rExpr && wExpr && !unique && strings.HasPrefix(rs, ws):
			best = MatchExpression // the saved key's expression may produce the rest
		case rExpr && rs != "" && rk != restore.Key && (strings.HasPrefix(ws, rs) || (wExpr && !unique && strings.HasPrefix(rs, ws))):
			best = MatchExpression
		}
	}
	if best != "" {
		return result(best, graph.Inferred)
	}
	return "", "", false
}

// memoryWF is one workflow's facts for the join.
type memoryWF struct {
	ID string
	F  *WorkflowFacts
}

// memoryPoison is one cache entry an exposed agent job saves and a job
// with secrets or a write token restores.
type memoryPoison struct {
	Writer, WriterJob string // workflow node ID and job of the saving agent job
	Triggers          []string
	Reader, ReaderJob string
	Paths             []string
	Key               string
	Line              int // the save step's line in the writer's file
	How               string
	Ev                graph.Evidence
	Why               string // why the evidence is not_visible
}

// privilegedJobs are the jobs that hold secrets, a contents: write or
// id-token: write token, or (agent jobs) any write scope.
func privilegedJobs(f *WorkflowFacts) map[string]bool {
	out := map[string]bool{}
	for _, j := range f.SecretJobs {
		out[j] = true
	}
	for _, j := range f.TokenWriteJobs {
		out[j] = true
	}
	for _, j := range f.IDTokenJobs {
		out[j.Job] = true
	}
	for _, a := range f.Agents {
		for _, p := range a.Perms {
			if p != "default" {
				out[a.Job] = true
			}
		}
	}
	return out
}

// memoryPoisons joins one repo's workflows: every save step of an agent job
// outsiders can start on a trigger that writes the default branch's cache
// scope, with every restore step of a privileged job that matches it. ghes
// says the host is GitHub Enterprise Server, where a save with no
// cache-mode is possible (the read-only default is documented for
// github.com only).
func memoryPoisons(wfs []memoryWF, ghes bool) []memoryPoison {
	var out []memoryPoison
	for _, w := range wfs {
		var trig []string
		for _, t := range w.F.Triggers {
			if cacheWriteTriggers[t] {
				trig = append(trig, t)
			}
		}
		if len(trig) == 0 {
			continue
		}
		for _, aj := range w.F.Agents {
			if aj.Exposure != graph.ExposureOutsiders {
				continue
			}
			ev, why := graph.Live, ""
			switch w.F.cacheModeOf(aj.Job) {
			case "write", "write-only":
			case "":
				if !ghes {
					continue // read-only on github.com
				}
				ev, why = graph.NotVisible, "GitHub Enterprise Server may not apply the read-only cache default to "+strings.Join(trig, ", ")
			default:
				continue // read or none: no save
			}
			if aj.Gate == graph.GateUnknown || agentConfidence(aj.Sources) == graph.AgentHeuristic {
				ev, why = graph.NotVisible, "the agent's actor check is unknown"
			}
			for _, s := range w.F.Caches {
				if s.Job != aj.Job || !s.Save {
					continue
				}
				for _, r := range wfs {
					priv := privilegedJobs(r.F)
					for _, rs := range r.F.Caches {
						if !rs.Restore || !priv[rs.Job] || r.F.cacheModeOf(rs.Job) == "none" || r.F.cacheModeOf(rs.Job) == "write-only" {
							continue
						}
						how, mev, ok := matchCache(s, rs)
						if !ok {
							continue
						}
						e := mev
						if ev == graph.NotVisible {
							e = graph.NotVisible
						}
						out = append(out, memoryPoison{Writer: w.ID, WriterJob: aj.Job, Triggers: trig, Reader: r.ID, ReaderJob: rs.Job,
							Paths: s.Paths, Key: s.Key, Line: s.Line, How: how, Ev: e, Why: why})
					}
				}
			}
		}
	}
	return out
}

// evRank orders evidence for the agent memory attrs: the strongest wins.
var memEvRank = map[graph.Evidence]int{graph.NotVisible: 0, graph.Inferred: 1, graph.Live: 2}

var matchRank = map[string]int{MatchExpression: 0, MatchPrefix: 1, MatchExact: 2}

// recordMemoryFacts keeps a workflow's facts for the agent memory join.
func (k *collector) recordMemoryFacts(wid string, f *WorkflowFacts) {
	if len(f.Caches) == 0 {
		return
	}
	if k.memFacts == nil {
		k.memFacts = map[string]*WorkflowFacts{}
	}
	k.memFacts[wid] = f
}

// addAgentMemory joins, per repo, the cache steps of its workflows and
// writes the agent_memory_* attrs on each writer workflow.
func (k *collector) addAgentMemory() {
	byRepo := map[string][]memoryWF{}
	for id, f := range k.memFacts {
		n := k.nodes[id]
		if n == nil {
			continue
		}
		byRepo[n.Attrs["repo"]] = append(byRepo[n.Attrs["repo"]], memoryWF{ID: id, F: f})
	}
	repos := make([]string, 0, len(byRepo))
	for r := range byRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	for _, repo := range repos {
		wfs := byRepo[repo]
		sort.Slice(wfs, func(i, j int) bool { return wfs[i].ID < wfs[j].ID })
		type acc struct {
			readers, paths, dirs, trig map[string]bool
			ev                         graph.Evidence
			how, key, why              string
			line                       int
		}
		got := map[string]*acc{}
		var order []string
		for _, p := range memoryPoisons(wfs, k.ghes) {
			a := got[p.Writer]
			if a == nil {
				a = &acc{readers: map[string]bool{}, paths: map[string]bool{}, dirs: map[string]bool{}, trig: map[string]bool{}, ev: p.Ev, how: p.How, key: p.Key, why: p.Why, line: p.Line}
				got[p.Writer] = a
				order = append(order, p.Writer)
			}
			a.readers[p.Reader] = true
			for _, t := range p.Triggers {
				a.trig[t] = true
			}
			for _, x := range p.Paths {
				if !strings.Contains(x, ",") {
					a.paths[x] = true
				}
				if d := MemoryDir(x); d != "" {
					a.dirs[d] = true
				}
			}
			if memEvRank[p.Ev] > memEvRank[a.ev] || (p.Ev == a.ev && matchRank[p.How] > matchRank[a.how]) {
				a.ev, a.how, a.key, a.why, a.line = p.Ev, p.How, p.Key, p.Why, p.Line
			}
		}
		for _, id := range order {
			a, n := got[id], k.nodes[id]
			setAttr(n, graph.AttrAgentMemoryStore, graph.MemoryStoreCache, graph.Live)
			setAttr(n, graph.AttrAgentMemoryReaders, strings.Join(sortedSet(a.readers), ","), a.ev)
			setAttr(n, graph.AttrAgentMemoryTriggers, strings.Join(sortedSet(a.trig), ","), graph.Live)
			if len(a.paths) > 0 {
				setAttr(n, graph.AttrAgentMemoryPaths, strings.Join(sortedSet(a.paths), ","), graph.Live)
			}
			if len(a.dirs) > 0 {
				setAttr(n, graph.AttrAgentMemoryDirs, strings.Join(sortedSet(a.dirs), ","), graph.Live)
			}
			setAttr(n, graph.AttrAgentMemoryMatch, a.how, a.ev)
			if a.line > 0 {
				setAttr(n, graph.AttrAgentMemoryLine, strconv.Itoa(a.line), graph.Live)
			}
			if a.why != "" {
				k.cover(id, "agent_memory", "possible cache write by an agent outsiders can start: "+a.why,
					"check the job's cache-mode in "+path.Base(n.Attrs["path"]))
			}
		}
	}
}
