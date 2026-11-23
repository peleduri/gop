package oidc

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Coverage fact and fix text for an oidc node no supplied trust matches.
const (
	FactCloudTrust     = "cloud_trust"
	NeedsFixCloudTrust = "supply the trust policy for the cloud role this workflow assumes"
)

// TrustFiles lists the files Parse reads for these paths: each file given
// directly, and every *.json file under each directory. Paths are cleaned and
// use '/' so they are stable in graph.json. Sorted.
func TrustFiles(paths ...string) ([]string, error) {
	set := map[string]bool{}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			set[cleanPath(p)] = true
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() && strings.EqualFold(filepath.Ext(path), ".json") {
				set[cleanPath(path)] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

func cleanPath(p string) string { return filepath.ToSlash(filepath.Clean(p)) }

// EnrichStats summarizes one Enrich call.
type EnrichStats struct {
	Confirmed int // CAN_ASSUME edges with evidence supplied
	Possible  int // CAN_ASSUME edges with evidence not_visible (undecided match)
	Targets   int // cloud_target nodes the edges point to
	Unmatched int // oidc nodes with a cloud_trust coverage entry
}

// Enrich adds the paths out of GitHub that the supplied trusts open: for every
// workflow -EXECUTES_WITH-> oidc edge and every trust, Evaluate decides
// whether the workflow's token can assume the trust's cloud identity. A match
// adds workflow -CAN_ASSUME-> cloud:<provider>:<target> with evidence
// supplied; an undecided match adds the edge with evidence not_visible and
// attrs.reason (possible reach). A non-match adds nothing. An oidc node none
// of whose workflows matched any trust gets a cloud_trust coverage entry.
//
// files are the files the trusts were read from (TrustFiles): CAN_ASSUME
// edges from earlier runs over the same files are replaced, so Enrich is
// idempotent. Trust.File must use the same spelling (Parse over the same
// paths). The graph is modified in place; new elements are appended in a
// deterministic order and observed_at is the graph's collected_at, so the
// same inputs give byte-identical output.
//
// fileWarnings are Parse's per-file warnings: a trust read from a file with
// an ignored Deny statement may be narrower than modeled, so its matches are
// only possible.
func Enrich(g *graph.Graph, trusts []Trust, files []string, fileWarnings []string) EnrichStats {
	fileSet := map[string]bool{}
	for _, f := range files {
		fileSet[cleanPath(f)] = true
	}
	denied := map[string]bool{}
	for _, w := range fileWarnings {
		if strings.Contains(w, "Deny statement") {
			for f := range fileSet {
				if strings.HasPrefix(w, f+": ") {
					denied[f] = true
				}
			}
		}
	}

	// Drop what an earlier run over the same files added.
	kept := g.Edges[:0:0]
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume && fileSet[cleanPath(e.Attrs[graph.AttrFile])] {
			continue
		}
		kept = append(kept, e)
	}
	g.Edges = kept
	referenced := map[string]bool{}
	for _, e := range g.Edges {
		referenced[e.From], referenced[e.To] = true, true
	}
	nodes := g.Nodes[:0:0]
	for _, n := range g.Nodes {
		if n.Kind == graph.KindCloudTarget && !referenced[n.ID] {
			continue
		}
		nodes = append(nodes, n)
	}
	g.Nodes = nodes
	cov := g.Coverage[:0:0]
	for _, c := range g.Coverage {
		if c.Fact != FactCloudTrust {
			cov = append(cov, c)
		}
	}
	g.Coverage = cov

	ix := graph.NewIndex(g)
	sorted := append([]Trust(nil), trusts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Pointer != b.Pointer {
			return a.Pointer < b.Pointer
		}
		return a.Target < b.Target
	})

	type key struct{ from, to, file, ptr string }
	added := map[key]graph.Edge{}
	newNodes := map[string]graph.Node{}
	oidcNodes := map[string]bool{}
	var execs []graph.Edge
	for _, e := range g.Edges {
		if e.Kind == graph.ExecutesWith && ix.Kind(e.To) == graph.KindOIDC {
			execs = append(execs, e)
			oidcNodes[e.To] = true
		}
	}
	sort.SliceStable(execs, func(i, j int) bool {
		if execs[i].From != execs[j].From {
			return execs[i].From < execs[j].From
		}
		return execs[i].To < execs[j].To
	})
	for _, ex := range execs {
		w := ClaimsFromEdge(ex)
		for _, t := range sorted {
			o := Evaluate(t, w)
			if o.Result == NoMatch {
				continue
			}
			file := cleanPath(t.File)
			ev := graph.Supplied
			reason := o.Reason
			if o.Result == Matched && denied[file] {
				reason = "the file has a Deny statement gop ignores; the real trust may be narrower"
				o.Result = Uncertain
			}
			if o.Result == Uncertain || !graph.Verified(ex.Evidence) {
				ev = graph.NotVisible
				if o.Result == Matched {
					reason = "the workflow's OIDC edge is not visible"
				}
			}
			n := cloudNode(t)
			attrs := map[string]string{
				graph.AttrFile:     file,
				graph.AttrProvider: string(t.Provider),
				graph.AttrOIDC:     ex.To,
			}
			if t.Pointer != "" {
				attrs[graph.AttrPointer] = t.Pointer
			}
			if len(o.MatchedSub) > 0 {
				attrs[graph.AttrMatchedSub] = strings.Join(o.MatchedSub, ",")
			}
			if len(o.Claims) > 0 {
				attrs[graph.AttrClaims] = strings.Join(o.Claims, ",")
			}
			if ev == graph.NotVisible {
				attrs[graph.AttrReason] = reason
			}
			if t.Target != strings.TrimPrefix(n.ID, "cloud:"+string(t.Provider)+":") {
				attrs[graph.AttrTrust] = t.Target
			}
			e := graph.Edge{From: ex.From, To: n.ID, Kind: graph.CanAssume, Evidence: ev,
				SourceAPI: graph.SourceSupplied + file, ObservedAt: g.CollectedAt, Attrs: attrs}
			k := key{ex.From, n.ID, file, t.Pointer}
			if old, ok := added[k]; !ok || (old.Evidence == graph.NotVisible && ev == graph.Supplied) {
				added[k] = e
			}
			if old, ok := newNodes[n.ID]; ok {
				n.Attrs[graph.AttrWarnings] = mergeList(old.Attrs[graph.AttrWarnings], n.Attrs[graph.AttrWarnings])
				if n.Attrs[graph.AttrWarnings] == "" {
					delete(n.Attrs, graph.AttrWarnings)
				}
			}
			newNodes[n.ID] = n
		}
	}

	var st EnrichStats
	keys := make([]key, 0, len(added))
	for k := range added {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.from != b.from {
			return a.from < b.from
		}
		if a.to != b.to {
			return a.to < b.to
		}
		if a.file != b.file {
			return a.file < b.file
		}
		return a.ptr < b.ptr
	})
	for _, k := range keys {
		e := added[k]
		g.Edges = append(g.Edges, e)
		if e.Evidence == graph.Supplied {
			st.Confirmed++
		} else {
			st.Possible++
		}
	}
	ids := make([]string, 0, len(newNodes))
	for id := range newNodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := newNodes[id]
		merged := false
		for i := range g.Nodes {
			if g.Nodes[i].ID == id {
				// Declared by another run (other files): keep it, add warnings.
				if g.Nodes[i].Attrs == nil {
					g.Nodes[i].Attrs = map[string]string{}
				}
				if w := mergeList(g.Nodes[i].Attrs[graph.AttrWarnings], n.Attrs[graph.AttrWarnings]); w != "" {
					g.Nodes[i].Attrs[graph.AttrWarnings] = w
				}
				merged = true
				break
			}
		}
		if !merged {
			g.Nodes = append(g.Nodes, n)
		}
	}
	st.Targets = len(ids)

	// oidc nodes no workflow of which can assume anything.
	assumes := map[string]bool{}
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume {
			assumes[e.From] = true
		}
	}
	matched := map[string]bool{}
	for _, ex := range execs {
		if assumes[ex.From] {
			matched[ex.To] = true
		}
	}
	var unmatched []string
	for id := range oidcNodes {
		if !matched[id] {
			unmatched = append(unmatched, id)
		}
	}
	sort.Strings(unmatched)
	for _, id := range unmatched {
		g.Coverage = append(g.Coverage, graph.Coverage{Scope: id, Fact: FactCloudTrust,
			Reason:   "no supplied trust policy matches a token this repo's workflows can mint",
			NeedsFix: NeedsFixCloudTrust})
	}
	st.Unmatched = len(unmatched)
	return st
}

// ClaimsFromEdge reads WorkflowClaims from a workflow -EXECUTES_WITH-> oidc
// edge. Without claim attrs (graphs collected before they were recorded) the
// repository comes from the oidc node ID and environments are unknown.
func ClaimsFromEdge(e graph.Edge) WorkflowClaims {
	a := e.Attrs
	w := WorkflowClaims{
		Workflow:        e.From,
		Repository:      a[graph.AttrRepository],
		RepositoryOwner: a[graph.AttrRepositoryOwner],
		Jobs:            splitList(a[graph.AttrJobs]),
		Environments:    splitList(a[graph.AttrEnvironments]),
		JobWorkflowRefs: splitList(a[graph.AttrJobWorkflowRef]),
	}
	w.Known = len(w.Jobs) > 0
	if w.Repository == "" {
		if r, ok := strings.CutPrefix(e.To, "oidc:"); ok && strings.Count(r, "/") == 1 {
			w.Repository = r
		}
	}
	return w
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mergeList(a, b string) string {
	set := map[string]bool{}
	for _, s := range append(splitList(a), splitList(b)...) {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// CloudID is the cloud_target node ID for a trust: "cloud:<provider>:<id>"
// where id is the AWS role ARN, "serviceAccount:<email>" for a GCP trust that
// can impersonate a service account (else the workload identity provider
// name), or the Azure application or managed identity (without the
// federated credential, which goes on the edge).
func CloudID(t Trust) string {
	id := t.Target
	switch t.Provider {
	case GCP:
		if t.ServiceAccount != "" {
			id = "serviceAccount:" + t.ServiceAccount
		}
	case Azure:
		if i := strings.LastIndex(id, "/fic:"); i >= 0 {
			id = id[:i]
		}
	}
	return "cloud:" + string(t.Provider) + ":" + id
}

func cloudNode(t Trust) graph.Node {
	id := CloudID(t)
	attrs := map[string]string{graph.AttrProvider: string(t.Provider)}
	account, role := "", t.TargetName
	switch t.Provider {
	case AWS:
		// arn:aws:iam::111111111111:role/deploy
		if parts := strings.SplitN(t.Target, ":", 6); len(parts) == 6 && parts[0] == "arn" {
			account = parts[4]
			if r, ok := strings.CutPrefix(parts[5], "role/"); ok {
				role = r[strings.LastIndex(r, "/")+1:]
			}
		}
	case GCP:
		if t.ServiceAccount != "" {
			role = t.ServiceAccount
			if _, dom, ok := strings.Cut(t.ServiceAccount, "@"); ok {
				if p, ok := strings.CutSuffix(dom, ".iam.gserviceaccount.com"); ok {
					account = p
				}
			}
		}
		if account == "" {
			if rest, ok := strings.CutPrefix(t.Target, "projects/"); ok {
				account, _, _ = strings.Cut(rest, "/")
			}
		}
	case Azure:
		if rest, ok := strings.CutPrefix(strings.TrimPrefix(id, "cloud:azure:identity:"), "/subscriptions/"); ok {
			account, _, _ = strings.Cut(rest, "/")
		}
		if r, ok := strings.CutPrefix(id, "cloud:azure:identity:"); ok {
			role = r[strings.LastIndex(r, "/")+1:]
		} else if r, ok := strings.CutPrefix(id, "cloud:azure:app:"); ok {
			role = r
		}
	}
	if account != "" {
		attrs[graph.AttrAccount] = account
	}
	if role != "" {
		attrs[graph.AttrRole] = role
	}
	if w := warningCodes(t.Warnings); w != "" {
		attrs[graph.AttrWarnings] = w
	}
	name := strings.TrimPrefix(id, "cloud:")
	return graph.Node{ID: id, Kind: graph.KindCloudTarget, Name: name, Attrs: attrs, Evidence: graph.Supplied}
}

// Warning codes on cloud_target nodes.
const (
	CodeNoSub        = "no_sub_condition"
	CodeNoAud        = "no_aud_condition"
	CodeWildcard     = "wildcard_owner"
	CodeUnparsed     = "unparsed_condition"
	CodeLooseAnd     = "conditions_merged"
	CodeUnknownIdent = "unknown_target"
)

// warningCodes maps a trust's warnings to short codes, sorted, comma joined.
func warningCodes(ws []string) string {
	set := map[string]bool{}
	for _, w := range ws {
		switch {
		case w == WarnNoSub:
			set[CodeNoSub] = true
		case w == WarnNoAud:
			set[CodeNoAud] = true
		case strings.HasPrefix(w, "wildcard owner"):
			set[CodeWildcard] = true
		case strings.HasPrefix(w, "condition not fully understood"), strings.HasPrefix(w, "negative condition"):
			set[CodeUnparsed] = true
		case strings.Contains(w, "must all hold"), strings.Contains(w, "must both hold"):
			set[CodeLooseAnd] = true
		case strings.Contains(w, "unknown"):
			set[CodeUnknownIdent] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
