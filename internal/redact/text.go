package redact

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// buildText builds the lookup tables free text is rewritten with, from the
// mapping recorded in the record pass. Third-party owners and repo names are
// left out of the single-word table: they collide with ordinary words in
// gop's messages ("actions", "checkout"); their owner/repo pairs are mapped.
func (r *redactor) buildText() {
	r.words, r.pairs = map[string]string{}, map[string]string{}
	add := func(m map[string]string, real, fake string) {
		k := strings.ToLower(real)
		if _, ok := m[k]; !ok {
			m[k] = fake
		}
	}
	for cat, m := range r.mapping {
		for real, fake := range m {
			switch cat {
			case CatRepo, CatExtRepo, CatTeam:
				add(r.pairs, real, fake)
				if cat != CatExtRepo {
					_, rn, _ := strings.Cut(real, "/")
					_, fn, _ := strings.Cut(fake, "/")
					add(r.words, rn, fn)
				}
			case CatExternal, CatRef, CatJob, CatPath:
				// not rewritten in free text
			default:
				add(r.words, real, fake)
			}
		}
	}
}

func runByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == '[' || c == ']' || c == '/' || c >= 0x80
}

// text rewrites free text (coverage reasons, attr values without a structured
// meaning) word by word through the name map. The self-check catches what
// it misses.
func (r *redactor) text(s string) string {
	if r.mode != final || s == "" {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !runByte(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && runByte(s[j]) {
			j++
		}
		b.WriteString(r.run(s[i:j]))
		i = j
	}
	return b.String()
}

// run rewrites one word: owner/repo pairs first, then single segments.
func (r *redactor) run(w string) string {
	core := strings.TrimRight(w, ".")
	trail := w[len(core):]
	if f, ok := r.words[strings.ToLower(core)]; ok {
		return f + trail
	}
	segs := strings.Split(core, "/")
	out := make([]string, 0, len(segs))
	for k := 0; k < len(segs); {
		if k+1 < len(segs) {
			if f, ok := r.pairs[strings.ToLower(segs[k]+"/"+segs[k+1])]; ok {
				out = append(out, f)
				k += 2
				continue
			}
		}
		if f, ok := r.words[strings.ToLower(segs[k])]; ok {
			out = append(out, f)
		} else {
			out = append(out, segs[k])
		}
		k++
	}
	return strings.Join(out, "/") + trail
}

// fixedVocab is gop's own wording that may contain an original name by
// coincidence (a user called "members"); the self-check masks it.
var fixedVocab = []string{
	"enterprise:", "org:", "members:", "identity:", "user:", "app:", "team:", "repo:", "workflow:", "action:",
	"secret:", "oidc:", "runner:", "cloud:", "external:", "external:anyone", "anyone on the internet", "members of ",
	".github/workflows/", "action.yml", "action.yaml", "github_token", "acme-enterprise",
	graph.EnvDynamic, graph.SourceSupplied,
}

// check is the self-check: it fails when an enterprise-internal name of
// minScan or more characters still appears in any string of out
// (case-insensitive). Synthetic names and gop's fixed wording are masked
// first, so a real name that happens to be part of them ("acme" inside
// "acme-org-01") is not a false alarm, and values that are wholly gop's
// vocabulary (enum attr values, source_api) are skipped.
func (r *redactor) check(out *graph.Graph) error {
	mask := map[string]bool{}
	for _, m := range r.mapping {
		for _, fake := range m {
			mask[strings.ToLower(fake)] = true
		}
	}
	for _, v := range fixedVocab {
		mask[strings.ToLower(v)] = true
	}
	whole := map[string]bool{}
	for v := range r.vocab {
		whole[v] = true
	}
	for _, e := range out.Edges {
		if !strings.HasPrefix(e.SourceAPI, graph.SourceSupplied) {
			whole[strings.ToLower(e.SourceAPI)] = true
		}
	}
	return checkGraph(out, r.scan, mask, whole)
}

// maxLeaks is how many leak locations the error lists.
const maxLeaks = 5

func checkGraph(g *graph.Graph, names, mask, whole map[string]bool) error {
	if len(names) == 0 {
		return nil
	}
	masker := replacer(mask, "\x00")
	finder := replacer(names, "\x01")
	leak := &LeakError{}
	look := func(loc, s string) {
		l := strings.ToLower(s)
		if l == "" || whole[l] {
			return
		}
		if strings.Contains(finder.Replace(masker.Replace(l)), "\x01") {
			leak.Count++
			if len(leak.Locations) < maxLeaks {
				leak.Locations = append(leak.Locations, loc)
			}
		}
	}
	look("enterprise", g.Enterprise)
	for i, n := range g.Nodes {
		look(fmt.Sprintf("nodes[%d].id", i), n.ID)
		look(fmt.Sprintf("nodes[%d].name", i), n.Name)
		for _, k := range sortedKeys(n.Attrs) {
			look(fmt.Sprintf("nodes[%d].attrs.%s", i, k), n.Attrs[k])
		}
	}
	for i, e := range g.Edges {
		look(fmt.Sprintf("edges[%d].from", i), e.From)
		look(fmt.Sprintf("edges[%d].to", i), e.To)
		look(fmt.Sprintf("edges[%d].source_api", i), e.SourceAPI)
		for _, k := range sortedKeys(e.Attrs) {
			look(fmt.Sprintf("edges[%d].attrs.%s", i, k), e.Attrs[k])
		}
	}
	for i, c := range g.Coverage {
		look(fmt.Sprintf("coverage[%d].scope", i), c.Scope)
		look(fmt.Sprintf("coverage[%d].fact", i), c.Fact)
		look(fmt.Sprintf("coverage[%d].reason", i), c.Reason)
		look(fmt.Sprintf("coverage[%d].needs_fix", i), c.NeedsFix)
	}
	if leak.Count > 0 {
		return leak
	}
	return nil
}

// replacer replaces every token with to, longest first so a longer token
// wins over its prefix.
func replacer(tokens map[string]bool, to string) *strings.Replacer {
	ts := make([]string, 0, len(tokens))
	for t := range tokens {
		if t != "" {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool {
		if len(ts[i]) != len(ts[j]) {
			return len(ts[i]) > len(ts[j])
		}
		return ts[i] < ts[j]
	})
	pairs := make([]string, 0, 2*len(ts))
	for _, t := range ts {
		pairs = append(pairs, t, to)
	}
	return strings.NewReplacer(pairs...)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
