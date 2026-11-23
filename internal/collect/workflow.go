package collect

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// Reference levels for Uses.
const (
	LevelJob  = "job"  // jobs.<id>.uses (reusable workflow)
	LevelStep = "step" // jobs.<id>.steps[].uses (action)
)

// ActionUse is one remote `uses:` reference found in a workflow or composite action.
type ActionUse struct {
	Raw     string // as written, e.g. "acme-actions/deploy@main"
	Owner   string
	Repo    string
	Path    string // sub-path inside the repo, may be ""
	Ref     string
	RefKind string // sha | tag | branch
	Level   string // job | step
	Job     string // job id ("" for composite action steps)
	Line    int    // 1-based line of the uses: value (0 if unknown)
	Column  int    // 1-based column where the uses: value starts (0 if unknown)
	File    string // repo-relative path of the file the reference was read from
	FileRef string // commit or branch that file was read at ("" if unknown)
}

// IsReusableWorkflow reports whether the reference points at a workflow file.
func (u ActionUse) IsReusableWorkflow() bool {
	return strings.HasPrefix(u.Path, ".github/workflows/") && isYAMLName(u.Path)
}

// WorkflowFacts is what gop extracts from one workflow file.
type WorkflowFacts struct {
	Uses            []ActionUse
	IDTokenWrite    bool
	IDTokenScopes   []string // "workflow" and/or job ids
	Secrets         []string // names referenced as secrets.NAME (GITHUB_TOKEN excluded); "*" for dynamic access
	InheritsSecrets bool
	SelfHosted      bool
	RunnerLabels    []string
	IDTokenLines    map[string]int // scope -> 1-based line of the id-token: write (or write-all) key
	RunsOnLine      int            // first runs-on: line of a self-hosted job (0 if none)
	// TokenContentsWrite is whether the GITHUB_TOKEN can push: TokenWrite when
	// any job resolves to contents: write, TokenDefault when some job declares
	// no permissions at either level (and none resolves to write), else TokenRead.
	TokenContentsWrite string
	TokenWriteJobs     []string // job ids whose token has contents: write, sorted
	TokenDefaultJobs   []string // job ids that take the repo or org default, sorted
	TokenScopes        []string // other write scopes (e.g. id-token, packages), sorted; "write-all" for write-all
	File               string   // repo-relative path, set by the caller
	FileRef            string   // commit or branch the file was read at, set by the caller
}

// SetFile records where the workflow was read from on the facts and every use.
func (f *WorkflowFacts) SetFile(path, ref string) {
	f.File, f.FileRef = path, ref
	setFile(f.Uses, path, ref)
}

func setFile(uses []ActionUse, path, ref string) {
	for i := range uses {
		uses[i].File, uses[i].FileRef = path, ref
	}
}

// IDTokenLine is the first line granting id-token: write (0 if none).
func (f *WorkflowFacts) IDTokenLine() int {
	first := 0
	for _, l := range f.IDTokenLines {
		if first == 0 || l < first {
			first = l
		}
	}
	return first
}

// locate adds the file position attributes to edge attrs, skipping unknowns.
func locate(attrs map[string]string, file, ref string, line, col int) {
	if file != "" {
		attrs[graph.AttrFile] = file
	}
	if ref != "" {
		attrs[graph.AttrFileRef] = ref
	}
	if line > 0 {
		attrs[graph.AttrLine] = strconv.Itoa(line)
	}
	if col > 0 {
		attrs[graph.AttrCol] = strconv.Itoa(col)
	}
}

// useAt parses a uses: node and records its position.
func useAt(n *yaml.Node) (ActionUse, bool) {
	if n.Kind != yaml.ScalarNode {
		return ActionUse{}, false
	}
	u, ok := ParseUses(n.Value)
	u.Line, u.Column = n.Line, n.Column
	return u, ok
}

// HasSecrets reports whether the workflow can read stored secrets.
func (f *WorkflowFacts) HasSecrets() bool { return f.InheritsSecrets || len(f.Secrets) > 0 }

var (
	shaRe       = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	tagRe       = regexp.MustCompile(`^(v\d|\d+\.\d+(\.\d+)?([-+.].*)?$)`)
	secretRefRe = regexp.MustCompile(`\bsecrets\.([A-Za-z_][A-Za-z0-9_-]*)`)
	secretIdxRe = regexp.MustCompile(`\bsecrets\s*\[`)
)

// RefKind classifies a git ref by its name: a 40-hex string is a sha, a "v<digit>"
// or semver-like name is a tag, anything else is a branch. The tag/branch split
// is a naming heuristic; the API is not asked.
func RefKind(ref string) string {
	switch {
	case shaRe.MatchString(ref):
		return "sha"
	case tagRe.MatchString(ref):
		return "tag"
	default:
		return "branch"
	}
}

// ParseUses parses a remote uses string. ok is false for local ("./"),
// docker ("docker://") and malformed references.
func ParseUses(s string) (ActionUse, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "docker://") || strings.Contains(s, "${{") {
		return ActionUse{}, false
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return ActionUse{}, false
	}
	target, ref := s[:at], s[at+1:]
	parts := strings.Split(target, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ActionUse{}, false
	}
	return ActionUse{
		Raw:     s,
		Owner:   parts[0],
		Repo:    parts[1],
		Path:    strings.Join(parts[2:], "/"),
		Ref:     ref,
		RefKind: RefKind(ref),
	}, true
}

// The workflow and action parsers walk the yaml.Node tree by hand instead of
// decoding into structs. yaml.v3 checks mapping keys for duplicates with a
// quadratic loop on every decoded mapping, so a 1 MiB file of flat keys took
// about 20 s to decode; files are attacker-controlled (anyone who can push to
// any repo writes one). The walk below checks duplicates with a map, follows
// aliases only along the few paths it reads, and charges every node it visits
// to a budget so alias fan-out cannot blow up. Its results match what the
// struct decode returned: the same fields, the same type errors, merge keys.

// maxYAMLVisits bounds the nodes the walk visits, alias expansion included.
const maxYAMLVisits = 1 << 20

// maxMergeDepth bounds nested and self-referencing merge keys (<<: *a).
const maxMergeDepth = 32

type yamlWalk struct{ visits int }

// resolve follows aliases and charges the visit. A nil node stays nil.
func (w *yamlWalk) resolve(n *yaml.Node) (*yaml.Node, error) {
	for i := 0; n != nil && n.Kind == yaml.AliasNode; i++ {
		if i > maxMergeDepth {
			return nil, fmt.Errorf("alias chain too deep")
		}
		n = n.Alias
	}
	w.visits++
	if w.visits > maxYAMLVisits {
		return nil, fmt.Errorf("document contains excessive aliasing")
	}
	return n, nil
}

func isNullNode(n *yaml.Node) bool {
	return n == nil || n.Kind == 0 || (n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null")
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "!!map"
	case yaml.SequenceNode:
		return "!!seq"
	case yaml.ScalarNode:
		return n.ShortTag()
	}
	return "node"
}

// yamlMap is a decoded mapping: values by key, with key nodes for positions.
// Direct keys win over merged (<<) keys, as in yaml.v3.
type yamlMap struct {
	keys []string // direct keys in document order, then merged keys
	key  map[string]*yaml.Node
	val  map[string]*yaml.Node
}

func (m *yamlMap) get(key string) (k, v *yaml.Node) {
	if m == nil {
		return nil, nil
	}
	return m.key[key], m.val[key]
}

// mapping decodes n (alias-resolved) as a mapping. A null node gives an empty
// map. what names the target in errors, like the struct decode did.
func (w *yamlWalk) mapping(n *yaml.Node, what string) (*yamlMap, error) {
	return w.mappingDepth(n, what, 0)
}

func (w *yamlWalk) mappingDepth(n *yaml.Node, what string, depth int) (*yamlMap, error) {
	n, err := w.resolve(n)
	if err != nil {
		return nil, err
	}
	m := &yamlMap{key: map[string]*yaml.Node{}, val: map[string]*yaml.Node{}}
	if isNullNode(n) {
		return m, nil
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: cannot unmarshal %s into %s", n.Line, kindName(n), what)
	}
	var merges []*yaml.Node
	seen := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		kn, vn := n.Content[i], n.Content[i+1]
		if isMergeKey(kn) {
			merges = append(merges, vn)
			continue
		}
		rk, err := w.resolve(kn)
		if err != nil {
			return nil, err
		}
		if rk.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: cannot unmarshal %s key in %s", kn.Line, kindName(rk), what)
		}
		if prev, ok := seen[rk.Value]; ok {
			return nil, fmt.Errorf("line %d: mapping key %q already defined at line %d", kn.Line, rk.Value, prev.Line)
		}
		seen[rk.Value] = kn
		if isNullNode(rk) {
			continue // yaml.v3 drops entries whose key is null
		}
		m.keys = append(m.keys, rk.Value)
		m.key[rk.Value], m.val[rk.Value] = kn, vn
	}
	for _, mn := range merges {
		if depth >= maxMergeDepth {
			return nil, fmt.Errorf("line %d: merge keys nested too deep", mn.Line)
		}
		src, err := w.resolve(mn)
		if err != nil {
			return nil, err
		}
		var srcs []*yaml.Node
		switch src.Kind {
		case yaml.MappingNode:
			srcs = []*yaml.Node{src}
		case yaml.SequenceNode:
			srcs = src.Content
		default:
			return nil, fmt.Errorf("line %d: map merge requires map or sequence of maps as the value", mn.Line)
		}
		for _, s := range srcs {
			sm, err := w.mappingDepth(s, what, depth+1)
			if err != nil {
				return nil, err
			}
			for _, k := range sm.keys {
				if _, ok := m.key[k]; !ok {
					m.keys = append(m.keys, k)
					m.key[k], m.val[k] = sm.key[k], sm.val[k]
				}
			}
		}
	}
	return m, nil
}

func isMergeKey(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Value == "<<" && (n.Tag == "" || n.Tag == "!" || n.ShortTag() == "!!merge")
}

// sequence decodes n (alias-resolved) as a sequence; null gives nil.
func (w *yamlWalk) sequence(n *yaml.Node, what string) ([]*yaml.Node, error) {
	n, err := w.resolve(n)
	if err != nil {
		return nil, err
	}
	if isNullNode(n) {
		return nil, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("line %d: cannot unmarshal %s into %s", n.Line, kindName(n), what)
	}
	return n.Content, nil
}

// field returns the raw value node for key (nil if absent). Like a yaml.Node
// struct field, an alias value is returned unresolved.
func field(m *yamlMap, key string) *yaml.Node {
	_, v := m.get(key)
	if v == nil {
		return &yaml.Node{}
	}
	return v
}

// stepUses returns the uses: node of every step in a steps: sequence.
func (w *yamlWalk) stepUses(steps *yaml.Node) ([]*yaml.Node, error) {
	items, err := w.sequence(steps, "[]step")
	if err != nil {
		return nil, err
	}
	var out []*yaml.Node
	for _, it := range items {
		sm, err := w.mapping(it, "step")
		if err != nil {
			return nil, err
		}
		out = append(out, field(sm, "uses"))
	}
	return out, nil
}

// GITHUB_TOKEN contents values (WorkflowFacts.TokenContentsWrite).
const (
	TokenWrite   = "true"
	TokenRead    = "false"
	TokenDefault = "default"
)

// permAll is the scope key for permissions: write-all and read-all.
const permAll = "*"

// permEntry is one scope of a permissions value and the line that sets it.
type permEntry struct {
	scope, level string
	line         int
}

// permissionsOf reads a permissions value. declared is false when the key is
// absent. write-all and read-all give one entry with scope "*"; a mapping
// gives its scopes; {} or null gives no entries (every scope is none). Any
// other scalar is read as none: GitHub rejects such a file. Malformed entries
// are skipped rather than failing the whole workflow.
func (w *yamlWalk) permissionsOf(n *yaml.Node) (entries []permEntry, declared bool, err error) {
	if n == nil || n.Kind == 0 {
		return nil, false, nil
	}
	n, err = w.resolve(n)
	if err != nil {
		return nil, true, err
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch v := strings.TrimSpace(n.Value); v {
		case "write-all", "read-all":
			return []permEntry{{scope: permAll, level: strings.TrimSuffix(v, "-all"), line: n.Line}}, true, nil
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := w.resolve(n.Content[i])
			if err != nil {
				return nil, true, err
			}
			v, err := w.resolve(n.Content[i+1])
			if err != nil {
				return nil, true, err
			}
			if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
				continue
			}
			entries = append(entries, permEntry{scope: k.Value, level: strings.TrimSpace(v.Value), line: k.Line})
		}
	}
	return entries, true, nil
}

// permMap turns permissions entries into scope -> level. nil entries that
// were declared give an empty map: every scope is none.
func permMap(entries []permEntry, declared bool) map[string]string {
	if !declared {
		return nil
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.scope] = e.level
	}
	return m
}

// resolvePermissions returns a job's effective GITHUB_TOKEN permissions as
// scope -> level, given the workflow-level map (permMap). A job-level
// permissions key replaces the workflow-level one. nil means neither level
// declares permissions, so the repo or org default applies. Scopes a declared
// mapping omits are none. fromJob reports whether the job's own key decided.
func resolvePermissions(wf map[string]string, job []permEntry, jobDeclared bool) (perms map[string]string, fromJob bool) {
	if jobDeclared {
		return permMap(job, true), true
	}
	return wf, false
}

// scopeLevel is the level of one scope in resolved permissions.
func scopeLevel(perms map[string]string, scope string) string {
	if l, ok := perms[scope]; ok {
		return l
	}
	if l, ok := perms[permAll]; ok {
		return l
	}
	return "none"
}

// ParseWorkflow extracts uses references, OIDC, secrets and runner facts.
func ParseWorkflow(data []byte) (*WorkflowFacts, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	f, err := workflowFacts(&doc)
	if err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	return f, nil
}

func workflowFacts(doc *yaml.Node) (*WorkflowFacts, error) {
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(doc), "workflow")
	if err != nil {
		return nil, err
	}
	f := &WorkflowFacts{IDTokenLines: map[string]int{}}
	wfPerms, wfDeclared, err := w.permissionsOf(field(root, "permissions"))
	if err != nil {
		return nil, err
	}
	wfMap := permMap(wfPerms, wfDeclared)
	scopes, wfUsed := map[string]bool{}, false
	if l := idTokenLine(wfPerms); l > 0 {
		f.IDTokenWrite = true
		f.IDTokenScopes = append(f.IDTokenScopes, "workflow")
		f.IDTokenLines["workflow"] = l
	}
	_, jobsNode := root.get("jobs")
	jobs, err := w.mapping(jobsNode, "map[string]job")
	if err != nil {
		return nil, err
	}
	jobIDs := append([]string(nil), jobs.keys...)
	sort.Strings(jobIDs)
	labels := map[string]bool{}
	for _, id := range jobIDs {
		_, jv := jobs.get(id)
		job, err := w.mapping(jv, "job")
		if err != nil {
			return nil, err
		}
		steps, err := w.stepUses(field(job, "steps"))
		if err != nil {
			return nil, err
		}
		if u, ok := useAt(field(job, "uses")); ok {
			u.Level, u.Job = LevelJob, id
			f.Uses = append(f.Uses, u)
		}
		for _, sn := range steps {
			if u, ok := useAt(sn); ok {
				u.Level, u.Job = LevelStep, id
				f.Uses = append(f.Uses, u)
			}
		}
		jobPerms, jobDeclared, err := w.permissionsOf(field(job, "permissions"))
		if err != nil {
			return nil, err
		}
		perms, fromJob := resolvePermissions(wfMap, jobPerms, jobDeclared)
		f.addToken(id, perms)
		if fromJob {
			addWriteScopes(perms, scopes)
		} else {
			wfUsed = true
		}
		if l := idTokenLine(jobPerms); l > 0 {
			f.IDTokenWrite = true
			f.IDTokenScopes = append(f.IDTokenScopes, id)
			f.IDTokenLines[id] = l
		}
		if sec := field(job, "secrets"); sec.Kind == yaml.ScalarNode && strings.TrimSpace(sec.Value) == "inherit" {
			f.InheritsSecrets = true
		}
		for _, l := range scalars(field(job, "runs-on")) {
			if strings.Contains(strings.ToLower(l), "self-hosted") {
				f.SelfHosted = true
				if k, _ := job.get("runs-on"); k != nil && (f.RunsOnLine == 0 || k.Line < f.RunsOnLine) {
					f.RunsOnLine = k.Line
				}
			}
			labels[l] = true
		}
	}
	if f.SelfHosted {
		for l := range labels {
			f.RunnerLabels = append(f.RunnerLabels, l)
		}
		sort.Strings(f.RunnerLabels)
	}
	f.Secrets = secretNames(doc)
	if wfUsed {
		addWriteScopes(wfMap, scopes) // once, not per job: the file may have thousands of jobs
	}
	f.TokenContentsWrite = TokenRead
	switch {
	case len(f.TokenWriteJobs) > 0:
		f.TokenContentsWrite = TokenWrite
	case len(f.TokenDefaultJobs) > 0:
		f.TokenContentsWrite = TokenDefault
	}
	f.TokenScopes = sortedSet(scopes)
	return f, nil
}

// addToken records one job's resolved token permissions (jobs come in sorted order).
func (f *WorkflowFacts) addToken(job string, perms map[string]string) {
	switch {
	case perms == nil:
		f.TokenDefaultJobs = append(f.TokenDefaultJobs, job)
	case scopeLevel(perms, "contents") == "write":
		f.TokenWriteJobs = append(f.TokenWriteJobs, job)
	}
}

// addWriteScopes adds the write scopes other than contents to scopes ("write-all" for write-all).
func addWriteScopes(perms map[string]string, scopes map[string]bool) {
	for scope, level := range perms {
		switch {
		case level != "write" || scope == "contents":
		case scope == permAll:
			scopes["write-all"] = true
		default:
			scopes[scope] = true
		}
	}
}

func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseCompositeAction returns the step-level uses of a composite action.yml.
// using is the runs.using value (composite, node20, docker, ...).
func ParseCompositeAction(data []byte) (uses []ActionUse, using string, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("parse action: %w", err)
	}
	uses, using, err = compositeUses(&doc)
	if err != nil {
		return nil, "", fmt.Errorf("parse action: %w", err)
	}
	return uses, using, nil
}

func compositeUses(doc *yaml.Node) ([]ActionUse, string, error) {
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(doc), "action")
	if err != nil {
		return nil, "", err
	}
	_, rv := root.get("runs")
	runs, err := w.mapping(rv, "runs")
	if err != nil {
		return nil, "", err
	}
	_, un := runs.get("using")
	un, err = w.resolve(un)
	if err != nil {
		return nil, "", err
	}
	var using string
	if !isNullNode(un) {
		if un.Kind != yaml.ScalarNode {
			return nil, "", fmt.Errorf("line %d: cannot unmarshal %s into string", un.Line, kindName(un))
		}
		using = un.Value
	}
	steps, err := w.stepUses(field(runs, "steps"))
	if err != nil {
		return nil, "", err
	}
	using = strings.TrimSpace(using)
	if using != "composite" {
		return nil, using, nil
	}
	var uses []ActionUse
	for _, sn := range steps {
		if u, ok := useAt(sn); ok {
			u.Level = LevelStep
			uses = append(uses, u)
		}
	}
	return uses, using, nil
}

// idTokenLine returns the line that grants id-token: write in a permissions
// value (the write-all scalar or the id-token key), or 0 if none does.
func idTokenLine(entries []permEntry) int {
	for _, e := range entries {
		if (e.scope == "id-token" || e.scope == permAll) && e.level == "write" {
			return e.line
		}
	}
	return 0
}

// rootMap returns the top-level mapping of a parsed document, or nil.
func rootMap(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return nil
}

// scalars returns every scalar value under n (recursively).
func scalars(n *yaml.Node) []string {
	var out []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return out
}

// secretNames finds secrets.NAME references in YAML values (comments are ignored).
func secretNames(doc *yaml.Node) []string {
	names := map[string]bool{}
	for _, s := range scalars(doc) {
		for _, m := range secretRefRe.FindAllStringSubmatch(s, -1) {
			if !strings.EqualFold(m[1], "GITHUB_TOKEN") {
				names[m[1]] = true
			}
		}
		if secretIdxRe.MatchString(s) {
			names["*"] = true
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func isYAMLName(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".yaml")
}
