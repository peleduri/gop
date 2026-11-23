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
	File            string         // repo-relative path, set by the caller
	FileRef         string         // commit or branch the file was read at, set by the caller
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

type rawStep struct {
	Uses yaml.Node `yaml:"uses"`
}

type rawJob struct {
	Uses        yaml.Node `yaml:"uses"`
	Permissions yaml.Node `yaml:"permissions"`
	RunsOn      yaml.Node `yaml:"runs-on"`
	Secrets     yaml.Node `yaml:"secrets"`
	Steps       []rawStep `yaml:"steps"`
}

type rawWorkflow struct {
	Permissions yaml.Node         `yaml:"permissions"`
	Jobs        map[string]rawJob `yaml:"jobs"`
}

// ParseWorkflow extracts uses references, OIDC, secrets and runner facts.
func ParseWorkflow(data []byte) (*WorkflowFacts, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	var wf rawWorkflow
	if err := doc.Decode(&wf); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	f := &WorkflowFacts{IDTokenLines: map[string]int{}}
	if l := idTokenLine(&wf.Permissions); l > 0 {
		f.IDTokenWrite = true
		f.IDTokenScopes = append(f.IDTokenScopes, "workflow")
		f.IDTokenLines["workflow"] = l
	}
	_, jobsNode := mapValue(rootMap(&doc), "jobs")
	jobIDs := make([]string, 0, len(wf.Jobs))
	for id := range wf.Jobs {
		jobIDs = append(jobIDs, id)
	}
	sort.Strings(jobIDs)
	labels := map[string]bool{}
	for _, id := range jobIDs {
		job := wf.Jobs[id]
		if u, ok := useAt(&job.Uses); ok {
			u.Level, u.Job = LevelJob, id
			f.Uses = append(f.Uses, u)
		}
		for _, st := range job.Steps {
			if u, ok := useAt(&st.Uses); ok {
				u.Level, u.Job = LevelStep, id
				f.Uses = append(f.Uses, u)
			}
		}
		if l := idTokenLine(&job.Permissions); l > 0 {
			f.IDTokenWrite = true
			f.IDTokenScopes = append(f.IDTokenScopes, id)
			f.IDTokenLines[id] = l
		}
		if job.Secrets.Kind == yaml.ScalarNode && strings.TrimSpace(job.Secrets.Value) == "inherit" {
			f.InheritsSecrets = true
		}
		for _, l := range scalars(&job.RunsOn) {
			if strings.Contains(strings.ToLower(l), "self-hosted") {
				f.SelfHosted = true
				_, jn := mapValue(jobsNode, id)
				if k, _ := mapValue(jn, "runs-on"); k != nil && (f.RunsOnLine == 0 || k.Line < f.RunsOnLine) {
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
	f.Secrets = secretNames(&doc)
	return f, nil
}

// ParseCompositeAction returns the step-level uses of a composite action.yml.
// using is the runs.using value (composite, node20, docker, ...).
func ParseCompositeAction(data []byte) (uses []ActionUse, using string, err error) {
	var a struct {
		Runs struct {
			Using string    `yaml:"using"`
			Steps []rawStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &a); err != nil {
		return nil, "", fmt.Errorf("parse action: %w", err)
	}
	using = strings.TrimSpace(a.Runs.Using)
	if using != "composite" {
		return nil, using, nil
	}
	for _, st := range a.Runs.Steps {
		if u, ok := useAt(&st.Uses); ok {
			u.Level = LevelStep
			uses = append(uses, u)
		}
	}
	return uses, using, nil
}

// idTokenLine returns the line that grants id-token: write in a permissions
// value (the write-all scalar or the id-token key), or 0 if none does.
func idTokenLine(n *yaml.Node) int {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.TrimSpace(n.Value) == "write-all" {
			return n.Line
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "id-token" && strings.TrimSpace(n.Content[i+1].Value) == "write" {
				return n.Content[i].Line
			}
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

// mapValue returns the key and value nodes for key in mapping m (nil, nil if absent).
func mapValue(m *yaml.Node, key string) (k, v *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
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
