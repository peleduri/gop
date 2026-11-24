package skills

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

// serverTools lists the tools the gop MCP server registers over the acme
// fixture, with every property name in each tool's input and output schemas.
func serverTools(t *testing.T) (tools map[string]map[string]bool, fields map[string]bool) {
	t.Helper()
	g, err := graph.LoadFile("../testdata/acme/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := mcpserver.NewServer(g, "test").Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, fields = map[string]map[string]bool{}, map[string]bool{}
	for _, tool := range res.Tools {
		in := map[string]bool{}
		collectProps(t, tool.InputSchema, in, true)
		tools[tool.Name] = in
		collectProps(t, tool.InputSchema, fields, false)
		collectProps(t, tool.OutputSchema, fields, false)
	}
	if len(tools) == 0 {
		t.Fatal("the MCP server lists no tools")
	}
	return tools, fields
}

// collectProps adds the property names of schema to out: only the top level
// when topOnly, else at every depth.
func collectProps(t *testing.T, schema any, out map[string]bool, topOnly bool) {
	t.Helper()
	if schema == nil {
		return
	}
	b, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(v any, top bool)
	walk = func(v any, top bool) {
		switch x := v.(type) {
		case map[string]any:
			if props, ok := x["properties"].(map[string]any); ok && (top || !topOnly) {
				for k := range props {
					out[k] = true
				}
			}
			if topOnly {
				return
			}
			for _, c := range x {
				walk(c, false)
			}
		case []any:
			for _, c := range x {
				walk(c, false)
			}
		}
	}
	walk(v, true)
}

// cliCommands returns the commands gop's run switch in cmd/gop/main.go dispatches.
func cliCommands(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("../cmd/gop/main.go")
	if err != nil {
		t.Fatal(err)
	}
	cmds := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\tcase ("[^:]+"):`).FindAllStringSubmatch(string(src), -1) {
		for _, q := range strings.Split(m[1], ",") {
			c, err := strconv.Unquote(strings.TrimSpace(q))
			if err == nil && !strings.HasPrefix(c, "-") {
				cmds[c] = true
			}
		}
	}
	for _, want := range []string{"collect", "serve", "doctor"} {
		if !cmds[want] {
			t.Fatalf("could not read the command switch in cmd/gop/main.go (no %q)", want)
		}
	}
	return cmds
}

type skill struct {
	dir, body string
	meta      struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
}

func loadSkills(t *testing.T) []skill {
	t.Helper()
	paths, err := filepath.Glob("*/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no skills/*/SKILL.md found")
	}
	var out []skill
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := skill{dir: filepath.Dir(p)}
		rest, ok := bytes.CutPrefix(b, []byte("---\n"))
		fm, body, ok2 := bytes.Cut(rest, []byte("\n---\n"))
		if !ok || !ok2 {
			t.Fatalf("%s: no --- frontmatter block at the top", p)
		}
		if err := yaml.Unmarshal(fm, &s.meta); err != nil {
			t.Fatalf("%s: frontmatter: %v", p, err)
		}
		s.body = string(body)
		out = append(out, s)
	}
	return out
}

func TestSkillFrontmatter(t *testing.T) {
	for _, s := range loadSkills(t) {
		if s.meta.Name != s.dir {
			t.Errorf("%s/SKILL.md: name %q must match its directory", s.dir, s.meta.Name)
		}
		if len(strings.Fields(s.meta.Description)) < 10 || !strings.Contains(s.meta.Description, "Use when") {
			t.Errorf("%s/SKILL.md: description must say what it does and when to use it (\"Use when ...\"), got %q", s.dir, s.meta.Description)
		}
		if n := strings.Count(s.body, "\n"); n > 150 {
			t.Errorf("%s/SKILL.md: %d lines; keep it under 150", s.dir, n)
		}
		if _, err := os.Stat(filepath.Join(s.dir, "README.md")); err != nil {
			t.Errorf("%s: README.md with install steps is missing", s.dir)
		}
	}
}

var (
	codeSpan = regexp.MustCompile("`([^`\n]+)`")
	ident    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	call     = regexp.MustCompile(`^([a-z][a-z0-9_]*)\((.*)\)$`)
	argName  = regexp.MustCompile(`(?:^|,)\s*([a-z][a-z0-9_]*)\s*=`)
)

// TestSkillNamesExist checks every code span in a skill against the code:
//   - `gop <command> ...` must name a command of cmd/gop;
//   - `tool(arg=...)` must name an MCP tool, and each arg one of its inputs;
//   - a bare lowercase identifier must be an MCP tool, a field of a tool's
//     input or output schema, an evidence level or an answerable value.
//
// So a renamed tool, argument, field or command fails here.
func TestSkillNamesExist(t *testing.T) {
	tools, fields := serverTools(t)
	cmds := cliCommands(t)
	vocab := map[string]bool{
		mcpserver.AnswerYes: true, mcpserver.AnswerPartial: true, mcpserver.AnswerNo: true,
	}
	for _, e := range []graph.Evidence{graph.Live, graph.Inferred, graph.Audit, graph.Supplied, graph.NotVisible} {
		vocab[string(e)] = true
	}
	for _, s := range loadSkills(t) {
		used := map[string]bool{}
		for _, m := range codeSpan.FindAllStringSubmatch(s.body, -1) {
			span := strings.TrimSpace(m[1])
			switch {
			case strings.HasPrefix(span, "gop "):
				c := strings.Fields(span)[1]
				if !cmds[c] {
					t.Errorf("%s/SKILL.md: `%s`: gop has no %q command", s.dir, span, c)
				}
			case call.MatchString(span):
				cm := call.FindStringSubmatch(span)
				in, ok := tools[cm[1]]
				if !ok {
					t.Errorf("%s/SKILL.md: `%s`: the MCP server has no %q tool", s.dir, span, cm[1])
					continue
				}
				used[cm[1]] = true
				for _, a := range argName.FindAllStringSubmatch(cm[2], -1) {
					if !in[a[1]] {
						t.Errorf("%s/SKILL.md: `%s`: tool %s has no input %q", s.dir, span, cm[1], a[1])
					}
				}
			case ident.MatchString(span):
				if _, ok := tools[span]; ok {
					used[span] = true
					continue
				}
				if !fields[span] && !vocab[span] {
					t.Errorf("%s/SKILL.md: `%s` is not an MCP tool, tool field, evidence level or answerable value", s.dir, span)
				}
			}
		}
		if s.dir == "gop" {
			var missing []string
			for _, want := range []string{"coverage", "check_answerable", "top_risks", "paths", "explain", "fix_plan"} {
				if !used[want] {
					missing = append(missing, want)
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("gop/SKILL.md: the triage flow must use %s", strings.Join(missing, ", "))
			}
		}
	}
}
