package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// controlGraphComment returns the control-graph rules comment above
// controlGraph in internal/graph/reach.go, with the "//\t" prefix removed.
func controlGraphComment(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../internal/graph/reach.go")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	in := false
	for _, l := range strings.Split(string(src), "\n") {
		switch {
		case strings.HasPrefix(l, "// The control graph is directed"):
			in = true
		case in && strings.HasPrefix(l, "type controlGraph"):
			return strings.Join(lines, "\n")
		case in && strings.HasPrefix(l, "//\t"):
			lines = append(lines, strings.TrimRight(strings.TrimPrefix(l, "//\t"), " "))
		}
	}
	t.Fatal("control-graph rules comment not found in internal/graph/reach.go")
	return ""
}

// TestArchitectureControlGraphRules keeps the copy of the control-graph rules
// in docs/architecture.md identical to the comment in reach.go, the source of
// truth.
func TestArchitectureControlGraphRules(t *testing.T) {
	doc, err := os.ReadFile("architecture.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- control-graph-rules:begin -->\n```text\n", "\n```\n<!-- control-graph-rules:end -->"
	s := string(doc)
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatal("docs/architecture.md: control-graph-rules markers not found")
	}
	got := s[i+len(begin) : j]
	if want := controlGraphComment(t); got != want {
		t.Errorf("docs/architecture.md control-graph rules differ from internal/graph/reach.go; "+
			"paste the comment above controlGraph between the markers.\n--- reach.go\n%s\n--- architecture.md\n%s", want, got)
	}
}

// mdLink matches inline Markdown links and images: [text](target) or
// [text](target "title").
var mdLink = regexp.MustCompile(`\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// TestRelativeLinks checks that every relative link in the top-level Markdown
// files and in docs/ points at a file or directory that exists. External
// links (http, mailto) and pure in-page anchors are not checked here.
func TestRelativeLinks(t *testing.T) {
	files := []string{
		"../README.md", "../SUPPORT.md", "../CONTRIBUTING.md", "../SECURITY.md",
		"../GOVERNANCE.md", "../MAINTAINERS.md", "../CODE_OF_CONDUCT.md", "../ADOPTERS.md", "../ROADMAP.md",
	}
	docs, err := filepath.Glob("*.md")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, docs...)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		inFence := false
		for n, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			for _, m := range mdLink.FindAllStringSubmatch(line, -1) {
				target := m[1]
				if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
					continue
				}
				if i := strings.IndexByte(target, '#'); i >= 0 {
					target = target[:i]
				}
				p := filepath.Join(filepath.Dir(f), filepath.FromSlash(target))
				if _, err := os.Stat(p); err != nil {
					t.Errorf("%s:%d: broken link %q", f, n+1, m[1])
				}
			}
		}
	}
}

// TestIssueForms checks the issue forms in .github/ISSUE_TEMPLATE against the
// parts of GitHub's issue form schema that a typo breaks: top-level keys, body
// element types, unique ids, labels and dropdown options. GitHub rejects an
// invalid form silently (it falls back to no template), so this runs in CI.
func TestIssueForms(t *testing.T) {
	forms, err := filepath.Glob("../.github/ISSUE_TEMPLATE/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(forms) < 4 {
		t.Fatalf("found %d issue templates, want at least 4", len(forms))
	}
	types := map[string]bool{"markdown": true, "textarea": true, "input": true, "dropdown": true, "checkboxes": true}
	for _, f := range forms {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(f) == "config.yml" {
			var cfg struct {
				Blank    *bool `yaml:"blank_issues_enabled"`
				Contacts []struct {
					Name, URL, About string
				} `yaml:"contact_links"`
			}
			if err := yaml.Unmarshal(src, &cfg); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			for i, c := range cfg.Contacts {
				if c.Name == "" || c.About == "" || !strings.HasPrefix(c.URL, "https://") {
					t.Errorf("%s: contact_links[%d] needs name, about and an https url", f, i)
				}
			}
			continue
		}
		var form struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			Body        []struct {
				Type       string                 `yaml:"type"`
				ID         string                 `yaml:"id"`
				Attributes map[string]interface{} `yaml:"attributes"`
			} `yaml:"body"`
		}
		if err := yaml.Unmarshal(src, &form); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if form.Name == "" || form.Description == "" || len(form.Body) == 0 {
			t.Errorf("%s: name, description and body are required", f)
		}
		ids := map[string]bool{}
		nonMarkdown := 0
		for i, el := range form.Body {
			where := f + ": body[" + strconv.Itoa(i) + "]"
			if !types[el.Type] {
				t.Errorf("%s: unknown type %q", where, el.Type)
			}
			if el.ID != "" {
				if ids[el.ID] {
					t.Errorf("%s: duplicate id %q", where, el.ID)
				}
				ids[el.ID] = true
			}
			switch el.Type {
			case "markdown":
				if s, _ := el.Attributes["value"].(string); s == "" {
					t.Errorf("%s: markdown needs attributes.value", where)
				}
				continue
			case "dropdown", "checkboxes":
				if opts, _ := el.Attributes["options"].([]interface{}); len(opts) == 0 {
					t.Errorf("%s: %s needs attributes.options", where, el.Type)
				}
			}
			nonMarkdown++
			if s, _ := el.Attributes["label"].(string); s == "" {
				t.Errorf("%s: %s needs attributes.label", where, el.Type)
			}
		}
		if nonMarkdown == 0 {
			t.Errorf("%s: a form needs at least one non-markdown field", f)
		}
	}
}
