package mcpserver

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/testutil"
)

func getPrompt(t *testing.T, cs *mcp.ClientSession, name string, args map[string]string) string {
	t.Helper()
	res, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(res.Messages) != 1 || res.Messages[0].Role != "user" {
		t.Fatalf("%s: messages = %+v", name, res.Messages)
	}
	tc, ok := res.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: content %T", name, res.Messages[0].Content)
	}
	return tc.Text
}

func TestPromptsListed(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	res, err := cs.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	type arg struct {
		name     string
		required bool
	}
	want := map[string][]arg{
		"triage_enterprise": {{"focus", false}},
		"review_action":     {{"action", true}},
		"explain_path":      {{"from", true}, {"to", true}},
	}
	if len(res.Prompts) != len(want) {
		t.Fatalf("prompts = %d, want %d", len(res.Prompts), len(want))
	}
	for _, p := range res.Prompts {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected prompt %s", p.Name)
			continue
		}
		if p.Description == "" || len(p.Arguments) != len(w) {
			t.Errorf("%s: description %q, %d args", p.Name, p.Description, len(p.Arguments))
			continue
		}
		for i, a := range p.Arguments {
			if a.Name != w[i].name || a.Required != w[i].required || a.Description == "" {
				t.Errorf("%s arg %d = %+v, want %+v", p.Name, i, a, w[i])
			}
		}
	}
}

func TestGoldenPrompts(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	for _, tc := range []struct {
		golden, name string
		args         map[string]string
	}{
		{"prompt_triage_enterprise.md", "triage_enterprise", nil},
		{"prompt_triage_enterprise_oidc.md", "triage_enterprise", map[string]string{"focus": "oidc"}},
		{"prompt_review_action.md", "review_action", map[string]string{"action": "action:acme-actions/deploy@main"}},
		{"prompt_explain_path.md", "explain_path", map[string]string{"from": "members:acme-actions", "to": "oidc:acme-app/web"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			text := getPrompt(t, cs, tc.name, tc.args)
			for _, a := range tc.args {
				if !strings.Contains(strings.ToLower(text), a) {
					t.Errorf("argument %q not filled in", a)
				}
			}
			if strings.Contains(text, "snapshot is") {
				t.Errorf("fresh snapshot warned as stale")
			}
			testutil.Golden(t, tc.golden, []byte(text))
		})
	}
}

// TestPromptTextsKeepEvidenceRules checks every embedded prompt keeps the
// confirmed vs possible split and the not_visible-is-not-off rule, and uses
// only synthetic acme names.
func TestPromptTextsKeepEvidenceRules(t *testing.T) {
	names, err := fs.Glob(promptFS, "prompts/*.md")
	if err != nil || len(names) != 3 {
		t.Fatalf("prompts = %v, %v", names, err)
	}
	// Words that look like an org, owner or repo name must be acme ones.
	nameRe := regexp.MustCompile(`[a-z0-9]+-[a-z0-9-]+/[a-z0-9-]+`)
	for _, n := range names {
		b, err := fs.ReadFile(promptFS, n)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, want := range []string{"Keep confirmed and possible separate", "Possible means", "not_visible", "Never say", "unknown (not visible)"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: missing %q", n, want)
			}
		}
		for _, m := range nameRe.FindAllString(s, -1) {
			if !strings.HasPrefix(m, "acme-") {
				t.Errorf("%s: non-synthetic name %q", n, m)
			}
		}
	}
}

func TestPromptStaleness(t *testing.T) {
	g := loadAcme(t)
	cs := connectAt(t, g, g.CollectedAt.Add(9*24*time.Hour))
	for _, tc := range []struct {
		name string
		args map[string]string
	}{
		{"triage_enterprise", map[string]string{"focus": "runners"}},
		{"review_action", map[string]string{"action": "action:acme-actions/deploy@main"}},
		{"explain_path", map[string]string{"from": "members:acme-actions", "to": "oidc:acme-app/web"}},
	} {
		if text := getPrompt(t, cs, tc.name, tc.args); !strings.HasPrefix(text, "Note: the snapshot is 9 days old") {
			t.Errorf("%s: no staleness line: %q", tc.name, firstLine(text))
		}
	}
}

func TestPromptArgumentErrors(t *testing.T) {
	cs := connectAt(t, loadAcme(t), acmeNow)
	for _, tc := range []struct {
		name string
		args map[string]string
		want string
	}{
		{"triage_enterprise", map[string]string{"focus": "everything"}, "focus must be"},
		{"review_action", nil, "action is required"},
		{"review_action", map[string]string{"action": "action:acme-actions/deploy@mai"}, "action:acme-actions/deploy@main"},
		{"explain_path", map[string]string{"from": "members:acme-actions"}, "to is required"},
	} {
		_, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: tc.name, Arguments: tc.args})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %v: err = %v, want %q", tc.name, tc.args, err, tc.want)
		}
	}
}
