package mcpserver

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/sanitize"
)

// promptFS holds the prompt texts, one text/template per prompt, so they can
// be reviewed as plain Markdown.
//
//go:embed prompts/*.md
var promptFS embed.FS

var promptTmpl = template.Must(template.New("prompts").Option("missingkey=error").ParseFS(promptFS, "prompts/*.md"))

// focusLabels maps the triage_enterprise focus argument to its wording.
var focusLabels = map[string]string{
	"all":     "",
	"oidc":    "OIDC trusts (workflows with id-token: write)",
	"secrets": "secret scopes",
	"runners": "self-hosted runners",
}

// promptData fills the prompt templates.
type promptData struct {
	Enterprise string
	Focus      string
	FocusLabel string
	Action     string
	From       string
	To         string
}

// RenderPrompt renders the named prompt with args against the graph as of now.
// It validates required arguments and node IDs.
func (e *Engine) RenderPrompt(name string, args map[string]string, now time.Time) (string, error) {
	d := promptData{Enterprise: e.ix.Graph().Enterprise}
	var err error
	switch name {
	case "triage_enterprise":
		d.Focus = strings.TrimSpace(args["focus"])
		if d.Focus == "" {
			d.Focus = "all"
		}
		label, ok := focusLabels[d.Focus]
		if !ok {
			return "", fmt.Errorf("focus must be oidc, secrets, runners or all, got %q", d.Focus)
		}
		d.FocusLabel = label
	case "review_action":
		if d.Action, err = e.resolve("action", args["action"]); err != nil {
			return "", err
		}
	case "explain_path":
		if d.From, err = e.resolve("from", args["from"]); err != nil {
			return "", err
		}
		if d.To, err = e.resolve("to", args["to"]); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unknown prompt %q", name)
	}
	var b bytes.Buffer
	if e.demo {
		b.WriteString(DemoMarker + " This graph is synthetic demo data.\n\n")
	}
	if e.partial != "" {
		b.WriteString(PartialMarker + " " + e.partial + " Say so in the answer: missing facts may be unread, not absent.\n\n")
	}
	if st := Staleness(e.ix.Graph().CollectedAt, now); st != "" {
		fmt.Fprintf(&b, "Note: the %s (collected %s); findings may be out of date. Say so in the answer, and re-run gop collect for current state.\n\n",
			st, e.ix.Graph().CollectedAt.UTC().Format(time.RFC3339))
	}
	// Names reach the prompt as data: escape control, bidi and zero-width
	// characters so none can start a line or hide text. IDs are not cut,
	// since the prompt tells the agent to pass them back to the tools.
	d.Enterprise, d.Action, d.From, d.To = sanitize.Code(d.Enterprise), sanitize.Code(d.Action), sanitize.Code(d.From), sanitize.Code(d.To)
	if err := promptTmpl.ExecuteTemplate(&b, name+".md", d); err != nil {
		return "", err
	}
	return b.String(), nil
}

// promptDefs are the prompts the server lists, in order.
var promptDefs = []*mcp.Prompt{
	{
		Name:  "triage_enterprise",
		Title: "Triage my enterprise",
		Description: "Walk the enterprise: read the summary, rank principals with top_risks, pick fixes with " +
			"suggest_fixes, check coverage, and end with a fix list and the access needed to close gaps.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "focus",
			Title:       "Focus",
			Description: "optional: oidc, secrets, runners or all (default all)",
		}},
	},
	{
		Name:        "review_action",
		Title:       "Review an action",
		Description: "Who can change an action, which workflows consume it, and what pinning it to a SHA removes.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "action",
			Title:       "Action",
			Description: "action node ID, e.g. action:acme-actions/deploy@main",
			Required:    true,
		}},
	},
	{
		Name:        "explain_path",
		Title:       "Explain a path",
		Description: "Walk each hop of the path from a principal to a target with explain.",
		Arguments: []*mcp.PromptArgument{
			{Name: "from", Title: "From", Description: "principal node ID, e.g. members:acme-actions", Required: true},
			{Name: "to", Title: "To", Description: "target node ID, e.g. oidc:acme-app/web", Required: true},
		},
	},
}

// addPrompts registers the triage prompts. now is the clock used for snapshot age.
func addPrompts(s *mcp.Server, e *Engine, now func() time.Time) {
	for _, p := range promptDefs {
		s.AddPrompt(p, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			text, err := e.RenderPrompt(p.Name, req.Params.Arguments, now())
			if err != nil {
				return nil, err
			}
			return &mcp.GetPromptResult{
				Description: p.Description,
				Messages:    []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}},
			}, nil
		})
	}
}
