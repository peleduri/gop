package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/testutil"
)

// TestGoldenToolText goldens the full TextContent of one representative call
// per tool, driven through the in-memory MCP transport.
func TestGoldenToolText(t *testing.T) {
	cs := connect(t)
	for _, tc := range []struct {
		golden, tool string
		args         map[string]any
	}{
		{"who_can_reach.txt", "who_can_reach", map[string]any{"target": "repo:acme-app/web", "detail": "full"}},
		{"blast_radius.txt", "blast_radius", map[string]any{"principal": "members:acme-actions", "detail": "full"}},
		{"paths.txt", "paths", map[string]any{"from": "members:acme-actions", "to": "oidc:acme-app/web", "detail": "full"}},
		{"top_risks.txt", "top_risks", map[string]any{"n": 3, "detail": "full"}},
		{"what_if.txt", "what_if", map[string]any{"fixes": []map[string]any{
			{"type": "pin_ref", "action": "action:acme-actions/deploy@main"},
		}}},
		{"suggest_fixes.txt", "suggest_fixes", map[string]any{"budget": 3, "detail": "full"}},
		{"explain.txt", "explain", map[string]any{"from": "repo:acme-actions/deploy", "to": "action:acme-actions/deploy@main"}},
		{"coverage.txt", "coverage", map[string]any{}},
		{"check_answerable.txt", "check_answerable", map[string]any{"question_kind": "who_can_reach", "subject": "acme-legacy"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("tool error: %s", text(res))
			}
			testutil.Golden(t, tc.golden, []byte(text(res)))
		})
	}
}
