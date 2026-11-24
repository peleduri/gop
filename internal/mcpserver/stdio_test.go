package mcpserver

// Regression: ISSUE-001 — piped requests followed by EOF got no replies
// Found by /qa on 2026-11-25
// Report: scratchpad qa/qa-report-gop-cli-2026-11-25.md

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestServeStreamAnswersBeforeEOF: a client that writes its requests and
// closes stdin at once (echo ... | gop serve) still gets one reply per request.
func TestServeStreamAnswersBeforeEOF(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"who_can_reach","arguments":{"target":"repo:acme-actions/deploy"}}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := serveStream(ctx, NewServer(loadAcme(t), "test"), strings.NewReader(in), &out); err != nil {
		t.Fatalf("serveStream: %v", err)
	}
	for _, id := range []string{`"id":1,`, `"id":2,`, `"id":3,`} {
		if !strings.Contains(out.String(), id) {
			t.Errorf("no reply with %s; output %d bytes: %.300s", id, out.Len(), out.String())
		}
	}
}
