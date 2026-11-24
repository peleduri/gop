package mcpserver

// Regression: ISSUE-001 — piped requests followed by EOF got no replies
// Found by /qa on 2026-11-25
// Report: scratchpad qa/qa-report-gop-cli-2026-11-25.md

import (
	"bytes"
	"context"
	"strings"
	"sync"
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

// TestPendingWaitGivesUpAfterTimeout: a request whose reply never comes does
// not hold the closed input open past the cap.
func TestPendingWaitGivesUpAfterTimeout(t *testing.T) {
	p := &pending{}
	p.cond = sync.NewCond(&p.mu)
	p.add(1, 0) // one request, no reply ever
	start := time.Now()
	p.wait(context.Background(), 50*time.Millisecond)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("wait took %v, want about 50ms", d)
	}
}

// TestPendingWaitStopsOnContext: cancelling the context ends the wait.
func TestPendingWaitStopsOnContext(t *testing.T) {
	p := &pending{}
	p.cond = sync.NewCond(&p.mu)
	p.add(1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	start := time.Now()
	p.wait(ctx, time.Hour)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("wait took %v after cancel", d)
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		line     string
		req, rep int
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 1, 0},
		{`{"jsonrpc":"2.0","id":"a","result":{}}`, 0, 1},
		{`{"jsonrpc":"2.0","id":2,"error":{"code":-1}}`, 0, 1},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, 0, 0},
		{`{"jsonrpc":"2.0","id":null,"error":{}}`, 0, 0},
		{`not json`, 0, 0},
		{``, 0, 0},
	} {
		req, rep := classify([]byte(c.line))
		if req != c.req || rep != c.rep {
			t.Errorf("classify(%q) = %d,%d want %d,%d", c.line, req, rep, c.req, c.rep)
		}
	}
}

func TestClassifyBatchAndCancel(t *testing.T) {
	req, rep := classify([]byte(`[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"},{"jsonrpc":"2.0","method":"n"}]`))
	if req != 2 || rep != 0 {
		t.Errorf("batch: got %d,%d want 2,0", req, rep)
	}
	req, rep = classify([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`))
	if req != 0 || rep != 1 {
		t.Errorf("cancelled: got %d,%d want 0,1", req, rep)
	}
}

// TestLinesSplitAndCap: lines are split across feeds, and a line longer
// than maxFrame is dropped without holding its bytes.
func TestLinesSplitAndCap(t *testing.T) {
	old := maxFrame
	maxFrame = 8
	defer func() { maxFrame = old }()
	var got []string
	var l lines
	each := func(b []byte) { got = append(got, string(b)) }
	l.feed([]byte("ab"), each)
	l.feed([]byte("c\nxxxxxxxx"), each)
	l.feed([]byte("xxxxxxxx\nok\n"), each)
	if len(got) != 2 || got[0] != "abc" || got[1] != "ok" {
		t.Fatalf("got %q, want [abc ok]", got)
	}
	if len(l.buf) != 0 || l.skip {
		t.Fatalf("buffer not reset: %d bytes, skip=%v", len(l.buf), l.skip)
	}
}

// TestServeStreamFinalLineWithoutNewline: the last request has no trailing
// newline and still gets its reply.
func TestServeStreamFinalLineWithoutNewline(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := serveStream(ctx, NewServer(loadAcme(t), "test"), strings.NewReader(in), &out); err != nil {
		t.Fatalf("serveStream: %v", err)
	}
	if !strings.Contains(out.String(), `"id":2,`) {
		t.Errorf("no reply to the unterminated last request: %.300s", out.String())
	}
}
