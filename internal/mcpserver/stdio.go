package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// drainTimeout bounds how long a closed input waits for replies still being
// computed.
var drainTimeout = 30 * time.Second

// serveStream runs srv over a line-delimited JSON-RPC stream.
//
// The SDK ends the session as soon as the input reaches EOF, which drops
// replies to requests still in flight: `echo '...' | gop serve` printed
// nothing and exited 0. serveStream holds the EOF back until every request
// read so far has a reply written (or drainTimeout passes, or ctx ends).
//
//	stdin ──► countingReader (requests += frames with id+method) ──► SDK
//	SDK   ──► countingWriter (replies  += frames with id, no method) ──► stdout
//	EOF on stdin: wait until replies >= requests, then pass EOF on
func serveStream(ctx context.Context, srv *mcp.Server, r io.Reader, w io.Writer) error {
	p := &pending{}
	p.cond = sync.NewCond(&p.mu)
	cr := &countingReader{r: r, p: p, ctx: ctx}
	cw := &countingWriter{w: w, p: p}
	return srv.Run(ctx, &mcp.IOTransport{Reader: io.NopCloser(cr), Writer: nopWriteCloser{cw}})
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// pending counts requests read and replies written.
type pending struct {
	mu       sync.Mutex
	cond     *sync.Cond
	requests int
	replies  int
}

func (p *pending) add(req, rep int) {
	p.mu.Lock()
	p.requests += req
	p.replies += rep
	p.mu.Unlock()
	p.cond.Broadcast()
}

// wait blocks until every request has a reply, the timeout passes or ctx ends.
func (p *pending) wait(ctx context.Context, timeout time.Duration) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		case <-stop:
			return
		}
		p.mu.Lock()
		p.replies = p.requests // give up waiting
		p.mu.Unlock()
		p.cond.Broadcast()
	}()
	p.mu.Lock()
	for p.replies < p.requests {
		p.cond.Wait()
	}
	p.mu.Unlock()
}

// frame is the part of a JSON-RPC message that tells requests from replies.
type frame struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

// classify returns (1, 0) for a request, (0, 1) for a reply, else (0, 0).
func classify(line []byte) (req, rep int) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return 0, 0
	}
	var f frame
	if json.Unmarshal(line, &f) != nil {
		return 0, 0
	}
	hasID := len(f.ID) > 0 && string(f.ID) != "null"
	switch {
	case hasID && f.Method != "":
		return 1, 0
	case hasID && f.Method == "":
		return 0, 1
	}
	return 0, 0
}

// lines splits a byte stream into complete lines across calls.
type lines struct{ buf []byte }

func (l *lines) feed(b []byte, each func([]byte)) {
	l.buf = append(l.buf, b...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			return
		}
		each(l.buf[:i])
		l.buf = l.buf[i+1:]
	}
}

type countingReader struct {
	r   io.Reader
	p   *pending
	ctx context.Context
	l   lines
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.l.feed(b[:n], func(line []byte) {
			if req, _ := classify(line); req > 0 {
				c.p.add(req, 0)
			}
		})
	}
	if err == io.EOF {
		if len(bytes.TrimSpace(c.l.buf)) > 0 { // last line without a newline
			if req, _ := classify(c.l.buf); req > 0 {
				c.p.add(req, 0)
			}
			c.l.buf = nil
		}
		if n > 0 {
			return n, nil // deliver the bytes first; EOF on the next call
		}
		c.p.wait(c.ctx, drainTimeout)
	}
	return n, err
}

type countingWriter struct {
	w io.Writer
	p *pending
	l lines
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if n > 0 {
		c.l.feed(b[:n], func(line []byte) {
			if _, rep := classify(line); rep > 0 {
				c.p.add(0, rep)
			}
		})
	}
	return n, err
}
