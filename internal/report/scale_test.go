package report

import (
	"bytes"
	"encoding/json"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// scaleSpec is graph.LargeEnterprise at a quarter of its repos and
// principals: big enough that a report which walks or embeds every
// (principal, target) pair blows the budgets below, small enough for go
// test -race.
var scaleSpec = graph.LargeSpec{Orgs: 20, Repos: 2000, Actions: 400, Principals: 5000,
	Agents: 66, Owners: 75, OwnedOrgs: 6, ExtraMemberships: 2}

// Budgets for TestRenderScale. On scaleSpec the report now writes a page of
// about 2.5 MB and a Markdown file of about 700 lines, peaks near 400 MB of
// heap over the loaded graph and takes a few seconds. Before it shared reach,
// bounded its embedded paths and capped the long sections, the same graph
// gave a 10 MB page, 2,200 Markdown lines and a 1.6 GB heap peak.
const (
	scaleHTMLBytes = 5 << 20 // a page a browser opens comfortably
	scaleMDLines   = 1500
	scalePeakBytes = 1 << 30 // heap in use over the loaded graph during one Render
	scaleWall      = 30 * time.Second
)

type scaleRun struct {
	out   []byte
	peak  uint64 // most heap in use (live and not yet swept) seen while rendering
	alloc uint64 // bytes allocated
	wall  time.Duration
}

// heapInUse is the heap object bytes the runtime holds right now.
func heapInUse() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

func renderMeasured(t testing.TB, g *graph.Graph, format string) scaleRun {
	t.Helper()
	var buf bytes.Buffer
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	base := heapInUse()
	stop, done := make(chan struct{}), make(chan uint64)
	go func() {
		var peak uint64
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			peak = max(peak, heapInUse())
			select {
			case <-stop:
				done <- peak
				return
			case <-tick.C:
			}
		}
	}()
	start := time.Now()
	if err := Render(&buf, g, Options{Format: format}); err != nil {
		t.Fatal(err)
	}
	wall := time.Since(start)
	close(stop)
	peak := <-done
	runtime.ReadMemStats(&after)
	return scaleRun{out: buf.Bytes(), peak: peak - min(peak, base), alloc: after.TotalAlloc - before.TotalAlloc, wall: wall}
}

// TestRenderScale renders both formats on a large synthetic enterprise and
// fails when the page size, the heap peak or (without -race) the wall time
// regresses badly, or when a long section stops being capped. Counts
// stay exact: the capped sections say how many rows they left out.
func TestRenderScale(t *testing.T) {
	if testing.Short() {
		t.Skip("large synthetic report in -short mode")
	}
	g := graph.SyntheticLarge(1, scaleSpec)
	for _, format := range []string{"html", "md"} {
		r := renderMeasured(t, g, format)
		t.Logf("%s: %d bytes, peak heap %d MB over the graph, %d MB allocated, %s", format, len(r.out), r.peak>>20, r.alloc>>20, r.wall.Round(time.Millisecond))
		if r.peak > scalePeakBytes {
			t.Errorf("%s report peaked at %d MB of heap over the loaded graph, budget %d MB", format, r.peak>>20, scalePeakBytes>>20)
		}
		if !raceEnabled && r.wall > scaleWall {
			t.Errorf("%s report took %s, budget %s", format, r.wall, scaleWall)
		}
		out := string(r.out)
		for _, want := range []string{"more agent workflows are not listed here", "gop report --rows 0 lists every one"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s report: capped agents section missing %q", format, want)
			}
		}
		switch format {
		case "html":
			if len(r.out) > scaleHTMLBytes {
				t.Errorf("HTML report is %d bytes, budget %d", len(r.out), scaleHTMLBytes)
			}
			var e embedded
			if err := json.Unmarshal([]byte(embeddedJSON(t, out)), &e); err != nil {
				t.Fatal(err)
			}
			if len(e.Paths) > maxEmbeddedPaths || len(e.Truncated) == 0 {
				t.Errorf("%d embedded paths, %d truncated orgs: want at most %d paths and a truncation note", len(e.Paths), len(e.Truncated), maxEmbeddedPaths)
			}
		case "md":
			if n := strings.Count(out, "\n"); n > scaleMDLines {
				t.Errorf("Markdown report is %d lines, budget %d", n, scaleMDLines)
			}
		}
	}
}

// BenchmarkRenderLarge times both formats on graph.LargeEnterprise (40
// orgs, 8,000 repos, 264 agent workflows, about a million edges) and reports
// the page size. Run it with -benchtime=1x.
func BenchmarkRenderLarge(b *testing.B) {
	g := graph.SyntheticLarge(1, graph.LargeEnterprise)
	for _, format := range []string{"html", "md"} {
		b.Run(format, func(b *testing.B) {
			b.ReportAllocs()
			var n int
			for b.Loop() {
				var buf bytes.Buffer
				if err := Render(&buf, g, Options{Format: format}); err != nil {
					b.Fatal(err)
				}
				n = buf.Len()
			}
			b.ReportMetric(float64(n)/(1<<20), "MB/page")
		})
	}
}
