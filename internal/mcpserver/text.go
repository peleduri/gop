package mcpserver

import (
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// WritePath prints one path as indented hops, each with its evidence and source.
func WritePath(w io.Writer, p graph.Path) {
	status := "confirmed"
	if p.Unverified {
		status = "possible: a hop is not visible"
	}
	fmt.Fprintf(w, "  %s -> %s  [%s]\n", p.From, p.To, status)
	for _, h := range p.Hops {
		kind := string(h.Kind)
		if h.Reverse {
			kind += " (reversed)"
		}
		src := ""
		if h.SourceAPI != "" {
			src = "  source: " + h.SourceAPI
		}
		fmt.Fprintf(w, "      %s =[%s, %s]=> %s%s\n", h.From, kind, EvidenceLabel(h.Evidence), h.To, src)
	}
}

func writeGroup(w io.Writer, title string, ps []graph.Path) {
	if len(ps) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s (%d):\n", title, len(ps))
	for _, p := range ps {
		WritePath(w, p)
	}
}

// WriteWho prints a who_can_reach answer as text.
func WriteWho(w io.Writer, o WhoCanReachOutput) {
	fmt.Fprintln(w, o.Summary)
	writeGroup(w, "Confirmed (every hop live or audit)", o.Confirmed)
	writeGroup(w, "Possible (at least one hop not visible)", o.Possible)
}

// WritePaths prints a paths answer as text.
func WritePaths(w io.Writer, o PathsOutput) {
	fmt.Fprintln(w, o.Summary)
	writeGroup(w, "Confirmed (every hop live or audit)", o.Confirmed)
	writeGroup(w, "Possible (at least one hop not visible)", o.Possible)
}

// firstLine is used for tool text content: summary, a blank line, then JSON.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
