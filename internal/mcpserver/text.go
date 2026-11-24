package mcpserver

import (
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sanitize"
)

// WritePath prints one path as indented hops, each with its evidence and source.
func WritePath(w io.Writer, p graph.Path) {
	status := "confirmed"
	switch {
	case p.Unverified && p.Stale:
		status = "possible: a hop is not visible or stale"
	case p.Unverified:
		status = "possible: a hop is not visible"
	}
	c := sanitize.Clean
	fmt.Fprintf(w, "  %s -> %s  [%s]\n", c(p.From), c(p.To), status)
	if n := p.SuppliedNote(); n != "" {
		fmt.Fprintf(w, "      note: %s\n", c(n))
	}
	for _, h := range p.Hops {
		kind := string(h.Kind)
		if h.Reverse {
			kind += " (reversed)"
		}
		src := ""
		if h.SourceAPI != "" {
			src = "  source: " + c(h.SourceAPI)
		}
		fmt.Fprintf(w, "      %s =[%s, %s]=> %s%s\n", c(h.From), kind, HopEvidenceLabel(h), c(h.To), src)
		if h.Reason != "" {
			fmt.Fprintf(w, "        undecided: %s\n", c(h.Reason))
		}
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
	fmt.Fprintln(w, sanitize.Line(o.Summary))
	writeGroup(w, confirmedTitle, o.Confirmed)
	writeGroup(w, "Possible (at least one hop not visible)", o.Possible)
}

// confirmedTitle heads the confirmed group in text output.
const confirmedTitle = "Confirmed (every hop live, inferred, audit or supplied)"

// WritePaths prints a paths answer as text.
func WritePaths(w io.Writer, o PathsOutput) {
	fmt.Fprintln(w, sanitize.Line(o.Summary))
	writeGroup(w, confirmedTitle, o.Confirmed)
	writeGroup(w, "Possible (at least one hop not visible)", o.Possible)
}

// firstLine is used for tool text content: summary, a blank line, then JSON.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
