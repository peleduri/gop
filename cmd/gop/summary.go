package main

import (
	"fmt"
	"io"

	"github.com/peleduri/gop/internal/summary"
)

// cmdSummary writes the gop.summary/v1 document of a graph: counts and
// coverage only, findings as hashes unless --names (see docs/cloud.md).
func (a *app) cmdSummary(args []string) error {
	fs := a.flags("summary")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	names := fs.Bool("names", false, "add repo, workflow and org names to the top findings (default: hash IDs only)")
	top := fs.Int("top", summary.DefaultTop, fmt.Sprintf("number of top findings to keep (1 to %d)", summary.MaxTop))
	out := fs.String("out", "", `path to write summary.json ("-" for stdout)`)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("summary", "out", *out); err != nil {
		return err
	}
	if *top < 1 || *top > summary.MaxTop {
		return usagef("summary: --top must be between 1 and %d, got %d", summary.MaxTop, *top)
	}
	g, err := a.loadGraph("summary", *gp, *useDemo)
	if err != nil {
		return err
	}
	s, err := summary.Build(g, summary.Options{Version: version, Names: *names, Top: *top})
	if err != nil {
		return err
	}
	b, err := summary.Marshal(s)
	if err != nil {
		return err
	}
	if err := a.writeFile(*out, func(w io.Writer) error { _, err := w.Write(b); return err }); err != nil {
		return err
	}
	note := ""
	if s.Truncated {
		note = fmt.Sprintf(" (top cut to %d to stay under %d bytes)", len(s.Top), summary.MaxBytes)
	}
	mode := "hash IDs only"
	if *names {
		mode = "with names"
	}
	fmt.Fprintf(a.stderr, "gop summary: %d bytes, %d findings, %d top findings, %s%s\n", len(b), s.Findings, len(s.Top), mode, note)
	return nil
}
