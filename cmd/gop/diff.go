package main

import (
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/peleduri/gop/internal/diff"
	"github.com/peleduri/gop/internal/graph"
)

// --fail-on conditions.
const (
	failConfirmedIncrease = "confirmed-increase"
	failAnyNewPath        = "any-new-path"
)

// parseInterspersed parses flags that may appear before, between or after
// positional arguments, and returns the positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err.Error()}
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func (a *app) cmdDiff(args []string) error {
	fs := a.flags("diff")
	format := fs.String("format", "text", "text, json or markdown")
	only := fs.String("only", "", "comma-separated sections to show: "+strings.Join(diff.Sections, ","))
	failOn := fs.String("fail-on", "", "exit 1 when: confirmed-increase (confirmed (principal, repo) pairs grow) or any-new-path (any added or upgraded path); comma-separated")
	force := fs.Bool("force", false, "compare snapshots of different enterprises, GitHub hosts or major schema versions")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usagef("diff: want OLD and NEW graph files, got %d argument(s)", len(pos))
	}
	f := strings.ToLower(*format)
	if f == "md" {
		f = "markdown"
	}
	if f != "text" && f != "json" && f != "markdown" {
		return usagef("diff: --format must be text, json or markdown, got %q", *format)
	}
	sections := splitList(*only)
	for _, s := range sections {
		if !slices.Contains(diff.Sections, s) {
			return usagef("diff: --only: unknown section %q (want %s)", s, strings.Join(diff.Sections, ","))
		}
	}
	conds := splitList(*failOn)
	for _, c := range conds {
		if c != failConfirmedIncrease && c != failAnyNewPath {
			return usagef("diff: --fail-on: unknown condition %q (want %s or %s)", c, failConfirmedIncrease, failAnyNewPath)
		}
	}
	old, err := graph.LoadFile(pos[0])
	if err != nil {
		return codeError{exitUsage, fmt.Errorf("load %s: %w", pos[0], err)}
	}
	cur, err := graph.LoadFile(pos[1])
	if err != nil {
		return codeError{exitUsage, fmt.Errorf("load %s: %w", pos[1], err)}
	}
	rep, err := diff.CompareWith(old, cur, diff.Options{Force: *force})
	if err != nil {
		return codeError{exitUsage, err}
	}
	shown := rep.Only(sections)
	switch f {
	case "json":
		if err := diff.WriteJSON(a.stdout, shown); err != nil {
			return codeError{exitRuntime, err}
		}
	case "markdown":
		diff.WriteMarkdown(a.stdout, shown)
	default:
		diff.WriteText(a.stdout, shown)
	}
	if msg := failed(rep, conds); msg != "" {
		return codeError{exitRuntime, fmt.Errorf("--fail-on matched: %s", msg)}
	}
	return nil
}

// failed evaluates --fail-on conditions on the full report (not the --only view).
func failed(r diff.Report, conds []string) string {
	var hits []string
	for _, c := range conds {
		switch c {
		case failConfirmedIncrease:
			if o, n := r.Totals.Old.ConfirmedPairs, r.Totals.New.ConfirmedPairs; n > o {
				hits = append(hits, fmt.Sprintf("%s (confirmed (principal, repo) pairs %d → %d)", c, o, n))
			}
		case failAnyNewPath:
			if n := r.Paths.Count(diff.Added, true) + r.Paths.Count(diff.Added, false) + r.Paths.Count(diff.Upgraded, false); n > 0 {
				hits = append(hits, fmt.Sprintf("%s (%d new or upgraded paths)", c, n))
			}
		}
	}
	return strings.Join(hits, "; ")
}
