package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/sarif"
)

// sarifWarning is printed on every gop sarif run.
const sarifWarning = "SARIF lists attack paths: uploading it to code scanning shows them to everyone with alert access on the repo. Keep it a private artifact (see docs/sarif.md)."

// cmdSARIF writes fixable edges as SARIF 2.1.0. gop never uploads it.
func (a *app) cmdSARIF(args []string) error {
	fs := a.flags("sarif")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	out := fs.String("out", "", `path to write the SARIF log ("-" for stdout)`)
	split := fs.String("split-by-repo", "", "directory to write one SARIF log per repo that owns a fix (DIR/<owner>/<repo>.sarif, org settings in DIR/<org>.org.sarif)")
	top := fs.Int("top", 0, "keep only the first N results, most severe first (0: all)")
	minSev := fs.String("min-severity", "low", "drop results below this severity: low, medium, high or critical")
	possible := fs.Bool("include-possible", false, "include results that hold only through a not_visible hop, at level note")
	if err := parse(fs, args); err != nil {
		return err
	}
	switch {
	case *out == "" && *split == "":
		return usagef("sarif: --out or --split-by-repo is required")
	case *out != "" && *split != "":
		return usagef("sarif: use --out or --split-by-repo, not both")
	}
	if *top < 0 {
		return usagef("sarif: --top must not be negative, got %d", *top)
	}
	if _, err := sarif.ParseSeverity(*minSev); err != nil {
		return usagef("sarif: --min-severity: %v", err)
	}
	g, err := a.loadGraph("sarif", *gp, *useDemo)
	if err != nil {
		return err
	}
	log, err := sarif.Build(g, sarif.Options{Version: version, Top: *top, MinSeverity: *minSev, IncludePossible: *possible})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "gop sarif: %s\n", sarifWarning)
	if *out != "" {
		if err := a.writeFile(*out, func(w io.Writer) error { return sarif.Write(w, log) }); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "gop sarif: %d results\n", len(log.Runs[0].Results))
		return nil
	}
	return a.writeSplit(*split, sarif.Split(log))
}

// writeSplit writes DIR/<owner>/<repo>.sarif per repo and DIR/<org>.org.sarif
// per org, each 0600 in 0700 directories.
func (a *app) writeSplit(dir string, logs map[string]*sarif.Log) error {
	keys := make([]string, 0, len(logs))
	for k := range logs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	paths := make(map[string]string, len(keys))
	for _, k := range keys {
		var rel string
		if org, ok := strings.CutPrefix(k, "org:"); ok {
			if !safeName(org) {
				return fmt.Errorf("unsafe org name %q", org)
			}
			rel = org + ".org.sarif"
		} else {
			owner, repo, ok := strings.Cut(k, "/")
			if !ok || !safeName(owner) || !safeName(repo) {
				return fmt.Errorf("unsafe repository name %q", k)
			}
			rel = filepath.Join(owner, repo+".sarif")
		}
		paths[k] = filepath.Join(dir, rel)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, k := range keys {
		p := paths[k]
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		l := logs[k]
		if err := a.writeFile(p, func(w io.Writer) error { return sarif.Write(w, l) }); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "gop sarif: %s: %d results\n", p, len(l.Runs[0].Results))
	}
	if len(keys) == 0 {
		fmt.Fprintf(a.stderr, "gop sarif: no results, no files written\n")
	}
	return nil
}

// safeName accepts a GitHub login or repo name as one path component.
func safeName(s string) bool {
	if strings.Trim(s, ".") == "" {
		return false
	}
	return !strings.ContainsAny(s, `/\`+"\x00")
}
