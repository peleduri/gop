package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/oidc"
)

// trustFlag collects --oidc-trust values: repeatable, each a file, a
// directory or a comma list of them.
type trustFlag []string

func (t *trustFlag) String() string { return strings.Join(*t, ",") }

func (t *trustFlag) Set(v string) error {
	*t = append(*t, splitList(v)...)
	return nil
}

const trustUsage = "cloud OIDC trust file or directory of *.json files (AWS role or trust policy, GCP workload identity provider " +
	"or service account IAM policy, Azure federated credentials); repeatable or comma-separated. Read locally, never from the cloud"

// cmdEnrich adds CAN_ASSUME paths into cloud roles from supplied trust files.
// It is offline: no token, no network.
func (a *app) cmdEnrich(args []string) error {
	fs := a.flags("enrich")
	gp := graphFlag(fs)
	out := fs.String("out", "", `path to write the enriched graph.json ("-" for stdout)`)
	var trusts trustFlag
	fs.Var(&trusts, "oidc-trust", trustUsage)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("enrich", "graph", *gp, "out", *out); err != nil {
		return err
	}
	if len(trusts) == 0 {
		return usagef("enrich: --oidc-trust is required")
	}
	g, err := a.loadGraph("enrich", *gp, false)
	if err != nil {
		return err
	}
	if err := a.enrich(g, trusts); err != nil {
		return err
	}
	return a.writeFile(*out, func(w io.Writer) error { return collect.WriteGraph(w, g) })
}

// enrich parses the trust files and adds their CAN_ASSUME edges to g.
func (a *app) enrich(g *graph.Graph, paths []string) error {
	files, err := oidc.TrustFiles(paths...)
	if err != nil {
		return fmt.Errorf("--oidc-trust: %w", err)
	}
	res, err := oidc.Parse(oidc.Options{}, paths...)
	if err != nil {
		return fmt.Errorf("--oidc-trust: %w", err)
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(a.stderr, "gop enrich: warning: %s\n", w)
	}
	st := oidc.Enrich(g, res.Trusts, files, res.Warnings)
	fmt.Fprintf(a.stderr, "gop enrich: %d trusts from %d files: %d confirmed and %d possible paths into %d cloud targets; %d oidc nodes match no supplied trust (cloud hops come from supplied files, not from the cloud)\n",
		len(res.Trusts), len(files), st.Confirmed, st.Possible, st.Targets, st.Unmatched)
	return nil
}
