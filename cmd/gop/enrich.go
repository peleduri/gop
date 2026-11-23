package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/cartography"
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

const cartographyUsage = "JSON or cypher-shell export of docs/cartography/oidc-trusts.cypher run against a Cartography Neo4j database: " +
	"AWS role trusts of GitHub Actions and the roles CloudTrail saw each repo assume. Read locally; gop never connects to Neo4j"

// cmdEnrich adds CAN_ASSUME paths into cloud roles from supplied trust files
// and a Cartography export. It is offline: no token, no network.
func (a *app) cmdEnrich(args []string) error {
	fs := a.flags("enrich")
	gp := graphFlag(fs)
	out := fs.String("out", "", `path to write the enriched graph.json ("-" for stdout)`)
	var trusts trustFlag
	fs.Var(&trusts, "oidc-trust", trustUsage)
	carto := fs.String("cartography", "", cartographyUsage)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("enrich", "graph", *gp, "out", *out); err != nil {
		return err
	}
	if len(trusts) == 0 && *carto == "" {
		return usagef("enrich: --oidc-trust or --cartography is required")
	}
	g, err := a.loadGraph("enrich", *gp, false)
	if err != nil {
		return err
	}
	if err := a.enrich(g, trusts, *carto); err != nil {
		return err
	}
	return a.writeFile(*out, func(w io.Writer) error { return collect.WriteGraph(w, g) })
}

// enrich parses the trust files and the Cartography export (either may be
// empty) and adds their CAN_ASSUME edges to g in one oidc.Enrich call.
func (a *app) enrich(g *graph.Graph, paths []string, cartographyPath string) error {
	var files []string
	res := &oidc.Result{}
	if len(paths) > 0 {
		var err error
		if files, err = oidc.TrustFiles(paths...); err != nil {
			return fmt.Errorf("--oidc-trust: %w", err)
		}
		if res, err = oidc.Parse(oidc.Options{}, paths...); err != nil {
			return fmt.Errorf("--oidc-trust: %w", err)
		}
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(a.stderr, "gop enrich: warning: %s\n", w)
	}
	trusts := res.Trusts
	var cr *cartography.Result
	if cartographyPath != "" {
		var err error
		if cr, err = cartography.ReadFile(cartographyPath); err != nil {
			return fmt.Errorf("--cartography: %w", err)
		}
		for _, w := range cr.Warnings {
			fmt.Fprintf(a.stderr, "gop enrich: warning: %s\n", w)
		}
		trusts = append(append([]oidc.Trust(nil), trusts...), cr.Trusts...)
		files = append(files, cr.File)
	}
	st := oidc.Enrich(g, trusts, files, res.Warnings)
	fmt.Fprintf(a.stderr, "gop enrich: %d trusts from %d files: %d confirmed and %d possible paths into %d cloud targets; %d oidc nodes match no supplied trust (cloud hops come from supplied files, not from the cloud)\n",
		len(trusts), len(files), st.Confirmed, st.Possible, st.Targets, st.Unmatched)
	if cr != nil {
		warns, ast := cartography.Annotate(g, cr)
		for _, w := range warns {
			fmt.Fprintf(a.stderr, "gop enrich: warning: %s\n", w)
		}
		fmt.Fprintf(a.stderr, "gop enrich: cartography %s: %d trusts from %d trust rows, %d observed-use rows; %d CAN_ASSUME edges marked observed_use, %d observations match no trust (not added)\n",
			cr.File, len(cr.Trusts), cr.TrustRows, len(cr.Observations), ast.Observed, ast.Orphans)
	}
	return nil
}
