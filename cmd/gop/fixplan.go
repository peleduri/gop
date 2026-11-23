package main

import (
	"strings"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/mcpserver"
)

// cmdFixPlan prints the change steps for one fix. It never runs them.
func (a *app) cmdFixPlan(args []string) error {
	fs := a.flags("fix-plan")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	pin := fs.String("pin", "", "action ref to pin to a commit SHA, e.g. action:acme-actions/deploy@main")
	lower := fs.String("lower-default-perm", "", "org whose default repository permission to lower, e.g. org:acme-actions")
	to := fs.String("to", "read", "with --lower-default-perm: read or none")
	format := fs.String("format", "text", "text, markdown or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	var spec mcpserver.FixSpec
	switch {
	case *pin != "" && *lower != "":
		return usagef("fix-plan: use --pin or --lower-default-perm, not both")
	case *pin != "":
		spec = mcpserver.FixSpec{Type: "pin_ref", Action: *pin}
	case *lower != "":
		spec = mcpserver.FixSpec{Type: "lower_default_perm", Org: *lower, To: *to}
	default:
		return usagef("fix-plan: --pin or --lower-default-perm is required")
	}
	f := strings.ToLower(*format)
	if f == "md" {
		f = "markdown"
	}
	if f != "text" && f != "markdown" && f != "json" {
		return usagef("fix-plan: --format must be text, markdown or json, got %q", *format)
	}
	g, err := a.loadGraph("fix-plan", *gp, *useDemo)
	if err != nil {
		return err
	}
	out, err := mcpserver.NewEngine(g).FixPlan(mcpserver.FixPlanInput{Fix: &spec})
	if err != nil {
		return err
	}
	switch f {
	case "json":
		return fixplan.WriteJSON(a.stdout, out.Plan)
	case "markdown":
		fixplan.WriteMarkdown(a.stdout, out.Plan)
	default:
		fixplan.WriteText(a.stdout, out.Plan)
	}
	return nil
}
