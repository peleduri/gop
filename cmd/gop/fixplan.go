package main

import (
	"strings"

	"github.com/peleduri/gop/internal/fixplan"
	"github.com/peleduri/gop/internal/mcpserver"
)

// fixFlags names the fix-plan fix flags in usage errors.
const fixFlags = "--pin, --lower-default-perm, --restrict-token or --harden-trigger"

// cmdFixPlan prints the change steps for one fix. It never runs them.
func (a *app) cmdFixPlan(args []string) error {
	fs := a.flags("fix-plan")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	pin := fs.String("pin", "", "action ref to pin to a commit SHA, e.g. action:acme-actions/deploy@main")
	lower := fs.String("lower-default-perm", "", "org whose default repository permission to lower, e.g. org:acme-actions")
	to := fs.String("to", "read", "with --lower-default-perm: read or none")
	restrict := fs.String("restrict-token", "", "workflow whose GITHUB_TOKEN to set to contents: read, e.g. workflow:acme-app/web/.github/workflows/ci.yml")
	harden := fs.String("harden-trigger", "", "workflow to stop running attacker-controlled code on its risky triggers, e.g. workflow:acme-app/docs/.github/workflows/preview.yml")
	format := fs.String("format", "text", "text, markdown or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	var specs []mcpserver.FixSpec
	if *pin != "" {
		specs = append(specs, mcpserver.FixSpec{Type: "pin_ref", Action: *pin})
	}
	if *lower != "" {
		specs = append(specs, mcpserver.FixSpec{Type: "lower_default_perm", Org: *lower, To: *to})
	}
	if *restrict != "" {
		specs = append(specs, mcpserver.FixSpec{Type: "restrict_token", Workflow: *restrict})
	}
	if *harden != "" {
		specs = append(specs, mcpserver.FixSpec{Type: "harden_trigger", Workflow: *harden})
	}
	switch len(specs) {
	case 0:
		return usagef("fix-plan: one of " + fixFlags + " is required")
	case 1:
	default:
		return usagef("fix-plan: use only one of " + fixFlags)
	}
	spec := specs[0]
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
