package main

import (
	"flag"
	"strings"

	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/whatif"
)

// listFlag is a string flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(s string) error {
	*l = append(*l, s)
	return nil
}

// cmdWhatIf re-scores the graph with one or more hypothetical fixes applied
// and prints what changes. It never changes anything.
func (a *app) cmdWhatIf(args []string) error {
	fs := a.flags("what-if")
	gp := graphFlag(fs)
	useDemo := demoFlag(fs)
	var pins, lowers, restricts, hardens listFlag
	fs.Var(&pins, "pin", "action ref to pin to a commit SHA, e.g. action:acme-actions/deploy@main (repeatable)")
	fs.Var(&lowers, "lower-default-perm", "org whose default repository permission to lower, e.g. org:acme-actions (repeatable)")
	to := fs.String("to", "read", "with --lower-default-perm: read or none")
	fs.Var(&restricts, "restrict-token", "workflow whose GITHUB_TOKEN to set to contents: read (repeatable)")
	fs.Var(&hardens, "harden-trigger", "workflow to stop running attacker-controlled code on its risky triggers (repeatable)")
	owners := fs.Int("reduce-owners", 0, "remove standing org ownership from accounts that own this many orgs or more; at least 2 owners stay in every org")
	top := fs.Int("top", whatif.DefaultTop, "remaining top principals to list")
	limit := fs.Int("limit", whatif.DefaultLimit, "removed paths to list (0 lists all; the total is always counted)")
	format := fs.String("format", "text", "text, markdown or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["to"] && len(lowers) == 0 {
		return usagef("what-if: --to needs --lower-default-perm")
	}
	if *to != "read" && *to != "none" {
		return usagef("what-if: --to must be read or none, got %q", *to)
	}
	if *owners < 0 {
		return usagef("what-if: --reduce-owners must be positive, got %d", *owners)
	}
	if *top < 1 {
		return usagef("what-if: --top must be at least 1, got %d", *top)
	}
	if *limit < 0 {
		return usagef("what-if: --limit must be 0 (all) or more, got %d", *limit)
	}
	var specs []mcpserver.FixSpec
	seen := map[string]bool{}
	add := func(name, value string, spec mcpserver.FixSpec) error {
		key := name + "=" + value
		if seen[key] {
			return usagef("what-if: --%s %s is given twice", name, value)
		}
		seen[key] = true
		specs = append(specs, spec)
		return nil
	}
	for _, v := range pins {
		if err := add("pin", v, mcpserver.FixSpec{Type: "pin_ref", Action: v}); err != nil {
			return err
		}
	}
	for _, v := range lowers {
		if err := add("lower-default-perm", v, mcpserver.FixSpec{Type: "lower_default_perm", Org: v, To: *to}); err != nil {
			return err
		}
	}
	for _, v := range restricts {
		if err := add("restrict-token", v, mcpserver.FixSpec{Type: "restrict_token", Workflow: v}); err != nil {
			return err
		}
	}
	for _, v := range hardens {
		if err := add("harden-trigger", v, mcpserver.FixSpec{Type: "harden_trigger", Workflow: v}); err != nil {
			return err
		}
	}
	if *owners > 0 {
		specs = append(specs, mcpserver.FixSpec{Type: "reduce_owners", Threshold: *owners})
	}
	if len(specs) == 0 {
		return usagef("what-if: at least one of " + fixFlags + " is required")
	}
	f := strings.ToLower(*format)
	if f == "md" {
		f = "markdown"
	}
	if f != "text" && f != "markdown" && f != "json" {
		return usagef("what-if: --format must be text, markdown or json, got %q", *format)
	}
	g, err := a.loadGraph("what-if", *gp, *useDemo)
	if err != nil {
		return err
	}
	lim := *limit
	if lim == 0 {
		lim = -1 // all
	}
	r, err := mcpserver.NewEngine(g).WhatIfReport(mcpserver.WhatIfInput{Fixes: specs}, whatif.Options{Top: *top, Limit: lim})
	if err != nil {
		return err
	}
	switch f {
	case "json":
		return whatif.WriteJSON(a.stdout, r)
	case "markdown":
		whatif.WriteMarkdown(a.stdout, r)
	default:
		whatif.WriteText(a.stdout, r)
	}
	return nil
}
