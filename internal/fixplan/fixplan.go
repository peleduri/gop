// Package fixplan turns a graph fix (pin an action ref, lower an org's default
// repository permission, restrict a workflow's GITHUB_TOKEN, harden a risky
// trigger) into concrete change steps: the workflow lines to edit, with a
// one-line diff or the change to make, and the settings to change.
//
// gop is read-only. A plan is text for a human or a coding agent to act on with
// their own credentials, outside gop: Build never runs a step, and the REST
// calls it names are documentation, never requests. This package works only on
// a loaded graph and makes no network calls.
package fixplan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Step kinds.
const (
	KindEditWorkflow  = "edit_workflow"
	KindChangeSetting = "change_setting"
	KindVerify        = "verify"
)

// ConfirmFirst is the note on a step whose evidence edge is not_visible.
const ConfirmFirst = "not visible to the token: confirm this exists first"

// FixSpec describes one fix in the shape the MCP tools take.
type FixSpec struct {
	Type     string `json:"type" jsonschema:"pin_ref, lower_default_perm, restrict_token, harden_trigger, block_bot_merge, reduce_owners, or the advisory require_reviews and enable_push_protection"`
	Action   string `json:"action,omitempty" jsonschema:"for pin_ref: the action node ID, e.g. action:acme-actions/deploy@main"`
	Org      string `json:"org,omitempty" jsonschema:"for lower_default_perm: the org node ID, e.g. org:acme-actions"`
	To       string `json:"to,omitempty" jsonschema:"for lower_default_perm: read or none"`
	Workflow string `json:"workflow,omitempty" jsonschema:"for restrict_token and harden_trigger: the workflow node ID, e.g. workflow:acme-app/web/.github/workflows/ci.yml"`
	Repo     string `json:"repo,omitempty" jsonschema:"for block_bot_merge and the advisory require_reviews and enable_push_protection: the repo node ID, e.g. repo:acme-app/web"`
	// Threshold is for reduce_owners: accounts that own this many orgs or
	// more lose standing ownership (0: graph.DefaultOwnerThreshold).
	Threshold int `json:"threshold,omitempty" jsonschema:"for reduce_owners: remove standing org ownership from accounts that own this many orgs or more (default 5); at least 2 owners stay in every org"`
}

// Step is one change a person or agent makes outside gop.
type Step struct {
	Kind    string `json:"kind" jsonschema:"edit_workflow, change_setting or verify"`
	Repo    string `json:"repo,omitempty" jsonschema:"repository the step applies to, e.g. acme-app/web"`
	File    string `json:"file,omitempty" jsonschema:"repo-relative file to edit, e.g. .github/workflows/release.yml"`
	FileRef string `json:"file_ref,omitempty" jsonschema:"commit or branch the file was read at, when known"`
	Line    int    `json:"line,omitempty" jsonschema:"1-based line of the uses: value; 0 or absent when the graph has no line attributes"`
	Col     int    `json:"col,omitempty"`
	Diff    string `json:"diff,omitempty" jsonschema:"unified diff for the one line, when the line is known"`
	Change  string `json:"change,omitempty" jsonschema:"the edit to make, in words, when a diff cannot be given"`
	Setting string `json:"setting,omitempty" jsonschema:"where the setting lives in the GitHub UI"`
	API     string `json:"api,omitempty" jsonschema:"the REST call that makes the same change, as text only: gop never calls it"`
	Owner   string `json:"owner,omitempty" jsonschema:"org that must make the change"`
	Edge    string `json:"edge,omitempty" jsonschema:"the evidence edge behind the step, as from KIND to"`
	// Evidence of the edge or setting behind the step. not_visible steps are
	// marked Unconfirmed and listed last.
	Evidence    graph.Evidence `json:"evidence,omitempty"`
	Unconfirmed bool           `json:"unconfirmed,omitempty" jsonschema:"true when the evidence is not_visible: confirm the edge exists before acting"`
	Note        string         `json:"note,omitempty"`
}

// Plan is the change list for one fix.
type Plan struct {
	FixID       string  `json:"fix_id"`
	Fix         FixSpec `json:"fix"`
	Description string  `json:"description"`
	// Removes compares reach before and after the fix. PerPrincipal keeps only
	// the principals whose reach changes.
	Removes graph.Delta `json:"removes"`
	Steps   []Step      `json:"steps"`
	Caveats []string    `json:"caveats"`
}

// Spec returns the FixSpec and a one-sentence description of a graph fix.
func Spec(f graph.Fix) (FixSpec, string) {
	switch v := f.(type) {
	case graph.PinRef:
		return FixSpec{Type: "pin_ref", Action: v.Action},
			"Pin " + strings.TrimPrefix(v.Action, "action:") + " to a commit SHA in every workflow that uses it"
	case graph.LowerDefaultPerm:
		return FixSpec{Type: "lower_default_perm", Org: v.Org, To: v.To},
			"Lower the default repository permission of " + strings.TrimPrefix(v.Org, "org:") + " to " + v.To
	case graph.RestrictToken:
		return FixSpec{Type: "restrict_token", Workflow: v.Workflow},
			"Set permissions: contents: read on the GITHUB_TOKEN of " + strings.TrimPrefix(v.Workflow, "workflow:")
	case graph.HardenTrigger:
		return FixSpec{Type: "harden_trigger", Workflow: v.Workflow},
			"Stop " + strings.TrimPrefix(v.Workflow, "workflow:") + " from running attacker-controlled code on its risky triggers"
	case graph.BlockBotMerge:
		return FixSpec{Type: "block_bot_merge", Repo: v.Repo},
			"Stop PR authors from getting code onto the default branch of " + strings.TrimPrefix(v.Repo, "repo:") + " through a bot approve and merge"
	case graph.ReduceOwners:
		return FixSpec{Type: "reduce_owners", Threshold: v.Threshold}, ReduceOwnersDescription(len(v.Accounts()), v.Threshold)
	case graph.RequireReviews:
		return FixSpec{Type: "require_reviews", Repo: v.Repo},
			"Require at least one approving review on the default branch of " + strings.TrimPrefix(v.Repo, "repo:")
	case graph.EnablePushProtection:
		return FixSpec{Type: "enable_push_protection", Repo: v.Repo},
			"Enable secret scanning push protection on " + strings.TrimPrefix(v.Repo, "repo:")
	}
	return FixSpec{}, f.ID()
}

// Describe is Spec with the graph read: a harden_trigger sentence says what
// the workflow lets outsiders do (untrusted code runs, or untrusted text
// reaches an AI step) and on which triggers. ix may be nil.
func Describe(ix *graph.Index, f graph.Fix) (FixSpec, string) {
	spec, desc := Spec(f)
	if v, ok := f.(graph.HardenTrigger); ok && ix != nil {
		if d := HardenDescription(ix, v.Workflow, func(s string) string { return s }); d != "" {
			desc = d
		}
	}
	return spec, desc
}

// HardenDescription is the harden_trigger sentence for a workflow, per kind
// of untrusted execution: "untrusted code runs on ..." (a checkout of the
// pull request's code that a later step runs, or an injection) or
// "untrusted text reaches an AI step on ..." (an agent). name formats the
// workflow's name. "" when the graph records neither.
func HardenDescription(ix *graph.Index, workflow string, name func(string) string) string {
	if ix == nil {
		return ""
	}
	code, ai := false, false
	var triggers []string
	for _, e := range graph.FixEdges(ix, graph.HardenTrigger{Workflow: workflow}) {
		if e.Attrs[attrExec] == execAgent {
			ai = true
		} else {
			code = true
		}
		if t := e.Attrs[attrTrigger]; t != "" {
			triggers = append(triggers, t)
		}
	}
	if n, ok := ix.Node(workflow); ok {
		// One CAN_TRIGGER edge per principal keeps only the first execution:
		// the workflow's own attrs name the other kind.
		code = code || n.Attrs[graph.AttrUntrustedCheckout] == "exec"
		ai = ai || n.Attrs[graph.AttrAgentExposure] == graph.ExposureOutsiders
		if len(triggers) == 0 {
			triggers = splitList(n.Attrs["risky_triggers"])
		}
	}
	on := "its risky triggers"
	if len(triggers) > 0 {
		sort.Strings(triggers)
		on = strings.Join(dedup(triggers), ", ")
	}
	wf := name(strings.TrimPrefix(workflow, "workflow:"))
	switch {
	case code && ai:
		return "Harden " + wf + " (untrusted code runs, and untrusted text reaches an AI step, on " + on + ")"
	case ai:
		return "Harden " + wf + " (untrusted text reaches an AI step on " + on + ")"
	case code:
		return "Harden " + wf + " (untrusted code runs on " + on + ")"
	}
	return ""
}

// ReduceOwnersDescription is the sentence for a reduce_owners fix that
// removes ownership from n accounts at threshold.
func ReduceOwnersDescription(n, threshold int) string {
	return fmt.Sprintf("Remove standing org ownership from %s that own %d or more orgs (keep at least %d owners per org)",
		plural(n, "account", "accounts"), threshold, graph.MinOwnersPerOrg)
}

// Build turns a fix into change steps. It only reads ix.
func Build(ix *graph.Index, f graph.Fix) Plan {
	spec, desc := Describe(ix, f)
	p := Plan{FixID: f.ID(), Fix: spec, Description: desc, Removes: removes(ix, f), Steps: []Step{}, Caveats: []string{}}
	switch v := f.(type) {
	case graph.PinRef:
		buildPin(ix, v, &p)
	case graph.LowerDefaultPerm:
		buildLower(ix, v, &p)
	case graph.RestrictToken:
		buildRestrict(ix, v, &p)
	case graph.HardenTrigger:
		buildHarden(ix, v, &p)
	case graph.BlockBotMerge:
		buildBotMerge(ix, v, &p)
	case graph.ReduceOwners:
		buildReduceOwners(ix, v, &p)
	case graph.RequireReviews, graph.EnablePushProtection:
		buildHardening(ix, f, &p)
	}
	p.Steps = confirmedFirst(p.Steps)
	return p
}

// removes runs WhatIf and drops principals whose reach does not change.
func removes(ix *graph.Index, f graph.Fix) graph.Delta {
	d := ix.WhatIf([]graph.Fix{f})
	kept := []graph.PrincipalDelta{}
	for _, pd := range d.PerPrincipal {
		if pd.Before.Confirmed != pd.After.Confirmed || pd.Before.Possible != pd.After.Possible {
			kept = append(kept, pd)
		}
	}
	d.PerPrincipal = kept
	return d
}

// confirmedFirst moves not_visible steps to the end, keeping order otherwise.
func confirmedFirst(steps []Step) []Step {
	out := make([]Step, 0, len(steps))
	var later []Step
	for _, s := range steps {
		if s.Unconfirmed {
			later = append(later, s)
		} else {
			out = append(out, s)
		}
	}
	return append(out, later...)
}

func edgeLabel(e graph.Edge) string {
	return e.From + " " + string(e.Kind) + " " + e.To
}

func login(id string) string {
	_, rest, _ := strings.Cut(id, ":")
	return rest
}

// splitRef splits "O/R[/path]@ref" at the last "@".
func splitRef(uses string) (base, ref string) {
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		return uses[:i], uses[i+1:]
	}
	return uses, ""
}

// location returns the repo and file that hold a USES edge's uses: line, and
// whether the edge comes from an action (a nested composite action or a
// reusable workflow) instead of a workflow.
func location(ix *graph.Index, e graph.Edge) (repo, file string, nested bool) {
	prefix, rest, _ := strings.Cut(e.From, ":")
	switch prefix {
	case "workflow":
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 2 {
			repo = parts[0] + "/" + parts[1]
		}
		if len(parts) == 3 {
			file = parts[2]
		}
	case "action":
		nested = true
		n, _ := ix.Node(e.From)
		if n.Attrs["owner"] != "" && n.Attrs["repo"] != "" {
			repo = n.Attrs["owner"] + "/" + n.Attrs["repo"]
			file = n.Attrs["path"]
		} else {
			base, _ := splitRef(rest)
			parts := strings.SplitN(base, "/", 3)
			if len(parts) >= 2 {
				repo = parts[0] + "/" + parts[1]
			}
			if len(parts) == 3 {
				file = parts[2]
			}
		}
	}
	if f := e.Attrs[graph.AttrFile]; f != "" {
		file = f
	}
	return repo, file, nested
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// PinDiff is the one-line unified diff that pins uses (O/R[/path]@ref) to sha.
// The lines show the uses: entry without the file's indentation or list marker.
// gop pin --offline prints the same hunks.
func PinDiff(file string, line int, uses, sha string) string {
	value, comment := PinnedUses(uses, sha)
	return fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n-uses: %s\n+uses: %s %s\n", file, file, line, line, uses, value, comment)
}

func buildPin(ix *graph.Index, f graph.PinRef, p *Plan) {
	uses := strings.TrimPrefix(f.Action, "action:")
	base, ref := splitRef(uses)
	sha := "<sha-of-" + ref + ">"
	// A ref with a known advisory moves to the first fixed version (or a
	// SHA after it): pinning the affected ref would keep the affected code.
	an, _ := ix.Node(f.Action)
	adv := graph.HasAdvisory(an)
	target := ref
	if adv {
		target = FixedRef(an, ref)
		if target != "" {
			sha = "<sha-of-" + target + ">"
			p.Description = "Move " + uses + " (known advisory) to " + target + " or a commit SHA after it in every workflow that uses it"
			p.Caveats = append(p.Caveats, fmt.Sprintf("%s has a known advisory (%s): pinning it keeps the affected code. Move to %s, the first fixed version, or a commit SHA after it",
				uses, strings.Join(graph.AdvisoryIDs(an), ", "), target))
		} else {
			target = ref
			p.Caveats = append(p.Caveats, fmt.Sprintf("%s has a known advisory (%s) with no fixed version: remove the action or replace it; the steps below only list where it is used",
				uses, strings.Join(graph.AdvisoryIDs(an), ", ")))
		}
	}
	switch st := ix.RefState(f.Action); {
	case adv:
	case st == graph.RefPinned:
		p.Caveats = append(p.Caveats, uses+" is already pinned to a commit SHA: there is nothing to change")
	case st == graph.RefLocked:
		p.Caveats = append(p.Caveats, uses+" is locked (an immutable tag or a protected branch with no bypass that applies): pushing cannot move it, so a pin changes no reach")
	case st == graph.RefPossiblyMutable:
		p.Caveats = append(p.Caveats, uses+" is "+ix.MutabilityNote(f.Action)+": the pin closes paths through it only if it can move")
	}

	type key struct {
		from, file string
		line       int
	}
	seen := map[key]bool{}
	var steps []Step
	noLine := 0
	for _, e := range ix.In(f.Action) {
		if e.Kind != graph.Uses || e.Attrs[graph.AttrActionsLock] != "" {
			continue // an actions.lock governs it: see LockGoverned below
		}
		repo, file, nested := location(ix, e)
		line := atoi(e.Attrs[graph.AttrLine])
		k := key{e.From, file, line}
		if seen[k] {
			continue
		}
		seen[k] = true
		s := Step{
			Kind: KindEditWorkflow, Repo: repo, File: file, FileRef: e.Attrs[graph.AttrFileRef],
			Line: line, Col: atoi(e.Attrs[graph.AttrCol]),
			Owner: strings.SplitN(repo, "/", 2)[0], Edge: edgeLabel(e), Evidence: e.Evidence,
		}
		var notes []string
		if line > 0 && file != "" {
			s.Diff = PinDiff(file, line, uses, sha)
			if target != ref {
				s.Diff = fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n-uses: %s\n+uses: %s@%s # %s\n", file, file, line, line, uses, base, sha, target)
			}
		} else {
			noLine++
			notes = append(notes, fmt.Sprintf("line not recorded in this graph: replace `uses: %s` with `uses: %s@%s # %s`", uses, base, sha, target))
		}
		if file == "" {
			notes = append(notes, "file not recorded: the action's action.yml or action.yaml")
		}
		if nested {
			notes = append(notes, fmt.Sprintf("nested: this uses: line is inside %s; callers pick up the change only when that ref points at the new commit (a SHA or tag pin needs a new pin)",
				strings.TrimPrefix(e.From, "action:")))
		}
		if !graph.Verified(e.Evidence) {
			s.Unconfirmed = true
			notes = append(notes, ConfirmFirst)
		}
		s.Note = strings.Join(notes, "; ")
		steps = append(steps, s)
	}
	sort.SliceStable(steps, func(i, j int) bool {
		a, b := steps[i], steps[j]
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Edge < b.Edge
	})
	locks := LockGoverned(ix, f.Action)
	for _, u := range locks {
		loc := u.Repo + " " + u.File
		if u.Line > 0 {
			loc += fmt.Sprintf(" line %d", u.Line)
		}
		p.Caveats = append(p.Caveats, loc+": "+u.Reason())
	}
	if len(steps) == 0 {
		if len(locks) == 0 {
			p.Caveats = append(p.Caveats, "no workflow or action in this graph uses "+uses)
		} else {
			p.Caveats = append(p.Caveats, "every use of "+uses+" is governed by an actions.lock: there is no workflow line to edit")
		}
		return
	}
	p.Steps = append(p.Steps, steps...)
	note := fmt.Sprintf("fix-plan works offline and does not know the commit %s points at: run `gop pin --action %s --graph graph.json` to resolve it with one read-only API call and print these edits as a git apply diff, or replace %s with the full commit SHA of %s yourself. Use the same SHA in every step.",
		ref, uses, sha, ref)
	if target != ref {
		note = fmt.Sprintf("fix-plan works offline and does not know the commit %s points at: run `gop pin --action %s` to resolve it with one read-only API call, "+
			"check that the commit is not one the advisory lists, and replace %s with it. Use the same SHA in every step.",
			target, base+"@"+target, sha)
	}
	p.Steps = append(p.Steps, Step{
		Kind:  KindVerify,
		Repo:  repoOf(base),
		Owner: strings.SplitN(base, "/", 2)[0],
		Note:  note,
	})
	if noLine > 0 {
		p.Caveats = append(p.Caveats, fmt.Sprintf("%d of %d uses: lines have no line number in this graph (collected before line attributes); those steps say what to replace instead of a diff",
			noLine, len(steps)))
	}
	if noLine < len(steps) {
		p.Caveats = append(p.Caveats, "diffs show the uses: entry without its indentation or list marker; keep those as they are in the file")
	}
	if ids, labels := NestedMutable(ix, f.Action); len(ids) > 0 {
		p.Caveats = append(p.Caveats, fmt.Sprintf("pinning %s alone does not close paths through the mutable refs it uses itself: %s. Pin those too (for example gop fix-plan --pin %s)",
			uses, strings.Join(labels, ", "), ids[0]))
	}
}

// NestedMutable lists the mutable action refs reachable from action through
// USES edges (nested composite actions and reusable workflows), each with its
// file:line when known: the node IDs and their labels, sorted by ID. A ref
// that is locked (graph.RefLocked) is left out; one whose gate is not visible
// is kept and labelled with graph.Index.MutabilityNote.
func NestedMutable(ix *graph.Index, action string) (ids, labels []string) {
	seen := map[string]bool{action: true}
	queue := []string{action}
	found := map[string]string{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range ix.Out(cur) {
			if e.Kind != graph.Uses || seen[e.To] {
				continue
			}
			seen[e.To] = true
			queue = append(queue, e.To)
			if ix.MutableRef(e.To) {
				label := strings.TrimPrefix(e.To, "action:")
				if file := e.Attrs[graph.AttrFile]; file != "" {
					loc := file
					if l := e.Attrs[graph.AttrLine]; l != "" {
						loc += ":" + l
					}
					label += " (" + strings.TrimPrefix(cur, "action:") + " " + loc + ")"
				}
				if note := ix.MutabilityNote(e.To); note != "" {
					label += " [" + note + "]"
				}
				if !graph.Verified(e.Evidence) {
					label += " [not visible]"
				}
				found[e.To] = label
			}
		}
	}
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		labels = append(labels, found[id])
	}
	return ids, labels
}

// repoOf returns "O/R" for "O/R[/path]".
func repoOf(base string) string {
	parts := strings.SplitN(base, "/", 3)
	if len(parts) < 2 {
		return base
	}
	return parts[0] + "/" + parts[1]
}

func buildLower(ix *graph.Index, f graph.LowerDefaultPerm, p *Plan) {
	org := login(f.Org)
	n, _ := ix.Node(f.Org)
	cur := n.Attrs[graph.AttrDefaultPerm]
	if f.To != "read" && f.To != "none" {
		p.Caveats = append(p.Caveats, fmt.Sprintf("lowering to %q does not remove push: gop models only read and none", f.To))
		return
	}
	ev := n.Evidence
	if e, ok := n.AttrEvidence[graph.AttrDefaultPerm]; ok {
		ev = e
	}
	setting := Step{
		Kind:     KindChangeSetting,
		Owner:    org,
		Setting:  fmt.Sprintf("Organization settings > Member privileges > Base permissions: %s", label(f.To)),
		API:      fmt.Sprintf(`PATCH /orgs/%s {"default_repository_permission": "%s"}`, org, f.To),
		Evidence: ev,
		Note:     "an org owner of " + org + " makes this change; the API call is shown as text only, gop never calls it",
	}
	if cur != "" {
		setting.Note = "current base permission: " + cur + "; " + setting.Note
	}
	if ev != "" && !graph.Verified(ev) {
		setting.Unconfirmed = true
		setting.Note += "; " + ConfirmFirst
	}

	type loss struct {
		repo   string
		edge   graph.Edge
		others []string
	}
	var losses []loss
	for _, e := range graph.FixEdges(ix, f) {
		var others []string
		for _, in := range ix.In(e.To) {
			if in.Kind == graph.CanPush && in.Attrs[graph.AttrVia] != graph.ViaDefaultPerm {
				others = append(others, in.From)
			}
		}
		sort.Strings(others)
		losses = append(losses, loss{repo: login(e.To), edge: e, others: dedup(others)})
	}
	sort.Slice(losses, func(i, j int) bool { return losses[i].repo < losses[j].repo })

	for _, l := range losses {
		s := Step{
			Kind: KindVerify, Repo: l.repo, Owner: org, Edge: edgeLabel(l.edge), Evidence: l.edge.Evidence,
			Note: fmt.Sprintf("before the change: members of %s lose push to %s (granted only by the base permission); give a team push first if members need it", org, l.repo),
		}
		if len(l.others) > 0 {
			s.Note += "; other push grants kept: " + strings.Join(l.others, ", ")
		}
		if !graph.Verified(l.edge.Evidence) {
			s.Unconfirmed = true
			s.Note += "; " + ConfirmFirst
		}
		p.Steps = append(p.Steps, s)
	}
	p.Steps = append(p.Steps, setting)

	p.Caveats = append(p.Caveats, fmt.Sprintf("members who rely on the default %s permission lose push to every %s repo where they have no team, direct or owner grant", orDefault(cur, "write"), org))
	if len(losses) == 0 {
		p.Caveats = append(p.Caveats, "this graph records no CAN_PUSH edge from the base permission of "+org)
		return
	}
	repos := make([]string, 0, len(losses))
	for _, l := range losses {
		r := l.repo
		if !graph.Verified(l.edge.Evidence) {
			r += " [not visible]"
		}
		repos = append(repos, r)
	}
	p.Caveats = append(p.Caveats, fmt.Sprintf("repos where members of %s have push only through the base permission: %s", org, strings.Join(repos, ", ")))
}

func label(to string) string {
	switch to {
	case "read":
		return "Read"
	case "none":
		return "No permission"
	}
	return to
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func dedup(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// LockUse is a uses: line of an action that a repo's actions.lock governs
// (its USES edge carries actions_lock). gop does not edit those lines: the
// lockfile decides what runs, and gh actions-lock maintains it.
type LockUse struct {
	Repo    string `json:"repo"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	State   string `json:"state" jsonschema:"locked or stale"`
	SHA     string `json:"locked_sha,omitempty"`
	Entry   string `json:"lock_entry,omitempty"`
	Missing string `json:"lock_missing,omitempty"`
	// Advisories lists the advisories that name the locked commit as
	// affected (lock_advisories); Fixed is the ref to move to before the
	// lock is refreshed (lock_advisory_fixed), "" when an advisory names no
	// fixed version.
	Advisories string `json:"lock_advisories,omitempty"`
	Fixed      string `json:"advisory_fixed,omitempty"`
	// Edge is the USES edge, for callers that report the line (SARIF).
	Edge graph.Edge `json:"-"`
}

// Reason says, in one sentence, why the line is left alone.
func (u LockUse) Reason() string {
	if u.State == graph.LockLocked && u.Advisories != "" {
		ids := strings.ReplaceAll(u.Advisories, ",", ", ")
		which := " (it pins " + u.SHA + ", listed by " + ids + ")"
		if u.Fixed == "" {
			return "actions.lock pins an affected commit and the advisory names no fixed version: remove or replace the action, then rerun gh actions-lock" + which
		}
		return "actions.lock pins an affected commit: rerun gh actions-lock after moving to " + u.Fixed + which
	}
	if u.State == graph.LockLocked {
		return "actions.lock governs this uses: and pins it to " + u.SHA + ": nothing to edit"
	}
	var why string
	switch {
	case u.Missing != "":
		why = "it does not pin the nested " + strings.ReplaceAll(u.Missing, ",", ", ")
	case u.Entry != "":
		why = "it pins " + strings.ReplaceAll(u.Entry, ",", ", ") + " instead"
	default:
		why = "it has no entry for this uses:"
	}
	return "stale actions.lock entry (" + why + "): rerun gh actions-lock in " + u.Repo + " instead of editing the workflow"
}

// LockGoverned lists the uses: lines of action that an actions.lock
// governs, sorted by repo, file and line.
func LockGoverned(ix *graph.Index, action string) []LockUse {
	var out []LockUse
	for _, e := range ix.In(action) {
		st := e.Attrs[graph.AttrActionsLock]
		if e.Kind != graph.Uses || st == "" {
			continue
		}
		repo, file, _ := location(ix, e)
		u := LockUse{Repo: repo, File: file, Line: atoi(e.Attrs[graph.AttrLine]), State: st,
			SHA: e.Attrs[graph.AttrLockedSHA], Entry: e.Attrs[graph.AttrLockEntry], Missing: e.Attrs[graph.AttrLockMissing],
			Advisories: e.Attrs[graph.AttrLockAdvisories], Edge: e}
		if u.Advisories != "" && st == graph.LockLocked {
			_, ref := splitRef(strings.TrimPrefix(action, "action:"))
			u.Fixed = withV(e.Attrs[graph.AttrLockAdvisoryFixed], ref)
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return out
}

// FixedRef is the ref to move an action with an advisory to: its
// advisory_fixed version, written with a leading v when the current ref has
// one and the version does not. "" when no fixed version is known.
func FixedRef(n graph.Node, ref string) string {
	return withV(n.Attrs[graph.AttrAdvisoryFixed], ref)
}

// withV writes a fixed version f with a leading v when ref has one and f
// does not. "" stays "".
func withV(f, ref string) string {
	if f == "" {
		return ""
	}
	if strings.HasPrefix(ref, "v") && !strings.HasPrefix(f, "v") {
		return "v" + f
	}
	return f
}

// HardeningCaveat is the caveat of every advisory hardening plan.
const HardeningCaveat = "advisory hardening: gop does not model branch protection or push protection as cutting a path, so this removes no confirmed reach"

// buildHardening plans an advisory hardening fix: one setting to change.
func buildHardening(ix *graph.Index, f graph.Fix, p *Plan) {
	p.Caveats = append(p.Caveats, HardeningCaveat)
	var repo string
	s := Step{Kind: KindChangeSetting}
	switch v := f.(type) {
	case graph.RequireReviews:
		repo = strings.TrimPrefix(v.Repo, "repo:")
		branch := "{default branch}"
		if n, ok := ix.Node(v.Repo); ok && n.Attrs["default_branch"] != "" {
			branch = n.Attrs["default_branch"]
		}
		s.Change = "add a branch ruleset (or classic protection) on " + branch + " that requires a pull request with at least one approval, dismisses stale approvals, and requires CODEOWNERS review for .github/workflows/"
		s.Setting = "Settings > Rules > Rulesets > New branch ruleset > Require a pull request before merging"
		s.API = "POST /repos/" + repo + "/rulesets"
	case graph.EnablePushProtection:
		repo = strings.TrimPrefix(v.Repo, "repo:")
		s.Change = "turn on secret scanning and push protection"
		s.Setting = "Settings > Advanced Security > Secret Protection > Push protection"
		s.API = "PATCH /repos/" + repo + " (security_and_analysis.secret_scanning_push_protection.status=enabled)"
	}
	s.Repo, s.Owner = repo, ownerOf(repo)
	if n, ok := ix.Node("repo:" + repo); ok {
		if h, ok := graph.RepoHardening(n); ok {
			s.Note = h.Summary()
		}
	}
	p.Steps = append(p.Steps, s)
}

// buildReduceOwners lists one role change per account, in every org where
// the fix removes its ownership (the weakest evidence of those grants), and names the ownerships it keeps so no
// org drops under graph.MinOwnersPerOrg owners.
func buildReduceOwners(ix *graph.Index, f graph.ReduceOwners, p *Plan) {
	p.Caveats = append(p.Caveats, "Prefer just-in-time ownership: grant owner access on demand for the task and remove it after, instead of standing ownership. "+
		"The kept owners, and anyone given owner access later, still hold this reach.")
	if len(f.Cuts) == 0 {
		p.Caveats = append(p.Caveats, fmt.Sprintf("no account owns %d or more orgs: there is nothing to change", f.Threshold))
		return
	}
	ev := map[string]graph.Evidence{}
	for _, e := range graph.FixEdges(ix, f) {
		k := e.From + "\x00" + graph.OrgOf(e.To)
		if old, ok := ev[k]; !ok || (!graph.Verified(old) && graph.Verified(e.Evidence)) {
			ev[k] = e.Evidence
		}
	}
	// One step per account: the same role change in each org it loses.
	var accounts []string
	orgsOf := map[string][]string{}
	for _, c := range f.Cuts {
		if orgsOf[c.Principal] == nil {
			accounts = append(accounts, c.Principal)
		}
		orgsOf[c.Principal] = append(orgsOf[c.Principal], c.Org)
	}
	for _, a := range accounts {
		user := login(a)
		orgs := orgsOf[a]
		names := make([]string, len(orgs))
		s := Step{Kind: KindChangeSetting, Evidence: graph.Live}
		for i, o := range orgs {
			names[i] = login(o)
			if e := ev[a+"\x00"+o]; evRank(e) < evRank(s.Evidence) {
				s.Evidence = e
			}
		}
		if len(orgs) == 1 {
			s.Owner = names[0]
		}
		s.Setting = fmt.Sprintf("Organization settings > People > %s > Change role: Member", user)
		if len(orgs) > 1 {
			s.Setting = fmt.Sprintf("in %s (%s): Organization settings > People > %s > Change role: Member",
				plural(len(orgs), "org", "orgs"), strings.Join(names, ", "), user)
		}
		s.API = fmt.Sprintf(`PUT /orgs/{org}/memberships/%s {"role": "member"}, once per org`, user)
		s.Edge = a + " " + string(graph.CanPush) + " repos of " + strings.Join(orgs, ", ") + " (via org_owner)"
		s.Note = fmt.Sprintf("%s owns %d orgs and keeps %d; another owner of each org makes the change and grants owner access again only when a task needs it; the API call is shown as text only, gop never calls it",
			user, len(ix.OwnedOrgs(a)), len(ix.OwnedOrgs(a))-len(orgs))
		if !graph.Verified(s.Evidence) {
			s.Unconfirmed = true
			s.Note += "; " + ConfirmFirst
		}
		p.Steps = append(p.Steps, s)
	}
	if len(f.Kept) > 0 {
		by := map[string][]string{}
		var orgs []string
		for _, k := range f.Kept {
			if by[k.Org] == nil {
				orgs = append(orgs, k.Org)
			}
			by[k.Org] = append(by[k.Org], login(k.Principal))
		}
		sort.Strings(orgs)
		parts := make([]string, 0, len(orgs))
		for _, o := range orgs {
			parts = append(parts, login(o)+" ("+strings.Join(by[o], ", ")+")")
		}
		p.Caveats = append(p.Caveats, fmt.Sprintf("kept so that every org has at least %d owners, the accounts that own the most orgs first: %s",
			graph.MinOwnersPerOrg, strings.Join(parts, "; ")))
	}
}

// evRank orders evidence for picking a step's weakest: not visible lowest.
func evRank(e graph.Evidence) int {
	switch e {
	case graph.Live:
		return 4
	case graph.Inferred:
		return 3
	case graph.Audit:
		return 2
	case graph.Supplied:
		return 1
	}
	return 0
}
