package graph

import (
	"fmt"
	"sort"
	"strings"
)

// Hardening is the default-branch protection, CODEOWNERS and secret scanning
// state of one repo, read from its node attrs. Fields are the attr values as
// collected: "unknown" when gop could not read them, "" when the graph has no
// such attr (collected before gop knew it, or the repo is archived).
type Hardening struct {
	Repo          string `json:"repo"`
	DefaultBranch string `json:"default_branch,omitempty"`
	Protected     string `json:"protected,omitempty"`
	Reviews       string `json:"required_reviews,omitempty"`
	CodeOwner     string `json:"require_code_owner_review,omitempty"`
	DismissStale  string `json:"dismiss_stale_reviews,omitempty"`
	LastPush      string `json:"require_last_push_approval,omitempty"`
	StatusChecks  string `json:"required_status_checks,omitempty"`
	Signed        string `json:"require_signed_commits,omitempty"`
	ForcePush     string `json:"allow_force_push,omitempty"`
	PushRestrict  string `json:"push_restricted,omitempty"`
	BypassActors  string `json:"bypass_actors,omitempty"`
	AdminBypass   string `json:"admin_bypass,omitempty"`
	AppBypass     string `json:"app_bypass,omitempty"`
	Sources       string `json:"sources,omitempty" jsonschema:"protecting sources: classic and ruleset:<id>, or none"`
	ValueSources  string `json:"value_sources,omitempty" jsonschema:"which source set each effective value, key=source[+source]"`
	Codeowners    string `json:"codeowners,omitempty"`
	CodeownersOK  string `json:"codeowners_valid,omitempty"`
	CodeownersWF  string `json:"codeowners_workflows,omitempty"`
	SecretScan    string `json:"secret_scanning,omitempty"`
	PushProtect   string `json:"secret_scanning_push_protection,omitempty"`
	ValidityCheck string `json:"secret_scanning_validity_checks,omitempty"`
}

// RepoHardening reads the hardening attrs of a repo node. ok is false when
// the node has none of them.
func RepoHardening(n Node) (h Hardening, ok bool) {
	a := n.Attrs
	h = Hardening{Repo: n.ID, DefaultBranch: a["default_branch"],
		Protected: a[AttrBranchProtected], Reviews: a[AttrBranchReviews], CodeOwner: a[AttrBranchCodeOwnerReview],
		DismissStale: a[AttrBranchDismissStale], LastPush: a[AttrBranchLastPush], StatusChecks: a[AttrBranchStatusChecks],
		Signed: a[AttrBranchSignedCommits], ForcePush: a[AttrBranchForcePush], PushRestrict: a[AttrBranchPushRestricted],
		BypassActors: a[AttrBranchBypassActors], AdminBypass: a[AttrBranchAdminBypass], AppBypass: a[AttrBranchAppBypass],
		Sources: a[AttrBranchSources], ValueSources: a[AttrBranchValueSources],
		Codeowners: a[AttrCodeowners], CodeownersOK: a[AttrCodeownersValid], CodeownersWF: a[AttrCodeownersWorkflows],
		SecretScan: a[AttrSecretScanning], PushProtect: a[AttrSecretPushProtection], ValidityCheck: a[AttrSecretValidity]}
	ok = h.Protected != "" || h.Codeowners != "" || h.SecretScan != "" || h.PushProtect != ""
	return h, ok
}

// branch is the default branch name for notes, "the default branch" when unknown.
func (h Hardening) branch() string {
	if h.DefaultBranch == "" {
		return "the default branch"
	}
	return "`" + h.DefaultBranch + "`"
}

// Summary is one line of the effective protection and its sources, e.g.
// "default branch `main`: protected (ruleset:7), 2 approvals, CODEOWNERS
// review, force push blocked; CODEOWNERS covers workflows; secret scanning
// on, push protection off". Unknown values read "unknown".
func (h Hardening) Summary() string {
	var parts []string
	switch h.Protected {
	case "":
	case "true":
		p := "protected"
		if h.Sources != "" && h.Sources != "none" {
			p += " (" + h.Sources + ")"
		}
		parts = append(parts, p)
		if h.Reviews != "" {
			parts = append(parts, approvals(h.Reviews))
		}
		if h.CodeOwner == "true" {
			parts = append(parts, "CODEOWNERS review")
		}
		switch h.ForcePush {
		case "true":
			parts = append(parts, "force push allowed")
		case "false":
			parts = append(parts, "force push blocked")
		}
		switch h.AdminBypass {
		case "true":
			parts = append(parts, "admins can bypass")
		case "unknown":
			parts = append(parts, "admin bypass unknown")
		}
	case "false":
		parts = append(parts, "not protected")
	default:
		parts = append(parts, "protection unknown")
	}
	out := ""
	if len(parts) > 0 {
		out = "default branch " + h.branch() + ": " + strings.Join(parts, ", ")
	}
	var more []string
	switch h.Codeowners {
	case "":
	case "none":
		more = append(more, "no CODEOWNERS")
	case "unknown":
		more = append(more, "CODEOWNERS unknown")
	default:
		switch h.CodeownersWF {
		case "true":
			more = append(more, "CODEOWNERS covers workflows")
		case "false":
			more = append(more, "CODEOWNERS does not cover workflows")
		default:
			more = append(more, "CODEOWNERS coverage of workflows unknown")
		}
	}
	if h.SecretScan != "" || h.PushProtect != "" {
		more = append(more, "secret scanning "+orUnknown(h.SecretScan)+", push protection "+orUnknown(h.PushProtect))
	}
	if len(more) > 0 {
		if out != "" {
			out += "; "
		}
		out += strings.Join(more, "; ")
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func approvals(n string) string {
	switch n {
	case "unknown":
		return "required approvals unknown"
	case "0":
		return "no approvals required"
	case "1":
		return "1 approval"
	}
	return n + " approvals"
}

// Path notes on CAN_PUSH hops.
const (
	// NoteDirect is the note on a push into a repo whose default branch a
	// push reaches without review.
	NoteDirect = "push reaches the default branch directly"
)

// HopNote is the hardening context of one hop: for a CAN_PUSH hop into a
// repo with default-branch facts, "push needs N approvals to reach `main`"
// (with " + CODEOWNERS on workflows" when code owner review is required and
// CODEOWNERS covers .github/workflows/), or NoteDirect when the branch is
// not protected, needs no approval, allows force pushes, or lets admins
// bypass and the pusher is an admin. It is "" for other hops, for bypass
// grants (via=ref_bypass), and whenever a deciding value is unknown: gop
// never reads unknown as unprotected. A CAN_MERGE_VIA_BOT hop, and a
// CAN_PUSH hop that does not reach the branch directly, into a repo with a
// review bypass get BotMergeNote instead: a PR author can get code onto the
// branch without human review, whatever the approval count says. Notes are
// context only; they change no evidence, count or score. A hop with a Gate
// (a required-reviewer deployment environment, envgate.go) returns the gate.
func (ix *Index) HopNote(h Hop) string {
	if h.Gate != "" {
		return h.Gate
	}
	if h.Reverse || (h.Kind != CanPush && h.Kind != CanMergeViaBot) {
		return ""
	}
	n, ok := ix.nodes[h.To]
	if !ok || n.Kind != KindRepo {
		return ""
	}
	if h.Kind == CanMergeViaBot {
		return BotMergeNote(n)
	}
	note, bypass := ix.pushNote(h, n)
	if !bypass && note != NoteDirect && ReviewBypassed(n) {
		return BotMergeNote(n)
	}
	return note
}

// pushNote is HopNote for a CAN_PUSH hop into repo n; bypass is true for a
// via=ref_bypass grant.
func (ix *Index) pushNote(h Hop, n Node) (note string, bypass bool) {
	var e *Edge
	for i, ed := range ix.out[h.From] {
		if ed.To == h.To && ed.Kind == CanPush {
			e = &ix.out[h.From][i]
			break
		}
	}
	if e != nil && e.Attrs[AttrVia] == ViaRefBypass {
		return "", true
	}
	hd, ok := RepoHardening(n)
	if !ok || hd.Protected == "" || hd.Protected == "unknown" {
		return "", false
	}
	if hd.Protected == "false" || hd.ForcePush == "true" {
		return NoteDirect, false
	}
	if hd.AdminBypass == "true" && e != nil &&
		(strings.EqualFold(e.Attrs["permission"], "admin") || e.Attrs[AttrVia] == ViaOrgOwner) {
		return NoteDirect, false
	}
	switch hd.Reviews {
	case "", "unknown":
		return "", false
	case "0":
		if hd.PushRestrict == "false" {
			return NoteDirect, false
		}
		return "", false
	}
	note = fmt.Sprintf("push needs %s to reach %s", approvals(hd.Reviews), hd.branch())
	if hd.CodeOwner == "true" && hd.CodeownersWF == "true" {
		note += " + CODEOWNERS on workflows"
	}
	return note, false
}

// Annotate returns a copy of p with Hop.Note set from HopNote. The path's
// evidence, hops and order are unchanged.
func (ix *Index) Annotate(p Path) Path {
	var hops []Hop
	for i, h := range p.Hops {
		if n := ix.HopNote(h); n != "" {
			if hops == nil {
				hops = append([]Hop(nil), p.Hops...)
			}
			hops[i].Note = n
		}
	}
	if hops != nil {
		p.Hops = hops
	}
	return p
}

// AnnotateAll is Annotate over a list, in place on a copy of the slice.
func (ix *Index) AnnotateAll(ps []Path) []Path {
	if ps == nil {
		return nil
	}
	out := make([]Path, len(ps))
	for i, p := range ps {
		out[i] = ix.Annotate(p)
	}
	return out
}

// PathNotes lists the distinct hop notes of p in hop order.
func (ix *Index) PathNotes(p Path) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range p.Hops {
		if n := ix.HopNote(h); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// HardeningRollup counts hardening facts over the non-archived repos of one
// org. Each Share counts repos where the fact holds (Yes), does not (No) and
// could not be read (Unknown); repos without the attr at all are Missing.
type HardeningRollup struct {
	Org            string `json:"org"`
	Repos          int    `json:"repos"`
	Protected      Share  `json:"protected"`
	Reviews        Share  `json:"required_reviews"`
	CodeownersWF   Share  `json:"codeowners_workflows"`
	SecretScanning Share  `json:"secret_scanning"`
	PushProtection Share  `json:"push_protection"`
}

// Share is a yes/no/unknown tally.
type Share struct {
	Yes     int `json:"yes"`
	No      int `json:"no"`
	Unknown int `json:"unknown"`
	Missing int `json:"missing,omitempty"`
}

func (s *Share) add(v string, yes ...string) {
	switch v {
	case "":
		s.Missing++
	case "unknown":
		s.Unknown++
	default:
		for _, y := range yes {
			if v == y {
				s.Yes++
				return
			}
		}
		s.No++
	}
}

// String renders "3/5" with " (1 unknown)" when some were not visible.
func (s Share) String() string {
	out := fmt.Sprintf("%d/%d", s.Yes, s.Yes+s.No+s.Unknown)
	if s.Unknown > 0 {
		out += fmt.Sprintf(" (%d unknown)", s.Unknown)
	}
	return out
}

// HardeningRollups returns one rollup per org with at least one repo that
// carries hardening attrs, sorted by org. A repo whose required reviews are
// unknown but whose branch is not protected counts as no.
func (ix *Index) HardeningRollups() []HardeningRollup {
	by := map[string]*HardeningRollup{}
	for _, n := range ix.g.Nodes {
		if n.Kind != KindRepo || n.Attrs[AttrArchived] == "true" {
			continue
		}
		h, ok := RepoHardening(n)
		if !ok {
			continue
		}
		org := OrgOf(n.ID)
		r := by[org]
		if r == nil {
			r = &HardeningRollup{Org: org}
			by[org] = r
		}
		r.Repos++
		r.Protected.add(h.Protected, "true")
		rev := h.Reviews
		if h.Protected == "false" {
			rev = "0"
		}
		switch rev {
		case "", "unknown":
			r.Reviews.add(rev)
		case "0":
			r.Reviews.add("no")
		default:
			r.Reviews.add("yes", "yes")
		}
		wf := h.CodeownersWF
		switch h.Codeowners {
		case "none":
			wf = "false"
		case "unknown":
			wf = "unknown"
		}
		r.CodeownersWF.add(wf, "true")
		r.SecretScanning.add(h.SecretScan, "on")
		r.PushProtection.add(h.PushProtect, "on")
	}
	out := make([]HardeningRollup, 0, len(by))
	for _, r := range by {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Org < out[j].Org })
	return out
}

// RequireReviews is an advisory hardening fix: require at least one
// approving review on a repo's default branch. It changes no edge: gop's
// reach model does not use branch protection to cut a push, so it never
// counts as removing confirmed reach.
type RequireReviews struct {
	Repo string `json:"repo"` // "repo:O/R"
}

func (f RequireReviews) ID() string          { return "require_reviews:" + f.Repo }
func (f RequireReviews) apply(*fixSet)       {}
func (f RequireReviews) edges(*Index) []Edge { return nil }

// EnablePushProtection is an advisory hardening fix: turn on secret scanning
// push protection on a repo. It changes no edge.
type EnablePushProtection struct {
	Repo string `json:"repo"` // "repo:O/R"
}

func (f EnablePushProtection) ID() string          { return "push_protection:" + f.Repo }
func (f EnablePushProtection) apply(*fixSet)       {}
func (f EnablePushProtection) edges(*Index) []Edge { return nil }

// HardeningOnly reports whether f is an advisory hardening fix (it changes no edge).
func HardeningOnly(f Fix) bool {
	switch f.(type) {
	case RequireReviews, EnablePushProtection:
		return true
	}
	return false
}

// HardeningSuggestion is one advisory fix with the reason it is listed.
type HardeningSuggestion struct {
	Fix    Fix    `json:"-"`
	FixID  string `json:"fix_id"`
	Reason string `json:"reason"`
}

// SuggestHardening lists advisory fixes for the repos that the top n
// principals reach through a confirmed CAN_PUSH hop, in rank order, at most
// limit: require reviews where the default branch is not protected or needs
// no approval, enable push protection where it is off. Unknown values are
// never suggested on. The list never affects SuggestFixes.
func (ix *Index) SuggestHardening(n, limit int) []HardeningSuggestion {
	var out []HardeningSuggestion
	if limit <= 0 {
		return out
	}
	seen := map[string]bool{}
	add := func(f Fix, why string) bool {
		if seen[f.ID()] {
			return false
		}
		seen[f.ID()] = true
		out = append(out, HardeningSuggestion{Fix: f, FixID: f.ID(), Reason: why})
		return len(out) >= limit
	}
	for _, repo := range ix.TopPathRepos(n) {
		node := ix.nodes[repo]
		h, _ := RepoHardening(node)
		switch {
		case h.Protected == "false":
			if add(RequireReviews{Repo: repo}, "default branch "+h.branch()+" is not protected") {
				return out
			}
		case h.Protected == "true" && h.Reviews == "0":
			if add(RequireReviews{Repo: repo}, "default branch "+h.branch()+" needs no approval") {
				return out
			}
		}
		if h.PushProtect == "off" {
			if add(EnablePushProtection{Repo: repo}, "secret scanning push protection is off") {
				return out
			}
		}
	}
	return out
}

// TopPathRepos lists the repos the top n principals push to on a confirmed
// path (the target of a forward CAN_PUSH hop), in principal rank order, then
// repo ID, without repeats.
func (ix *Index) TopPathRepos(n int) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range ix.TopPaths(n) {
		r := ix.Reach(s.Principal, Options{})
		var mine []string
		for _, p := range r.Paths {
			if p.Unverified {
				continue
			}
			for _, h := range p.Hops {
				if h.Kind == CanPush && !h.Reverse && ix.Kind(h.To) == KindRepo && !seen[h.To] {
					seen[h.To] = true
					mine = append(mine, h.To)
				}
			}
		}
		sort.Strings(mine)
		out = append(out, mine...)
	}
	return out
}
