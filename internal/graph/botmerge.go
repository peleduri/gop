package graph

import (
	"path"
	"sort"
	"strings"
)

// AI approve + self-merge (docs/agents-in-ci.md): a workflow that approves
// pull requests with a bot token, and a workflow the pull request's author
// can start that merges with a bot token the default branch's rules let
// through. Together they give a principal that can open a pull request a
// CAN_MERGE_VIA_BOT edge to the repo: the engine treats it like CAN_PUSH.

// ReviewBypassed reports whether a repo node carries review_bypass, confirmed
// or possible.
func ReviewBypassed(n Node) bool {
	return n.Kind == KindRepo && n.Attrs[AttrReviewBypass] == ReviewBypassBotSelfMerge
}

// ReviewBypassConfirmed reports whether a repo's review bypass was decided
// from facts gop read (its attr evidence is not not_visible).
func ReviewBypassConfirmed(n Node) bool {
	return ReviewBypassed(n) && n.AttrEvidence[AttrReviewBypass] != NotVisible
}

// BotMergeChain names the workflows of a repo's review bypass, as
// "approve.yml + merge.yml" (file base names), or the merge workflow alone
// when no approval is needed.
func BotMergeChain(n Node) string {
	var parts []string
	for _, f := range splitAttr(n.Attrs[AttrReviewBypassApprove]) {
		parts = append(parts, "`"+path.Base(f)+"`")
	}
	if m := n.Attrs[AttrReviewBypassMerge]; m != "" {
		p := "`" + path.Base(m) + "`"
		if s := BotMergeScript(n); s != "" {
			p += " (merges in `" + s + "`)"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " + ")
}

// BotMergeScript is the repo script a node's bot merge happens in (from
// bot_merge_source=script:<path>), "" when the merge is a workflow step.
func BotMergeScript(n Node) string {
	s, _ := strings.CutPrefix(n.Attrs[AttrBotMergeSource], BotScriptPrefix)
	return s
}

// StaleApprovalsSuspected reports whether a node's bot merge is suspected
// (heuristic, never confirmed) to count approvals not tied to the head
// commit.
func StaleApprovalsSuspected(n Node) bool {
	return n.Attrs[AttrBotMergeStale] == StaleSuspected
}

// staleNote is the path note suffix when the approval may not cover the
// merged code.
const staleNote = "; the approval may not cover the merged code (suspected, heuristic: the merge counts older approvals and the review does not re-run on push)"

// recountNote is the path note suffix when the rules dismiss stale reviews
// and the merge script counts DISMISSED reviews.
const recountNote = "; the script re-counts approvals GitHub dismissed, so the approval may not cover the merged code (suspected, heuristic: the rules dismiss stale reviews on push and the merge script counts DISMISSED reviews)"

// RecountsDismissed reports whether a repo's bot merge is suspected
// (heuristic) to re-count approvals GitHub dismissed.
func RecountsDismissed(n Node) bool {
	return n.Attrs[AttrReviewBypassRecount] == StaleSuspected
}

// BotMergeNote is the path note of a repo with a review bypass: "a PR author
// can get code onto `main` without human review: `ai-review.yml` +
// `ai-merge.yml`", with "may" and the unknown fact when it is possible
// only. "" when the repo has none.
func BotMergeNote(n Node) string {
	if !ReviewBypassed(n) {
		return ""
	}
	h, _ := RepoHardening(n)
	stale := ""
	switch {
	case RecountsDismissed(n):
		stale = recountNote
	case n.Attrs[AttrReviewBypassStale] == StaleSuspected:
		stale = staleNote
	}
	if !ReviewBypassConfirmed(n) {
		return "a PR author may get code onto " + h.branch() + " without human review (" + botUnknown(n) + "): " + BotMergeChain(n) + stale
	}
	return "a PR author can get code onto " + h.branch() + " without human review: " + BotMergeChain(n) + stale
}

// botUnknown names the fact that makes a review bypass possible only.
func botUnknown(n Node) string {
	switch {
	case n.Attrs[AttrReviewBypassReason] == ReviewBypassApp && n.Attrs[AttrBranchAppBypass] == "unknown":
		return "the bypass list is not visible"
	case n.Attrs[AttrReviewBypassReason] == ReviewBypassApp && n.Attrs[AttrReviewBypassAppMatch] == AppUnmatched:
		return "the merging App is not one of the bypass Apps gop read"
	case n.Attrs[AttrReviewBypassReason] == ReviewBypassApp && n.Attrs[AttrReviewBypassAppMatch] == AppUnknown:
		return "whether the merging App is the bypass App is not visible"
	case n.Attrs[AttrReviewBypassReason] == ReviewBypassAdmin:
		return "whether the merging token belongs to an admin is not visible"
	case n.Attrs[AttrBranchReviews] == "unknown" || n.Attrs[AttrBranchCodeOwnerReview] == "unknown":
		return "the required reviews are not visible"
	}
	return "a deciding fact is not visible"
}

// BotMergeFixes are the changes that close a repo's review bypass, most
// effective first. Empty when the repo has none.
func BotMergeFixes(n Node) []string {
	if !ReviewBypassed(n) {
		return nil
	}
	h, _ := RepoHardening(n)
	out := []string{
		"Require a human approval that bots cannot give: require CODEOWNERS review on " + h.branch() + " with human owners (or a team), so a bot approval never satisfies the rule.",
	}
	switch n.Attrs[AttrReviewBypassReason] {
	case ReviewBypassApp:
		if app := BotMergeApp(n); app != "" && n.Attrs[AttrReviewBypassAppMatch] == AppMatched {
			out = append(out, "Remove the GitHub App "+app+" from the bypass actors of the rules on "+h.branch()+": the merging workflow uses its token, so the merge skips every rule.")
		} else {
			out = append(out, "Check which GitHub App the merging workflow mints its token for, and remove it from the bypass actors of the rules on "+h.branch()+" if it is listed: a bypass App's merge skips every rule.")
		}
	case ReviewBypassAdmin:
		out = append(out, "Drop --admin from the merge step and do not give it an admin's token: admins bypass the rules on "+h.branch()+".")
	default:
		out = append(out, "Do not let a bot identity bypass the rules on "+h.branch()+": keep apps and admins out of the bypass actors.")
	}
	out = append(out,
		"Do not let PR authors trigger the merge: drop the author check from "+mergeName(n)+", or require a maintainer (author_association OWNER, or a write-permission check) and an environment with required reviewers.",
		"Do not give the reviewer write or approve rights: let the AI reviewer comment (pull-requests: write without approving, or a read-only token) and keep approve and merge with people.")
	for _, x := range BotMergeExtras(n) {
		out = append(out, x.Change)
	}
	return out
}

// BotMergeApp names the Apps a repo's bot merge mints its token for, from
// bot_merge_apps without unknown: "`77`". "" when none is named.
func BotMergeApp(n Node) string {
	var out []string
	for _, r := range splitAttr(n.Attrs[AttrBotMergeApps]) {
		if r != AppUnknown {
			out = append(out, "`"+r+"`")
		}
	}
	return strings.Join(out, ", ")
}

// BotMergeExtra is a fix for a script or key finding of a review bypass,
// with the file it changes ("" when it is not one file).
type BotMergeExtra struct {
	File, Change string
}

// BotMergeExtras are the fixes after the four of BotMergeFixes, in order:
// the stale-approval logic of the merge script (suspected), the review that
// does not re-run on push, the setting that lets GITHUB_TOKEN approve, and
// the merge key held by an AI step.
func BotMergeExtras(n Node) []BotMergeExtra {
	if !ReviewBypassed(n) {
		return nil
	}
	var out []BotMergeExtra
	if StaleApprovalsSuspected(n) {
		file, where := BotMergeScript(n), "the merge step"
		if file != "" {
			where = "`" + file + "`"
		}
		change := "Count only approvals of the head commit in " + where + " (suspected, heuristic: confirm by hand): skip reviews whose commit_id is not the head SHA and never count DISMISSED reviews."
		if RecountsDismissed(n) {
			change = "Stop counting DISMISSED reviews in " + where + " (suspected, heuristic: confirm by hand): the rules already dismiss stale reviews on push, but the script re-counts approvals GitHub dismissed. Count only APPROVED reviews whose commit_id is the head SHA."
		}
		out = append(out, BotMergeExtra{File: file, Change: change})
	}
	if n.Attrs[AttrReviewBypassStale] == StaleSuspected {
		for _, f := range splitAttr(n.Attrs[AttrReviewBypassApprove]) {
			out = append(out, BotMergeExtra{File: f, Change: "Re-run the AI review on every push: add synchronize to the pull_request types of `" + path.Base(f) + "`, so an approval always covers the code that is merged."})
		}
	}
	if n.Attrs[AttrReviewBypassReason] == ReviewBypassApprovals && n.Attrs[AttrActionsCanApprove] == "true" {
		out = append(out, BotMergeExtra{Change: "Turn off \"Allow GitHub Actions to create and approve pull requests\" (Settings > Actions > General > Workflow permissions): then a GITHUB_TOKEN approval is refused and never counts toward the required reviews."})
	}
	if files := SelfEditablePolicy(n); len(files) > 0 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = "`/" + f + "`"
		}
		file := ".github/CODEOWNERS"
		if co := n.Attrs[AttrCodeowners]; co != "" && co != "none" && co != "unknown" {
			file = co
		}
		out = append(out, BotMergeExtra{File: file, Change: "Add CODEOWNERS lines with human owners for " + strings.Join(names, ", ") +
			": these files steer the AI agents and reviewers, and a pull request can change them and still be merged by the bot."})
	}
	if n.Attrs[AttrAgentHoldsMergeKey] == "true" {
		files := splitAttr(n.Attrs[AttrAgentMergeKeyWorkflows])
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = "`" + path.Base(f) + "`"
		}
		file := ""
		if len(files) == 1 {
			file = files[0]
		}
		out = append(out, BotMergeExtra{File: file, Change: "Keep the merge key out of the AI step: the agent in " + strings.Join(names, ", ") + " holds the secret the merge uses, so a prompt injection can merge by itself. Give the merge its own App and key, outside the agent's env."})
	}
	return out
}

func mergeName(n Node) string {
	if m := n.Attrs[AttrReviewBypassMerge]; m != "" {
		return "`" + path.Base(m) + "`"
	}
	return "the merging workflow"
}

// BotMergeRepos lists the repos with a review bypass, sorted by ID.
func (ix *Index) BotMergeRepos() []string {
	var out []string
	for id, n := range ix.nodes {
		if ReviewBypassed(n) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// botMergeOn counts the repos r confirmed-reaches through its own
// CAN_MERGE_VIA_BOT hop: it lands code there without push access and without
// human review.
func (ix *Index) botMergeOn(r Result) int {
	if !ix.hasBotMerge() {
		return 0
	}
	n := 0
	for _, repo := range r.Confirmed.Repos {
		if p, ok := r.Paths[repo]; ok && !p.Unverified && hasHop(p, CanMergeViaBot, repo) {
			n++
		}
	}
	return n
}

// hasBotMerge reports whether any edge is CAN_MERGE_VIA_BOT (cached).
func (ix *Index) hasBotMerge() bool {
	ix.botOnce.Do(func() {
		for _, e := range ix.g.Edges {
			if e.Kind == CanMergeViaBot {
				ix.botAny = true
				return
			}
		}
	})
	return ix.botAny
}

// BlockBotMerge closes a repo's AI approve + self-merge path (one of
// BotMergeFixes: require a human CODEOWNERS approval, remove the app from
// the bypass actors, or stop PR authors from starting the merge): it removes
// every CAN_MERGE_VIA_BOT edge into the repo.
type BlockBotMerge struct {
	Repo string `json:"repo"` // "repo:O/R"
}

func (f BlockBotMerge) ID() string { return "block_bot_merge:" + f.Repo }

func (f BlockBotMerge) apply(fs *fixSet) { setFlag(&fs.botBlocked, f.Repo) }

func (f BlockBotMerge) edges(ix *Index) []Edge {
	var out []Edge
	for _, e := range ix.in[f.Repo] {
		if e.Kind == CanMergeViaBot {
			out = append(out, e)
		}
	}
	return out
}
