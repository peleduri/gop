package graph

// PolicyFiles are the repo files that steer AI coding agents and AI
// reviewers: agent instructions (AGENTS.md, CLAUDE.md, Copilot and Cursor
// rules) and review policies (REVIEW.md). In a repo where a bot can approve
// or merge, a pull request that edits them changes the rules its own AI
// review follows. .cursor/rules is a directory.
var PolicyFiles = []string{
	"AGENTS.md",
	"CLAUDE.md",
	"REVIEW.md",
	".github/copilot-instructions.md",
	".cursorrules",
	".cursor/rules",
}

// SelfEditablePolicy lists the policy files of a repo with a review bypass
// (a bot can approve or merge) that no CODEOWNERS rule protects: a pull
// request can edit them and still be merged by the bot. Nil when the repo
// has no review bypass or every policy file is owned; nil too when the
// ownership is unknown (see PolicyUnknown).
func SelfEditablePolicy(n Node) []string {
	if !ReviewBypassed(n) {
		return nil
	}
	switch v := n.Attrs[AttrPolicyFilesUnowned]; v {
	case "", "none", "unknown":
		return nil
	default:
		return splitAttr(v)
	}
}

// PolicyUnknown reports whether a repo with a review bypass has policy
// files whose CODEOWNERS ownership gop could not read.
func PolicyUnknown(n Node) bool {
	return ReviewBypassed(n) && n.Attrs[AttrPolicyFilesUnowned] == "unknown"
}
