package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/peleduri/gop/internal/mcpserver"
	"github.com/peleduri/gop/internal/sanitize"
)

// mdEsc makes a value safe inside Markdown text and table cells: HTML is
// neutralized, and characters that break tables or formatting are escaped.
// md first escapes newlines, control, bidi and zero-width characters
// (sanitize.Truncate), so a GitHub name can never start a line or hide
// text, and caps the value at sanitize.MaxLine runes.
var mdEsc = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;",
	"|", `\|`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"\r", " ", "\n", " ",
)

func md(s string) string { return mdEsc.Replace(sanitize.Truncate(s, sanitize.MaxLine)) }

func writeMDHops(p func(string, ...any), hops []hopView) {
	for i, h := range hops {
		kind := h.Kind
		if h.Reverse {
			kind += " (reversed)"
		}
		p("  %d. %s → %s, %s, **%s**, %s\n", i+1, md(h.From), md(h.To), md(kind), h.Evidence, md(h.SourceAPI))
		if h.Reason != "" {
			p("     undecided: %s\n", md(h.Reason))
		}
		if h.Note != "" {
			p("     note: %s\n", md(h.Note))
		}
	}
}

func writeMarkdown(w io.Writer, d data) error {
	b := bufio.NewWriter(w)
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }

	title := "gop: who can make code run where"
	if d.Demo {
		title = mcpserver.DemoMarker + " " + title
	}
	p("# %s\n\n", title)
	if d.Enterprise != "" || d.CollectedAt != "" {
		p("Enterprise **%s**, collected %s\n\n", md(d.Enterprise), md(d.CollectedAt))
	}
	if bn := d.Banner; bn != nil {
		p("## What changed\n\nPrevious snapshot %s → this snapshot %s. %s\n\n", md(bn.Since), md(bn.Until), md(bn.Summary))
		if bn.Score.Text != "" {
			p("- Top principal: %s\n", md(bn.Score.Text))
		}
		for _, g := range bn.Groups {
			p("- %s: %d\n", g.Title, g.Count)
			for _, it := range g.Items {
				ev := ""
				if it.Ev != "" {
					ev = it.Ev + ": "
				}
				p("  - %s%s\n", ev, md(it.Text))
			}
			if g.More > 0 {
				p("  - and %d more: gop diff lists every change\n", g.More)
			}
		}
		p("\n")
	}
	p("> %s\n", md(d.Headline))
	if d.FixLine != "" {
		p(">\n> %s\n", md(d.FixLine))
	}
	if d.PinLine != "" {
		p(">\n> %s\n", md(d.PinLine))
	}
	if d.HasCloud {
		p("\nConfirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry, or (a cloud hop) from a supplied file: a cloud trust policy you supplied, not read from the cloud. Possible means at least one hop is not visible to the token: unknown, not absent.\n\n")
	} else {
		p("\nConfirmed means every hop was read live, inferred from other observed facts by a documented rule, or read from a recent audit log entry. Possible means at least one hop is not visible to the token: unknown, not absent.\n\n")
	}

	p("## Top risks\n\n")
	if len(d.Risks) == 0 {
		p("The graph has no principals.\n\n")
	} else {
		if d.HasCloud {
			p("| Principal | Confirmed repos | Orgs | Cloud roles | OIDC | Secrets | Runners | Possible | Score |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
		} else {
			p("| Principal | Confirmed repos | Orgs | OIDC | Secrets | Runners | Possible | Score |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
		}
		ranged := false
		for _, r := range d.Risks {
			poss := plural(r.PossibleRepos, "repo", "repos")
			if r.PossibleOther > 0 {
				poss += fmt.Sprintf(" + %d impact", r.PossibleOther)
			}
			repos, orgs := fmt.Sprint(r.Repos), fmt.Sprint(r.Orgs)
			if r.ReposRange != "" {
				repos, orgs = r.ReposRange, r.OrgsRange
				ranged = true
			}
			if d.HasCloud {
				p("| %s | %s | %s | %d | %d | %d | %d | %s | %s |\n", principalCell(r), repos, orgs, r.Cloud, r.OIDC, r.Secrets, r.Runners, poss, r.Score)
			} else {
				p("| %s | %s | %s | %d | %d | %d | %s | %s |\n", principalCell(r), repos, orgs, r.OIDC, r.Secrets, r.Runners, poss, r.Score)
			}
		}
		agent := map[string]int{}
		for _, s := range d.ix.Scores() {
			if s.AgentExposed > 0 {
				agent[s.Principal] = s.AgentExposed
			}
		}
		for _, r := range d.Risks {
			if n := agent[r.Principal]; n > 0 {
				p("\n- %s can start %s without push access (see AI agents in CI).", md(r.Principal), plural(n, "exposed AI agent workflow", "exposed AI agent workflows"))
			}
		}
		bot := map[string]int{}
		for _, s := range d.ix.Scores() {
			if s.BotSelfMerge > 0 {
				bot[s.Principal] = s.BotSelfMerge
			}
		}
		for _, r := range d.Risks {
			if n := bot[r.Principal]; n > 0 {
				p("\n- %s can get code onto the default branch of %s without human review [bot_self_merge] (see AI approve + self-merge).", md(r.Principal), plural(n, "repo", "repos"))
			}
		}
		if len(agent) > 0 || len(bot) > 0 {
			p("\n")
		}
		p("\nScore counts confirmed reach only.")
		if ranged {
			p(" A row grouped by cause shows the range of its members' confirmed repos and orgs; its other columns are its first member's. The JSON (`top_risks`) lists each member's own figures.")
		}
		p("\n\n")
	}
	writeMDAgents(p, d)
	writeMDBotMerge(p, d)
	if o := d.Ownership; o != nil {
		p("## Org ownership\n\n%s\n\n| Orgs owned | Accounts |\n|---|---:|\n", md(o.Line))
		for _, b := range o.Buckets {
			p("| %s | %d |\n", b.Label, b.Accounts)
		}
		p("\n%s\n\n", md(o.Note))
	}

	p("## Suggested fixes\n\n")
	if len(d.Fixes) == 0 {
		p("No candidate fix removes confirmed reach.\n\n")
	} else {
		p("| # | Fix | Confirmed pairs removed | Cumulative removed |\n|---:|---|---:|---:|\n")
		for _, f := range d.Fixes {
			p("| %d | %s | %d | %s |\n", f.N, md(f.Description), f.Removed, f.CumulativePct)
		}
		p("\n")
	}

	if len(d.Pinned) > 0 {
		p("## Pinned, still reachable\n\n")
		p("A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:\n\n")
		for _, r := range d.Pinned {
			via := "**" + md(r.Via) + "**"
			if r.ViaNote != "" {
				via += " (" + r.ViaNote + ")"
			}
			p("- **%s** (used by %s) runs %s. %s can change it", md(r.Action),
				plural(r.Consumers, "workflow", "workflows"), via, md(r.Principal))
			if r.Path.Confirmed {
				p(" (confirmed):\n")
			} else {
				p(" (possible: a hop is not visible):\n")
			}
			writeMDHops(p, r.Path.Hops)
		}
		p("\n")
	}

	p("## Top paths\n\n")
	for _, pp := range d.Paths {
		if pp.Group != "" {
			p("### %s, one of %s\n\n", md(pp.Principal), md(pp.Group))
		} else {
			p("### %s\n\n", md(pp.Principal))
		}
		for _, pv := range pp.Paths {
			status := "confirmed"
			if !pv.Confirmed {
				status = "possible: a hop is not visible"
			}
			p("- **%s** to %s\n", status, md(pv.To))
			if pv.Note != "" {
				p("  _%s_\n", md(pv.Note))
			}
			if pv.Hardening != "" {
				p("  _Context, not part of the score: %s_\n", md(pv.Hardening))
			}
			writeMDHops(p, pv.Hops)
		}
		p("\n")
	}

	if len(d.Orgs) > 0 {
		titles := settingTitles()
		p("## Org settings\n\n| Org | %s |\n|---|%s\n", strings.Join(titles, " | "), strings.Repeat("---|", len(titles)))
		for _, o := range d.Orgs {
			p("| %s |", md(o.Org))
			for _, c := range o.Cells {
				if c.NV {
					p(" [_%s_](#why-unknown) |", md(c.Value))
				} else {
					p(" %s |", md(c.Value))
				}
			}
			p("\n")
		}
		p("\n")
		if len(d.OrgWhy) > 0 {
			p("### Why unknown\n\n")
			for _, w := range d.OrgWhy {
				p("- **%s**\n", md(w.Org))
				for _, it := range w.Items {
					p("  - %s: %s", md(it.Settings), md(it.Reason))
					if it.Fix != "" {
						p(". Access that fixes it: %s", md(it.Fix))
					}
					p("\n")
				}
			}
			p("\n")
		}
	}

	if len(d.RepoHardening) > 0 {
		writeMDHardening(p, d)
	}

	p("## Coverage\n\n")
	if d.LockLine != "" {
		p("%s\n\n", md(d.LockLine))
	}
	if len(d.Coverage) == 0 {
		p("Every fact gop looked for was visible to the token.\n\n")
	} else {
		p("| Scope | Not visible | Why | Access that fixes it |\n|---|---|---|---|\n")
		for _, c := range d.Coverage {
			p("| %s | %s | %s | %s |\n", md(c.Scope), md(c.Fact), md(c.Reason), md(c.NeedsFix))
		}
		p("\n")
	}
	p("---\n\nGenerated by gop %s. %s\n", md(d.Version), footer)
	return b.Flush()
}

// principalCell is a risks-table principal, with its advisory note.
func principalCell(r riskRow) string {
	who := md(r.Principal)
	if r.Group != "" {
		who = md(r.Group + ": " + r.MembersText)
	}
	if r.Advisory == "" {
		return who
	}
	return who + " (" + md(r.Advisory) + ")"
}

// writeMDAgents writes the AI agents in CI section.
func writeMDAgents(p func(string, ...any), d data) {
	if len(d.Agents) == 0 {
		return
	}
	p("## AI agents in CI\n\n%s An agent reads the text of whoever starts it and acts with its job's token, secrets and tools, so a prompt injection uses all of them.\n\n", md(d.AgentLine))
	for _, r := range d.Agents {
		kind := r.Kind
		if r.NameOnly {
			kind = "name only"
		}
		p("### %s (%s)\n\n", md(r.Workflow), md(kind))
		who := r.Exposure
		if r.Who != "" {
			if r.Possible {
				who += ": possible: " + r.Who
			} else {
				who += ": " + r.Who
			}
		}
		if r.Triggers != "" {
			who += " on " + r.Triggers
		}
		p("- Who can start it: %s\n", md(who))
		if !r.NameOnly {
			p("- What it holds: %s\n- What it reaches: %s\n", md(r.Holds), md(r.Reach))
			if r.Prompt != "" || r.Reads != "" {
				var inj []string
				if r.Prompt != "" {
					inj = append(inj, r.Prompt+" in the prompt")
				}
				if r.Reads != "" {
					inj = append(inj, "reads "+r.Reads)
				}
				p("- Prompt injection: %s\n", md(strings.Join(inj, "; ")))
			}
			if r.Tools != "" {
				p("- Approvals off: %s\n", md(r.Tools))
			}
			for i, f := range r.Fixes {
				p("  %d. %s\n", i+1, md(f))
			}
		}
		p("\n")
	}
	p("Agents are found by known actions and CLIs (docs/agents-in-ci.md). A name-only match is listed but never ranked. An action whose actor check gop does not know counts as possible, never as closed.\n\n")
}

// writeMDHardening writes the repo hardening section: context only.
func writeMDHardening(p func(string, ...any), d data) {
	p("## Repo hardening\n\n")
	p("Context only: these facts never change evidence, counts or scores. Each cell is repos where it holds / repos with the fact; unknown (not visible to the token) is counted separately, never as off.\n\n")
	p("| Org | Repos | Protected default branch | Required reviews | CODEOWNERS covers workflows | Secret scanning | Push protection |\n|---|---:|---|---|---|---|---|\n")
	for _, h := range d.RepoHardening {
		p("| %s | %d | %s | %s | %s | %s | %s |\n", md(h.Org), h.Repos, h.Protected, h.Reviews, h.CodeownersWF, h.SecretScan, h.PushProt)
	}
	p("\n")
	if len(d.HardenRepos) > 0 {
		p("Repos on the top paths:\n\n")
		for _, r := range d.HardenRepos {
			p("- **%s**: %s\n", md(r.Repo), md(r.State))
		}
		p("\n")
	}
	if len(d.HardenFixes) > 0 {
		p("Hardening suggestions (advisory: not counted as removing confirmed reach):\n\n")
		for _, f := range d.HardenFixes {
			p("- %s (%s)\n", md(f.Description), md(f.Reason))
		}
		p("\n")
	}
}
