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
		for _, r := range d.Risks {
			poss := plural(r.PossibleRepos, "repo", "repos")
			if r.PossibleOther > 0 {
				poss += fmt.Sprintf(" + %d impact", r.PossibleOther)
			}
			if d.HasCloud {
				p("| %s | %d | %d | %d | %d | %d | %d | %s | %s |\n", md(r.Principal), r.Repos, r.Orgs, r.Cloud, r.OIDC, r.Secrets, r.Runners, poss, r.Score)
			} else {
				p("| %s | %d | %d | %d | %d | %d | %s | %s |\n", md(r.Principal), r.Repos, r.Orgs, r.OIDC, r.Secrets, r.Runners, poss, r.Score)
			}
		}
		p("\nScore counts confirmed reach only.\n\n")
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
		p("### %s\n\n", md(pp.Principal))
		for _, pv := range pp.Paths {
			status := "confirmed"
			if !pv.Confirmed {
				status = "possible: a hop is not visible"
			}
			p("- **%s** to %s\n", status, md(pv.To))
			if pv.Note != "" {
				p("  _%s_\n", md(pv.Note))
			}
			writeMDHops(p, pv.Hops)
		}
		p("\n")
	}

	if len(d.Orgs) > 0 {
		p("## Org settings\n\n| Org | Default permission | 2FA | SSO | IP allow list | Members |\n|---|---|---|---|---|---|\n")
		for _, o := range d.Orgs {
			p("| %s |", md(o.Org))
			for _, c := range o.Cells {
				if c.NV {
					p(" _%s_ |", md(c.Value))
				} else {
					p(" %s |", md(c.Value))
				}
			}
			p("\n")
		}
		p("\n")
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
