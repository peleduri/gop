package fixplan

import (
	"fmt"
	"sort"
	"strings"
)

// diffContext is the number of unchanged lines around each change in a
// FileDiff hunk, as in git diff.
const diffContext = 3

// PinnedUses returns the pinned form of uses (O/R[/path]@ref): the value
// "O/R[/path]@sha" and the trailing comment "# ref" that keeps the old ref
// readable.
func PinnedUses(uses, sha string) (value, comment string) {
	base, ref := splitRef(uses)
	return base + "@" + sha, "# " + ref
}

// PinLine rewrites one file line that holds `uses: <uses>` (bare or quoted,
// with or without a list marker or trailing comment) to the pinned value. The
// indentation and everything around the value stay as they are. ok is false
// when the line has no uses: key with exactly that value.
func PinLine(line, uses, sha string) (string, bool) {
	value, comment := PinnedUses(uses, sha)
	for off := 0; off < len(line); {
		i := strings.Index(line[off:], uses)
		if i < 0 {
			return "", false
		}
		i += off
		off = i + 1
		pre, rest := line[:i], line[i+len(uses):]
		quote := ""
		if strings.HasSuffix(pre, `"`) || strings.HasSuffix(pre, "'") {
			quote = pre[len(pre)-1:]
			pre = pre[:len(pre)-1]
		}
		if !strings.HasSuffix(strings.TrimRight(pre, " \t"), "uses:") {
			continue
		}
		if quote != "" {
			if !strings.HasPrefix(rest, quote) {
				continue
			}
			rest = rest[1:]
		}
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '\r' {
			continue
		}
		return pre + quote + value + quote + " " + comment + rest, true
	}
	return "", false
}

// Edit replaces one line of a file. Line is 1-based.
type Edit struct {
	Line int
	New  string
}

// FileDiff renders the git-style unified diff (with a diff --git header) that
// applies edits to content. Hunks carry diffContext lines of context, and
// hunks that touch or overlap are merged, so the output applies with git
// apply. Edits outside the file are ignored; it returns "" when no edit
// changes a line.
func FileDiff(file string, content []byte, edits []Edit) string {
	text := string(content)
	noEOL := text != "" && !strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		lines = nil
	}
	n := len(lines)
	changed := map[int]string{}
	for _, e := range edits {
		if e.Line >= 1 && e.Line <= n && lines[e.Line-1] != e.New {
			changed[e.Line] = e.New
		}
	}
	if len(changed) == 0 {
		return ""
	}
	at := make([]int, 0, len(changed))
	for l := range changed {
		at = append(at, l)
	}
	sort.Ints(at)

	type span struct{ start, end int }
	var spans []span
	for _, l := range at {
		s, e := max(1, l-diffContext), min(n, l+diffContext)
		if len(spans) > 0 && s <= spans[len(spans)-1].end+1 {
			spans[len(spans)-1].end = e
			continue
		}
		spans = append(spans, span{s, e})
	}

	var b strings.Builder
	fmt.Fprintf(&b, "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n", file, file, file, file)
	eol := func(l int) {
		if noEOL && l == n {
			b.WriteString("\\ No newline at end of file\n")
		}
	}
	for _, sp := range spans {
		count := sp.end - sp.start + 1
		fmt.Fprintf(&b, "@@ -%s +%s @@\n", hunkRange(sp.start, count), hunkRange(sp.start, count))
		for l := sp.start; l <= sp.end; l++ {
			if nl, ok := changed[l]; ok {
				b.WriteString("-" + lines[l-1] + "\n")
				eol(l)
				b.WriteString("+" + nl + "\n")
				eol(l)
				continue
			}
			b.WriteString(" " + lines[l-1] + "\n")
			eol(l)
		}
	}
	return b.String()
}

func hunkRange(start, count int) string {
	if count == 1 {
		return fmt.Sprint(start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}

// PinFileDiff pins uses to sha on the given 1-based lines of a file and
// returns the diff. missing lists the lines that do not hold `uses: <uses>`
// (the file changed since the graph was collected); they are left out.
func PinFileDiff(file string, content []byte, lines []int, uses, sha string) (diff string, missing []int) {
	all := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	var edits []Edit
	for _, l := range lines {
		if l < 1 || l > len(all) {
			missing = append(missing, l)
			continue
		}
		nl, ok := PinLine(all[l-1], uses, sha)
		if !ok {
			missing = append(missing, l)
			continue
		}
		edits = append(edits, Edit{Line: l, New: nl})
	}
	return FileDiff(file, content, edits), missing
}
