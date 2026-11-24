// Package sanitize makes values that come from GitHub safe to show to a
// person or an agent. Repo, workflow, job, team, branch and environment
// names, file paths and descriptions are written by whoever can create them,
// so gop treats them as data that may carry a prompt injection: a name with a
// newline and a fake heading, a closing tool tag, a Unicode bidi override, a
// zero-width or tag character, or simply 10 kB of text.
//
// Clean escapes the characters that can break a line or hide text. Value
// also caps the length and wraps the result in backticks, the fixed
// delimiter text summaries use around every value. Line cleans and caps a
// whole summary line. JSON escapes the same characters inside marshaled JSON
// so the decoded values stay exactly as they were. NoLinks and NoAutolink
// keep a name from turning into a live link in Markdown, including bare and
// angle-bracket autolinks and email addresses.
package sanitize

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Length caps, in runes of escaped output.
const (
	// MaxValue caps one delimited value in a summary. The full value stays
	// in the structured (JSON) output.
	MaxValue = 200
	// MaxLine caps a whole summary line.
	MaxLine = 1024
)

// Ellipsis marks a truncated value.
const Ellipsis = "…"

// Unsafe reports whether r is a character that can break a line, change the
// reading order or hide text: control characters (C0, DEL, C1), line and
// paragraph separators, format characters (bidi embeddings, overrides,
// isolates and marks, zero-width space and joiners, word joiner, BOM, soft
// hyphen, tag characters) and variation selectors.
func Unsafe(r rune) bool {
	switch {
	case r == utf8.RuneError:
		return true
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r >= 0xfe00 && r <= 0xfe0f, r >= 0xe0100 && r <= 0xe01ef: // variation selectors
		return true
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}

// escape returns the visible escape for an unsafe rune.
func escape(r rune) string {
	switch r {
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	}
	if r > 0xffff {
		return fmt.Sprintf(`\U%08X`, r)
	}
	return fmt.Sprintf(`\u%04X`, r)
}

// write escapes s, and backticks too when tick is set. With limit > 0 an
// output longer than limit runes is cut at a piece boundary (an escape is
// never split) and ends in Ellipsis, so it is at most limit runes long.
func write(s string, limit int, tick bool) string {
	pieces := make([]string, 0, len(s))
	total := 0
	for _, r := range s {
		var p string
		switch {
		case Unsafe(r):
			p = escape(r)
		case tick && r == '`':
			p = `\u0060`
		default:
			p = string(r)
		}
		pieces = append(pieces, p)
		total += utf8.RuneCountInString(p)
	}
	var b strings.Builder
	if limit <= 0 || total <= limit {
		for _, p := range pieces {
			b.WriteString(p)
		}
		return b.String()
	}
	n := 0
	for _, p := range pieces {
		w := utf8.RuneCountInString(p)
		if n+w > limit-1 {
			break
		}
		n += w
		b.WriteString(p)
	}
	b.WriteString(Ellipsis)
	return b.String()
}

// Clean escapes unsafe characters (Unsafe) as visible \n, \r, \t, \uXXXX or
// \UXXXXXXXX sequences. Invalid UTF-8 is escaped as U+FFFD. The result is one line.
func Clean(s string) string { return write(s, 0, false) }

// Code is Clean with backticks escaped too, for text that sits inside a
// Markdown code span or fence, where a backtick would end it.
func Code(s string) string { return write(s, 0, true) }

// Truncate is Clean with a cap of limit runes of output, ending in Ellipsis
// when cut.
func Truncate(s string, limit int) string { return write(s, limit, false) }

// Value is a value from GitHub, ready to embed in a text summary: cleaned,
// backticks escaped, capped at MaxValue runes and wrapped in backticks.
func Value(s string) string { return "`" + write(s, MaxValue, true) + "`" }

// Line makes a whole summary line safe: unsafe characters escaped and capped
// at MaxLine runes. It never adds delimiters; build the line with Value.
func Line(s string) string { return write(s, MaxLine, false) }

// JSON escapes unsafe runes in marshaled JSON as \uXXXX (surrogate pairs above
// U+FFFF). Such runes can only occur inside JSON strings, so the result is
// valid JSON that decodes to exactly the same values. Go's encoder already
// escapes C0 controls, U+2028 and U+2029; this adds DEL, C1, bidi, zero-width,
// tag characters and variation selectors.
func JSON(b []byte) []byte {
	clean := true
	for _, r := range string(b) {
		if r >= 0x7f && Unsafe(r) {
			clean = false
			break
		}
	}
	if clean {
		return b
	}
	var out strings.Builder
	out.Grow(len(b) + 64)
	for _, r := range string(b) {
		if r < 0x7f || !Unsafe(r) {
			out.WriteRune(r)
			continue
		}
		if r > 0xffff {
			r -= 0x10000
			fmt.Fprintf(&out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			continue
		}
		fmt.Fprintf(&out, `\u%04x`, r)
	}
	return []byte(out.String())
}

// HTML replaces unsafe runes in rendered HTML, except the page's own
// newlines and tabs, with numeric character references (&#x202E;), so a
// browser shows the same text but no raw bidi, zero-width or control
// character is left in the source an agent reads. Run it on a page whose
// script blocks hold no unsafe runes (JSON passed through JSON), since
// character references are not decoded inside a script.
func HTML(b []byte) []byte {
	unsafe := func(r rune) bool { return r != '\n' && r != '\t' && Unsafe(r) }
	if !strings.ContainsFunc(string(b), unsafe) {
		return b
	}
	var out strings.Builder
	out.Grow(len(b) + 64)
	for _, r := range string(b) {
		if unsafe(r) {
			fmt.Fprintf(&out, "&#x%X;", r)
			continue
		}
		out.WriteRune(r)
	}
	return []byte(out.String())
}

// NoLinks escapes the Markdown that turns plain text into a live link or
// image: the "](" of [text](url) and ![alt](src) gets a backslash, and so do
// the autolinks NoAutolink breaks. Reference links need a definition at the
// start of a line, which a cleaned value cannot write, so other brackets stay
// as they are. Run it once, on cleaned text (Clean) in Markdown prose, not in
// a code span.
func NoLinks(s string) string { return NoAutolink(strings.ReplaceAll(s, "](", `\](`)) }

// NoAutolink breaks the GitHub-flavored Markdown autolinks a name could
// make: a backslash goes before the colon of a bare http://, https:// and
// ftp:// and before the dot of www. (any letter case), before the @ of an
// email address (alice@example.invalid, also after mailto:), and before the
// < of an angle-bracket autolink (<scheme:...> or <alice@example.invalid>).
// The text still renders the same, without the link. A < that does not open
// an autolink, such as the <sha-of-main> placeholder, stays as it is.
func NoAutolink(s string) string {
	var b strings.Builder
	last, changed := 0, false
	for i := 0; i < len(s); i++ {
		esc := false
		switch s[i] {
		case ':':
			esc = strings.HasPrefix(s[i:], "://") &&
				(foldSuffix(s[:i], "http") || foldSuffix(s[:i], "https") || foldSuffix(s[:i], "ftp"))
		case '.':
			esc = foldSuffix(s[:i], "www")
		case '@':
			esc = i > 0 && emailLocal(s[i-1]) && emailDomain(s[i+1:])
		case '<':
			esc = angleAutolink(s[i+1:])
		}
		if esc {
			b.WriteString(s[last:i])
			b.WriteString(`\`)
			last, changed = i, true
		}
	}
	if !changed {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// emailLocal reports whether c can end the local part of a GFM email
// autolink (letters, digits, '.', '-', '_', '+').
func emailLocal(c byte) bool {
	return isAlnum(c) || c == '.' || c == '-' || c == '_' || c == '+'
}

// emailDomain reports whether s starts with what GFM accepts after the @ of
// an email autolink: labels of letters, digits, '-' and '_', with at least
// one '.' followed by another label character.
func emailDomain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlnum(c) || c == '-' || c == '_':
		case c == '.' && i > 0 && i+1 < len(s) && (isAlnum(s[i+1]) || s[i+1] == '-' || s[i+1] == '_'):
			return true
		default:
			return false
		}
	}
	return false
}

// angleAutolink reports whether s, the text after a '<', opens a CommonMark
// autolink: a scheme (a letter, then 1 to 31 letters, digits, '+', '.' or
// '-') and a colon, or an email local part and an @. The closing '>' is not
// required: escaping a '<' that turns out not to open a link is harmless.
func angleAutolink(s string) bool {
	if s != "" && isAlpha(s[0]) {
		i := 1
		for i < len(s) && i <= 32 && (isAlnum(s[i]) || s[i] == '+' || s[i] == '.' || s[i] == '-') {
			i++
		}
		if i >= 2 && i <= 32 && i < len(s) && s[i] == ':' {
			return true
		}
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '@':
			return i > 0
		case isAlnum(c) || strings.IndexByte(".!#$%&'*+/=?^_`{|}~-", c) >= 0:
		default:
			return false
		}
	}
	return false
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func isAlnum(c byte) bool { return isAlpha(c) || c >= '0' && c <= '9' }

// foldSuffix reports whether s ends with the lowercase ASCII word w, in any
// letter case.
func foldSuffix(s, w string) bool {
	if len(s) < len(w) {
		return false
	}
	return strings.EqualFold(s[len(s)-len(w):], w)
}
