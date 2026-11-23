package cartography

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// maxDepth bounds list and map nesting in cypher-shell output.
const maxDepth = 64

// plainRows reads cypher-shell --format plain output: a header line of
// column names, then one line per record with comma-separated Cypher values
// (strings in double quotes, TRUE/FALSE, NULL, numbers, lists, maps).
func plainRows(text string) ([]map[string]any, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var cols []string
	var out []map[string]any
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if cols == nil {
			for _, c := range strings.Split(line, ",") {
				c = strings.Trim(strings.TrimSpace(c), "`")
				if c == "" || unicode.IsDigit(rune(c[0])) || strings.ContainsFunc(c, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' }) {
					return nil, fmt.Errorf("%w: not JSON, and the first line is not a cypher-shell header of column names", ErrFormat)
				}
				cols = append(cols, c)
			}
			continue
		}
		p := &literal{s: line}
		row := map[string]any{}
		ok := true
		for i := 0; ; i++ {
			p.space()
			v, err := p.value(0)
			if err != nil {
				ok = false
				break
			}
			if i < len(cols) {
				row[cols[i]] = v
			}
			p.space()
			if p.eof() {
				if i+1 != len(cols) {
					ok = false
				}
				break
			}
			if !p.consume(',') {
				ok = false
				break
			}
		}
		if !ok {
			row = map[string]any{"kind": "unparsed cypher-shell line"}
		}
		out = append(out, row)
	}
	return out, nil
}

// literal parses Cypher value literals as cypher-shell prints them.
type literal struct {
	s   string
	pos int
}

func (p *literal) eof() bool { return p.pos >= len(p.s) }

func (p *literal) space() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func (p *literal) consume(c byte) bool {
	if p.pos < len(p.s) && p.s[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

var errSyntax = fmt.Errorf("cypher value syntax")

func (p *literal) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errSyntax
	}
	p.space()
	if p.eof() {
		return nil, errSyntax
	}
	switch c := p.s[p.pos]; {
	case c == '"' || c == '\'':
		return p.str()
	case c == '[':
		p.pos++
		var out []any
		p.space()
		if p.consume(']') {
			return []any{}, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			p.space()
			if p.consume(']') {
				return out, nil
			}
			if !p.consume(',') {
				return nil, errSyntax
			}
		}
	case c == '{':
		p.pos++
		out := map[string]any{}
		p.space()
		if p.consume('}') {
			return out, nil
		}
		for {
			p.space()
			k, err := p.key()
			if err != nil {
				return nil, err
			}
			p.space()
			if !p.consume(':') {
				return nil, errSyntax
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
			p.space()
			if p.consume('}') {
				return out, nil
			}
			if !p.consume(',') {
				return nil, errSyntax
			}
		}
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.pos
		p.pos++
		for p.pos < len(p.s) && strings.IndexByte("0123456789.eE+-", p.s[p.pos]) >= 0 {
			p.pos++
		}
		n := json.Number(p.s[start:p.pos])
		if _, err := n.Float64(); err != nil {
			return nil, errSyntax
		}
		return n, nil
	default:
		w := p.word()
		switch strings.ToLower(w) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		}
		return nil, errSyntax
	}
}

func (p *literal) word() string {
	start := p.pos
	for p.pos < len(p.s) && (p.s[p.pos] == '_' || unicode.IsLetter(rune(p.s[p.pos])) || unicode.IsDigit(rune(p.s[p.pos]))) {
		p.pos++
	}
	return p.s[start:p.pos]
}

func (p *literal) key() (string, error) {
	if p.eof() {
		return "", errSyntax
	}
	switch p.s[p.pos] {
	case '"', '\'':
		return p.str()
	case '`':
		p.pos++
		end := strings.IndexByte(p.s[p.pos:], '`')
		if end < 0 {
			return "", errSyntax
		}
		k := p.s[p.pos : p.pos+end]
		p.pos += end + 1
		return k, nil
	}
	if w := p.word(); w != "" {
		return w, nil
	}
	return "", errSyntax
}

// str reads a quoted string. A backslash escapes the next character; \n,
// \t, \r and \uXXXX are decoded.
func (p *literal) str() (string, error) {
	q := p.s[p.pos]
	p.pos++
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch {
		case c == q:
			p.pos++
			return b.String(), nil
		case c == '\\' && p.pos+1 < len(p.s):
			e := p.s[p.pos+1]
			p.pos += 2
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'u':
				var s string
				if p.pos+4 <= len(p.s) && json.Unmarshal([]byte(`"\u`+p.s[p.pos:p.pos+4]+`"`), &s) == nil {
					b.WriteString(s)
					p.pos += 4
				} else {
					b.WriteString(`\u`)
				}
			default:
				b.WriteByte(e)
			}
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", errSyntax
}
