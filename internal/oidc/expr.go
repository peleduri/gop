package oidc

import (
	"errors"
	"strings"
)

// A small expression parser shared by GCP attribute conditions (a CEL subset)
// and Azure flexible federated credential expressions. It understands
// comparisons of one claim against string literals combined with and/or and
// parentheses. Anything else becomes an unknown leaf whose source text is kept
// as a "cel" pattern, so the condition is treated as possible, never dropped.

// leaf is one condition on one claim. key is the claim name ("sub",
// "repository", ...) or "" when the claim could not be resolved.
type leaf struct {
	key   string
	pats  []Pattern
	known bool
	raw   string
}

type node interface{}

type andNode struct{ a, b node }
type orNode struct{ a, b node }

const (
	maxExprLen   = 64 << 10
	maxExprDepth = 64
	maxDNF       = 64
)

var errExpr = errors.New("expression not understood")

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tStr
	tPunct
	tOther
)

type token struct {
	kind       tokKind
	text       string // identifier, punctuation, or decoded string value
	start, end int
}

func tokenize(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i + 1
			for j < len(src) && (src[j] == '_' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			out = append(out, token{tIdent, src[i:j], i, j})
			i = j
		case c == '\'' || c == '"':
			var b strings.Builder
			j := i + 1
			closed := false
			for j < len(src) {
				if src[j] == '\\' && j+1 < len(src) {
					switch src[j+1] {
					case '\\', '\'', '"':
						b.WriteByte(src[j+1])
					default:
						// Other escapes are kept verbatim; the leaf stays exact text.
						b.WriteByte('\\')
						b.WriteByte(src[j+1])
					}
					j += 2
					continue
				}
				if src[j] == c {
					closed = true
					j++
					break
				}
				b.WriteByte(src[j])
				j++
			}
			if !closed {
				return nil, errExpr
			}
			out = append(out, token{tStr, b.String(), i, j})
			i = j
		default:
			two := ""
			if i+1 < len(src) {
				two = src[i : i+2]
			}
			switch two {
			case "==", "!=", "&&", "||", "<=", ">=":
				out = append(out, token{tPunct, two, i, i + 2})
				i += 2
				continue
			}
			if strings.IndexByte("()[],.!<>+-*/%?:{}", c) >= 0 {
				out = append(out, token{tPunct, string(c), i, i + 1})
			} else {
				out = append(out, token{tOther, string(c), i, i + 1})
			}
			i++
		}
	}
	out = append(out, token{tEOF, "", len(src), len(src)})
	return out, nil
}

// dialect is what differs between CEL and Azure expressions.
type dialect struct {
	and, or, not string
	// atom parses one recognized comparison at p.i, or returns ok=false.
	atom func(p *parser) (leaf, bool)
}

type parser struct {
	src     string
	toks    []token
	i       int
	depth   int
	tooDeep bool // sticky: nesting limit hit, give up on the whole expression
	d       *dialect
	// resolve maps a path ("assertion.sub", "attribute.repo", "claims") to a
	// claim name.
	resolve func(path string) (string, bool)
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}
func (p *parser) is(t token, s string) bool {
	return (t.kind == tPunct || t.kind == tIdent) && strings.EqualFold(t.text, s)
}
func (p *parser) atTerminator() bool {
	t := p.peek()
	return t.kind == tEOF || p.is(t, p.d.and) || p.is(t, p.d.or) || p.is(t, ")")
}

// parseExpr parses src into DNF: a list of conjunctions, any of which grants.
// On a syntax error or blow-up the whole expression is one unknown leaf.
func parseExpr(src string, d *dialect, resolve func(string) (string, bool)) [][]leaf {
	whole := [][]leaf{{{pats: []Pattern{{Raw: strings.TrimSpace(src), Op: OpCEL}}, raw: strings.TrimSpace(src)}}}
	if len(src) > maxExprLen {
		return whole
	}
	toks, err := tokenize(src)
	if err != nil {
		return whole
	}
	p := &parser{src: src, toks: toks, d: d, resolve: resolve}
	n, err := p.parseOr()
	if err != nil || p.tooDeep || p.peek().kind != tEOF {
		return whole
	}
	out, err := dnf(n)
	if err != nil {
		return whole
	}
	return out
}

func (p *parser) parseOr() (node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.is(p.peek(), p.d.or) {
		p.next()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = orNode{l, r}
	}
	return l, nil
}

func (p *parser) parseAnd() (node, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.is(p.peek(), p.d.and) {
		p.next()
		r, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		l = andNode{l, r}
	}
	return l, nil
}

func (p *parser) parseUnary() (node, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxExprDepth || p.tooDeep {
		p.tooDeep = true
		return nil, errExpr
	}
	t := p.peek()
	if p.d.not != "" && p.is(t, p.d.not) {
		// A negation is not modeled: keep its text as an unknown leaf.
		p.next()
		if _, err := p.parseUnary(); err != nil {
			return nil, err
		}
		return p.unknown(t.start, p.toks[p.i-1].end), nil
	}
	if p.is(t, "(") {
		save := p.i
		p.next()
		n, err := p.parseOr()
		if err == nil && p.is(p.peek(), ")") {
			p.next()
			if p.atTerminator() {
				return n, nil
			}
		}
		// "(...)" followed by more (e.g. "(a).size() > 0"): one unknown chunk.
		p.i = save
		return p.chunk()
	}
	save := p.i
	if l, ok := p.d.atom(p); ok && p.atTerminator() {
		return l, nil
	}
	p.i = save
	return p.chunk()
}

// chunk consumes tokens up to the next top-level and/or/")" and returns them
// as one unknown leaf.
func (p *parser) chunk() (node, error) {
	start := p.peek().start
	depth := 0
	n := 0
	for {
		t := p.peek()
		if t.kind == tEOF {
			break
		}
		if depth == 0 && (p.is(t, p.d.and) || p.is(t, p.d.or) || p.is(t, ")")) {
			break
		}
		switch t.text {
		case "(", "[", "{":
			if t.kind == tPunct {
				depth++
			}
		case ")", "]", "}":
			if t.kind == tPunct {
				depth--
			}
		}
		if depth < 0 {
			return nil, errExpr
		}
		p.next()
		n++
	}
	if n == 0 || depth != 0 {
		return nil, errExpr
	}
	return p.unknown(start, p.toks[p.i-1].end), nil
}

// unknown builds an unknown leaf for src[start:end]. When the text starts
// with a resolvable claim path the leaf is keyed on that claim.
func (p *parser) unknown(start, end int) leaf {
	raw := strings.TrimSpace(p.src[start:end])
	l := leaf{raw: raw, pats: []Pattern{{Raw: raw, Op: OpCEL}}}
	// Find the first path-like run in the chunk to key the leaf on.
	for i := range p.toks {
		if p.toks[i].start < start {
			continue
		}
		if p.toks[i].start >= end {
			break
		}
		if p.toks[i].kind == tIdent {
			// Azure: claims['k'] ...
			if strings.EqualFold(p.toks[i].text, "claims") && p.is(p.toks[i+1], "[") && p.toks[i+2].kind == tStr && p.toks[i+2].end <= end {
				l.key = p.toks[i+2].text
				break
			}
			sub := &parser{src: p.src, toks: p.toks, i: i, d: p.d, resolve: p.resolve}
			if path, _, ok := sub.path(); ok {
				if key, ok := p.resolve(path); ok {
					l.key = key
				}
			}
			break
		}
	}
	return l
}

// path reads ident('.'ident)*. If it is followed by '(' the last segment is a
// method name and is returned separately.
func (p *parser) path() (path, method string, ok bool) {
	t := p.peek()
	if t.kind != tIdent {
		return "", "", false
	}
	segs := []string{p.next().text}
	for p.is(p.peek(), ".") && p.toks[p.i+1].kind == tIdent {
		p.next()
		segs = append(segs, p.next().text)
	}
	if p.is(p.peek(), "(") && len(segs) > 1 {
		return strings.Join(segs[:len(segs)-1], "."), segs[len(segs)-1], true
	}
	return strings.Join(segs, "."), "", true
}

func (p *parser) strLit() (string, bool) {
	if p.peek().kind != tStr {
		return "", false
	}
	return p.next().text, true
}

func (p *parser) leafAt(start int, path string, pats ...Pattern) (leaf, bool) {
	key, ok := p.resolve(path)
	if !ok {
		return leaf{}, false
	}
	return leaf{key: key, pats: pats, known: true, raw: strings.TrimSpace(p.src[start:p.toks[p.i-1].end])}, true
}

// celDialect: assertion.X == 'v', 'v' == assertion.X, assertion.X in ['a','b'],
// assertion.X.startsWith('v'), with && || ! and parentheses.
var celDialect = &dialect{and: "&&", or: "||", not: "!", atom: celAtom}

func celAtom(p *parser) (leaf, bool) {
	start := p.peek().start
	if s, ok := p.strLit(); ok {
		if !p.is(p.next(), "==") {
			return leaf{}, false
		}
		path, method, ok := p.path()
		if !ok || method != "" {
			return leaf{}, false
		}
		return p.leafAt(start, path, Pattern{Raw: s, Op: OpEquals})
	}
	path, method, ok := p.path()
	if !ok {
		return leaf{}, false
	}
	if method != "" {
		if method != "startsWith" || !p.is(p.next(), "(") {
			return leaf{}, false
		}
		s, ok := p.strLit()
		if !ok || !p.is(p.next(), ")") {
			return leaf{}, false
		}
		return p.leafAt(start, path, Pattern{Raw: s, Op: OpLike})
	}
	switch op := p.next(); {
	case p.is(op, "=="):
		s, ok := p.strLit()
		if !ok {
			return leaf{}, false
		}
		return p.leafAt(start, path, Pattern{Raw: s, Op: OpEquals})
	case op.kind == tIdent && op.text == "in":
		if !p.is(p.next(), "[") {
			return leaf{}, false
		}
		var pats []Pattern
		for {
			s, ok := p.strLit()
			if !ok {
				return leaf{}, false
			}
			pats = append(pats, Pattern{Raw: s, Op: OpEquals})
			t := p.next()
			if p.is(t, "]") {
				break
			}
			if !p.is(t, ",") {
				return leaf{}, false
			}
		}
		return p.leafAt(start, path, pats...)
	}
	return leaf{}, false
}

// azureDialect: claims['sub'] eq 'v', claims['sub'] matches 'glob', with
// and/or and parentheses.
var azureDialect = &dialect{and: "and", or: "or", atom: azureAtom}

func azureAtom(p *parser) (leaf, bool) {
	start := p.peek().start
	t := p.next()
	if t.kind != tIdent || !strings.EqualFold(t.text, "claims") || !p.is(p.next(), "[") {
		return leaf{}, false
	}
	key, ok := p.strLit()
	if !ok || key == "" || !p.is(p.next(), "]") {
		return leaf{}, false
	}
	var op string
	switch t := p.next(); {
	case p.is(t, "eq"):
		op = OpEquals
	case p.is(t, "matches"):
		op = OpGlob
	default:
		return leaf{}, false
	}
	s, ok := p.strLit()
	if !ok {
		return leaf{}, false
	}
	return leaf{key: key, pats: []Pattern{{Raw: s, Op: op}}, known: true, raw: strings.TrimSpace(p.src[start:p.toks[p.i-1].end])}, true
}

// azureResolve: Azure atoms carry their own claim name; bare paths never
// resolve.
func azureResolve(string) (string, bool) { return "", false }

// dnf flattens n into a list of conjunctions.
func dnf(n node) ([][]leaf, error) {
	switch x := n.(type) {
	case leaf:
		return [][]leaf{{x}}, nil
	case orNode:
		a, err := dnf(x.a)
		if err != nil {
			return nil, err
		}
		b, err := dnf(x.b)
		if err != nil {
			return nil, err
		}
		if len(a)+len(b) > maxDNF {
			return nil, errExpr
		}
		return append(a, b...), nil
	case andNode:
		a, err := dnf(x.a)
		if err != nil {
			return nil, err
		}
		b, err := dnf(x.b)
		if err != nil {
			return nil, err
		}
		if len(a)*len(b) > maxDNF {
			return nil, errExpr
		}
		var out [][]leaf
		for _, ca := range a {
			for _, cb := range b {
				c := append(append([]leaf(nil), ca...), cb...)
				out = append(out, c)
			}
		}
		return out, nil
	}
	return nil, errExpr
}
