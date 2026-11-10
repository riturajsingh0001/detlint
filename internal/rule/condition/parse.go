package condition

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/span"
)

// Error is a condition parse error with a source span.
type Error struct {
	Msg  string
	Span span.Span
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s at %s", e.Msg, e.Span)
}

type parser struct {
	toks []token
	i    int
	src  string
	base span.Span
}

// Parse parses a condition string. base is the span of the condition value
// in the YAML file, used to produce useful error locations.
func Parse(src string, base span.Span) (Expr, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, &Error{Msg: err.Error(), Span: base}
	}
	p := &parser{toks: toks, src: src, base: base}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind == tokPipe {
		expr, err = p.parseAgg(expr)
		if err != nil {
			return nil, err
		}
	}
	if p.peek().kind != tokEOF {
		return nil, p.errf(p.peek(), "unexpected %s", p.peek())
	}
	return expr, nil
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}

func (p *parser) expect(k tokenKind, what string) (token, error) {
	t := p.peek()
	if t.kind != k {
		return t, p.errf(t, "expected %s, got %s", what, t)
	}
	return p.next(), nil
}

func (p *parser) errf(t token, format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...), Span: p.span(t.pos, t.pos+len(t.lit))}
}

func (p *parser) span(start, end int) span.Span {
	line, col := p.base.Line, p.base.Col
	if line == 0 {
		line, col = 1, 1
	}
	for i := 0; i < start && i < len(p.src); i++ {
		if p.src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	endLine, endCol := line, col
	for i := start; i < end && i < len(p.src); i++ {
		if p.src[i] == '\n' {
			endLine++
			endCol = 1
		} else {
			endCol++
		}
	}
	return span.Span{File: p.base.File, Line: line, Col: col, EndLine: endLine, EndCol: endCol}
}

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Or{Left: left, Right: right, Span: span.Merge(left.GetSpan(), right.GetSpan())}
	}
	return left, nil
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &And{Left: left, Right: right, Span: span.Merge(left.GetSpan(), right.GetSpan())}
	}
	return left, nil
}

func (p *parser) parseNot() (Expr, error) {
	if p.peek().kind == tokNot {
		t := p.next()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &Not{X: x, Span: span.Merge(p.span(t.pos, t.pos+len(t.lit)), x.GetSpan())}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tokLParen:
		p.next()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRParen, "')'"); err != nil {
			return nil, err
		}
		return expr, nil
	case tokNumber:
		p.next()
		of, err := p.expect(tokOf, "'of' after a count")
		if err != nil {
			return nil, p.errf(t, "a number must be followed by 'of' (for example: 1 of them)")
		}
		return p.parseOf(t, of, false)
	case tokAll, tokAny:
		p.next()
		if p.peek().kind != tokOf {
			if t.kind == tokAll {
				return &Ident{Name: t.lit, Span: p.span(t.pos, t.pos+len(t.lit))}, nil
			}
			return nil, p.errf(t, "'%s' must be followed by 'of'", t.lit)
		}
		of := p.next()
		return p.parseOf(t, of, t.kind == tokAll)
	case tokIdent:
		p.next()
		return &Ident{Name: t.lit, Span: p.span(t.pos, t.pos+len(t.lit))}, nil
	case tokThem:
		return nil, p.errf(t, "'them' must follow '1 of' or 'all of'")
	default:
		return nil, p.errf(t, "expected a selection name or '(', got %s", t)
	}
}

func (p *parser) parseOf(countTok, ofTok token, all bool) (Expr, error) {
	count := 1
	if !all && countTok.kind == tokNumber {
		n, err := strconv.Atoi(countTok.lit)
		if err != nil || n < 1 {
			return nil, p.errf(countTok, "invalid selection count %q", countTok.lit)
		}
		count = n
	}
	pat := p.peek()
	var pattern string
	switch pat.kind {
	case tokThem:
		pattern = "them"
		p.next()
	case tokIdent:
		pattern = pat.lit
		p.next()
	case tokAll, tokAny:
		// A selection literally named "all" is unusual but legal.
		pattern = pat.lit
		p.next()
	default:
		return nil, p.errf(pat, "expected 'them' or a selection pattern after 'of', got %s", pat)
	}
	return &Of{
		Count:   count,
		All:     all,
		Pattern: pattern,
		Span:    span.Merge(p.span(countTok.pos, countTok.pos+len(countTok.lit)), p.span(pat.pos, pat.pos+len(pat.lit))),
	}, nil
}

func (p *parser) parseAgg(base Expr) (Expr, error) {
	p.next() // consume '|'
	fn, err := p.expect(tokIdent, "an aggregation function such as count()")
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(fn.lit, "count") {
		return nil, p.errf(fn, "unsupported aggregation function %q (only count is supported)", fn.lit)
	}
	if _, err := p.expect(tokLParen, "'('"); err != nil {
		return nil, err
	}
	var args []string
	if p.peek().kind != tokRParen {
		for {
			a := p.peek()
			if a.kind != tokIdent {
				return nil, p.errf(a, "expected an argument name, got %s", a)
			}
			args = append(args, a.lit)
			p.next()
			if p.peek().kind != tokComma {
				break
			}
			p.next()
		}
	}
	if _, err := p.expect(tokRParen, "')'"); err != nil {
		return nil, err
	}
	var groupBy []string
	if p.peek().kind == tokBy {
		p.next()
		for {
			g := p.peek()
			if g.kind != tokIdent {
				return nil, p.errf(g, "expected a field name after 'by', got %s", g)
			}
			groupBy = append(groupBy, g.lit)
			p.next()
			if p.peek().kind != tokComma {
				break
			}
			p.next()
		}
	}
	opTok := p.peek()
	op := ""
	switch opTok.kind {
	case tokGt:
		op = ">"
	case tokGe:
		op = ">="
	case tokLt:
		op = "<"
	case tokLe:
		op = "<="
	case tokEq:
		op = "="
	case tokNe:
		op = "!="
	default:
		return nil, p.errf(opTok, "expected a comparison operator after the aggregation, got %s", opTok)
	}
	p.next()
	valTok := p.peek()
	if valTok.kind != tokNumber {
		return nil, p.errf(valTok, "expected a number after %q, got %s", op, valTok)
	}
	p.next()
	val, err := strconv.ParseFloat(valTok.lit, 64)
	if err != nil {
		return nil, p.errf(valTok, "invalid number %q", valTok.lit)
	}
	return &Agg{
		X:       base,
		Func:    "count",
		Args:    args,
		GroupBy: groupBy,
		Op:      op,
		Value:   val,
		Span:    span.Merge(base.GetSpan(), p.span(valTok.pos, valTok.pos+len(valTok.lit))),
	}, nil
}

var _ = span.Merge
