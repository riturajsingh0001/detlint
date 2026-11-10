package condition

import (
	"fmt"
	"strings"
)

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokNumber
	tokString
	tokLParen
	tokRParen
	tokPipe
	tokAnd
	tokOr
	tokNot
	tokOf
	tokThem
	tokAll
	tokAny
	tokBy
	tokComma
	tokGt
	tokGe
	tokLt
	tokLe
	tokEq
	tokNe
)

type token struct {
	kind tokenKind
	lit  string
	pos  int
}

func (t token) String() string {
	if t.kind == tokEOF {
		return "end of condition"
	}
	return fmt.Sprintf("%q", t.lit)
}

func lex(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		start := i
		switch c {
		case '(':
			out = append(out, token{tokLParen, "(", i})
			i++
		case ')':
			out = append(out, token{tokRParen, ")", i})
			i++
		case '|':
			out = append(out, token{tokPipe, "|", i})
			i++
		case ',':
			out = append(out, token{tokComma, ",", i})
			i++
		case '>':
			if i+1 < len(src) && src[i+1] == '=' {
				out = append(out, token{tokGe, ">=", i})
				i += 2
			} else {
				out = append(out, token{tokGt, ">", i})
				i++
			}
		case '<':
			if i+1 < len(src) && src[i+1] == '=' {
				out = append(out, token{tokLe, "<=", i})
				i += 2
			} else {
				out = append(out, token{tokLt, "<", i})
				i++
			}
		case '=':
			if i+1 < len(src) && src[i+1] == '=' {
				i++
			}
			out = append(out, token{tokEq, "=", i - 1})
			i++
		case '!':
			if i+1 < len(src) && src[i+1] == '=' {
				out = append(out, token{tokNe, "!=", i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '!' at column %d (did you mean 'not'?)", i+1)
			}
		case '\'', '"':
			quote := c
			i++
			var b strings.Builder
			closed := false
			for i < len(src) {
				if src[i] == '\\' && i+1 < len(src) {
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if src[i] == quote {
					closed = true
					i++
					break
				}
				b.WriteByte(src[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string at column %d", start+1)
			}
			out = append(out, token{tokString, b.String(), start})
		default:
			if isDigit(c) || (c == '-' && i+1 < len(src) && isDigit(src[i+1])) {
				i++
				for i < len(src) && (isDigit(src[i]) || src[i] == '.') {
					i++
				}
				out = append(out, token{tokNumber, src[start:i], start})
				continue
			}
			if isIdentStart(c) {
				i++
				for i < len(src) && isIdentPart(src[i]) {
					i++
				}
				lit := src[start:i]
				kind := tokIdent
				switch strings.ToLower(lit) {
				case "and":
					kind = tokAnd
				case "or":
					kind = tokOr
				case "not":
					kind = tokNot
				case "of":
					kind = tokOf
				case "them":
					kind = tokThem
				case "all":
					kind = tokAll
				case "any":
					kind = tokAny
				case "by":
					kind = tokBy
				}
				out = append(out, token{kind, lit, start})
				continue
			}
			return nil, fmt.Errorf("unexpected character %q at column %d", string(c), i+1)
		}
	}
	out = append(out, token{tokEOF, "", len(src)})
	return out, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '-' || c == '.' || c == '*'
}
