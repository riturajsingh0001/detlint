// Package span tracks source locations for findings.
package span

import "fmt"

// Span is a half-open source range. Lines and columns are 1-based.
type Span struct {
	File    string
	Line    int
	Col     int
	EndLine int
	EndCol  int
}

// New returns a single-character span.
func New(file string, line, col int) Span {
	return Span{File: file, Line: line, Col: col, EndLine: line, EndCol: col + 1}
}

// WithFile returns a copy of s with File set.
func (s Span) WithFile(file string) Span {
	s.File = file
	return s
}

// IsZero reports whether the span has no position.
func (s Span) IsZero() bool { return s.Line == 0 }

// String renders file:line:col.
func (s Span) String() string {
	if s.File == "" {
		return fmt.Sprintf("%d:%d", s.Line, s.Col)
	}
	return fmt.Sprintf("%s:%d:%d", s.File, s.Line, s.Col)
}

// Merge returns the smallest span covering both a and b.
func Merge(a, b Span) Span {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	out := a
	if b.Line < out.Line || (b.Line == out.Line && b.Col < out.Col) {
		out.Line, out.Col = b.Line, b.Col
	}
	if b.EndLine > out.EndLine || (b.EndLine == out.EndLine && b.EndCol > out.EndCol) {
		out.EndLine, out.EndCol = b.EndLine, b.EndCol
	}
	return out
}

// Length returns the number of characters covered on a single line.
func (s Span) Length() int {
	if s.EndLine != s.Line || s.EndCol <= s.Col {
		return 1
	}
	return s.EndCol - s.Col
}
