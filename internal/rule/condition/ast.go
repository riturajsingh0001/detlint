// Package condition parses and represents Sigma-style detection conditions.
package condition

import "github.com/riturajsingh0001/detlint/internal/span"

// Expr is a condition expression.
type Expr interface {
	exprNode()
	GetSpan() span.Span
}

// Ident references a named selection.
type Ident struct {
	Name string
	Span span.Span
}

func (*Ident) exprNode()            {}
func (e *Ident) GetSpan() span.Span { return e.Span }

// And is logical conjunction.
type And struct {
	Left, Right Expr
	Span        span.Span
}

func (*And) exprNode()            {}
func (e *And) GetSpan() span.Span { return e.Span }

// Or is logical disjunction.
type Or struct {
	Left, Right Expr
	Span        span.Span
}

func (*Or) exprNode()            {}
func (e *Or) GetSpan() span.Span { return e.Span }

// Not is logical negation.
type Not struct {
	X    Expr
	Span span.Span
}

func (*Not) exprNode()            {}
func (e *Not) GetSpan() span.Span { return e.Span }

// Of is a quantified selection reference: "1 of them", "all of selection_*".
type Of struct {
	Count   int
	All     bool
	Pattern string // "them" or a glob such as "selection_*"
	Span    span.Span
}

func (*Of) exprNode()            {}
func (e *Of) GetSpan() span.Span { return e.Span }

// Agg is an aggregation such as "| count() by User > 5".
type Agg struct {
	X       Expr
	Func    string
	Args    []string
	GroupBy []string
	Op      string
	Value   float64
	Span    span.Span
}

func (*Agg) exprNode()            {}
func (e *Agg) GetSpan() span.Span { return e.Span }

// Walk calls fn for every node in depth-first order.
func Walk(e Expr, fn func(Expr)) {
	if e == nil {
		return
	}
	fn(e)
	switch x := e.(type) {
	case *And:
		Walk(x.Left, fn)
		Walk(x.Right, fn)
	case *Or:
		Walk(x.Left, fn)
		Walk(x.Right, fn)
	case *Not:
		Walk(x.X, fn)
	case *Agg:
		Walk(x.X, fn)
	}
}
