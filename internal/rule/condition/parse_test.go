package condition

import (
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/span"
)

var base = span.Span{File: "r.yml", Line: 10, Col: 14, EndLine: 10, EndCol: 40}

func parseOK(t *testing.T, src string) Expr {
	t.Helper()
	e, err := Parse(src, base)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return e
}

func TestParseIdent(t *testing.T) {
	e := parseOK(t, "selection")
	id, ok := e.(*Ident)
	if !ok || id.Name != "selection" {
		t.Fatalf("got %#v", e)
	}
	if id.Span.Line != 10 || id.Span.Col != 14 {
		t.Fatalf("span = %#v", id.Span)
	}
}

func TestParsePrecedence(t *testing.T) {
	e := parseOK(t, "a or b and c")
	or, ok := e.(*Or)
	if !ok {
		t.Fatalf("root = %T, want *Or", e)
	}
	if _, ok := or.Left.(*Ident); !ok {
		t.Fatalf("left = %T", or.Left)
	}
	and, ok := or.Right.(*And)
	if !ok {
		t.Fatalf("right = %T, want *And", or.Right)
	}
	if and.Left.(*Ident).Name != "b" || and.Right.(*Ident).Name != "c" {
		t.Fatalf("and = %#v", and)
	}
}

func TestParseParentheses(t *testing.T) {
	e := parseOK(t, "(a or b) and c")
	and, ok := e.(*And)
	if !ok {
		t.Fatalf("root = %T", e)
	}
	if _, ok := and.Left.(*Or); !ok {
		t.Fatalf("left = %T", and.Left)
	}
}

func TestParseNot(t *testing.T) {
	e := parseOK(t, "not selection")
	n, ok := e.(*Not)
	if !ok {
		t.Fatalf("root = %T", e)
	}
	if n.X.(*Ident).Name != "selection" {
		t.Fatalf("not = %#v", n)
	}
}

func TestParseQuantifiers(t *testing.T) {
	cases := []struct {
		src     string
		all     bool
		count   int
		pattern string
	}{
		{"1 of them", false, 1, "them"},
		{"2 of selection_*", false, 2, "selection_*"},
		{"all of them", true, 1, "them"},
		{"any of them", false, 1, "them"},
	}
	for _, tc := range cases {
		e := parseOK(t, tc.src)
		of, ok := e.(*Of)
		if !ok {
			t.Fatalf("%q = %T", tc.src, e)
		}
		if of.All != tc.all || of.Count != tc.count || of.Pattern != tc.pattern {
			t.Fatalf("%q = %#v", tc.src, of)
		}
	}
}

func TestParseAggregation(t *testing.T) {
	e := parseOK(t, "selection | count(User) by Computer > 5")
	agg, ok := e.(*Agg)
	if !ok {
		t.Fatalf("root = %T", e)
	}
	if agg.Func != "count" || len(agg.Args) != 1 || agg.Args[0] != "User" {
		t.Fatalf("args = %#v", agg.Args)
	}
	if len(agg.GroupBy) != 1 || agg.GroupBy[0] != "Computer" {
		t.Fatalf("groupBy = %#v", agg.GroupBy)
	}
	if agg.Op != ">" || agg.Value != 5 {
		t.Fatalf("op/value = %q %v", agg.Op, agg.Value)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		"",
		"a and",
		"(a or b",
		"1 selection",
		"them",
		"a | sum(x) > 1",
		"a | count(x",
		"a | count() by > 1",
		"a | count() > x",
		"a ! b",
		"'unterminated",
		"a & b",
	}
	for _, src := range cases {
		if _, err := Parse(src, base); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", src)
		}
	}
}

func TestParseErrorSpan(t *testing.T) {
	_, err := Parse("a and", base)
	if err == nil {
		t.Fatal("expected error")
	}
	ce, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if ce.Span.File != "r.yml" || ce.Span.Line != 10 {
		t.Fatalf("span = %#v", ce.Span)
	}
	if !strings.Contains(ce.Error(), "r.yml") {
		t.Fatalf("error text = %q", ce.Error())
	}
}

func TestWalk(t *testing.T) {
	e := parseOK(t, "a and (b or not c)")
	var names []string
	Walk(e, func(x Expr) {
		if id, ok := x.(*Ident); ok {
			names = append(names, id.Name)
		}
	})
	want := []string{"a", "b", "c"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("walk = %v, want %v", names, want)
	}
}

func TestWalkNil(t *testing.T) {
	Walk(nil, func(Expr) { t.Fatal("should not be called") })
}
