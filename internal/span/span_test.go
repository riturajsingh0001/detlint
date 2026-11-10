package span

import "testing"

func TestNewAndString(t *testing.T) {
	s := New("rules/a.yml", 3, 5)
	if s.File != "rules/a.yml" || s.Line != 3 || s.Col != 5 || s.EndLine != 3 || s.EndCol != 6 {
		t.Fatalf("New = %#v", s)
	}
	if got := s.String(); got != "rules/a.yml:3:5" {
		t.Fatalf("String = %q", got)
	}
}

func TestStringWithoutFile(t *testing.T) {
	if got := (Span{Line: 2, Col: 7}).String(); got != "2:7" {
		t.Fatalf("String = %q", got)
	}
}

func TestMerge(t *testing.T) {
	a := Span{File: "f", Line: 4, Col: 2, EndLine: 4, EndCol: 6}
	b := Span{File: "f", Line: 2, Col: 9, EndLine: 5, EndCol: 1}
	got := Merge(a, b)
	if got.Line != 2 || got.Col != 9 || got.EndLine != 5 || got.EndCol != 1 {
		t.Fatalf("Merge = %#v", got)
	}
}

func TestMergeZero(t *testing.T) {
	a := Span{File: "f", Line: 4, Col: 2, EndLine: 4, EndCol: 6}
	if got := Merge(Span{}, a); got != a {
		t.Fatalf("Merge(zero, a) = %#v", got)
	}
	if got := Merge(a, Span{}); got != a {
		t.Fatalf("Merge(a, zero) = %#v", got)
	}
}

func TestLengthAndZero(t *testing.T) {
	if !(Span{}).IsZero() {
		t.Fatal("empty span should be zero")
	}
	if (Span{Line: 1}).IsZero() {
		t.Fatal("span with line should not be zero")
	}
	if got := (Span{Line: 1, Col: 3, EndLine: 1, EndCol: 8}).Length(); got != 5 {
		t.Fatalf("Length = %d", got)
	}
	if got := (Span{Line: 1, Col: 3, EndLine: 2, EndCol: 8}).Length(); got != 1 {
		t.Fatalf("multi-line Length = %d", got)
	}
}
