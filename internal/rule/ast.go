package rule

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule/condition"
	"github.com/riturajsingh0001/detlint/internal/span"
)

// ValueKind is the inferred type of a scalar value.
type ValueKind int

const (
	StringValue ValueKind = iota
	IntValue
	FloatValue
	BoolValue
	NullValue
)

func (k ValueKind) String() string {
	switch k {
	case IntValue:
		return "int"
	case FloatValue:
		return "float"
	case BoolValue:
		return "bool"
	case NullValue:
		return "null"
	default:
		return "string"
	}
}

// Value is a single scalar on the right-hand side of a selection field.
type Value struct {
	Text   string
	Raw    string
	Quoted bool
	Style  byte
	Kind   ValueKind
	Span   span.Span
}

// Canonical returns a normalized form for equality comparisons.
func (v Value) Canonical() string {
	switch v.Kind {
	case IntValue, FloatValue:
		if f, err := strconv.ParseFloat(v.Text, 64); err == nil {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
	}
	return strings.ToLower(strings.TrimSpace(v.Text))
}

// IsWildcard reports whether the value contains unescaped glob metacharacters.
func (v Value) IsWildcard() bool {
	for i := 0; i < len(v.Text); i++ {
		if v.Text[i] == '\\' {
			i++
			continue
		}
		if v.Text[i] == '*' || v.Text[i] == '?' {
			return true
		}
	}
	return false
}

// Field is one field constraint inside a selection.
type Field struct {
	Name      string
	Modifiers []string
	Values    []Value
	KeySpan   span.Span
	Span      span.Span
}

// HasModifier reports whether the field carries the named modifier.
func (f Field) HasModifier(name string) bool {
	for _, m := range f.Modifiers {
		if strings.EqualFold(m, name) {
			return true
		}
	}
	return false
}

// IsExact reports whether the constraint is a plain equality test (possibly
// with the no-op "all" modifier).
func (f Field) IsExact() bool {
	for _, m := range f.Modifiers {
		switch strings.ToLower(m) {
		case "", "all", "any":
		default:
			return false
		}
	}
	return true
}

// FieldGroup is a set of fields that must all match. A selection with multiple
// groups is an OR of groups.
type FieldGroup []Field

// Selection is a named group of field constraints.
type Selection struct {
	Name   string
	Groups []FieldGroup
	Span   span.Span
}

// LogSource describes where a rule expects its events to come from.
type LogSource struct {
	Product    string
	Service    string
	Category   string
	Definition string
	Span       span.Span
}

// Detection holds the selection definitions and parsed condition.
type Detection struct {
	Selections    []*Selection
	ByName        map[string]*Selection
	Condition     condition.Expr
	ConditionRaw  string
	ConditionSpan span.Span
	Timeframe     string
	Undefined     []string
	Span          span.Span
}

// Rule is a parsed detection rule.
type Rule struct {
	File           string
	Title          string
	ID             string
	Status         string
	Description    string
	Author         string
	Level          string
	Date           string
	Modified       string
	LogSource      LogSource
	Detection      Detection
	Tags           []string
	References     []string
	FalsePositives []string
	Span           span.Span
	Root           *Node
}

// File is a loaded rule file, including the raw source for snippets.
type File struct {
	Path  string
	Data  []byte
	Lines []string
	Root  *Node
	Rule  *Rule
}

// Selection returns the named selection.
func (r *Rule) Selection(name string) *Selection {
	if r == nil {
		return nil
	}
	return r.Detection.ByName[name]
}

// SelectionNames returns selection names in source order.
func (r *Rule) SelectionNames() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Detection.Selections))
	for _, s := range r.Detection.Selections {
		out = append(out, s.Name)
	}
	return out
}

// MatchSelections returns selections matching a "them" or glob pattern.
func (r *Rule) MatchSelections(pattern string) []*Selection {
	if r == nil {
		return nil
	}
	if pattern == "them" || pattern == "" {
		return r.Detection.Selections
	}
	var out []*Selection
	for _, s := range r.Detection.Selections {
		ok, err := path.Match(pattern, s.Name)
		if err == nil && ok {
			out = append(out, s)
			continue
		}
		// Fall back to a simple glob for patterns path.Match rejects.
		if simpleGlob(pattern, s.Name) {
			out = append(out, s)
		}
	}
	return out
}

func simpleGlob(pattern, name string) bool {
	// path.Match treats [] specially; this handles the common * and ? forms.
	var match func(p, n string) bool
	match = func(p, n string) bool {
		for len(p) > 0 {
			switch p[0] {
			case '*':
				for i := 0; i <= len(n); i++ {
					if match(p[1:], n[i:]) {
						return true
					}
				}
				return false
			case '?':
				if len(n) == 0 {
					return false
				}
				p, n = p[1:], n[1:]
			default:
				if len(n) == 0 || p[0] != n[0] {
					return false
				}
				p, n = p[1:], n[1:]
			}
		}
		return len(n) == 0
	}
	return match(pattern, name)
}

// String renders a human-readable rule identifier.
func (r *Rule) String() string {
	if r == nil {
		return ""
	}
	if r.Title != "" {
		return r.Title
	}
	if r.ID != "" {
		return r.ID
	}
	return r.File
}

// Describe returns "title (id)" when both exist.
func (r *Rule) Describe() string {
	if r == nil {
		return ""
	}
	switch {
	case r.Title != "" && r.ID != "":
		return fmt.Sprintf("%s (%s)", r.Title, r.ID)
	case r.Title != "":
		return r.Title
	case r.ID != "":
		return r.ID
	default:
		return r.File
	}
}
