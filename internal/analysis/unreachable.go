package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/rule/condition"
)

func unreachablePass(ctx *Context) []Finding {
	r := ctx.Rule
	var out []Finding

	defined := map[string]bool{}
	for _, s := range r.Detection.Selections {
		defined[s.Name] = true
	}

	reported := map[string]bool{}
	condition.Walk(r.Detection.Condition, func(e condition.Expr) {
		switch x := e.(type) {
		case *condition.Ident:
			if !defined[x.Name] && !reported[x.Name] {
				reported[x.Name] = true
				names := r.SelectionNames()
				help := "Define the selection or fix the name."
				if len(names) > 0 {
					help = "Defined selections: " + strings.Join(names, ", ") + "."
				}
				out = append(out, newFinding("unreachable", Error, r, x.Span,
					fmt.Sprintf("condition references undefined selection %q, so the rule can never fire", x.Name), help))
			}
		case *condition.Of:
			sels := r.MatchSelections(x.Pattern)
			if len(sels) == 0 {
				out = append(out, newFinding("unreachable", Error, r, x.Span,
					fmt.Sprintf("condition pattern %q matches no selections, so the rule can never fire", x.Pattern),
					"Check the selection names and the wildcard pattern."))
			} else if !x.All && x.Count > len(sels) {
				out = append(out, newFinding("unreachable", Error, r, x.Span,
					fmt.Sprintf("condition asks for %d of %q but only %d selections match", x.Count, x.Pattern, len(sels)),
					"Lower the count or add selections."))
			}
		}
	})

	if len(reported) == 0 && exprAlwaysFalse(r.Detection.Condition, r) {
		out = append(out, newFinding("unreachable", Error, r, r.Detection.ConditionSpan,
			"condition is unsatisfiable, so the rule can never fire",
			"The condition is a contradiction, such as 'selection and not selection'."))
	}

	out = append(out, impossibleValues(ctx)...)
	return out
}

func impossibleValues(ctx *Context) []Finding {
	r := ctx.Rule
	sch := ctx.Schemas.Match(r.LogSource)
	if sch == nil {
		return nil
	}
	var out []Finding
	for _, sel := range r.Detection.Selections {
		for _, group := range sel.Groups {
			for _, f := range group {
				sf, ok := sch.Field(f.Name)
				if !ok || !f.IsExact() {
					continue
				}
				for _, v := range f.Values {
					if v.Kind == rule.NullValue || v.IsWildcard() {
						continue
					}
					if len(sf.Enum) > 0 && !enumContains(sf.Enum, v) {
						out = append(out, newFinding("unreachable", Error, r, v.Span,
							fmt.Sprintf("value %q for field %q is not allowed by schema %q, so the rule can never match", v.Text, f.Name, sch.Name),
							"Allowed values: "+summarizeEnum(sf.Enum)+"."))
						continue
					}
					if sf.Type == "int" {
						if _, err := strconv.ParseFloat(strings.TrimSpace(v.Text), 64); err != nil {
							out = append(out, newFinding("unreachable", Error, r, v.Span,
								fmt.Sprintf("field %q is an integer in schema %q but the rule compares it to %q", f.Name, sch.Name, v.Text),
								"Use an integer value or a string modifier such as |contains."))
						}
					}
				}
			}
		}
	}
	return out
}

func enumContains(enum []string, v rule.Value) bool {
	for _, e := range enum {
		if strings.EqualFold(strings.TrimSpace(e), strings.TrimSpace(v.Text)) {
			return true
		}
		if ef, err1 := strconv.ParseFloat(e, 64); err1 == nil {
			if vf, err2 := strconv.ParseFloat(v.Text, 64); err2 == nil && ef == vf {
				return true
			}
		}
	}
	return false
}

func summarizeEnum(enum []string) string {
	if len(enum) > 8 {
		return strings.Join(enum[:8], ", ") + ", ..."
	}
	return strings.Join(enum, ", ")
}

func isNegation(a, b condition.Expr) bool {
	n, ok := b.(*condition.Not)
	if !ok {
		return false
	}
	return exprString(a) == exprString(n.X)
}

func exprString(e condition.Expr) string {
	switch x := e.(type) {
	case *condition.Ident:
		return x.Name
	case *condition.Not:
		return "not(" + exprString(x.X) + ")"
	case *condition.And:
		return "(" + exprString(x.Left) + " and " + exprString(x.Right) + ")"
	case *condition.Or:
		return "(" + exprString(x.Left) + " or " + exprString(x.Right) + ")"
	case *condition.Of:
		if x.All {
			return "all of " + x.Pattern
		}
		return fmt.Sprintf("%d of %s", x.Count, x.Pattern)
	case *condition.Agg:
		return exprString(x.X) + " | count()"
	default:
		return ""
	}
}
