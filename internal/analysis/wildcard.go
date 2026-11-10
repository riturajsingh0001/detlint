package analysis

import (
	"fmt"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

func wildcardPass(ctx *Context) []Finding {
	r := ctx.Rule
	var out []Finding

	for _, sel := range r.Detection.Selections {
		for _, group := range sel.Groups {
			if len(group) == 0 {
				out = append(out, newFinding("wildcard", Error, r, sel.Span,
					fmt.Sprintf("selection %q has no field constraints and matches every record", sel.Name),
					"Add at least one field, or remove the selection and fix the condition."))
			}
			for _, f := range group {
				if f.Name == "*" {
					out = append(out, newFinding("wildcard", Error, r, f.KeySpan,
						"wildcard field name matches every field",
						"Use a concrete field name from the schema."))
					continue
				}
				for _, v := range f.Values {
					switch {
					case v.Kind == rule.NullValue:
						out = append(out, newFinding("wildcard", Warning, r, v.Span,
							fmt.Sprintf("field %q compares to null; this only matches events where the field is missing", f.Name),
							"Use |exists: false to test for absence explicitly."))
					case v.Text == "*":
						out = append(out, newFinding("wildcard", Warning, r, v.Span,
							fmt.Sprintf("value \"*\" for field %q matches any value", f.Name),
							"Constrain the value, or remove the field and rely on the rest of the selection."))
					case v.Text == "":
						out = append(out, newFinding("wildcard", Warning, r, v.Span,
							fmt.Sprintf("empty value for field %q matches only empty or missing fields", f.Name),
							"Use |exists: false if absence is intended."))
					}
					if f.HasModifier("re") && isMatchEverythingRegex(v.Text) {
						out = append(out, newFinding("wildcard", Warning, r, v.Span,
							fmt.Sprintf("regular expression %q matches every string", v.Text),
							"Constrain the expression."))
					}
				}
			}
		}
	}

	if exprAlwaysTrue(r.Detection.Condition, r) && !hasError(out) {
		out = append(out, newFinding("wildcard", Error, r, r.Detection.ConditionSpan,
			"condition is true for every record, so this rule fires on all events",
			"Add a real constraint or fix the condition."))
	}
	return out
}

func hasError(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

func isMatchEverythingRegex(pat string) bool {
	pat = strings.TrimSpace(pat)
	pat = strings.TrimPrefix(pat, "^")
	pat = strings.TrimSuffix(pat, "$")
	switch pat {
	case "", ".*", ".+", "(?s).*", "(?i).*":
		return true
	}
	return false
}
