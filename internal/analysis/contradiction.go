package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/rule/condition"
)

func contradictionPass(ctx *Context) []Finding {
	r := ctx.Rule
	var out []Finding
	seen := map[string]bool{}
	for _, pair := range andSelectionPairs(r.Detection.Condition, r) {
		a, b := pair[0], pair[1]
		if a == nil || b == nil || a == b {
			continue
		}
		conflicts := selectionConflicts(a, b)
		for _, c := range conflicts {
			key := a.Name + "\x00" + b.Name + "\x00" + c.field
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, newFinding("contradiction", Error, r, b.Span,
				fmt.Sprintf("selections %q and %q can never both match: field %q must be one of [%s] in %q but [%s] in %q",
					a.Name, b.Name, c.field, strings.Join(c.aValues, ", "), a.Name, strings.Join(c.bValues, ", "), b.Name),
				"ANDed selections must agree on shared fields. Remove one constraint or move it into an OR branch."))
		}
	}
	return out
}

type conflict struct {
	field   string
	aValues []string
	bValues []string
}

func selectionConflicts(a, b *rule.Selection) []conflict {
	av := exactConstraints(a)
	bv := exactConstraints(b)
	var out []conflict
	for name, aVals := range av {
		bVals, ok := bv[name]
		if !ok {
			continue
		}
		if intersects(aVals, bVals) {
			continue
		}
		out = append(out, conflict{
			field:   name,
			aValues: sortedKeys(aVals),
			bValues: sortedKeys(bVals),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].field < out[j].field })
	return out
}

func exactConstraints(s *rule.Selection) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if s == nil {
		return out
	}
	for _, group := range s.Groups {
		for _, f := range group {
			if !f.IsExact() || f.HasModifier("all") && len(f.Values) > 1 {
				continue
			}
			key := strings.ToLower(f.Name)
			set := out[key]
			if set == nil {
				set = map[string]bool{}
			}
			skip := false
			for _, v := range f.Values {
				if v.Kind == rule.NullValue || v.IsWildcard() {
					skip = true
					break
				}
				set[v.Canonical()] = true
			}
			if !skip {
				out[key] = set
			}
		}
	}
	return out
}

func intersects(a, b map[string]bool) bool {
	for v := range a {
		if b[v] {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func andSelectionPairs(e condition.Expr, r *rule.Rule) [][2]*rule.Selection {
	var out [][2]*rule.Selection
	switch x := e.(type) {
	case *condition.And:
		left := positiveSelections(x.Left, r)
		right := positiveSelections(x.Right, r)
		for _, a := range left {
			for _, b := range right {
				out = append(out, [2]*rule.Selection{a, b})
			}
		}
		out = append(out, andSelectionPairs(x.Left, r)...)
		out = append(out, andSelectionPairs(x.Right, r)...)
	case *condition.Or:
		out = append(out, andSelectionPairs(x.Left, r)...)
		out = append(out, andSelectionPairs(x.Right, r)...)
	}
	return out
}

func positiveSelections(e condition.Expr, r *rule.Rule) []*rule.Selection {
	var out []*rule.Selection
	switch x := e.(type) {
	case *condition.Ident:
		if s := r.Selection(x.Name); s != nil {
			out = append(out, s)
		}
	case *condition.And:
		out = append(out, positiveSelections(x.Left, r)...)
		out = append(out, positiveSelections(x.Right, r)...)
	case *condition.Or:
		out = append(out, positiveSelections(x.Left, r)...)
		out = append(out, positiveSelections(x.Right, r)...)
	}
	return out
}
