// Package eval matches parsed rules against decoded log records.
package eval

import (
	"encoding/base64"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/rule/condition"
)

// MatchRule evaluates a rule against one record. Aggregation conditions are
// batch operations and always return false here; use MatchBatch.
func MatchRule(r *rule.Rule, rec Record) bool {
	if r == nil || r.Detection.Condition == nil {
		return false
	}
	if len(r.Detection.Undefined) > 0 {
		return false
	}
	if _, ok := r.Detection.Condition.(*condition.Agg); ok {
		return false
	}
	return evalExpr(r.Detection.Condition, r, rec)
}

// Eval evaluates a condition expression against one record.
func Eval(e condition.Expr, r *rule.Rule, rec Record) bool {
	return evalExpr(e, r, rec)
}

func evalExpr(e condition.Expr, r *rule.Rule, rec Record) bool {
	switch x := e.(type) {
	case nil:
		return false
	case *condition.Ident:
		sel := r.Selection(x.Name)
		return sel != nil && MatchSelection(sel, rec)
	case *condition.And:
		return evalExpr(x.Left, r, rec) && evalExpr(x.Right, r, rec)
	case *condition.Or:
		return evalExpr(x.Left, r, rec) || evalExpr(x.Right, r, rec)
	case *condition.Not:
		return !evalExpr(x.X, r, rec)
	case *condition.Of:
		sels := r.MatchSelections(x.Pattern)
		if len(sels) == 0 {
			return false
		}
		matched := 0
		for _, s := range sels {
			if MatchSelection(s, rec) {
				matched++
			}
		}
		if x.All {
			return matched == len(sels)
		}
		return matched >= x.Count
	case *condition.Agg:
		return false
	default:
		return false
	}
}

// MatchSelection evaluates a named selection against one record.
func MatchSelection(s *rule.Selection, rec Record) bool {
	if s == nil {
		return false
	}
	for _, group := range s.Groups {
		ok := true
		for _, f := range group {
			if !MatchField(f, rec) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// MatchField evaluates one field constraint.
func MatchField(f rule.Field, rec Record) bool {
	if f.Name == "*" {
		return true
	}
	if f.HasModifier("exists") {
		_, present := Lookup(rec, f.Name)
		want := true
		if len(f.Values) > 0 {
			want = strings.EqualFold(strings.TrimSpace(f.Values[0].Text), "true")
		}
		return present == want
	}
	if len(f.Values) == 0 {
		return false
	}
	actual, present := Lookup(rec, f.Name)
	if f.HasModifier("neq") {
		if !present {
			return false
		}
		eq := f
		eq.Modifiers = nil
		for _, m := range f.Modifiers {
			if !strings.EqualFold(m, "neq") {
				eq.Modifiers = append(eq.Modifiers, m)
			}
		}
		for _, v := range f.Values {
			if matchValue(actual, present, v, eq, rec) {
				return false
			}
		}
		return true
	}
	all := f.HasModifier("all")
	if all {
		for _, v := range f.Values {
			if !matchValue(actual, present, v, f, rec) {
				return false
			}
		}
		return true
	}
	for _, v := range f.Values {
		if matchValue(actual, present, v, f, rec) {
			return true
		}
	}
	return false
}

func matchValue(actual any, present bool, v rule.Value, f rule.Field, rec Record) bool {
	if v.Kind == rule.NullValue {
		return !present || actual == nil
	}
	if !present {
		return false
	}
	if f.HasModifier("fieldref") {
		other, ok := Lookup(rec, v.Text)
		if !ok {
			return false
		}
		return equalAny(actual, other, f.HasModifier("cased"))
	}
	if f.HasModifier("cidr") {
		s, ok := AsString(actual)
		if !ok {
			return false
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return false
		}
		for _, variant := range expectedVariants(f, v) {
			_, network, err := net.ParseCIDR(variant)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}
	if op := comparisonOp(f); op != "" {
		av, aok := AsFloat(actual)
		ev, err := strconv.ParseFloat(strings.TrimSpace(v.Text), 64)
		if !aok || err != nil {
			return false
		}
		switch op {
		case ">":
			return av > ev
		case ">=":
			return av >= ev
		case "<":
			return av < ev
		case "<=":
			return av <= ev
		}
	}
	if list, ok := actual.([]any); ok {
		for _, el := range list {
			if matchScalar(el, v, f) {
				return true
			}
		}
		return false
	}
	for _, variant := range expectedVariants(f, v) {
		if matchScalarVariant(actual, variant, f) {
			return true
		}
	}
	return false
}

func comparisonOp(f rule.Field) string {
	for _, m := range f.Modifiers {
		switch strings.ToLower(m) {
		case "gt":
			return ">"
		case "gte":
			return ">="
		case "lt":
			return "<"
		case "lte":
			return "<="
		}
	}
	return ""
}

func matchScalar(actual any, v rule.Value, f rule.Field) bool {
	for _, variant := range expectedVariants(f, v) {
		if matchScalarVariant(actual, variant, f) {
			return true
		}
	}
	return false
}

func matchScalarVariant(actual any, exp string, f rule.Field) bool {
	cased := f.HasModifier("cased")
	if f.HasModifier("windash") {
		exp = strings.ReplaceAll(exp, "/", "-")
	}
	switch av := actual.(type) {
	case bool:
		want, err := strconv.ParseBool(strings.TrimSpace(exp))
		if err == nil {
			return av == want
		}
		return false
	case float64:
		if want, err := strconv.ParseFloat(strings.TrimSpace(exp), 64); err == nil {
			return av == want
		}
	case nil:
		return exp == "" || strings.EqualFold(exp, "null")
	}
	s, ok := AsString(actual)
	if !ok {
		return false
	}
	if f.HasModifier("windash") {
		s = strings.ReplaceAll(s, "/", "-")
	}
	if f.HasModifier("re") {
		re, err := compileRegex(exp, cased)
		if err != nil {
			return false
		}
		return re.MatchString(s)
	}
	hay, needle := s, exp
	if !cased {
		hay, needle = strings.ToLower(hay), strings.ToLower(needle)
	}
	contains := f.HasModifier("contains")
	starts := f.HasModifier("startswith")
	ends := f.HasModifier("endswith")
	wild := hasGlob(needle)
	if contains || starts || ends {
		if wild {
			pat := globToRegex(needle)
			switch {
			case starts && ends:
				pat = "^" + pat + "$"
			case starts:
				pat = "^" + pat
			case ends:
				pat = pat + "$"
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return false
			}
			return re.MatchString(hay)
		}
		switch {
		case contains:
			return strings.Contains(hay, needle)
		case starts:
			return strings.HasPrefix(hay, needle)
		default:
			return strings.HasSuffix(hay, needle)
		}
	}
	if wild {
		re, err := regexp.Compile("^" + globToRegex(needle) + "$")
		if err != nil {
			return false
		}
		return re.MatchString(hay)
	}
	return hay == needle
}

func equalAny(a, b any, cased bool) bool {
	as, aok := AsString(a)
	bs, bok := AsString(b)
	if !aok || !bok {
		return false
	}
	if cased {
		return as == bs
	}
	return strings.EqualFold(as, bs)
}

func hasGlob(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

func globToRegex(pat string) string {
	var b strings.Builder
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '\\':
			if i+1 < len(pat) {
				i++
				b.WriteString(regexp.QuoteMeta(string(pat[i])))
			} else {
				b.WriteString(`\\`)
			}
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(pat[i])))
		}
	}
	return b.String()
}

var regexCache sync.Map

func compileRegex(pat string, cased bool) (*regexp.Regexp, error) {
	key := pat
	if !cased {
		key = "(?i)" + pat
	}
	if v, ok := regexCache.Load(key); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(key)
	if err != nil {
		return nil, err
	}
	regexCache.Store(key, re)
	return re, nil
}

func expectedVariants(f rule.Field, v rule.Value) []string {
	s := v.Text
	mods := f.Modifiers
	for _, m := range mods {
		switch strings.ToLower(m) {
		case "utf16", "utf16le", "wide":
			s = utf16LE(s)
		case "utf16be":
			s = utf16BE(s)
		case "base64":
			s = base64.StdEncoding.EncodeToString([]byte(s))
		case "base64offset":
			return base64Offsets(s)
		}
	}
	return []string{s}
}

func utf16LE(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0xFFFF {
			r1, r2 := utf16Pair(r)
			b.WriteByte(byte(r1))
			b.WriteByte(byte(r1 >> 8))
			b.WriteByte(byte(r2))
			b.WriteByte(byte(r2 >> 8))
			continue
		}
		b.WriteByte(byte(r))
		b.WriteByte(byte(r >> 8))
	}
	return b.String()
}

func utf16BE(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0xFFFF {
			r1, r2 := utf16Pair(r)
			b.WriteByte(byte(r1 >> 8))
			b.WriteByte(byte(r1))
			b.WriteByte(byte(r2 >> 8))
			b.WriteByte(byte(r2))
			continue
		}
		b.WriteByte(byte(r >> 8))
		b.WriteByte(byte(r))
	}
	return b.String()
}

func utf16Pair(r rune) (rune, rune) {
	r -= 0x10000
	return 0xD800 + (r >> 10), 0xDC00 + (r & 0x3FF)
}

func base64Offsets(s string) []string {
	var out []string
	for i := 0; i < 3; i++ {
		padded := strings.Repeat("\x00", i) + s
		enc := base64.StdEncoding.EncodeToString([]byte(padded))
		// Trim characters that depend on the offset prefix/suffix.
		if i > 0 {
			enc = enc[4:]
		}
		out = append(out, enc)
	}
	return out
}

// MatchBatch evaluates a rule against a batch, including aggregation
// conditions. Without an aggregation, it reports whether any record matches.
func MatchBatch(r *rule.Rule, records []Record) bool {
	if r == nil {
		return false
	}
	if len(r.Detection.Undefined) > 0 {
		return false
	}
	agg, ok := r.Detection.Condition.(*condition.Agg)
	if !ok {
		for _, rec := range records {
			if MatchRule(r, rec) {
				return true
			}
		}
		return false
	}

	type group struct {
		count int
	}
	groups := map[string]*group{}
	groupOrder := []string{}
	for _, rec := range records {
		if !evalExpr(agg.X, r, rec) {
			continue
		}
		if len(agg.Args) > 0 {
			v, present := Lookup(rec, agg.Args[0])
			if !present || v == nil {
				continue
			}
		}
		key := ""
		if len(agg.GroupBy) > 0 {
			parts := make([]string, len(agg.GroupBy))
			for i, name := range agg.GroupBy {
				v, _ := Lookup(rec, name)
				s, _ := AsString(v)
				parts[i] = s
			}
			key = strings.Join(parts, "\x00")
		}
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		}
		g.count++
	}
	if len(groups) == 0 {
		return compareCount(0, agg.Op, agg.Value)
	}
	for _, k := range groupOrder {
		if compareCount(groups[k].count, agg.Op, agg.Value) {
			return true
		}
	}
	return false
}

func compareCount(n int, op string, want float64) bool {
	v := float64(n)
	switch op {
	case ">":
		return v > want
	case ">=":
		return v >= want
	case "<":
		return v < want
	case "<=":
		return v <= want
	case "=":
		return v == want
	case "!=":
		return v != want
	}
	return false
}

// CountHits counts how many records a rule fires on. Aggregated rules are
// evaluated once over the batch and report 1 when their condition holds.
func CountHits(r *rule.Rule, records []Record) int {
	if r == nil {
		return 0
	}
	if _, ok := r.Detection.Condition.(*condition.Agg); ok {
		if MatchBatch(r, records) {
			return 1
		}
		return 0
	}
	n := 0
	for _, rec := range records {
		if MatchRule(r, rec) {
			n++
		}
	}
	return n
}
