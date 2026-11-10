// Package analysis implements detlint's rule checks.
package analysis

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/rule/condition"
	"github.com/riturajsingh0001/detlint/internal/schema"
	"github.com/riturajsingh0001/detlint/internal/span"
)

// Severity is the importance of a finding.
type Severity int

const (
	Info Severity = iota
	Warning
	Error
)

func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warning:
		return "warning"
	default:
		return "info"
	}
}

// Label returns an uppercase display label.
func (s Severity) Label() string {
	switch s {
	case Error:
		return "ERROR"
	case Warning:
		return "WARN"
	default:
		return "INFO"
	}
}

// MarshalJSON encodes severity as a lowercase string.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON decodes a lowercase severity string.
func (s *Severity) UnmarshalJSON(b []byte) error {
	text := string(b)
	if len(text) >= 2 && text[0] == '"' {
		text = text[1 : len(text)-1]
	}
	switch text {
	case "error":
		*s = Error
	case "warning", "warn":
		*s = Warning
	case "info", "note":
		*s = Info
	default:
		return fmt.Errorf("unknown severity %q", text)
	}
	return nil
}

// ParseSeverity parses a --fail-on value.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "info":
		return Info, nil
	case "warning", "warn":
		return Warning, nil
	case "error":
		return Error, nil
	case "never", "none":
		return Severity(99), nil
	default:
		return Error, fmt.Errorf("invalid severity %q (use info, warning, error, or never)", s)
	}
}

// Finding is one problem detected in one rule.
type Finding struct {
	Pass      string   `json:"pass"`
	Severity  Severity `json:"severity"`
	File      string   `json:"file"`
	Line      int      `json:"line"`
	Col       int      `json:"col"`
	EndLine   int      `json:"end_line,omitempty"`
	EndCol    int      `json:"end_col,omitempty"`
	RuleID    string   `json:"rule_id,omitempty"`
	RuleTitle string   `json:"rule_title,omitempty"`
	Message   string   `json:"message"`
	Help      string   `json:"help,omitempty"`
}

// Fingerprint returns a stable identifier for CI deduplication.
func (f Finding) Fingerprint() string {
	h := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%d|%d|%s", f.Pass, f.File, f.Line, f.Col, f.Message)))
	return hex.EncodeToString(h[:])
}

// Span returns the finding location as a span.
func (f Finding) Span() span.Span {
	return span.Span{File: f.File, Line: f.Line, Col: f.Col, EndLine: f.EndLine, EndCol: f.EndCol}
}

// Summary aggregates counts.
type Summary struct {
	Total   int `json:"total"`
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
	Rules   int `json:"rules"`
}

// Summarize counts findings by severity and distinct file.
func Summarize(findings []Finding) Summary {
	s := Summary{Total: len(findings)}
	files := map[string]bool{}
	for _, f := range findings {
		files[f.File] = true
		switch f.Severity {
		case Error:
			s.Error++
		case Warning:
			s.Warning++
		default:
			s.Info++
		}
	}
	s.Rules = len(files)
	return s
}

// Context is passed to each pass.
type Context struct {
	File    *rule.File
	Rule    *rule.Rule
	Schemas *schema.Registry
}

// Pass is a named analysis check.
type Pass struct {
	ID          string
	Description string
	Run         func(*Context) []Finding
}

var registry = []Pass{
	{ID: "metadata", Description: "rule metadata hygiene", Run: metadataPass},
	{ID: "dupkeys", Description: "duplicate YAML keys", Run: dupKeysPass},
	{ID: "typos", Description: "unknown fields and case mistakes", Run: typosPass},
	{ID: "unreachable", Description: "conditions that can never fire", Run: unreachablePass},
	{ID: "contradiction", Description: "mutually exclusive constraints", Run: contradictionPass},
	{ID: "escaping", Description: "bad escapes and regular expressions", Run: escapingPass},
	{ID: "wildcard", Description: "overly broad matches", Run: wildcardPass},
}

// Passes returns the registered passes.
func Passes() []Pass { return registry }

// Run executes every pass against one parsed rule.
func Run(f *rule.File, schemas *schema.Registry) []Finding {
	if f == nil || f.Rule == nil {
		return nil
	}
	ctx := &Context{File: f, Rule: f.Rule, Schemas: schemas}
	var out []Finding
	for _, p := range registry {
		out = append(out, p.Run(ctx)...)
	}
	return out
}

// Sort orders findings by file, line, column, pass and message.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		if a.Pass != b.Pass {
			return a.Pass < b.Pass
		}
		return a.Message < b.Message
	})
}

func newFinding(pass string, sev Severity, r *rule.Rule, sp span.Span, msg, help string) Finding {
	f := Finding{
		Pass:     pass,
		Severity: sev,
		File:     sp.File,
		Line:     sp.Line,
		Col:      sp.Col,
		EndLine:  sp.EndLine,
		EndCol:   sp.EndCol,
		Message:  msg,
		Help:     help,
	}
	if r != nil {
		f.RuleID = r.ID
		f.RuleTitle = r.Title
	}
	return f
}

// exprAlwaysTrue reports whether an expression is structurally true for every
// record (for example a reference to an empty selection).
func exprAlwaysTrue(e condition.Expr, r *rule.Rule) bool {
	switch x := e.(type) {
	case *condition.Ident:
		sel := r.Selection(x.Name)
		return sel != nil && sel.AlwaysTrue()
	case *condition.And:
		return exprAlwaysTrue(x.Left, r) && exprAlwaysTrue(x.Right, r)
	case *condition.Or:
		return exprAlwaysTrue(x.Left, r) || exprAlwaysTrue(x.Right, r)
	case *condition.Of:
		sels := r.MatchSelections(x.Pattern)
		if len(sels) == 0 {
			return false
		}
		matched := 0
		for _, s := range sels {
			if s.AlwaysTrue() {
				matched++
			}
		}
		if x.All {
			return matched == len(sels)
		}
		return matched >= x.Count
	default:
		return false
	}
}

// exprAlwaysFalse reports whether an expression is structurally false.
func exprAlwaysFalse(e condition.Expr, r *rule.Rule) bool {
	switch x := e.(type) {
	case *condition.Ident:
		return r.Selection(x.Name) == nil
	case *condition.And:
		if isNegation(x.Left, x.Right) || isNegation(x.Right, x.Left) {
			return true
		}
		return exprAlwaysFalse(x.Left, r) || exprAlwaysFalse(x.Right, r)
	case *condition.Or:
		return exprAlwaysFalse(x.Left, r) && exprAlwaysFalse(x.Right, r)
	case *condition.Not:
		return exprAlwaysTrue(x.X, r)
	case *condition.Of:
		return len(r.MatchSelections(x.Pattern)) == 0
	case *condition.Agg:
		return exprAlwaysFalse(x.X, r)
	default:
		return false
	}
}
