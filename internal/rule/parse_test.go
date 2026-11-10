package rule

import (
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/rule/condition"
)

const sampleRule = `title: Suspicious PowerShell
id: 12345678-1234-4234-8234-123456789012
status: test
description: Finds encoded commands.
author: detlint
level: HIGH
date: 2026-01-01
modified: 2026-02-01
logsource:
  product: windows
  service: security
  definition: Audit process creation
detection:
  selection:
    EventID: 4688
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|all:
      - '-enc'
      - 'SQB'
  filter:
    User|endswith: '$'
  condition: selection and not filter
  timeframe: 5m
fields:
  - CommandLine
tags:
  - attack.execution
  - attack.t1059.001
references:
  - https://example.com/rule
falsepositives:
  - Admin scripts
`

func TestParseFullRule(t *testing.T) {
	f, err := Parse("rules/powershell.yml", []byte(sampleRule))
	if err != nil {
		t.Fatal(err)
	}
	r := f.Rule
	if r == nil {
		t.Fatal("no rule")
	}
	if r.Title != "Suspicious PowerShell" || r.ID != "12345678-1234-4234-8234-123456789012" {
		t.Fatalf("metadata = %q %q", r.Title, r.ID)
	}
	if r.Level != "high" {
		t.Fatalf("level = %q", r.Level)
	}
	if r.LogSource.Product != "windows" || r.LogSource.Service != "security" {
		t.Fatalf("logsource = %#v", r.LogSource)
	}
	if r.LogSource.Definition != "Audit process creation" {
		t.Fatalf("definition = %q", r.LogSource.Definition)
	}
	if got := r.SelectionNames(); strings.Join(got, ",") != "selection,filter" {
		t.Fatalf("selections = %v", got)
	}
	sel := r.Selection("selection")
	if sel == nil || sel.FieldCount() != 3 {
		t.Fatalf("selection = %#v", sel)
	}
	image := sel.Groups[0][1]
	if image.Name != "Image" || !image.HasModifier("endswith") || len(image.Values) != 2 {
		t.Fatalf("image = %#v", image)
	}
	cmd := sel.Groups[0][2]
	if !cmd.HasModifier("contains") || !cmd.HasModifier("all") || len(cmd.Values) != 2 {
		t.Fatalf("command line = %#v", cmd)
	}
	if _, ok := r.Detection.Condition.(*condition.And); !ok {
		t.Fatalf("condition = %T", r.Detection.Condition)
	}
	if r.Detection.Timeframe != "5m" {
		t.Fatalf("timeframe = %q", r.Detection.Timeframe)
	}
	if len(r.Tags) != 2 || len(r.References) != 1 || len(r.FalsePositives) != 1 {
		t.Fatalf("lists = %v %v %v", r.Tags, r.References, r.FalsePositives)
	}
	if len(r.Detection.Undefined) != 0 {
		t.Fatalf("undefined = %v", r.Detection.Undefined)
	}
	if f.Lines[0] != "title: Suspicious PowerShell" {
		t.Fatalf("lines = %q", f.Lines[0])
	}
}

func TestParseValueKinds(t *testing.T) {
	src := `title: kinds
id: x
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4688
    Ratio: 1.5
    Enabled: true
    Missing: null
    Text: "004688"
  condition: selection
`
	f, err := Parse("kinds.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	fields := f.Rule.Selection("selection").Groups[0]
	kinds := map[string]ValueKind{}
	for _, field := range fields {
		kinds[field.Name] = field.Values[0].Kind
	}
	want := map[string]ValueKind{
		"EventID": IntValue,
		"Ratio":   FloatValue,
		"Enabled": BoolValue,
		"Missing": NullValue,
		"Text":    StringValue,
	}
	for name, kind := range want {
		if kinds[name] != kind {
			t.Errorf("%s kind = %v, want %v", name, kinds[name], kind)
		}
	}
}

func TestParseRuleIDAlias(t *testing.T) {
	src := "title: t\nrule_id: alias-id\nlogsource: {product: windows}\ndetection:\n  s:\n    EventID: 1\n  condition: s\n"
	f, err := Parse("alias.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if f.Rule.ID != "alias-id" {
		t.Fatalf("id = %q", f.Rule.ID)
	}
}

func TestParseSequenceSelection(t *testing.T) {
	src := `title: seq
id: seq
logsource: {product: windows, service: security}
detection:
  selection:
    - EventID: 4688
      Image|endswith: '\cmd.exe'
    - EventID: 4624
      LogonType: 10
  condition: selection
`
	f, err := Parse("seq.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	sel := f.Rule.Selection("selection")
	if len(sel.Groups) != 2 || len(sel.Groups[0]) != 2 || len(sel.Groups[1]) != 2 {
		t.Fatalf("groups = %#v", sel.Groups)
	}
}

func TestParseUndefinedSelection(t *testing.T) {
	src := `title: u
id: u
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection and not missing_filter and missing_filter
`
	f, err := Parse("u.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rule.Detection.Undefined) != 1 || f.Rule.Detection.Undefined[0] != "missing_filter" {
		t.Fatalf("undefined = %v", f.Rule.Detection.Undefined)
	}
}

func TestParseDuplicateSelectionKeepsLast(t *testing.T) {
	src := `title: d
id: d
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 1
  selection:
    EventID: 2
  condition: selection
`
	f, err := Parse("d.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rule.Detection.Selections) != 1 {
		t.Fatalf("selections = %d", len(f.Rule.Detection.Selections))
	}
	if got := f.Rule.Selection("selection").Groups[0][0].Values[0].Text; got != "2" {
		t.Fatalf("value = %q, want last value", got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"not mapping", "- a\n- b\n", "mapping"},
		{"no detection", "title: x\n", "detection"},
		{"detection not mapping", "detection: nope\n", "mapping"},
		{"no condition", "detection:\n  s:\n    EventID: 1\n", "condition"},
		{"condition not scalar", "detection:\n  s:\n    EventID: 1\n  condition: [a]\n", "condition"},
		{"empty selection", "detection:\n  '':\n    EventID: 1\n  condition: x\n", "empty"},
		{"selection scalar", "detection:\n  s: nope\n  condition: s\n", "mapping"},
		{"unknown modifier", "detection:\n  s:\n    EventID|nope: 1\n  condition: s\n", "modifier"},
		{"empty modifier", "detection:\n  s:\n    'EventID|': 1\n  condition: s\n", "modifier"},
		{"nested value", "detection:\n  s:\n    EventID:\n      - a: b\n  condition: s\n", "nested"},
		{"bad condition", "detection:\n  s:\n    EventID: 1\n  condition: 's and'\n", "condition"},
	}
	for _, tc := range cases {
		_, err := Parse("x.yml", []byte(tc.src))
		if err == nil {
			t.Errorf("%s: expected error", tc.name)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
			t.Errorf("%s: error = %q, want substring %q", tc.name, err, tc.want)
		}
	}
}

func TestParseErrorTypeAndSpan(t *testing.T) {
	_, err := Parse("x.yml", []byte("title: x\n"))
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if pe.Span.IsZero() {
		t.Fatalf("span = %#v", pe.Span)
	}
	if !strings.Contains(pe.Error(), "x.yml") {
		t.Fatalf("error text = %q", pe.Error())
	}
}

func TestValueHelpers(t *testing.T) {
	if !(Value{Text: "a*b"}).IsWildcard() {
		t.Fatal("a*b should be a wildcard")
	}
	if !(Value{Text: "a?b"}).IsWildcard() {
		t.Fatal("a?b should be a wildcard")
	}
	if (Value{Text: `a\*b`}).IsWildcard() {
		t.Fatal("escaped star is not a wildcard")
	}
	if got := (Value{Kind: IntValue, Text: "0042"}).Canonical(); got != "42" {
		t.Fatalf("canonical = %q", got)
	}
	if got := (Value{Kind: StringValue, Text: " ABC "}).Canonical(); got != "abc" {
		t.Fatalf("canonical = %q", got)
	}
}

func TestSelectionHelpers(t *testing.T) {
	s := &Selection{Name: "s", Groups: []FieldGroup{{}, {}}}
	if !s.AlwaysTrue() {
		t.Fatal("empty group should be always true")
	}
	if got := s.FieldCount(); got != 0 {
		t.Fatalf("field count = %d", got)
	}
	nonEmpty := &Selection{Name: "s", Groups: []FieldGroup{{{Name: "EventID"}}}}
	if nonEmpty.AlwaysTrue() {
		t.Fatal("non-empty selection should not be always true")
	}
	if got := nonEmpty.FieldCount(); got != 1 {
		t.Fatalf("field count = %d", got)
	}
	var nilSel *Selection
	if !nilSel.AlwaysTrue() {
		t.Fatal("nil selection is always true")
	}
}

func TestMatchSelections(t *testing.T) {
	src := `title: m
id: m
logsource: {product: windows, service: security}
detection:
  selection_one:
    EventID: 1
  selection_two:
    EventID: 2
  other:
    EventID: 3
  condition: 1 of selection_*
`
	f, err := Parse("m.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	r := f.Rule
	if got := len(r.MatchSelections("them")); got != 3 {
		t.Fatalf("them = %d", got)
	}
	if got := len(r.MatchSelections("")); got != 3 {
		t.Fatalf("empty = %d", got)
	}
	if got := len(r.MatchSelections("selection_*")); got != 2 {
		t.Fatalf("selection_* = %d", got)
	}
	if got := len(r.MatchSelections("other")); got != 1 {
		t.Fatalf("other = %d", got)
	}
	if got := len(r.MatchSelections("nope_*")); got != 0 {
		t.Fatalf("nope_* = %d", got)
	}
}

func TestRuleStringHelpers(t *testing.T) {
	r := &Rule{Title: "Title", ID: "id", File: "f.yml"}
	if got := r.String(); got != "Title" {
		t.Fatalf("String = %q", got)
	}
	if got := r.Describe(); got != "Title (id)" {
		t.Fatalf("Describe = %q", got)
	}
	if got := (&Rule{ID: "id", File: "f.yml"}).Describe(); got != "id" {
		t.Fatalf("Describe = %q", got)
	}
	if got := (&Rule{File: "f.yml"}).Describe(); got != "f.yml" {
		t.Fatalf("Describe = %q", got)
	}
	var nilRule *Rule
	if nilRule.String() != "" || nilRule.Describe() != "" {
		t.Fatal("nil rule should be empty")
	}
}

func TestFieldIsExact(t *testing.T) {
	if !(Field{}).IsExact() {
		t.Fatal("plain field should be exact")
	}
	if !(Field{Modifiers: []string{"all"}}).IsExact() {
		t.Fatal("all is a no-op for exactness")
	}
	if (Field{Modifiers: []string{"contains"}}).IsExact() {
		t.Fatal("contains is not exact")
	}
}
