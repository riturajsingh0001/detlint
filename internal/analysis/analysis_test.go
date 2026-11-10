package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/schema"
	"github.com/riturajsingh0001/detlint/internal/span"
)

func runRule(t *testing.T, src string) []Finding {
	t.Helper()
	f, err := rule.Parse("test.yml", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Run(f, schema.Default())
}

func byPass(findings []Finding, pass string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Pass == pass {
			out = append(out, f)
		}
	}
	return out
}

func withPass(t *testing.T, src, pass string) []Finding {
	t.Helper()
	return byPass(runRule(t, src), pass)
}

func hasMessage(findings []Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func hasSeverity(findings []Finding, sev Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

const cleanRule = `title: Clean
id: clean
status: stable
description: A well formed rule.
author: tests
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image|endswith: '\cmd.exe'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
`

func TestCleanRuleHasNoFindings(t *testing.T) {
	if got := runRule(t, cleanRule); len(got) != 0 {
		t.Fatalf("findings = %#v", got)
	}
}

func TestMetadataPass(t *testing.T) {
	src := "detection:\n  s:\n    EventID: 1\n  condition: s\n"
	got := withPass(t, src, "metadata")
	for _, want := range []string{"no title", "no id", "no level", "no logsource", "no tags", "no description"} {
		if !hasMessage(got, want) {
			t.Errorf("missing %q in %#v", want, got)
		}
	}
	if !hasSeverity(got, Warning) || !hasSeverity(got, Info) {
		t.Fatalf("severities = %#v", got)
	}

	src = strings.Replace(cleanRule, "level: high", "level: severe", 1)
	got = withPass(t, src, "metadata")
	if !hasMessage(got, "unknown level") {
		t.Fatalf("findings = %#v", got)
	}
}

func TestDupKeysPass(t *testing.T) {
	src := `title: dup
id: dup
level: low
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4688
    EventID: 4624
  condition: selection
tags: [attack.execution]
description: x
`
	got := withPass(t, src, "dupkeys")
	if len(got) != 1 || got[0].Severity != Error {
		t.Fatalf("findings = %#v", got)
	}
	if !strings.Contains(got[0].Message, "EventID") || !strings.Contains(got[0].Message, "line") {
		t.Fatalf("message = %q", got[0].Message)
	}
	if got[0].Line != 8 {
		t.Fatalf("line = %d", got[0].Line)
	}
}

func TestTyposPass(t *testing.T) {
	src := strings.Replace(cleanRule, "Image|endswith", "ComandLine|contains", 1)
	got := withPass(t, src, "typos")
	if len(got) != 1 || got[0].Severity != Error {
		t.Fatalf("findings = %#v", got)
	}
	if !strings.Contains(got[0].Message, "did you mean") || !strings.Contains(got[0].Message, "CommandLine") {
		t.Fatalf("message = %q", got[0].Message)
	}

	src = strings.Replace(cleanRule, "EventID", "eventid", 1)
	got = withPass(t, src, "typos")
	if len(got) != 1 || got[0].Severity != Warning {
		t.Fatalf("findings = %#v", got)
	}
	if !strings.Contains(got[0].Message, "differs only by case") {
		t.Fatalf("message = %q", got[0].Message)
	}

	src = strings.Replace(cleanRule, "product: windows\n  service: security", "product: nope", 1)
	got = withPass(t, src, "typos")
	if len(got) != 1 || !strings.Contains(got[0].Message, "no schema") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "User|fieldref: MissingField", 1)
	got = withPass(t, src, "typos")
	if !hasMessage(got, "fieldref target") {
		t.Fatalf("findings = %#v", got)
	}
}

func TestUnreachablePass(t *testing.T) {
	src := `title: u
id: u
level: low
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection and not missing_filter
tags: [attack.execution]
description: x
`
	got := withPass(t, src, "unreachable")
	if len(got) != 1 || !strings.Contains(got[0].Message, "undefined selection") {
		t.Fatalf("findings = %#v", got)
	}
	if !strings.Contains(got[0].Help, "Defined selections") {
		t.Fatalf("help = %q", got[0].Help)
	}

	src = strings.Replace(cleanRule, "condition: selection", "condition: 1 of nope_*", 1)
	got = withPass(t, src, "unreachable")
	if !hasMessage(got, "matches no selections") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "condition: selection", "condition: 3 of selection", 1)
	got = withPass(t, src, "unreachable")
	if !hasMessage(got, "only 1 selections match") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "EventID: 9999", 1)
	got = withPass(t, src, "unreachable")
	if !hasMessage(got, "not allowed by schema") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "Image|endswith: '\\cmd.exe'", "ProcessId: not-a-number", 1)
	got = withPass(t, src, "unreachable")
	if !hasMessage(got, "is an integer") {
		t.Fatalf("findings = %#v", got)
	}

	// Wildcards and nulls are not checked against enums.
	src = strings.Replace(cleanRule, "EventID: 4688", "EventID: '*'", 1)
	if got := withPass(t, src, "unreachable"); len(got) != 0 {
		t.Fatalf("findings = %#v", got)
	}
}

func TestUnreachableContradiction(t *testing.T) {
	src := strings.Replace(cleanRule, "condition: selection", "condition: selection and not selection", 1)
	got := withPass(t, src, "unreachable")
	if !hasMessage(got, "unsatisfiable") {
		t.Fatalf("findings = %#v", got)
	}
}

func TestContradictionPass(t *testing.T) {
	src := `title: c
id: c
level: low
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4624
    LogonType: 10
  filter:
    EventID: 4624
    LogonType: 3
  condition: selection and filter
tags: [attack.lateral-movement]
description: x
`
	got := withPass(t, src, "contradiction")
	if len(got) != 1 || got[0].Severity != Error {
		t.Fatalf("findings = %#v", got)
	}
	if !strings.Contains(got[0].Message, "logontype") {
		t.Fatalf("message = %q", got[0].Message)
	}

	// Compatible constraints do not conflict.
	src = strings.Replace(src, "LogonType: 3", "LogonType: 10", 1)
	if got := withPass(t, src, "contradiction"); len(got) != 0 {
		t.Fatalf("findings = %#v", got)
	}

	// OR branches are not treated as simultaneous.
	src = strings.Replace(src, "condition: selection and filter", "condition: selection or filter", 1)
	if got := withPass(t, src, "contradiction"); len(got) != 0 {
		t.Fatalf("findings = %#v", got)
	}
}

func TestEscapingPass(t *testing.T) {
	src := strings.Replace(cleanRule, "Image|endswith: '\\cmd.exe'", "CommandLine|re: '(?<bad'", 1)
	got := withPass(t, src, "escaping")
	if !hasMessage(got, "invalid regular expression") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "Image|endswith: '\\cmd.exe'", "IpAddress|cidr: '10.0.0.0/99'", 1)
	got = withPass(t, src, "escaping")
	if !hasMessage(got, "invalid CIDR") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "Image|endswith: '\\cmd.exe'", "CommandLine|re|contains: 'cmd'", 1)
	got = withPass(t, src, "escaping")
	if !hasMessage(got, "combines |re") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "Image|endswith: '\\cmd.exe'", `CommandLine|re: "\d+"`, 1)
	got = withPass(t, src, "escaping")
	if !hasMessage(got, "invalid YAML escape") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "Image|endswith: '\\cmd.exe'", `Image: C:\Windows\`, 1)
	got = withPass(t, src, "escaping")
	if !hasMessage(got, "ends with a backslash") {
		t.Fatalf("findings = %#v", got)
	}
}

func TestWildcardPass(t *testing.T) {
	src := strings.Replace(cleanRule, "selection:\n    EventID: 4688\n    Image|endswith: '\\cmd.exe'", "selection: {}", 1)
	got := withPass(t, src, "wildcard")
	if !hasMessage(got, "matches every record") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "'*': anything", 1)
	got = withPass(t, src, "wildcard")
	if !hasMessage(got, "wildcard field name") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "EventID: '*'", 1)
	got = withPass(t, src, "wildcard")
	if !hasMessage(got, "matches any value") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "User: null", 1)
	got = withPass(t, src, "wildcard")
	if !hasMessage(got, "compares to null") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "User: ''", 1)
	got = withPass(t, src, "wildcard")
	if !hasMessage(got, "empty value") {
		t.Fatalf("findings = %#v", got)
	}

	src = strings.Replace(cleanRule, "EventID: 4688", "CommandLine|re: '.*'", 1)
	got = withPass(t, src, "wildcard")
	if !hasMessage(got, "matches every string") {
		t.Fatalf("findings = %#v", got)
	}
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		sev   Severity
		str   string
		label string
	}{
		{Info, "info", "INFO"},
		{Warning, "warning", "WARN"},
		{Error, "error", "ERROR"},
	}
	for _, tc := range cases {
		if got := tc.sev.String(); got != tc.str {
			t.Errorf("String = %q, want %q", got, tc.str)
		}
		if got := tc.sev.Label(); got != tc.label {
			t.Errorf("Label = %q, want %q", got, tc.label)
		}
		b, err := json.Marshal(tc.sev)
		if err != nil || string(b) != `"`+tc.str+`"` {
			t.Errorf("Marshal = %s, %v", b, err)
		}
	}
	for _, tc := range []struct {
		in   string
		want Severity
	}{
		{`"error"`, Error},
		{`"warning"`, Warning},
		{`"warn"`, Warning},
		{`"info"`, Info},
		{`"note"`, Info},
	} {
		var s Severity
		if err := json.Unmarshal([]byte(tc.in), &s); err != nil || s != tc.want {
			t.Errorf("Unmarshal(%s) = %v, %v", tc.in, s, err)
		}
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"info":    Info,
		"warning": Warning,
		"warn":    Warning,
		"error":   Error,
	}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"never", "none"} {
		got, err := ParseSeverity(in)
		if err != nil || got < 99 {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSummarizeAndSort(t *testing.T) {
	findings := []Finding{
		{Pass: "b", Severity: Error, File: "b.yml", Line: 2, Col: 1, Message: "z"},
		{Pass: "a", Severity: Warning, File: "a.yml", Line: 1, Col: 1, Message: "y"},
		{Pass: "c", Severity: Info, File: "a.yml", Line: 1, Col: 1, Message: "x"},
	}
	sum := Summarize(findings)
	if sum.Total != 3 || sum.Error != 1 || sum.Warning != 1 || sum.Info != 1 || sum.Rules != 2 {
		t.Fatalf("summary = %#v", sum)
	}
	Sort(findings)
	if findings[0].File != "a.yml" || findings[0].Pass != "a" || findings[1].Pass != "c" || findings[2].File != "b.yml" {
		t.Fatalf("sorted = %#v", findings)
	}
}

func TestFingerprintAndSpan(t *testing.T) {
	f := Finding{Pass: "typos", File: "a.yml", Line: 3, Col: 4, Message: "msg"}
	if len(f.Fingerprint()) != 40 {
		t.Fatalf("fingerprint = %q", f.Fingerprint())
	}
	first, second := f.Fingerprint(), f.Fingerprint()
	if first != second {
		t.Fatal("fingerprint should be stable")
	}
	other := f
	other.Message = "different"
	if f.Fingerprint() == other.Fingerprint() {
		t.Fatal("fingerprint should change with message")
	}
	sp := f.Span()
	if sp.File != "a.yml" || sp.Line != 3 || sp.Col != 4 {
		t.Fatalf("span = %#v", sp)
	}
}

func TestPassesRegistered(t *testing.T) {
	want := []string{"metadata", "dupkeys", "typos", "unreachable", "contradiction", "escaping", "wildcard"}
	passes := Passes()
	if len(passes) != len(want) {
		t.Fatalf("passes = %d", len(passes))
	}
	for i, p := range passes {
		if p.ID != want[i] || p.Description == "" || p.Run == nil {
			t.Fatalf("pass %d = %#v", i, p)
		}
	}
}

func TestRunNil(t *testing.T) {
	if Run(nil, schema.Default()) != nil {
		t.Fatal("nil file should have no findings")
	}
	f := &rule.File{Path: "x.yml"}
	if Run(f, schema.Default()) != nil {
		t.Fatal("file without rule should have no findings")
	}
}

func TestFindingSpanHelper(t *testing.T) {
	f := Finding{File: "a", Line: 1, Col: 2, EndLine: 1, EndCol: 5}
	if got := f.Span(); got != (span.Span{File: "a", Line: 1, Col: 2, EndLine: 1, EndCol: 5}) {
		t.Fatalf("span = %#v", got)
	}
}
