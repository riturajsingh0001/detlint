package schema

import (
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

func TestDefaultSchemas(t *testing.T) {
	reg := Default()
	if len(reg.Sources) < 5 {
		t.Fatalf("sources = %d", len(reg.Sources))
	}
	for _, name := range []string{"windows_security", "windows_powershell", "linux_auditd", "aws_cloudtrail", "okta"} {
		s := reg.Find(name)
		if s == nil {
			t.Fatalf("missing schema %q", name)
		}
		if len(s.Fields) == 0 {
			t.Fatalf("%s has no fields", name)
		}
		if s.Product == "" && s.Service == "" && s.Category == "" {
			t.Fatalf("%s has no logsource", name)
		}
	}
}

func TestRegistryMatch(t *testing.T) {
	reg := Default()
	cases := []struct {
		ls   rule.LogSource
		want string
	}{
		{rule.LogSource{Product: "windows", Service: "security"}, "windows_security"},
		{rule.LogSource{Product: "windows", Service: "powershell"}, "windows_powershell"},
		{rule.LogSource{Product: "linux", Service: "auditd"}, "linux_auditd"},
		{rule.LogSource{Product: "aws", Service: "cloudtrail"}, "aws_cloudtrail"},
		{rule.LogSource{Product: "okta", Service: "okta"}, "okta"},
		// With only a product, every windows schema ties; the first loaded
		// (alphabetical) wins.
		{rule.LogSource{Product: "windows"}, "windows_powershell"},
	}
	for _, tc := range cases {
		s := reg.Match(tc.ls)
		if s == nil {
			t.Errorf("Match(%#v) = nil", tc.ls)
			continue
		}
		if s.Name != tc.want {
			t.Errorf("Match(%#v) = %q, want %q", tc.ls, s.Name, tc.want)
		}
	}
	if s := reg.Match(rule.LogSource{}); s != nil {
		t.Fatalf("empty logsource matched %q", s.Name)
	}
	if s := reg.Match(rule.LogSource{Product: "nope"}); s != nil {
		t.Fatalf("unknown product matched %q", s.Name)
	}
}

func TestRegistryProducts(t *testing.T) {
	got := Default().Products()
	want := map[string]bool{"aws": true, "linux": true, "okta": true, "windows": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected product %q", p)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("products = %v", got)
	}
}

func TestLogSourceLookup(t *testing.T) {
	s := &LogSource{Name: "test", Fields: []Field{
		{Name: "EventID", Type: TypeInt},
		{Name: "CommandLine"},
		{Name: "User"},
	}}
	s.Finalize()
	if !s.HasField("EventID") {
		t.Fatal("missing EventID")
	}
	if s.HasField("eventid") {
		t.Fatal("HasField should be case-sensitive")
	}
	if got, ok := s.FindCaseInsensitive("eventid"); !ok || got != "EventID" {
		t.Fatalf("FindCaseInsensitive = %q %v", got, ok)
	}
	if f, ok := s.Field("EventID"); !ok || f.Type != TypeInt {
		t.Fatalf("Field = %#v %v", f, ok)
	}
	if got := s.FieldNames(); strings.Join(got, ",") != "CommandLine,EventID,User" {
		t.Fatalf("FieldNames = %v", got)
	}
	if got := s.Suggest("ComandLine"); got != "CommandLine" {
		t.Fatalf("Suggest = %q", got)
	}
	if got := s.Suggest("TotallyDifferent"); got != "" {
		t.Fatalf("Suggest = %q", got)
	}
}

func TestLogSourceNilSafe(t *testing.T) {
	var s *LogSource
	if s.HasField("x") || s.FieldNames() != nil || s.Suggest("x") != "" {
		t.Fatal("nil LogSource should be safe")
	}
	if _, ok := s.Field("x"); ok {
		t.Fatal("nil Field should be false")
	}
}

func TestParseSchema(t *testing.T) {
	src := `name: custom
product: custom
service: app
description: A custom schema
fields:
  - name: EventID
    type: int
    required: true
  - name: User
    type: string
    enum: [alice, bob]
eventids:
  - id: 1
    name: Start
  - 2
`
	s, err := Parse([]byte(src), "custom.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "custom" || s.Product != "custom" || s.Service != "app" {
		t.Fatalf("schema = %#v", s)
	}
	if len(s.Fields) != 2 || !s.Fields[0].Required || s.Fields[0].Type != TypeInt {
		t.Fatalf("fields = %#v", s.Fields)
	}
	if len(s.Fields[1].Enum) != 2 {
		t.Fatalf("enum = %#v", s.Fields[1].Enum)
	}
	if len(s.EventIDs) != 2 || s.EventIDs[0].Name != "Start" || s.EventIDs[1].ID != 2 {
		t.Fatalf("eventids = %#v", s.EventIDs)
	}
	if !s.HasField("User") {
		t.Fatal("schema not finalized")
	}
}

func TestParseSchemaMappingFields(t *testing.T) {
	src := "product: p\nfields:\n  EventID: int\n  User:\n    type: string\n    description: name\n"
	s, err := Parse([]byte(src), "m.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "m" {
		t.Fatalf("name = %q", s.Name)
	}
	if f, ok := s.Field("EventID"); !ok || f.Type != TypeInt {
		t.Fatalf("EventID = %#v %v", f, ok)
	}
	if f, ok := s.Field("User"); !ok || f.Type != TypeString || f.Description != "name" {
		t.Fatalf("User = %#v %v", f, ok)
	}
}

func TestParseSchemaErrors(t *testing.T) {
	cases := []string{
		"- a\n- b\n",
		"name: x\n",
		"product: x\n",
		"product: x\nfields: nope\n",
		"product: x\nfields:\n  - nope\n",
		"product: x\nfields:\n  - type: int\n",
	}
	for _, src := range cases {
		if _, err := Parse([]byte(src), "bad.yaml"); err == nil {
			t.Errorf("Parse(%q) succeeded", src)
		}
	}
}

func TestLearnAndMarshal(t *testing.T) {
	records := []map[string]any{
		{"EventID": float64(4688), "User": "alice", "Nested": map[string]any{"Name": "x"}},
		{"EventID": float64(4688), "User": "bob"},
	}
	s := Learn(records, "learned", "windows", "security")
	if s.Name != "learned" || s.Product != "windows" || s.Service != "security" {
		t.Fatalf("schema = %#v", s)
	}
	if f, ok := s.Field("EventID"); !ok || f.Type != TypeInt || !f.Required {
		t.Fatalf("EventID = %#v %v", f, ok)
	}
	if f, ok := s.Field("User"); !ok || !f.Required || len(f.Enum) != 2 {
		t.Fatalf("User = %#v %v", f, ok)
	}
	if _, ok := s.Field("Nested.Name"); !ok {
		t.Fatal("nested field missing")
	}

	data := MarshalYAML(s)
	round, err := Parse(data, "learned.yaml")
	if err != nil {
		t.Fatalf("round trip: %v\n%s", err, data)
	}
	if len(round.Fields) != len(s.Fields) {
		t.Fatalf("round trip fields = %d, want %d\n%s", len(round.Fields), len(s.Fields), data)
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"kitten", "sitting", 3},
		{"abc", "abc", 0},
		{"CommandLine", "ComandLine", 1},
	}
	for _, tc := range cases {
		if got := Levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("Levenshtein(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestFieldTypeDefault(t *testing.T) {
	s := &LogSource{Fields: []Field{{Name: "x"}}}
	s.Finalize()
	if s.Fields[0].Type != TypeString {
		t.Fatalf("type = %q", s.Fields[0].Type)
	}
}
