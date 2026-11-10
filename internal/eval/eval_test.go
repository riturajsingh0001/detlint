package eval

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

func mustRule(t *testing.T, src string) *rule.Rule {
	t.Helper()
	f, err := rule.Parse("test.yml", []byte(src))
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	return f.Rule
}

func oneFieldRule(t *testing.T, field string) *rule.Rule {
	t.Helper()
	src := `title: t
id: t
logsource: {product: windows, service: security}
detection:
  selection:
    ` + field + `
  condition: selection
`
	return mustRule(t, src)
}

func TestMatchFieldExact(t *testing.T) {
	r := oneFieldRule(t, "User: alice")
	if !MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("exact match failed")
	}
	if !MatchRule(r, Record{"user": "ALICE"}) {
		t.Fatal("match should be case-insensitive and key-insensitive")
	}
	if MatchRule(r, Record{"User": "bob"}) {
		t.Fatal("unexpected match")
	}
	if MatchRule(r, Record{}) {
		t.Fatal("missing field should not match")
	}
}

func TestMatchFieldCased(t *testing.T) {
	r := oneFieldRule(t, "User|cased: Alice")
	if !MatchRule(r, Record{"User": "Alice"}) {
		t.Fatal("cased exact match failed")
	}
	if MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("cased should be case-sensitive")
	}
}

func TestMatchFieldStringModifiers(t *testing.T) {
	cases := []struct {
		field string
		rec   Record
		want  bool
	}{
		{"CommandLine|contains: whoami", Record{"CommandLine": "cmd /c whoami /all"}, true},
		{"CommandLine|contains: whoami", Record{"CommandLine": "cmd /c dir"}, false},
		{"Image|startswith: 'C:\\Windows'", Record{"Image": `C:\Windows\System32\cmd.exe`}, true},
		{"Image|endswith: '\\cmd.exe'", Record{"Image": `C:\Windows\System32\cmd.exe`}, true},
		{"Image|endswith: '\\cmd.exe'", Record{"Image": `C:\Windows\System32\notepad.exe`}, false},
		{"Image|contains|all: [cmd, System32]", Record{"Image": `C:\Windows\System32\cmd.exe`}, true},
		{"Image|contains|all: [cmd, missing]", Record{"Image": `C:\Windows\System32\cmd.exe`}, false},
		{"User|contains: [alice, bob]", Record{"User": "bob"}, true},
	}
	for _, tc := range cases {
		r := oneFieldRule(t, tc.field)
		if got := MatchRule(r, tc.rec); got != tc.want {
			t.Errorf("%s on %v = %v, want %v", tc.field, tc.rec, got, tc.want)
		}
	}
}

func TestMatchFieldWildcards(t *testing.T) {
	r := oneFieldRule(t, "Image: '*\\powershell.exe'")
	if !MatchRule(r, Record{"Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}) {
		t.Fatal("glob match failed")
	}
	if MatchRule(r, Record{"Image": `C:\Windows\System32\cmd.exe`}) {
		t.Fatal("unexpected glob match")
	}
	r = oneFieldRule(t, "User: 'a?ice'")
	if !MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("? glob failed")
	}
	r = oneFieldRule(t, "User|contains: 'a*e'")
	if !MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("contains glob failed")
	}
}

func TestMatchFieldRegex(t *testing.T) {
	r := oneFieldRule(t, "CommandLine|re: '-enc(odedcommand)?'")
	if !MatchRule(r, Record{"CommandLine": "powershell -encodedcommand SQB"}) {
		t.Fatal("regex match failed")
	}
	r = oneFieldRule(t, "CommandLine|re|cased: 'ABC'")
	if MatchRule(r, Record{"CommandLine": "abc"}) {
		t.Fatal("cased regex should not match lowercase")
	}
	r = oneFieldRule(t, "CommandLine|re: '(?<bad'")
	if MatchRule(r, Record{"CommandLine": "(?<bad"}) {
		t.Fatal("invalid regex should not match")
	}
}

func TestMatchFieldExistsAndNull(t *testing.T) {
	r := oneFieldRule(t, "User|exists: true")
	if !MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("exists true failed")
	}
	if MatchRule(r, Record{}) {
		t.Fatal("exists true matched missing field")
	}
	r = oneFieldRule(t, "User|exists: false")
	if !MatchRule(r, Record{}) {
		t.Fatal("exists false failed")
	}
	if MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("exists false matched present field")
	}
	r = oneFieldRule(t, "User: null")
	if !MatchRule(r, Record{}) {
		t.Fatal("null should match missing field")
	}
	if MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("null matched present field")
	}
}

func TestMatchFieldNumericAndBool(t *testing.T) {
	r := oneFieldRule(t, "EventID: 4688")
	if !MatchRule(r, Record{"EventID": float64(4688)}) {
		t.Fatal("numeric match failed")
	}
	if !MatchRule(r, Record{"EventID": "4688"}) {
		t.Fatal("stringified numeric match failed")
	}
	r = oneFieldRule(t, "EventID|gte: 4000")
	if !MatchRule(r, Record{"EventID": float64(5000)}) {
		t.Fatal("gte failed")
	}
	if MatchRule(r, Record{"EventID": float64(1)}) {
		t.Fatal("gte matched too low")
	}
	r = oneFieldRule(t, "Enabled: true")
	if !MatchRule(r, Record{"Enabled": true}) {
		t.Fatal("bool match failed")
	}
	if MatchRule(r, Record{"Enabled": false}) {
		t.Fatal("bool mismatch")
	}
}

func TestMatchFieldNotEqual(t *testing.T) {
	r := oneFieldRule(t, "User|neq: alice")
	if !MatchRule(r, Record{"User": "bob"}) {
		t.Fatal("neq should match a different value")
	}
	if MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("neq matched the excluded value")
	}
	if MatchRule(r, Record{}) {
		t.Fatal("neq should not match a missing field")
	}
}

func TestMatchFieldCIDR(t *testing.T) {
	r := oneFieldRule(t, "IpAddress|cidr: 10.0.0.0/8")
	if !MatchRule(r, Record{"IpAddress": "10.1.2.3"}) {
		t.Fatal("cidr match failed")
	}
	if MatchRule(r, Record{"IpAddress": "192.168.1.1"}) {
		t.Fatal("cidr matched outside range")
	}
	if MatchRule(r, Record{"IpAddress": "not-an-ip"}) {
		t.Fatal("cidr matched invalid IP")
	}
}

func TestMatchFieldFieldRef(t *testing.T) {
	r := oneFieldRule(t, "User|fieldref: TargetUser")
	if !MatchRule(r, Record{"User": "alice", "TargetUser": "ALICE"}) {
		t.Fatal("fieldref failed")
	}
	if MatchRule(r, Record{"User": "alice", "TargetUser": "bob"}) {
		t.Fatal("fieldref matched different values")
	}
	if MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("fieldref matched missing target")
	}
}

func TestMatchFieldWindash(t *testing.T) {
	r := oneFieldRule(t, "CommandLine|windash|contains: '/c'")
	if !MatchRule(r, Record{"CommandLine": "cmd.exe -c whoami"}) {
		t.Fatal("windash failed")
	}
}

func TestMatchFieldEncodings(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	r := oneFieldRule(t, "Payload|base64: hello")
	if !MatchRule(r, Record{"Payload": b64}) {
		t.Fatal("base64 failed")
	}
	r = oneFieldRule(t, "Payload|utf16le: AB")
	if !MatchRule(r, Record{"Payload": "A\x00B\x00"}) {
		t.Fatal("utf16le failed")
	}
	r = oneFieldRule(t, "Payload|utf16be: AB")
	if !MatchRule(r, Record{"Payload": "\x00A\x00B"}) {
		t.Fatal("utf16be failed")
	}
	r = oneFieldRule(t, "Payload|wide: AB")
	if !MatchRule(r, Record{"Payload": "A\x00B\x00"}) {
		t.Fatal("wide failed")
	}
	// base64offset produces three candidate encodings; the plain one is the
	// zero-offset variant.
	r = oneFieldRule(t, "Payload|base64offset|contains: hello")
	if !MatchRule(r, Record{"Payload": b64}) {
		t.Fatal("base64offset failed")
	}
}

func TestMatchFieldArraysAndNesting(t *testing.T) {
	r := oneFieldRule(t, "Tags: evil")
	if !MatchRule(r, Record{"Tags": []any{"good", "evil"}}) {
		t.Fatal("array match failed")
	}
	r = oneFieldRule(t, "user.name: alice")
	if !MatchRule(r, Record{"user": map[string]any{"name": "Alice"}}) {
		t.Fatal("dotted lookup failed")
	}
	r = oneFieldRule(t, "USER.NAME: alice")
	if !MatchRule(r, Record{"user": map[string]any{"Name": "alice"}}) {
		t.Fatal("case-insensitive dotted lookup failed")
	}
	if MatchRule(r, Record{"user": "alice"}) {
		t.Fatal("dotted lookup should fail on scalar")
	}
}

func TestMatchWildcardField(t *testing.T) {
	r := oneFieldRule(t, "'*': anything")
	if !MatchRule(r, Record{"Whatever": "value"}) {
		t.Fatal("wildcard field failed")
	}
}

func TestMatchSelectionGroups(t *testing.T) {
	src := `title: g
id: g
logsource: {product: windows, service: security}
detection:
  selection:
    - EventID: 1
      User: alice
    - EventID: 2
  condition: selection
`
	r := mustRule(t, src)
	if !MatchRule(r, Record{"EventID": float64(1), "User": "alice"}) {
		t.Fatal("first group failed")
	}
	if !MatchRule(r, Record{"EventID": float64(2)}) {
		t.Fatal("second group failed")
	}
	if MatchRule(r, Record{"EventID": float64(3), "User": "bob"}) {
		t.Fatal("unexpected match")
	}
}

func TestMatchConditions(t *testing.T) {
	src := `title: c
id: c
logsource: {product: windows, service: security}
detection:
  sel_a:
    EventID: 1
  sel_b:
    EventID: 2
  sel_c:
    User: alice
  condition: (sel_a or sel_b) and not sel_c
`
	r := mustRule(t, src)
	if !MatchRule(r, Record{"EventID": float64(1), "User": "bob"}) {
		t.Fatal("condition failed")
	}
	if MatchRule(r, Record{"EventID": float64(1), "User": "alice"}) {
		t.Fatal("not branch failed")
	}
	if MatchRule(r, Record{"EventID": float64(3), "User": "bob"}) {
		t.Fatal("or branch failed")
	}
}

func TestMatchQuantifiers(t *testing.T) {
	src := `title: q
id: q
logsource: {product: windows, service: security}
detection:
  sel_one:
    EventID: 1
  sel_two:
    User: alice
  condition: 1 of them
`
	r := mustRule(t, src)
	if !MatchRule(r, Record{"EventID": float64(1)}) {
		t.Fatal("1 of them failed")
	}
	if !MatchRule(r, Record{"User": "alice"}) {
		t.Fatal("1 of them failed for second selection")
	}
	if MatchRule(r, Record{"EventID": float64(2)}) {
		t.Fatal("1 of them matched nothing")
	}

	src = strings.Replace(src, "1 of them", "all of them", 1)
	r = mustRule(t, src)
	if !MatchRule(r, Record{"EventID": float64(1), "User": "alice"}) {
		t.Fatal("all of them failed")
	}
	if MatchRule(r, Record{"EventID": float64(1)}) {
		t.Fatal("all of them matched partial")
	}

	src = strings.Replace(src, "all of them", "2 of sel_*", 1)
	r = mustRule(t, src)
	if !MatchRule(r, Record{"EventID": float64(1), "User": "alice"}) {
		t.Fatal("2 of glob failed")
	}
	if MatchRule(r, Record{"EventID": float64(1)}) {
		t.Fatal("2 of glob matched one")
	}
}

func TestMatchUndefinedSelection(t *testing.T) {
	src := `title: u
id: u
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 1
  condition: selection and not missing
`
	r := mustRule(t, src)
	if MatchRule(r, Record{"EventID": float64(1)}) {
		t.Fatal("rule with undefined selection must never match")
	}
}

func TestMatchBatchAggregation(t *testing.T) {
	src := `title: agg
id: agg
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection | count() by User > 2
`
	r := mustRule(t, src)
	records := []Record{
		{"EventID": float64(4625), "User": "alice"},
		{"EventID": float64(4625), "User": "alice"},
		{"EventID": float64(4625), "User": "alice"},
		{"EventID": float64(4625), "User": "bob"},
	}
	if !MatchBatch(r, records) {
		t.Fatal("aggregation should fire")
	}
	if MatchBatch(r, records[:2]) {
		t.Fatal("aggregation should not fire")
	}
	if got := CountHits(r, records); got != 1 {
		t.Fatalf("CountHits = %d", got)
	}
	if got := CountHits(r, records[:2]); got != 0 {
		t.Fatalf("CountHits = %d", got)
	}
	if MatchRule(r, records[0]) {
		t.Fatal("MatchRule must not evaluate aggregations")
	}
}

func TestMatchBatchAggregationArgsAndNoGroups(t *testing.T) {
	src := `title: agg2
id: agg2
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection | count(User) >= 2
`
	r := mustRule(t, src)
	records := []Record{
		{"EventID": float64(4625), "User": "alice"},
		{"EventID": float64(4625), "User": "bob"},
	}
	if !MatchBatch(r, records) {
		t.Fatal("count(User) should count records with User")
	}
	missing := []Record{
		{"EventID": float64(4625)},
		{"EventID": float64(4625)},
	}
	if MatchBatch(r, missing) {
		t.Fatal("count(User) should skip records without User")
	}
	if MatchBatch(r, nil) {
		t.Fatal("empty batch should not satisfy >= 2")
	}
}

func TestMatchBatchNoAggregation(t *testing.T) {
	r := oneFieldRule(t, "EventID: 1")
	if !MatchBatch(r, []Record{{"EventID": float64(2)}, {"EventID": float64(1)}}) {
		t.Fatal("batch should match when any record matches")
	}
	if MatchBatch(r, []Record{{"EventID": float64(2)}}) {
		t.Fatal("batch matched none")
	}
	if MatchBatch(nil, nil) {
		t.Fatal("nil rule should not match")
	}
}

func TestCountHits(t *testing.T) {
	r := oneFieldRule(t, "EventID: 1")
	records := []Record{{"EventID": float64(1)}, {"EventID": float64(2)}, {"EventID": float64(1)}}
	if got := CountHits(r, records); got != 2 {
		t.Fatalf("CountHits = %d", got)
	}
	if got := CountHits(nil, records); got != 0 {
		t.Fatalf("CountHits(nil) = %d", got)
	}
}

func TestEvalNil(t *testing.T) {
	if Eval(nil, nil, nil) {
		t.Fatal("nil expression should be false")
	}
	if MatchRule(nil, nil) || MatchRule(&rule.Rule{}, nil) {
		t.Fatal("nil rule/condition should be false")
	}
	if MatchSelection(nil, nil) || MatchField(rule.Field{}, nil) {
		t.Fatal("nil selection/field should be false")
	}
}

func TestDecodeFormats(t *testing.T) {
	jsonl := "{\"a\":1}\n# comment\n\n{\"a\":2}\n"
	recs, err := Decode([]byte(jsonl), "x.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("jsonl records = %d", len(recs))
	}
	arr, err := Decode([]byte(`[{"a":1},{"a":2}]`), "x.json")
	if err != nil || len(arr) != 2 {
		t.Fatalf("array = %v, %v", arr, err)
	}
	one, err := Decode([]byte(`{"a": 1}`), "x.json")
	if err != nil || len(one) != 1 {
		t.Fatalf("object = %v, %v", one, err)
	}
	pretty, err := Decode([]byte("{\n  \"a\": 1\n}\n"), "x.json")
	if err != nil || len(pretty) != 1 {
		t.Fatalf("pretty object = %v, %v", pretty, err)
	}
	if recs, err := Decode(nil, "x"); err != nil || recs != nil {
		t.Fatalf("empty = %v, %v", recs, err)
	}
	if _, err := Decode([]byte("{bad}\n"), "x.jsonl"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := Decode([]byte("[bad]"), "x.json"); err == nil {
		t.Fatal("expected array parse error")
	}
}

func TestDecodeDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.jsonl", "{\"a\":1}\n")
	write("b.log", "{\"a\":2}\n")
	write("c.txt", "{\"a\":3}\n")
	write("d.md", "ignored")
	recs, err := DecodeDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("records = %d", len(recs))
	}
	single, err := DecodeDir(filepath.Join(dir, "a.jsonl"))
	if err != nil || len(single) != 1 {
		t.Fatalf("single = %v, %v", single, err)
	}
	if _, err := DecodeDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestLookupAndFlatten(t *testing.T) {
	rec := Record{
		"User": "alice",
		"nested": map[string]any{
			"Value": float64(1),
			"Deep":  map[string]any{"X": "y"},
		},
	}
	if v, ok := Lookup(rec, "user"); !ok || v != "alice" {
		t.Fatalf("Lookup = %v %v", v, ok)
	}
	if v, ok := Lookup(rec, "NESTED.value"); !ok || v != float64(1) {
		t.Fatalf("dotted Lookup = %v %v", v, ok)
	}
	if v, ok := Lookup(rec, "nested.deep.x"); !ok || v != "y" {
		t.Fatalf("deep Lookup = %v %v", v, ok)
	}
	if _, ok := Lookup(rec, "nested.nope"); ok {
		t.Fatal("unexpected lookup")
	}
	if _, ok := Lookup(rec, "nested.deep.x.y"); ok {
		t.Fatal("unexpected deep lookup")
	}
	flat := Flatten(rec)
	if flat["nested.Deep.X"] != "y" || flat["nested.Value"] != float64(1) || flat["User"] != "alice" {
		t.Fatalf("Flatten = %#v", flat)
	}
}

func TestAsHelpers(t *testing.T) {
	cases := []struct {
		in  any
		str string
		ok  bool
	}{
		{"x", "x", true},
		{true, "true", true},
		{float64(4), "4", true},
		{float64(1.5), "1.5", true},
		{nil, "", false},
		{[]any{1}, "[1]", true},
	}
	for _, tc := range cases {
		got, ok := AsString(tc.in)
		if got != tc.str || ok != tc.ok {
			t.Errorf("AsString(%v) = %q %v, want %q %v", tc.in, got, ok, tc.str, tc.ok)
		}
	}
	if f, ok := AsFloat("2.5"); !ok || f != 2.5 {
		t.Fatalf("AsFloat = %v %v", f, ok)
	}
	if f, ok := AsFloat(true); !ok || f != 1 {
		t.Fatalf("AsFloat(bool) = %v %v", f, ok)
	}
	if _, ok := AsFloat(struct{}{}); ok {
		t.Fatal("AsFloat(struct) should fail")
	}
	if b, ok := AsBool("true"); !ok || !b {
		t.Fatalf("AsBool = %v %v", b, ok)
	}
	if b, ok := AsBool(float64(0)); !ok || b {
		t.Fatalf("AsBool(0) = %v %v", b, ok)
	}
	if _, ok := AsBool(struct{}{}); ok {
		t.Fatal("AsBool(struct) should fail")
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := map[string]string{
		"a*b":  "a.*b",
		"a?b":  "a.b",
		"a.b":  `a\.b`,
		`a\*b`: `a\*b`,
		`a\\b`: `a\\b`,
	}
	for in, want := range cases {
		if got := globToRegex(in); got != want {
			t.Errorf("globToRegex(%q) = %q, want %q", in, got, want)
		}
	}
	if !hasGlob("a*b") || hasGlob(`a\*b`) || hasGlob("abc") {
		t.Fatal("hasGlob mismatch")
	}
}
