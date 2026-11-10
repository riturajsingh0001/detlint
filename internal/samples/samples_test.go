package samples

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/rule"
)

func mustFile(t *testing.T, path, src string) *rule.File {
	t.Helper()
	f, err := rule.Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

func ruleSrc(id, title string) string {
	return `title: ` + title + `
id: ` + id + `
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4688
  condition: selection
`
}

func TestLoadSetFS(t *testing.T) {
	fsys := fstest.MapFS{
		"pos/global.jsonl":              &fstest.MapFile{Data: []byte("{\"a\":1}\n")},
		"pos/rule-one/one.jsonl":        &fstest.MapFile{Data: []byte("{\"a\":2}\n{\"a\":3}\n")},
		"pos/rule_two/two.json":         &fstest.MapFile{Data: []byte(`[{"a":4}]`)},
		"pos/.hidden/x.jsonl":           &fstest.MapFile{Data: []byte("{\"a\":5}\n")},
		"pos/ignored.md":                &fstest.MapFile{Data: []byte("x")},
		"pos/rule-one/nested/three.log": &fstest.MapFile{Data: []byte("{\"a\":6}\n")},
	}
	s, err := LoadSetFS(fsys, "pos")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Global) != 1 {
		t.Fatalf("global = %d", len(s.Global))
	}
	if len(s.ByRule["rule_one"]) != 3 {
		t.Fatalf("rule_one = %d", len(s.ByRule["rule_one"]))
	}
	if len(s.ByRule["rule_two"]) != 1 {
		t.Fatalf("rule_two = %d", len(s.ByRule["rule_two"]))
	}
}

func TestLoadSetFSRootPrefix(t *testing.T) {
	fsys := fstest.MapFS{
		"samples/pos/global.jsonl": &fstest.MapFile{Data: []byte("{\"a\":1}\n")},
		"samples/pos/r/x.jsonl":    &fstest.MapFile{Data: []byte("{\"a\":2}\n")},
	}
	s, err := LoadSetFS(fsys, "samples/pos")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Global) != 1 || len(s.ByRule["r"]) != 1 {
		t.Fatalf("set = %#v", s)
	}
}

func TestLoadSetFileAndEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "one.jsonl")
	if err := os.WriteFile(p, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSet(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Global) != 1 {
		t.Fatalf("global = %d", len(s.Global))
	}

	s, err = LoadSet("")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Global) != 0 || s.ByRule == nil {
		t.Fatalf("empty set = %#v", s)
	}

	if _, err := LoadSet(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestForRuleSelectors(t *testing.T) {
	fsys := fstest.MapFS{
		"pos/global.jsonl":             &fstest.MapFile{Data: []byte("{\"a\":1}\n")},
		"pos/my_rule_id/id.jsonl":      &fstest.MapFile{Data: []byte("{\"a\":2}\n")},
		"pos/my_title/title.jsonl":     &fstest.MapFile{Data: []byte("{\"a\":3}\n")},
		"pos/file_stem/stem.jsonl":     &fstest.MapFile{Data: []byte("{\"a\":4}\n")},
		"pos/other/other.jsonl":        &fstest.MapFile{Data: []byte("{\"a\":5}\n")},
		"pos/my_rule_id/extra.jsonl":   &fstest.MapFile{Data: []byte("{\"a\":6}\n")},
		"pos/my_title/extra_two.jsonl": &fstest.MapFile{Data: []byte("{\"a\":7}\n")},
	}
	s, err := LoadSetFS(fsys, "pos")
	if err != nil {
		t.Fatal(err)
	}
	f := mustFile(t, "rules/file_stem.yml", ruleSrc("my-rule-id", "My Title"))
	recs := s.ForRule(f.Rule, f.Path)
	// 1 global + 2 id + 2 title + 1 stem.
	if len(recs) != 6 {
		t.Fatalf("records = %d, want 6", len(recs))
	}
	if len(s.ForRule(nil, "")) != 1 {
		t.Fatalf("nil rule should only get globals")
	}
	var nilSet *Set
	if nilSet.ForRule(f.Rule, f.Path) != nil {
		t.Fatal("nil set should return nil")
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"My Rule!":          "my_rule",
		"  --Hello__World ": "hello_world",
		"a.b/c":             "a_b_c",
		"":                  "",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEvaluateShared(t *testing.T) {
	pos := []eval.Record{{"EventID": float64(4688)}, {"EventID": float64(1)}}
	neg := []eval.Record{{"EventID": float64(1)}, {"EventID": float64(2)}}
	files := []*rule.File{mustFile(t, "r.yml", ruleSrc("r", "R"))}
	results := Evaluate(files, pos, neg)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	r := results[0]
	if r.Pos != 2 || r.Neg != 2 || r.TP != 1 || r.FN != 1 || r.FP != 0 || r.TN != 2 {
		t.Fatalf("result = %#v", r)
	}
	if r.Precision != 1 || r.Recall != 0.5 {
		t.Fatalf("precision/recall = %v/%v", r.Precision, r.Recall)
	}
	if r.Pass(0.9, 0.9) {
		t.Fatal("should fail recall")
	}
	if !r.Pass(0.9, 0.5) {
		t.Fatal("should pass with lower recall")
	}
	if !Failed(results, 0.9, 0.9) {
		t.Fatal("Failed = false")
	}
	if Failed(results, 0.9, 0.5) {
		t.Fatal("Failed = true")
	}
}

func TestEvaluateZeroDenominators(t *testing.T) {
	files := []*rule.File{mustFile(t, "r.yml", ruleSrc("r", "R"))}
	results := Evaluate(files, nil, nil)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	r := results[0]
	if r.Precision != 1 || r.Recall != 1 {
		t.Fatalf("zero denominator = %v/%v", r.Precision, r.Recall)
	}
	if !r.Pass(0.9, 0.9) {
		t.Fatal("empty samples should pass")
	}
}

func TestEvaluateSets(t *testing.T) {
	pos := &Set{ByRule: map[string][]eval.Record{
		"r": {{"EventID": float64(4688)}},
	}}
	neg := &Set{ByRule: map[string][]eval.Record{
		"r": {{"EventID": float64(1)}},
	}}
	files := []*rule.File{mustFile(t, "r.yml", ruleSrc("r", "R"))}
	results := EvaluateSets(files, pos, neg)
	if results[0].TP != 1 || results[0].TN != 1 {
		t.Fatalf("result = %#v", results[0])
	}
}

func TestEvaluateSkipsAggregations(t *testing.T) {
	src := `title: agg
id: agg
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4688
  condition: selection | count() > 5
`
	files := []*rule.File{mustFile(t, "agg.yml", src)}
	results := Evaluate(files, []eval.Record{{"EventID": float64(4688)}}, nil)
	if len(results) != 1 || results[0].Skipped == "" {
		t.Fatalf("results = %#v", results)
	}
	if !results[0].Pass(1, 1) {
		t.Fatal("skipped result should pass")
	}
}

func TestEvaluateIgnoresUnparsed(t *testing.T) {
	f := &rule.File{Path: "bad.yml"}
	if got := Evaluate([]*rule.File{f}, nil, nil); len(got) != 0 {
		t.Fatalf("results = %#v", got)
	}
}

func TestWritePretty(t *testing.T) {
	files := []*rule.File{mustFile(t, "r.yml", ruleSrc("r", "R"))}
	results := Evaluate(files, []eval.Record{{"EventID": float64(4688)}}, []eval.Record{{"EventID": float64(4688)}})
	var buf bytes.Buffer
	if err := WritePretty(&buf, results, Options{MinPrecision: 0.9, MinRecall: 0.9}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "rule") || !strings.Contains(out, "FAIL") {
		t.Fatalf("output = %q", out)
	}

	buf.Reset()
	if err := WritePretty(&buf, results, Options{MinPrecision: 0, MinRecall: 0, Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[32m") {
		t.Fatalf("expected color output: %q", buf.String())
	}

	skipped := []Result{{Rule: files[0].Rule, File: files[0].Path, Skipped: "batch"}}
	buf.Reset()
	if err := WritePretty(&buf, skipped, Options{MinPrecision: 1, MinRecall: 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "SKIP") || !strings.Contains(buf.String(), "note: batch") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	files := []*rule.File{mustFile(t, "r.yml", ruleSrc("r", "R"))}
	results := Evaluate(files, []eval.Record{{"EventID": float64(4688)}}, nil)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, results); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Results []struct {
			File      string  `json:"file"`
			RuleID    string  `json:"rule_id"`
			Pos       int     `json:"pos"`
			Precision float64 `json:"precision"`
		} `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	if len(got.Results) != 1 || got.Results[0].RuleID != "r" || got.Results[0].Pos != 1 || got.Results[0].Precision != 1 {
		t.Fatalf("json = %#v", got)
	}
}
