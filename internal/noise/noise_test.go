package noise

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/rule"
)

func mustFile(t *testing.T, path, src string) *rule.File {
	t.Helper()
	f, err := rule.Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func src(id, title, eventID string) string {
	return `title: ` + title + `
id: ` + id + `
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: ` + eventID + `
  condition: selection
`
}

func TestAnalyze(t *testing.T) {
	files := []*rule.File{
		mustFile(t, "a.yml", src("a", "A", "4688")),
		mustFile(t, "b.yml", src("b", "B", "4624")),
		mustFile(t, "c.yml", src("c", "C", "1")),
	}
	records := []eval.Record{
		{"EventID": float64(4688)},
		{"EventID": float64(4688)},
		{"EventID": float64(4624)},
	}
	hits := Analyze(files, records)
	if len(hits) != 3 {
		t.Fatalf("hits = %d", len(hits))
	}
	// Sorted by count descending, then file.
	if hits[0].Rule.ID != "a" || hits[0].Count != 2 {
		t.Fatalf("hits[0] = %#v", hits[0])
	}
	if hits[1].Rule.ID != "b" || hits[1].Count != 1 {
		t.Fatalf("hits[1] = %#v", hits[1])
	}
	if hits[2].Rule.ID != "c" || hits[2].Count != 0 {
		t.Fatalf("hits[2] = %#v", hits[2])
	}
	if hits[0].Total != 3 || hits[0].Rate < 0.66 || hits[0].Rate > 0.67 {
		t.Fatalf("rate = %#v", hits[0])
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	files := []*rule.File{mustFile(t, "a.yml", src("a", "A", "1"))}
	hits := Analyze(files, nil)
	if len(hits) != 1 || hits[0].Total != 0 || hits[0].Rate != 0 {
		t.Fatalf("hits = %#v", hits)
	}
}

func TestAnalyzeSkipsUnparsed(t *testing.T) {
	hits := Analyze([]*rule.File{{Path: "bad.yml"}}, []eval.Record{{}})
	if len(hits) != 0 {
		t.Fatalf("hits = %#v", hits)
	}
}

func TestExceeded(t *testing.T) {
	hits := []Hit{{Count: 5}, {Count: 11}}
	if Exceeded(hits, 0) {
		t.Fatal("max 0 should never fail")
	}
	if Exceeded(hits, 10) != true {
		t.Fatal("should exceed 10")
	}
	if Exceeded(hits, 20) {
		t.Fatal("should not exceed 20")
	}
	if Exceeded(nil, 1) {
		t.Fatal("empty should not exceed")
	}
}

func TestWritePretty(t *testing.T) {
	files := []*rule.File{mustFile(t, "a.yml", src("a", "A", "4688"))}
	hits := Analyze(files, []eval.Record{{"EventID": float64(4688)}, {"EventID": float64(4688)}})
	var buf bytes.Buffer
	if err := WritePretty(&buf, hits, Options{Top: 1, Max: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "records scanned: 2") || !strings.Contains(out, "NOISY") {
		t.Fatalf("output = %q", out)
	}

	buf.Reset()
	if err := WritePretty(&buf, nil, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no rules") {
		t.Fatalf("output = %q", buf.String())
	}

	buf.Reset()
	if err := WritePretty(&buf, hits, Options{Top: 1, Max: 1, Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Fatalf("expected color: %q", buf.String())
	}
}

func TestWritePrettyTop(t *testing.T) {
	files := []*rule.File{
		mustFile(t, "a.yml", src("a", "A", "4688")),
		mustFile(t, "b.yml", src("b", "B", "4624")),
	}
	hits := Analyze(files, []eval.Record{{"EventID": float64(4688)}})
	var buf bytes.Buffer
	if err := WritePretty(&buf, hits, Options{Top: 1}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "B") {
		t.Fatalf("top 1 should hide second rule: %q", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	files := []*rule.File{mustFile(t, "a.yml", src("a", "A", "4688"))}
	hits := Analyze(files, []eval.Record{{"EventID": float64(4688)}})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, hits, Options{Top: 5, Max: 0}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Total int `json:"total"`
		Hits  []struct {
			File  string  `json:"file"`
			Rule  string  `json:"rule_id"`
			Count int     `json:"count"`
			Rate  float64 `json:"rate"`
			Noisy bool    `json:"noisy"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	if got.Total != 1 || len(got.Hits) != 1 || got.Hits[0].Rule != "a" || got.Hits[0].Count != 1 || got.Hits[0].Noisy {
		t.Fatalf("json = %#v", got)
	}
}
