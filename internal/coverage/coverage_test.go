package coverage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

func mustFile(t *testing.T, path, title, id string, tags ...string) *rule.File {
	t.Helper()
	var b strings.Builder
	b.WriteString("title: " + title + "\nid: " + id + "\n")
	b.WriteString("logsource: {product: windows, service: security}\ndetection:\n  selection:\n    EventID: 4688\n  condition: selection\n")
	if len(tags) > 0 {
		b.WriteString("tags:\n")
		for _, tag := range tags {
			b.WriteString("  - " + tag + "\n")
		}
	}
	f, err := rule.Parse(path, []byte(b.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func TestParseMatrix(t *testing.T) {
	data := []byte(`{"tactics":[{"id":"TA0002","name":"Execution","techniques":[{"id":"t1059","name":"Shell"}]}]}`)
	m, err := ParseMatrix(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tactics) != 1 {
		t.Fatalf("tactics = %d", len(m.Tactics))
	}
	if tech, ok := m.Technique("T1059"); !ok || tech.Name != "Shell" || tech.ID != "T1059" {
		t.Fatalf("technique = %#v %v", tech, ok)
	}
	if _, ok := m.Technique("T9999"); ok {
		t.Fatal("unexpected technique")
	}
	if tac, ok := m.Tactic("Execution"); !ok || tac.ID != "TA0002" {
		t.Fatalf("tactic = %#v %v", tac, ok)
	}
	if tac, ok := m.Tactic("ta0002"); !ok || tac.Name != "Execution" {
		t.Fatalf("tactic by id = %#v %v", tac, ok)
	}
	if ids := m.TechniqueIDs(); len(ids) != 1 || ids[0] != "T1059" {
		t.Fatalf("ids = %v", ids)
	}
	if _, err := ParseMatrix([]byte("{")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestDefaultMatrix(t *testing.T) {
	m := Default()
	if len(m.Tactics) < 10 {
		t.Fatalf("tactics = %d", len(m.Tactics))
	}
	if _, ok := m.Technique("T1059.001"); !ok {
		t.Fatal("missing T1059.001")
	}
	if got := len(m.TechniqueIDs()); got < 80 {
		t.Fatalf("technique ids = %d", got)
	}
}

func TestAnalyze(t *testing.T) {
	files := []*rule.File{
		mustFile(t, "a.yml", "PowerShell", "a", "attack.execution", "attack.t1059.001"),
		mustFile(t, "b.yml", "Unknown Technique", "b", "attack.t9999"),
		mustFile(t, "c.yml", "Not Attack", "c", "custom.tag"),
		mustFile(t, "d.yml", "No Tags", "d"),
	}
	rep := Analyze(files, Default())
	if rep.Rules != 4 {
		t.Fatalf("rules = %d", rep.Rules)
	}
	if len(rep.UnknownTags) != 1 || rep.UnknownTags[0] != "T9999" {
		t.Fatalf("unknown = %v", rep.UnknownTags)
	}
	if len(rep.Untagged) != 2 || rep.Untagged[0] != "No Tags" || rep.Untagged[1] != "Not Attack" {
		t.Fatalf("untagged = %v", rep.Untagged)
	}
	if rep.TacticRules["TA0002"] != 1 {
		t.Fatalf("tactic rules = %v", rep.TacticRules)
	}
	if got := rep.TechniqueMap["T1059.001"]; len(got) != 1 || got[0] != "PowerShell" {
		t.Fatalf("technique map = %v", rep.TechniqueMap)
	}
	if rep.Covered != 1 || rep.Total < 80 {
		t.Fatalf("coverage = %d/%d", rep.Covered, rep.Total)
	}
}

func TestAnalyzeTacticIDs(t *testing.T) {
	rep := Analyze([]*rule.File{
		mustFile(t, "a.yml", "Tactic ID", "a", "attack.ta0002"),
	}, Default())
	if rep.TacticRules["TA0002"] != 1 {
		t.Fatalf("tactic rules = %v", rep.TacticRules)
	}
	if len(rep.UnknownTags) != 0 || len(rep.Untagged) != 0 {
		t.Fatalf("unknown=%v untagged=%v", rep.UnknownTags, rep.Untagged)
	}
}

func TestAnalyzeDeduplicatesRuleNames(t *testing.T) {
	files := []*rule.File{
		mustFile(t, "a.yml", "Same", "a", "attack.t1059.001"),
		mustFile(t, "b.yml", "Same", "b", "attack.t1059.001"),
	}
	rep := Analyze(files, Default())
	if got := rep.TechniqueMap["T1059.001"]; len(got) != 1 {
		t.Fatalf("technique map = %v", got)
	}
}

func TestAnalyzeNilMatrixAndFiles(t *testing.T) {
	rep := Analyze(nil, nil)
	if rep.Rules != 0 || rep.Covered != 0 {
		t.Fatalf("report = %#v", rep)
	}
	rep = Analyze([]*rule.File{{Path: "bad.yml"}}, Default())
	if rep.Rules != 0 {
		t.Fatalf("rules = %d", rep.Rules)
	}
}

func TestFilter(t *testing.T) {
	files := []*rule.File{
		mustFile(t, "a.yml", "PowerShell", "a", "attack.execution", "attack.t1059.001"),
	}
	rep := Analyze(files, Default())
	exec := rep.Filter("Execution")
	if len(exec.Tactics) != 1 || exec.Tactics[0].ID != "TA0002" {
		t.Fatalf("filter = %#v", exec)
	}
	if exec.Covered != 1 || exec.Total != exec.Tactics[0].Total {
		t.Fatalf("filter totals = %d/%d", exec.Covered, exec.Total)
	}
	if got := rep.Filter("TA0002"); len(got.Tactics) != 1 {
		t.Fatalf("filter by id = %#v", got)
	}
	if got := rep.Filter(""); got != rep {
		t.Fatal("empty filter should return the same report")
	}
	if got := rep.Filter("nope"); len(got.Tactics) != 0 {
		t.Fatalf("unknown filter = %#v", got)
	}
}

func TestPercentAndString(t *testing.T) {
	r := &Report{Covered: 1, Total: 4}
	if got := r.Percent(); got != 25 {
		t.Fatalf("percent = %v", got)
	}
	if got := r.String(); got != "1/4 techniques (25%)" {
		t.Fatalf("string = %q", got)
	}
	var nilReport *Report
	if nilReport.Percent() != 0 {
		t.Fatal("nil percent should be 0")
	}
}

func TestWritePretty(t *testing.T) {
	rep := Analyze([]*rule.File{
		mustFile(t, "a.yml", "PowerShell", "a", "attack.execution", "attack.t1059.001", "attack.t9999"),
	}, Default())
	var buf bytes.Buffer
	if err := WritePretty(&buf, rep, Options{ShowMissing: 2}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"ATT&CK coverage:", "tactic", "Execution", "unknown ATT&CK tags", "T9999"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := WritePretty(&buf, rep, Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[33m") {
		t.Fatalf("expected color output")
	}
}

func TestWriteJSON(t *testing.T) {
	rep := Analyze([]*rule.File{
		mustFile(t, "a.yml", "PowerShell", "a", "attack.execution", "attack.t1059.001"),
	}, Default())
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Covered int `json:"covered"`
		Total   int `json:"total"`
		Rules   int `json:"rules"`
		Tactics []struct {
			ID string `json:"id"`
		} `json:"tactics"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	if got.Covered != 1 || got.Total != rep.Total || got.Rules != 1 || len(got.Tactics) != len(rep.Tactics) {
		t.Fatalf("json = %#v", got)
	}
}
