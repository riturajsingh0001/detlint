package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

var update = flag.Bool("update", false, "update golden files")

func sampleFindings() []analysis.Finding {
	return []analysis.Finding{
		{
			Pass: "metadata", Severity: analysis.Warning,
			File: "rules/one.yml", Line: 1, Col: 1, EndLine: 1, EndCol: 6,
			RuleID: "one", RuleTitle: "One",
			Message: "rule has no level", Help: "Set level.",
		},
		{
			Pass: "typos", Severity: analysis.Error,
			File: "rules/two.yml", Line: 5, Col: 5, EndLine: 5, EndCol: 14,
			RuleID: "two", RuleTitle: "Two",
			Message: `unknown field "ComandLine" in selection "selection" (schema "windows_security"); did you mean "CommandLine"?`,
			Help:    `Did you mean "CommandLine"?`,
		},
		{
			Pass: "wildcard", Severity: analysis.Info,
			File: "rules/two.yml", Line: 14, Col: 3,
			RuleID: "two", RuleTitle: "Two",
			Message: "info only",
		},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run go test -run Golden -update): %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("output mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestGoldenOutputs(t *testing.T) {
	findings := sampleFindings()
	opts := Options{Version: "test", Color: false}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings, opts); err != nil {
		t.Fatal(err)
	}
	golden(t, "findings.json", buf.Bytes())

	buf.Reset()
	if err := WriteSARIF(&buf, findings, opts); err != nil {
		t.Fatal(err)
	}
	golden(t, "findings.sarif", buf.Bytes())

	buf.Reset()
	if err := WriteMarkdown(&buf, findings, opts); err != nil {
		t.Fatal(err)
	}
	golden(t, "findings.md", buf.Bytes())

	buf.Reset()
	src := NewSources()
	src.AddLines("rules/two.yml", []string{
		"title: Two",
		"",
		"detection:",
		"  selection:",
		`    ComandLine|contains: whoami`,
	})
	if err := WritePretty(&buf, findings, Options{Version: "test", Sources: src}); err != nil {
		t.Fatal(err)
	}
	golden(t, "findings.txt", buf.Bytes())
}

func TestWriteDispatch(t *testing.T) {
	var buf bytes.Buffer
	for _, format := range []string{"", "pretty", "text", "json", "sarif", "markdown", "md"} {
		if err := Write(&buf, nil, Options{Format: format}); err != nil {
			t.Errorf("Write(%q): %v", format, err)
		}
	}
	if err := Write(&buf, nil, Options{Format: "bogus"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestWritePrettyNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePretty(&buf, nil, Options{Version: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "detlint 1.2.3") || !strings.Contains(buf.String(), "no findings") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestWritePrettyColorAndSnippet(t *testing.T) {
	f := analysis.Finding{
		Pass: "typos", Severity: analysis.Error, File: "r.yml", Line: 1, Col: 3, EndLine: 1, EndCol: 6,
		Message: "bad", Help: "fix it",
	}
	src := NewSources()
	src.AddLines("r.yml", []string{"\tkey: value"})
	var buf bytes.Buffer
	if err := WritePretty(&buf, []analysis.Finding{f}, Options{Color: true, Sources: src}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"\x1b[", "help:", "fix it", "key: value", "^"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestSources(t *testing.T) {
	src := NewSources()
	src.Add("a.yml", []byte("one\r\ntwo\rthree\n"))
	if got := src.Lines("a.yml"); len(got) != 4 || got[0] != "one" || got[2] != "three" {
		t.Fatalf("lines = %#v", got)
	}
	if got := src.Lines(filepath.Join(".", "a.yml")); got == nil {
		t.Fatal("relative lookup failed")
	}
	if got := src.Lines("missing.yml"); got != nil {
		t.Fatalf("missing = %#v", got)
	}
	var nilSources *Sources
	if nilSources.Lines("a.yml") != nil {
		t.Fatal("nil sources should return nil")
	}
}

func TestWriteJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, nil, Options{}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tool     string             `json:"tool"`
		Version  string             `json:"version"`
		Findings []analysis.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "detlint" || got.Version != "dev" || got.Findings == nil {
		t.Fatalf("json = %#v", got)
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleFindings(), Options{Version: "9"}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine int `json:"startLine"`
							StartCol  int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "2.1.0" || len(got.Runs) != 1 {
		t.Fatalf("sarif = %#v", got)
	}
	run := got.Runs[0]
	if run.Tool.Driver.Name != "detlint" || run.Tool.Driver.Version != "9" {
		t.Fatalf("driver = %#v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d", len(run.Results))
	}
	levels := []string{"warning", "error", "note"}
	for i, r := range run.Results {
		if r.Level != levels[i] {
			t.Errorf("result %d level = %q", i, r.Level)
		}
		if r.PartialFingerprints["detlint/v1"] == "" {
			t.Errorf("result %d has no fingerprint", i)
		}
		if r.Locations[0].PhysicalLocation.Region.StartLine < 1 || r.Locations[0].PhysicalLocation.Region.StartCol < 1 {
			t.Errorf("result %d has invalid region", i)
		}
	}
}

func TestWriteSARIFBadRegion(t *testing.T) {
	f := analysis.Finding{Pass: "x", Severity: analysis.Info, File: "./r.yml", Line: 0, Col: 0, EndLine: 0, EndCol: 0}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, []analysis.Finding{f}, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"startLine": 1`) {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestWriteMarkdownNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, nil, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestWriteMarkdownEscaping(t *testing.T) {
	f := analysis.Finding{
		Pass: "x", Severity: analysis.Warning, File: "r.yml", Line: 1, Col: 1,
		RuleID: "id", Message: "a | b\nnext", Help: "help",
	}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, []analysis.Finding{f}, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `a \| b<br>next`) {
		t.Fatalf("output = %q", out)
	}
	if !strings.Contains(out, "WARN") || !strings.Contains(out, "`x`") {
		t.Fatalf("output = %q", out)
	}
}
