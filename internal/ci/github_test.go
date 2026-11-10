package ci

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

func TestIsGitHub(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	if !IsGitHub(env(map[string]string{"GITHUB_ACTIONS": "true"})) {
		t.Fatal("expected true")
	}
	if !IsGitHub(env(map[string]string{"GITHUB_ACTIONS": "TRUE"})) {
		t.Fatal("expected case-insensitive true")
	}
	if IsGitHub(env(map[string]string{"GITHUB_ACTIONS": "false"})) {
		t.Fatal("expected false")
	}
	if IsGitHub(env(nil)) {
		t.Fatal("expected false for empty env")
	}
}

func TestEscaping(t *testing.T) {
	if got := EscapeData("a%b\r\nc"); got != "a%25b%0D%0Ac" {
		t.Fatalf("EscapeData = %q", got)
	}
	if got := EscapeProp("a:b,c%d"); got != "a%3Ab%2Cc%25d" {
		t.Fatalf("EscapeProp = %q", got)
	}
}

func TestAnnotate(t *testing.T) {
	f := analysis.Finding{
		Pass: "typos", Severity: analysis.Error,
		File: "rules/a.yml", Line: 3, Col: 4, EndLine: 3, EndCol: 9,
		RuleTitle: "A Rule", Message: "bad\nthing", Help: "fix",
	}
	var buf bytes.Buffer
	Annotate(&buf, f)
	out := buf.String()
	for _, want := range []string{
		"::error ",
		"file=rules/a.yml",
		"line=3",
		"col=4",
		"endLine=3",
		"endColumn=9",
		"title=typos%3A A Rule",
		"::bad%0Athing%0Afix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestAnnotateLevels(t *testing.T) {
	cases := []struct {
		sev  analysis.Severity
		want string
	}{
		{analysis.Error, "::error "},
		{analysis.Warning, "::warning "},
		{analysis.Info, "::notice "},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		Annotate(&buf, analysis.Finding{Severity: tc.sev, Message: "m"})
		if !strings.HasPrefix(buf.String(), tc.want) {
			t.Errorf("%v = %q", tc.sev, buf.String())
		}
	}
}

func TestAnnotateAll(t *testing.T) {
	var buf bytes.Buffer
	AnnotateAll(&buf, []analysis.Finding{
		{Severity: analysis.Error, Message: "one"},
		{Severity: analysis.Warning, Message: "two"},
	})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestWriteStepSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.md")
	env := func(k string) string {
		if k == "GITHUB_STEP_SUMMARY" {
			return path
		}
		return ""
	}
	if err := WriteStepSummary(env, "hello\n"); err != nil {
		t.Fatal(err)
	}
	if err := WriteStepSummary(env, "world\n"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello\nworld\n" {
		t.Fatalf("summary = %q", data)
	}

	// No summary path is a no-op.
	if err := WriteStepSummary(func(string) string { return "" }, "x"); err != nil {
		t.Fatal(err)
	}
}

func TestChangedFilesOutsideGit(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if _, err := ChangedFiles(""); err == nil {
		t.Fatal("expected error outside a git repository")
	}
}
