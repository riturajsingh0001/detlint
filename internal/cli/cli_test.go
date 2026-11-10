package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envEmpty(string) string { return "" }

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := RunWith(args, &stdout, &stderr, envEmpty)
	return code, stdout.String(), stderr.String()
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const cleanRule = `title: Clean Rule
id: clean-rule
status: stable
description: A clean rule.
author: tests
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image|endswith: '\powershell.exe'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
`

const typoRule = `title: Typo Rule
id: typo-rule
status: stable
description: A broken rule.
author: tests
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ComandLine|contains: whoami
  condition: selection
tags:
  - attack.execution
`

func TestHelpAndVersion(t *testing.T) {
	code, out, _ := run(t)
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Fatalf("help = %d %q", code, out)
	}
	code, out, _ = run(t, "help")
	if code != 0 || !strings.Contains(out, "detlint check") {
		t.Fatalf("help = %d %q", code, out)
	}
	code, out, _ = run(t, "version")
	if code != 0 || !strings.Contains(out, "detlint 0.1.0") {
		t.Fatalf("version = %d %q", code, out)
	}
	code, out, _ = run(t, "--version")
	if code != 0 || !strings.Contains(out, "detlint 0.1.0") {
		t.Fatalf("--version = %d %q", code, out)
	}
	code, out, _ = run(t, "version", "--short")
	if code != 0 || strings.TrimSpace(out) != Version {
		t.Fatalf("short = %d %q", code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errOut := run(t, "nope")
	if code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestCheckClean(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	code, out, errOut := run(t, "check", rule, "--color", "never")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q, stdout = %q", code, errOut, out)
	}
	if !strings.Contains(out, "no findings") {
		t.Fatalf("output = %q", out)
	}
}

func TestCheckFindsErrors(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "typo.yml", typoRule)
	code, out, _ := run(t, "check", rule, "--color", "never")
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "ERROR") || !strings.Contains(out, "ComandLine") {
		t.Fatalf("output = %q", out)
	}
}

func TestCheckFailOnNever(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "typo.yml", typoRule)
	code, _, _ := run(t, "check", rule, "--fail-on", "never", "--quiet")
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
}

func TestCheckQuiet(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "typo.yml", typoRule)
	code, out, _ := run(t, "check", rule, "--quiet")
	if code != 1 || out != "" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

// --quiet only silences human-readable output; machine formats are documents
// scripts consume and must still be written.
func TestCheckQuietKeepsMachineFormats(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "typo.yml", typoRule)
	for _, format := range []string{"json", "sarif", "markdown"} {
		code, out, _ := run(t, "check", rule, "--format", format, "--quiet")
		if code != 1 {
			t.Errorf("%s: code = %d", format, code)
		}
		if out == "" {
			t.Errorf("%s: --quiet swallowed the %s document", format, format)
		}
	}
	// Quiet human formats still emit nothing.
	for _, format := range []string{"pretty", "text", ""} {
		code, out, _ := run(t, "check", rule, "--format", format, "--quiet")
		if code != 1 || out != "" {
			t.Errorf("%s: code=%d out=%q", format, code, out)
		}
	}
	// A bad format must still be rejected even when quiet.
	if code, _, _ := run(t, "check", rule, "--format", "bogus", "--quiet"); code != 2 {
		t.Errorf("bad format with --quiet = %d, want 2", code)
	}
}

func TestCheckJSON(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "typo.yml", typoRule)
	code, out, _ := run(t, "check", rule, "--format", "json")
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	var got struct {
		Tool    string `json:"tool"`
		Summary struct {
			Total int `json:"total"`
			Error int `json:"error"`
		} `json:"summary"`
		Findings []struct {
			Pass string `json:"pass"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got.Tool != "detlint" || got.Summary.Error == 0 || len(got.Findings) == 0 {
		t.Fatalf("json = %#v", got)
	}
}

func TestCheckSARIFAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "typo.yml", typoRule)
	code, out, _ := run(t, "check", rule, "--format", "sarif")
	if code != 1 || !strings.Contains(out, `"version": "2.1.0"`) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	code, out, _ = run(t, "check", rule, "--format", "markdown")
	if code != 1 || !strings.Contains(out, "## detlint report") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestCheckFlagOrder(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	for _, args := range [][]string{
		{"check", "--format", "json", rule},
		{"check", rule, "--format", "json"},
		{"--format", "json", "check", rule},
	} {
		code, out, _ := run(t, args...)
		if code != 0 || !strings.Contains(out, `"tool": "detlint"`) {
			t.Fatalf("%v = %d %q", args, code, out)
		}
	}
}

func TestCheckListPasses(t *testing.T) {
	code, out, _ := run(t, "check", "--list-passes")
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	for _, pass := range []string{"metadata", "dupkeys", "typos", "unreachable", "contradiction", "escaping", "wildcard"} {
		if !strings.Contains(out, pass) {
			t.Errorf("missing %q in %q", pass, out)
		}
	}
}

func TestCheckErrors(t *testing.T) {
	if code, _, errOut := run(t, "check", "--bogus"); code != 2 || !strings.Contains(errOut, "unknown flag") {
		t.Fatalf("unknown flag: %d %q", code, errOut)
	}
	if code, _, _ := run(t, "check", filepath.Join(t.TempDir(), "missing")); code != 2 {
		t.Fatalf("missing path = %d", code)
	}
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	if code, _, errOut := run(t, "check", rule, "--fail-on", "bogus"); code != 2 || !strings.Contains(errOut, "invalid severity") {
		t.Fatalf("bad fail-on = %d %q", code, errOut)
	}
	if code, _, _ := run(t, "check", rule, "--format", "bogus"); code != 2 {
		t.Fatalf("bad format = %d", code)
	}
}

func TestCheckHelp(t *testing.T) {
	if code, _, _ := run(t, "check", "-h"); code != 0 {
		t.Fatalf("code = %d", code)
	}
}

func TestTestCommand(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "rules/clean.yml", cleanRule)
	pos := write(t, dir, "pos/hit.jsonl", `{"EventID":4688,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}`+"\n")
	neg := write(t, dir, "neg/miss.jsonl", `{"EventID":4624}`+"\n")
	_ = pos
	code, out, errOut := run(t, "test", filepath.Dir(rule), "--pos", filepath.Dir(pos), "--neg", filepath.Dir(neg), "--color", "never")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q, stdout = %q", code, errOut, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Fatalf("output = %q", out)
	}

	// JSON output.
	code, out, _ = run(t, "test", filepath.Dir(rule), "--pos", filepath.Dir(pos), "--format", "json")
	if code != 0 {
		t.Fatalf("json code = %d", code)
	}
	var got struct {
		Results []struct {
			TP int `json:"tp"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Results) != 1 || got.Results[0].TP != 1 {
		t.Fatalf("json = %#v, %v\n%s", got, err, out)
	}
}

func TestTestCommandFailures(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "rules/clean.yml", cleanRule)
	pos := write(t, dir, "pos/hit.jsonl", `{"EventID":4688,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}`+"\n")
	if code, _, _ := run(t, "test", filepath.Dir(rule)); code != 2 {
		t.Fatalf("missing samples = %d", code)
	}
	// One positive sample, but the rule does not match it.
	badPos := write(t, dir, "badpos/miss.jsonl", `{"EventID":4624}`+"\n")
	if code, out, _ := run(t, "test", filepath.Dir(rule), "--pos", filepath.Dir(badPos), "--color", "never"); code != 1 || !strings.Contains(out, "FAIL") {
		t.Fatalf("threshold = %d %q", code, out)
	}
	// No samples for the rule, but --require-samples turns that into a failure.
	if code, _, errOut := run(t, "test", filepath.Dir(rule), "--pos", filepath.Join(dir, "empty"), "--require-samples"); code != 2 {
		t.Fatalf("missing sample dir = %d %q", code, errOut)
	}
	empty := t.TempDir()
	code, _, errOut := run(t, "test", filepath.Dir(rule), "--pos", empty, "--require-samples")
	if code != 1 || !strings.Contains(errOut, "has no samples") {
		t.Fatalf("require samples = %d %q", code, errOut)
	}
	_ = pos
}

func TestNoiseCommand(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "rules/clean.yml", cleanRule)
	logs := write(t, dir, "logs/day.jsonl",
		`{"EventID":4688,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}`+"\n"+
			`{"EventID":4688,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}`+"\n"+
			`{"EventID":4624}`+"\n")
	code, out, errOut := run(t, "noise", filepath.Dir(rule), "--logs", logs, "--max", "1", "--color", "never")
	if code != 1 {
		t.Fatalf("code = %d, stderr = %q, stdout = %q", code, errOut, out)
	}
	if !strings.Contains(out, "records scanned: 3") || !strings.Contains(out, "NOISY") {
		t.Fatalf("output = %q", out)
	}

	code, out, _ = run(t, "noise", filepath.Dir(rule), "--logs", logs, "--format", "json", "--top", "1")
	if code != 0 {
		t.Fatalf("json code = %d", code)
	}
	var got struct {
		Total int `json:"total"`
		Hits  []struct {
			Count int `json:"count"`
		} `json:"hits"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Total != 3 || len(got.Hits) != 1 || got.Hits[0].Count != 2 {
		t.Fatalf("json = %#v, %v\n%s", got, err, out)
	}
}

func TestNoiseErrors(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "rules/clean.yml", cleanRule)
	if code, _, _ := run(t, "noise", filepath.Dir(rule)); code != 2 {
		t.Fatal("missing --logs should fail")
	}
	empty := write(t, dir, "logs/empty.jsonl", "\n")
	if code, _, errOut := run(t, "noise", filepath.Dir(rule), "--logs", empty); code != 2 || !strings.Contains(errOut, "no records") {
		t.Fatalf("empty logs = %d %q", code, errOut)
	}
	if code, _, _ := run(t, "noise", filepath.Dir(rule), "--logs", filepath.Join(dir, "missing")); code != 2 {
		t.Fatal("missing logs should fail")
	}
}

func TestMapCommand(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	code, out, _ := run(t, "map", rule, "--color", "never")
	if code != 0 || !strings.Contains(out, "ATT&CK coverage:") || !strings.Contains(out, "Execution") {
		t.Fatalf("code=%d out=%q", code, out)
	}

	code, out, _ = run(t, "map", rule, "--format", "json")
	if code != 0 {
		t.Fatalf("json code = %d", code)
	}
	var got struct {
		Covered int `json:"covered"`
		Total   int `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Covered != 1 || got.Total == 0 {
		t.Fatalf("json = %#v, %v", got, err)
	}

	if code, _, _ := run(t, "map", rule, "--tactic", "execution", "--quiet"); code != 0 {
		t.Fatal("tactic filter failed")
	}
	if code, _, errOut := run(t, "map", rule, "--tactic", "nope"); code != 2 || !strings.Contains(errOut, "unknown tactic") {
		t.Fatalf("unknown tactic = %d %q", code, errOut)
	}
	if code, _, _ := run(t, "map", rule, "--min-coverage", "100", "--quiet"); code != 1 {
		t.Fatalf("min coverage = %d", code)
	}
}

func TestSchemaCommand(t *testing.T) {
	code, out, _ := run(t, "schema", "list")
	if code != 0 || !strings.Contains(out, "windows_security") {
		t.Fatalf("list = %d %q", code, out)
	}
	if code, _, _ := run(t, "schema"); code != 2 {
		t.Fatal("missing schema subcommand should fail")
	}
	if code, _, _ := run(t, "schema", "nope"); code != 2 {
		t.Fatal("unknown schema subcommand should fail")
	}
	if code, _, _ := run(t, "schema", "help"); code != 0 {
		t.Fatal("schema help should succeed")
	}

	dir := t.TempDir()
	sample := write(t, dir, "sample.jsonl", `{"EventID":4688,"User":"alice"}`+"\n")
	code, out, _ = run(t, "schema", "learn", sample, "--name", "learned", "--product", "windows")
	if code != 0 || !strings.Contains(out, "name: learned") || !strings.Contains(out, "EventID") {
		t.Fatalf("learn = %d %q", code, out)
	}
	outFile := filepath.Join(dir, "learned.yaml")
	code, _, errOut := run(t, "schema", "learn", sample, "-o", outFile)
	if code != 0 || !strings.Contains(errOut, "wrote") {
		t.Fatalf("learn -o = %d %q", code, errOut)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, "schema", "learn"); code != 2 {
		t.Fatal("learn without samples should fail")
	}
	empty := write(t, dir, "empty.jsonl", "\n")
	if code, _, errOut := run(t, "schema", "learn", empty); code != 2 || !strings.Contains(errOut, "no sample records") {
		t.Fatalf("empty learn = %d %q", code, errOut)
	}
}

func TestDemo(t *testing.T) {
	code, out, errOut := run(t, "demo", "--color", "never")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut)
	}
	for _, want := range []string{"detlint demo", "detlint check rules/", "detlint test rules/", "detlint noise rules/", "detlint map rules/", "demo summary"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if code, _, _ := run(t, "demo", "--fail", "--color", "never"); code != 1 {
		t.Fatalf("demo --fail = %d", code)
	}
}

func TestOtherCommandsFailOnParseErrors(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	write(t, dir, "rules/clean.yml", cleanRule)
	write(t, dir, "rules/bad.yml", "title: [\n")
	pos := write(t, dir, "pos/hit.jsonl", `{"EventID":4688,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}`+"\n")
	logs := write(t, dir, "logs/day.jsonl", `{"EventID":4688,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}`+"\n")

	if code, _, _ := run(t, "test", rules, "--pos", filepath.Dir(pos), "--quiet"); code != 1 {
		t.Fatalf("test with parse errors = %d", code)
	}
	if code, _, _ := run(t, "noise", rules, "--logs", logs, "--quiet"); code != 1 {
		t.Fatalf("noise with parse errors = %d", code)
	}
	if code, _, _ := run(t, "map", rules, "--quiet"); code != 1 {
		t.Fatalf("map with parse errors = %d", code)
	}
}

func TestChangedOutsideGit(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if code, _, _ := run(t, "check", rule, "--changed"); code != 2 {
		t.Fatalf("changed = %d", code)
	}
}

func TestDoubleDash(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	code, out, _ := run(t, "check", "--", rule, "--color", "never")
	// Flags after -- are positional, so "--color" is treated as a path and
	// loading fails; this at least proves -- is honored.
	if code == 0 {
		t.Fatalf("expected failure, out = %q", out)
	}
}

func TestReorderArgs(t *testing.T) {
	dir := t.TempDir()
	rule := write(t, dir, "clean.yml", cleanRule)
	fs := newFlagSet("t", &environment{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}})
	var g Globals
	addGlobals(fs, &g)
	reordered, err := reorderArgs(fs, []string{rule, "--format", "json", "--quiet", "extra"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--format", "json", "--quiet", rule, "extra"}
	if strings.Join(reordered, " ") != strings.Join(want, " ") {
		t.Fatalf("reordered = %v, want %v", reordered, want)
	}
	if _, err := reorderArgs(fs, []string{"--bogus"}); err == nil {
		t.Fatal("expected unknown flag error")
	}
	if _, err := reorderArgs(fs, []string{"--format"}); err == nil {
		t.Fatal("expected missing value error")
	}
}

func TestGlobalTakesValue(t *testing.T) {
	for _, name := range []string{"--format", "-format", "--fail-on", "--color", "--schema", "--base"} {
		if !globalTakesValue(name) {
			t.Errorf("%s should take a value", name)
		}
	}
	for _, name := range []string{"--quiet", "--ci", "--changed", "--version"} {
		if globalTakesValue(name) {
			t.Errorf("%s should not take a value", name)
		}
	}
}
