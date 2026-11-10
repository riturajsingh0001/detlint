package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const ruleSrc = `title: Test Rule
id: test-rule
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection
`

func writeFile(t *testing.T, dir, name, content string) string {
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

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/rule.yml", ruleSrc)
	writeFile(t, dir, "b/rule.yaml", strings.ReplaceAll(ruleSrc, "test-rule", "second"))
	writeFile(t, dir, "notes.txt", "ignored")
	writeFile(t, dir, ".hidden/rule.yml", ruleSrc)

	res, err := LoadDir(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v", res.Errors)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(res.Files))
	}
	if len(res.Lines) != 2 {
		t.Fatalf("lines = %d", len(res.Lines))
	}
	for _, f := range res.Files {
		if f.Rule == nil {
			t.Fatalf("%s has no rule", f.Path)
		}
	}
}

func TestLoadSingleFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rule.yml", ruleSrc)
	res, err := LoadDir(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != p {
		t.Fatalf("files = %#v", res.Files)
	}
}

func TestLoadDirNoRules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "readme.md", "nothing")
	if _, err := LoadDir(dir, Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadDirMissing(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadDirParseError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yml", ruleSrc)
	bad := writeFile(t, dir, "bad.yml", "title: [\n")
	res, err := LoadDir(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || res.Errors[0].Path != bad {
		t.Fatalf("errors = %#v", res.Errors)
	}
	if len(res.Files) != 2 {
		// The parser returns a partial file even on error.
		t.Fatalf("files = %d", len(res.Files))
	}
}

func TestLoadChangedFilter(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yml", ruleSrc)
	writeFile(t, dir, "b.yml", strings.ReplaceAll(ruleSrc, "test-rule", "b"))
	abs, err := filepath.Abs(a)
	if err != nil {
		t.Fatal(err)
	}
	res, err := LoadDir(dir, Options{Changed: map[string]bool{
		filepath.ToSlash(abs): true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != a {
		t.Fatalf("files = %#v", res.Files)
	}
}

func TestLoadChangedNoMatches(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yml", ruleSrc)
	res, err := LoadDir(dir, Options{Changed: map[string]bool{"other.yml": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 || len(res.Errors) != 0 {
		t.Fatalf("result = %#v", res)
	}
}

func TestLoadFS(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/a.yml":       &fstest.MapFile{Data: []byte(ruleSrc)},
		"rules/sub/b.yaml":  &fstest.MapFile{Data: []byte(strings.ReplaceAll(ruleSrc, "test-rule", "b"))},
		"rules/.git/c.yaml": &fstest.MapFile{Data: []byte(ruleSrc)},
		"rules/readme.txt":  &fstest.MapFile{Data: []byte("x")},
	}
	res, err := LoadFS(fsys, "rules", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d", len(res.Files))
	}
}

func TestLoadFSNoRules(t *testing.T) {
	fsys := fstest.MapFS{"rules/readme.txt": &fstest.MapFile{Data: []byte("x")}}
	if _, err := LoadFS(fsys, "rules", Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadFSMissing(t *testing.T) {
	if _, err := LoadFS(fstest.MapFS{}, "nope", Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadFSFile(t *testing.T) {
	fsys := fstest.MapFS{"rule.yml": &fstest.MapFile{Data: []byte(ruleSrc)}}
	res, err := LoadFS(fsys, "rule.yml", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d", len(res.Files))
	}
}
