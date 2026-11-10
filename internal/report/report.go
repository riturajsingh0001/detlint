// Package report renders findings in human and machine formats.
package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

// Sources stores file contents for snippet rendering.
type Sources struct {
	lines map[string][]string
}

// NewSources returns an empty source store.
func NewSources() *Sources {
	return &Sources{lines: map[string][]string{}}
}

// Add stores raw file contents.
func (s *Sources) Add(path string, data []byte) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	s.AddLines(path, strings.Split(text, "\n"))
}

// AddLines stores split lines.
func (s *Sources) AddLines(path string, lines []string) {
	if s.lines == nil {
		s.lines = map[string][]string{}
	}
	for _, key := range sourceKeys(path) {
		s.lines[key] = lines
	}
}

// Lines returns the lines for a path.
func (s *Sources) Lines(path string) []string {
	if s == nil {
		return nil
	}
	for _, key := range sourceKeys(path) {
		if l, ok := s.lines[key]; ok {
			return l
		}
	}
	return nil
}

func sourceKeys(path string) []string {
	keys := []string{path, filepath.ToSlash(filepath.Clean(path))}
	if abs, err := filepath.Abs(path); err == nil {
		keys = append(keys, filepath.ToSlash(filepath.Clean(abs)))
	}
	return keys
}

// Options controls report rendering.
type Options struct {
	Format  string
	Color   bool
	Version string
	Sources *Sources
}

// Write renders findings in the requested format.
func Write(w io.Writer, findings []analysis.Finding, opts Options) error {
	switch strings.ToLower(opts.Format) {
	case "", "pretty", "text":
		return WritePretty(w, findings, opts)
	case "json":
		return WriteJSON(w, findings, opts)
	case "sarif":
		return WriteSARIF(w, findings, opts)
	case "markdown", "md":
		return WriteMarkdown(w, findings, opts)
	default:
		return fmt.Errorf("unknown format %q (use pretty, json, sarif, or markdown)", opts.Format)
	}
}
