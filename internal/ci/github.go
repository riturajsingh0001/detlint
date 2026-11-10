// Package ci integrates detlint with GitHub Actions.
package ci

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

// IsGitHub reports whether we are running inside GitHub Actions.
func IsGitHub(getenv func(string) string) bool {
	return strings.EqualFold(getenv("GITHUB_ACTIONS"), "true")
}

// EscapeData escapes a GitHub Actions workflow command message.
func EscapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// EscapeProp escapes a workflow command property.
func EscapeProp(s string) string {
	s = EscapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

// Annotate writes one GitHub Actions annotation.
func Annotate(w io.Writer, f analysis.Finding) {
	level := "notice"
	switch f.Severity {
	case analysis.Error:
		level = "error"
	case analysis.Warning:
		level = "warning"
	}
	var props []string
	if f.File != "" {
		props = append(props, "file="+EscapeProp(f.File))
	}
	if f.Line > 0 {
		props = append(props, fmt.Sprintf("line=%d", f.Line))
	}
	if f.Col > 0 {
		props = append(props, fmt.Sprintf("col=%d", f.Col))
	}
	if f.EndLine > 0 {
		props = append(props, fmt.Sprintf("endLine=%d", f.EndLine))
	}
	if f.EndCol > 0 {
		props = append(props, fmt.Sprintf("endColumn=%d", f.EndCol))
	}
	title := f.Pass
	if f.RuleTitle != "" {
		title += ": " + f.RuleTitle
	}
	props = append(props, "title="+EscapeProp(title))
	msg := f.Message
	if f.Help != "" {
		msg += "\n" + f.Help
	}
	fmt.Fprintf(w, "::%s %s::%s\n", level, strings.Join(props, ","), EscapeData(msg))
}

// AnnotateAll writes annotations for every finding.
func AnnotateAll(w io.Writer, findings []analysis.Finding) {
	for _, f := range findings {
		Annotate(w, f)
	}
}

// WriteStepSummary appends markdown to the GitHub step summary.
func WriteStepSummary(getenv func(string) string, markdown string) error {
	path := getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(markdown)
	return err
}
