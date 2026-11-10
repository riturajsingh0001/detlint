package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

// SGR parameters only: colorize wraps them in the ESC[ ... m envelope, so
// attributes combine naturally with ";" (e.g. ansiRed+";"+ansiBold renders
// bold red). ansiReset is a complete sequence because it is used verbatim.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "1"
	ansiDim   = "2"
	ansiRed   = "31"
	ansiGreen = "32"
	ansiYell  = "33"
	ansiCyan  = "36"
)

func colorize(s, code string, enabled bool) string {
	if !enabled || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + ansiReset
}

// WritePretty prints a human-readable finding list with source snippets.
func WritePretty(w io.Writer, findings []analysis.Finding, opts Options) error {
	sum := analysis.Summarize(findings)
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	fmt.Fprintf(w, "%s %s", colorize("detlint", ansiBold, opts.Color), version)
	if sum.Total == 0 {
		fmt.Fprintf(w, " — %s\n", colorize("no findings", ansiGreen+";"+ansiBold, opts.Color))
		return nil
	}
	fmt.Fprintf(w, " — %d finding%s in %d rule%s", sum.Total, plural(sum.Total), sum.Rules, plural(sum.Rules))
	var parts []string
	if sum.Error > 0 {
		parts = append(parts, colorize(fmt.Sprintf("%d error%s", sum.Error, plural(sum.Error)), ansiRed+";"+ansiBold, opts.Color))
	}
	if sum.Warning > 0 {
		parts = append(parts, colorize(fmt.Sprintf("%d warning%s", sum.Warning, plural(sum.Warning)), ansiYell+";"+ansiBold, opts.Color))
	}
	if sum.Info > 0 {
		parts = append(parts, colorize(fmt.Sprintf("%d info", sum.Info), ansiCyan, opts.Color))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// Group by file for readability.
	byFile := map[string][]analysis.Finding{}
	var order []string
	for _, f := range findings {
		if _, ok := byFile[f.File]; !ok {
			order = append(order, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	sort.Strings(order)

	for _, file := range order {
		items := byFile[file]
		fmt.Fprintln(w, colorize(file, ansiBold, opts.Color))
		for _, f := range items {
			writeFinding(w, f, opts)
		}
	}
	return nil
}

func writeFinding(w io.Writer, f analysis.Finding, opts Options) {
	code := ansiCyan
	switch f.Severity {
	case analysis.Error:
		code = ansiRed
	case analysis.Warning:
		code = ansiYell
	}
	badge := fmt.Sprintf("%-5s", f.Severity.Label())
	fmt.Fprintf(w, "  %s %-14s %s:%d:%d\n",
		colorize(badge, code+";"+ansiBold, opts.Color),
		colorize(f.Pass, ansiDim, opts.Color),
		f.File, f.Line, f.Col)

	if f.RuleTitle != "" || f.RuleID != "" {
		name := f.RuleTitle
		if name == "" {
			name = f.RuleID
		} else if f.RuleID != "" {
			name += " (" + f.RuleID + ")"
		}
		fmt.Fprintf(w, "        %s\n", colorize("rule "+name, ansiDim, opts.Color))
	}
	fmt.Fprintf(w, "        %s\n", f.Message)

	if lines := opts.Sources.Lines(f.File); lines != nil && f.Line > 0 && f.Line <= len(lines) {
		writeSnippet(w, lines[f.Line-1], f, opts)
	}
	if f.Help != "" {
		fmt.Fprintf(w, "        %s %s\n", colorize("help:", ansiDim, opts.Color), f.Help)
	}
	fmt.Fprintln(w)
}

func writeSnippet(w io.Writer, line string, f analysis.Finding, opts Options) {
	expanded, col := expandTabs(line, f.Col)
	width := len(fmt.Sprintf("%d", f.Line))
	prefix := fmt.Sprintf("%*d | ", width, f.Line)
	fmt.Fprintf(w, "        %s%s\n", colorize(prefix, ansiDim, opts.Color), expanded)
	length := f.EndCol - f.Col
	if length < 1 {
		length = 1
	}
	if col-1+length > len(expanded) {
		length = len(expanded) - (col - 1)
	}
	if length < 1 {
		length = 1
	}
	caret := strings.Repeat(" ", col-1) + "^" + strings.Repeat("~", length-1)
	fmt.Fprintf(w, "        %s%s\n", colorize(strings.Repeat(" ", len(prefix)), ansiDim, opts.Color),
		colorize(caret, ansiRed, opts.Color))
}

func expandTabs(line string, col int) (string, int) {
	if !strings.Contains(line, "\t") {
		return line, col
	}
	var b strings.Builder
	visual := 1
	target := col
	for i := 0; i < len(line); i++ {
		if line[i] == '\t' {
			n := 4 - (visual-1)%4
			b.WriteString(strings.Repeat(" ", n))
			if i+1 < col {
				target += n - 1
			}
			visual += n
			continue
		}
		b.WriteByte(line[i])
		visual++
	}
	if target < 1 {
		target = 1
	}
	return b.String(), target
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
