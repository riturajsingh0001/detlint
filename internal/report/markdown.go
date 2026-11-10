package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

// WriteMarkdown emits a pull-request comment.
func WriteMarkdown(w io.Writer, findings []analysis.Finding, opts Options) error {
	sum := analysis.Summarize(findings)
	fmt.Fprintln(w, "## detlint report")
	fmt.Fprintln(w)
	if sum.Total == 0 {
		fmt.Fprintln(w, "No findings. Rules look clean.")
		return nil
	}
	fmt.Fprintf(w, "**%d error%s**, %d warning%s, %d info across %d rule file%s.\n\n",
		sum.Error, plural(sum.Error), sum.Warning, plural(sum.Warning), sum.Info, sum.Rules, plural(sum.Rules))
	fmt.Fprintln(w, "| Severity | Check | Location | Rule | Finding |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, f := range findings {
		rule := f.RuleTitle
		if rule == "" {
			rule = f.RuleID
		}
		msg := f.Message
		if f.Help != "" {
			msg += " _(" + f.Help + ")_"
		}
		fmt.Fprintf(w, "| %s | `%s` | `%s:%d:%d` | %s | %s |\n",
			f.Severity.Label(), f.Pass, f.File, f.Line, f.Col,
			mdEscape(rule), mdEscape(msg))
	}
	return nil
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
}
