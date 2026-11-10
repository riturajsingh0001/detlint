// Package exitcode defines detlint's process exit codes.
package exitcode

import "github.com/riturajsingh0001/detlint/internal/analysis"

const (
	// Clean means no findings at or above the fail threshold.
	Clean = 0
	// Findings means at least one finding met the fail threshold.
	Findings = 1
	// ToolErr means detlint itself failed (bad flags, unreadable files, ...).
	ToolErr = 2
)

// FromFindings maps findings and a fail-on threshold to an exit code.
func FromFindings(findings []analysis.Finding, failOn analysis.Severity) int {
	if failOn >= 99 {
		return Clean
	}
	for _, f := range findings {
		if f.Severity >= failOn {
			return Findings
		}
	}
	return Clean
}

// FromSeverity maps a single severity to an exit code.
func FromSeverity(sev, failOn analysis.Severity) int {
	if failOn >= 99 {
		return Clean
	}
	if sev >= failOn {
		return Findings
	}
	return Clean
}
