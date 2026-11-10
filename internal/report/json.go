package report

import (
	"encoding/json"
	"io"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

type jsonReport struct {
	Tool     string             `json:"tool"`
	Version  string             `json:"version"`
	Summary  analysis.Summary   `json:"summary"`
	Findings []analysis.Finding `json:"findings"`
}

// WriteJSON emits a stable machine-readable report.
func WriteJSON(w io.Writer, findings []analysis.Finding, opts Options) error {
	if findings == nil {
		findings = []analysis.Finding{}
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Tool:     "detlint",
		Version:  version,
		Summary:  analysis.Summarize(findings),
		Findings: findings,
	})
}
