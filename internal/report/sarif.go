package report

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription sarifText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// WriteSARIF emits SARIF 2.1.0 for GitHub code scanning.
func WriteSARIF(w io.Writer, findings []analysis.Finding, opts Options) error {
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	descriptions := map[string]string{}
	for _, p := range analysis.Passes() {
		descriptions[p.ID] = p.Description
	}

	index := map[string]int{}
	var rules []sarifRule
	for _, f := range findings {
		if _, ok := index[f.Pass]; ok {
			continue
		}
		index[f.Pass] = len(rules)
		rules = append(rules, sarifRule{
			ID:               f.Pass,
			Name:             f.Pass,
			ShortDescription: sarifText{Text: descriptions[f.Pass]},
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		level := "note"
		switch f.Severity {
		case analysis.Error:
			level = "error"
		case analysis.Warning:
			level = "warning"
		}
		startLine := f.Line
		if startLine < 1 {
			startLine = 1
		}
		startCol := f.Col
		if startCol < 1 {
			startCol = 1
		}
		endLine := f.EndLine
		if endLine < startLine {
			endLine = startLine
		}
		endCol := f.EndCol
		if endCol <= startCol {
			endCol = startCol + 1
		}
		msg := f.Message
		if f.Help != "" {
			msg += "\n" + f.Help
		}
		results = append(results, sarifResult{
			RuleID:    f.Pass,
			RuleIndex: index[f.Pass],
			Level:     level,
			Message:   sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(strings.TrimPrefix(f.File, "./"))},
					Region:           sarifRegion{StartLine: startLine, StartColumn: startCol, EndLine: endLine, EndColumn: endCol},
				},
			}},
			PartialFingerprints: map[string]string{"detlint/v1": f.Fingerprint()},
		})
	}

	out := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "detlint",
				Version:        version,
				InformationURI: "https://github.com/riturajsingh0001/detlint",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
