package coverage

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Options controls pretty output.
type Options struct {
	Color bool
	// ShowMissing limits how many missing technique IDs are printed per tactic.
	ShowMissing int
}

// WritePretty prints the coverage matrix.
func WritePretty(w io.Writer, r *Report, opts Options) error {
	fmt.Fprintf(w, "ATT&CK coverage: %s\n\n", r.String())
	fmt.Fprintln(w, "tactic                        covered  bar         gaps")
	fmt.Fprintln(w, "-------------------------------------------------------------------------------")
	for _, t := range r.Tactics {
		pct := 0.0
		if t.Total > 0 {
			pct = float64(t.Covered) / float64(t.Total)
		}
		bar := strings.Repeat("#", int(pct*10)) + strings.Repeat(".", 10-int(pct*10))
		var gaps []string
		for _, tech := range t.Techniques {
			if len(tech.Rules) == 0 {
				gaps = append(gaps, tech.ID)
			}
		}
		limit := opts.ShowMissing
		if limit <= 0 {
			limit = 6
		}
		gapText := "-"
		if len(gaps) > 0 {
			if len(gaps) > limit {
				gapText = strings.Join(gaps[:limit], ", ") + fmt.Sprintf(" +%d", len(gaps)-limit)
			} else {
				gapText = strings.Join(gaps, ", ")
			}
		}
		line := fmt.Sprintf("%-28s %3d/%-3d  [%s]  %s", t.Name, t.Covered, t.Total, bar, gapText)
		if opts.Color && len(gaps) > 0 {
			line = "\x1b[33m" + line + "\x1b[0m"
		}
		fmt.Fprintln(w, line)
	}
	if len(r.UnknownTags) > 0 {
		fmt.Fprintf(w, "\nunknown ATT&CK tags: %s\n", strings.Join(r.UnknownTags, ", "))
	}
	if len(r.Untagged) > 0 {
		fmt.Fprintf(w, "untagged rules: %d\n", len(r.Untagged))
		limit := 8
		for i, name := range r.Untagged {
			if i >= limit {
				fmt.Fprintf(w, "  ... and %d more\n", len(r.Untagged)-limit)
				break
			}
			fmt.Fprintf(w, "  - %s\n", name)
		}
	}
	return nil
}

// WriteJSON emits the coverage report as JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
