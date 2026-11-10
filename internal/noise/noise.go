// Package noise counts rule hits over a log file.
package noise

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/rule"
)

// Hit is the hit count for one rule.
type Hit struct {
	Rule  *rule.Rule
	File  string
	Count int
	Total int
	Rate  float64
}

// Analyze counts hits for every rule.
func Analyze(files []*rule.File, records []eval.Record) []Hit {
	total := len(records)
	var out []Hit
	for _, f := range files {
		if f.Rule == nil {
			continue
		}
		n := eval.CountHits(f.Rule, records)
		rate := 0.0
		if total > 0 {
			rate = float64(n) / float64(total)
		}
		out = append(out, Hit{Rule: f.Rule, File: f.Path, Count: n, Total: total, Rate: rate})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].File < out[j].File
	})
	return out
}

// Options controls pretty output.
type Options struct {
	Top   int
	Max   int
	Color bool
}

// WritePretty prints the hit table.
func WritePretty(w io.Writer, hits []Hit, opts Options) error {
	if len(hits) == 0 {
		fmt.Fprintln(w, "no rules to evaluate")
		return nil
	}
	total := hits[0].Total
	fmt.Fprintf(w, "records scanned: %d\n\n", total)
	fmt.Fprintln(w, "   count    rate  rule")
	fmt.Fprintln(w, "------------------------")
	shown := 0
	for _, h := range hits {
		if opts.Top > 0 && shown >= opts.Top {
			break
		}
		shown++
		name := h.Rule.Title
		if name == "" {
			name = h.File
		}
		line := fmt.Sprintf("%8d  %5.1f%%  %s", h.Count, h.Rate*100, name)
		if opts.Max > 0 && h.Count > opts.Max {
			line += "  NOISY"
			if opts.Color {
				line = "\x1b[31m" + line + "\x1b[0m"
			}
		}
		fmt.Fprintln(w, line)
		fmt.Fprintf(w, "                  %s:%d\n", h.File, h.Rule.Detection.ConditionSpan.Line)
	}
	return nil
}

// WriteJSON emits hit counts as JSON.
func WriteJSON(w io.Writer, hits []Hit, opts Options) error {
	type row struct {
		File  string  `json:"file"`
		Rule  string  `json:"rule_id,omitempty"`
		Title string  `json:"title,omitempty"`
		Count int     `json:"count"`
		Total int     `json:"total"`
		Rate  float64 `json:"rate"`
		Noisy bool    `json:"noisy"`
	}
	out := struct {
		Total int   `json:"total"`
		Hits  []row `json:"hits"`
	}{}
	if len(hits) > 0 {
		out.Total = hits[0].Total
	}
	for i, h := range hits {
		if opts.Top > 0 && i >= opts.Top {
			break
		}
		out.Hits = append(out.Hits, row{
			File: h.File, Rule: h.Rule.ID, Title: h.Rule.Title,
			Count: h.Count, Total: h.Total, Rate: h.Rate,
			Noisy: opts.Max > 0 && h.Count > opts.Max,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Exceeded reports whether any rule exceeds the max hit threshold.
func Exceeded(hits []Hit, max int) bool {
	if max <= 0 {
		return false
	}
	for _, h := range hits {
		if h.Count > max {
			return true
		}
	}
	return false
}
