package samples

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/rule/condition"
)

// Set is a sample directory. Files directly in the directory apply to every
// rule; files in a subdirectory apply only to the rule whose id, title slug,
// or file stem matches the subdirectory name.
type Set struct {
	Global []eval.Record
	ByRule map[string][]eval.Record
}

// LoadSet reads a sample directory or a single sample file.
func LoadSet(root string) (*Set, error) {
	if root == "" {
		return &Set{ByRule: map[string][]eval.Record{}}, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		recs, err := eval.DecodeFile(root)
		if err != nil {
			return nil, err
		}
		return &Set{Global: recs, ByRule: map[string][]eval.Record{}}, nil
	}
	return LoadSetFS(os.DirFS(root), ".")
}

// LoadSetFS reads a sample tree from any fs.FS.
func LoadSetFS(fsys fs.FS, root string) (*Set, error) {
	s := &Set{ByRule: map[string][]eval.Record{}}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".json", ".jsonl", ".ndjson", ".log", ".txt":
		default:
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		recs, err := eval.Decode(data, p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(filepath.ToSlash(p), filepath.ToSlash(root))
		rel = strings.TrimPrefix(rel, "/")
		parts := strings.Split(rel, "/")
		if len(parts) <= 1 {
			s.Global = append(s.Global, recs...)
			return nil
		}
		key := slug(parts[0])
		s.ByRule[key] = append(s.ByRule[key], recs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ForRule returns global samples plus samples in the rule's subdirectory.
func (s *Set) ForRule(r *rule.Rule, file string) []eval.Record {
	if s == nil {
		return nil
	}
	out := append([]eval.Record(nil), s.Global...)
	seen := map[string]bool{}
	for _, sel := range ruleSelectors(r, file) {
		if seen[sel] {
			continue
		}
		seen[sel] = true
		out = append(out, s.ByRule[sel]...)
	}
	return out
}

func ruleSelectors(r *rule.Rule, file string) []string {
	var out []string
	if r != nil {
		if r.ID != "" {
			out = append(out, slug(r.ID))
		}
		if r.Title != "" {
			out = append(out, slug(r.Title))
		}
	}
	if file != "" {
		base := filepath.Base(file)
		out = append(out, slug(strings.TrimSuffix(base, filepath.Ext(base))))
	}
	return out
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

// Result is the per-rule precision/recall report.
type Result struct {
	Rule      *rule.Rule
	File      string
	Pos       int
	Neg       int
	TP        int
	FP        int
	FN        int
	TN        int
	Precision float64
	Recall    float64
	Skipped   string
}

// Evaluate runs every rule against shared sample sets.
func Evaluate(files []*rule.File, pos, neg []eval.Record) []Result {
	return evaluate(files, func(*rule.Rule, string) []eval.Record { return pos },
		func(*rule.Rule, string) []eval.Record { return neg })
}

// EvaluateSets runs every rule against its own positive/negative sample sets.
func EvaluateSets(files []*rule.File, pos, neg *Set) []Result {
	return evaluate(files, pos.ForRule, neg.ForRule)
}

func evaluate(files []*rule.File, posFor, negFor func(*rule.Rule, string) []eval.Record) []Result {
	var out []Result
	for _, f := range files {
		r := f.Rule
		if r == nil {
			continue
		}
		pos := posFor(r, f.Path)
		neg := negFor(r, f.Path)
		res := Result{Rule: r, File: f.Path, Pos: len(pos), Neg: len(neg)}
		if _, ok := r.Detection.Condition.(*condition.Agg); ok {
			res.Skipped = "aggregation conditions are evaluated over a batch"
			out = append(out, res)
			continue
		}
		for _, rec := range pos {
			if eval.MatchRule(r, rec) {
				res.TP++
			} else {
				res.FN++
			}
		}
		for _, rec := range neg {
			if eval.MatchRule(r, rec) {
				res.FP++
			} else {
				res.TN++
			}
		}
		res.Precision = ratio(res.TP, res.TP+res.FP)
		res.Recall = ratio(res.TP, res.TP+res.FN)
		out = append(out, res)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

// Pass reports whether a result meets the thresholds.
func (r Result) Pass(minPrecision, minRecall float64) bool {
	if r.Skipped != "" {
		return true
	}
	return r.Precision+1e-9 >= minPrecision && r.Recall+1e-9 >= minRecall
}

// Failed reports whether any rule missed the thresholds.
func Failed(results []Result, minPrecision, minRecall float64) bool {
	for _, r := range results {
		if !r.Pass(minPrecision, minRecall) {
			return true
		}
	}
	return false
}

// Options controls pretty output.
type Options struct {
	Color        bool
	MinPrecision float64
	MinRecall    float64
}

// WritePretty prints a precision/recall table.
func WritePretty(w io.Writer, results []Result, opts Options) error {
	fmt.Fprintln(w, "rule                                         pos  neg   tp   fp   fn   tn  prec  rec  status")
	fmt.Fprintln(w, "-------------------------------------------------------------------------------------------")
	for _, r := range results {
		status := "PASS"
		if r.Skipped != "" {
			status = "SKIP"
		} else if !r.Pass(opts.MinPrecision, opts.MinRecall) {
			status = "FAIL"
		}
		name := r.Rule.Title
		if name == "" {
			name = r.File
		}
		if len(name) > 42 {
			name = name[:39] + "..."
		}
		line := fmt.Sprintf("%-44s %3d  %3d  %3d  %3d  %3d  %3d  %.2f  %.2f  %s",
			name, r.Pos, r.Neg, r.TP, r.FP, r.FN, r.TN, r.Precision, r.Recall, status)
		if opts.Color {
			switch status {
			case "FAIL":
				line = color(line, "31")
			case "PASS":
				line = color(line, "32")
			default:
				line = color(line, "33")
			}
		}
		fmt.Fprintln(w, line)
		if r.Skipped != "" {
			fmt.Fprintf(w, "    note: %s\n", r.Skipped)
		}
	}
	return nil
}

// WriteJSON emits the sample report as JSON.
func WriteJSON(w io.Writer, results []Result) error {
	type row struct {
		File      string  `json:"file"`
		RuleID    string  `json:"rule_id,omitempty"`
		Title     string  `json:"title,omitempty"`
		Pos       int     `json:"pos"`
		Neg       int     `json:"neg"`
		TP        int     `json:"tp"`
		FP        int     `json:"fp"`
		FN        int     `json:"fn"`
		TN        int     `json:"tn"`
		Precision float64 `json:"precision"`
		Recall    float64 `json:"recall"`
		Skipped   string  `json:"skipped,omitempty"`
	}
	out := struct {
		Results []row `json:"results"`
	}{}
	for _, r := range results {
		out.Results = append(out.Results, row{
			File: r.File, RuleID: r.Rule.ID, Title: r.Rule.Title,
			Pos: r.Pos, Neg: r.Neg, TP: r.TP, FP: r.FP, FN: r.FN, TN: r.TN,
			Precision: r.Precision, Recall: r.Recall, Skipped: r.Skipped,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func color(s, code string) string {
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
