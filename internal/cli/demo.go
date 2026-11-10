package cli

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
	"github.com/riturajsingh0001/detlint/internal/coverage"
	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/exitcode"
	"github.com/riturajsingh0001/detlint/internal/loader"
	"github.com/riturajsingh0001/detlint/internal/noise"
	"github.com/riturajsingh0001/detlint/internal/report"
	"github.com/riturajsingh0001/detlint/internal/samples"
	"github.com/riturajsingh0001/detlint/internal/schema"
)

//go:embed demo_repo
var demoFS embed.FS

func runDemo(args []string, e *environment) int {
	fsx := newFlagSet("demo", e)
	var g Globals
	addGlobals(fsx, &g)
	fail := fsx.Bool("fail", false, "exit non-zero when the demo repo has problems")
	fsx.Usage = func() {
		fmt.Fprintln(e.stderr, "usage: detlint demo [flags]")
		fsx.PrintDefaults()
	}
	if help, err := parseFlags(fsx, args); err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	} else if help {
		return exitcode.Clean
	}

	col := useColor(g.Color, e.stdout)
	fmt.Fprintln(e.stdout, colorDemo("detlint demo", "1;36", col))
	fmt.Fprintln(e.stdout, "A detection-rule repo with real mistakes. One command, four checks.")
	fmt.Fprintln(e.stdout)

	schemas := schema.Default()
	res, err := loader.LoadFS(demoFS, "demo_repo/rules", loader.Options{})
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: demo: %v\n", err)
		return exitcode.ToolErr
	}
	findings := parseFindings(res)
	for _, f := range res.Files {
		findings = append(findings, analysis.Run(f, schemas)...)
	}
	analysis.Sort(findings)
	src := sourcesFrom(res)

	section(e, 1, "detlint check rules/", col)
	_ = report.WritePretty(e.stdout, findings, report.Options{
		Format: "pretty", Color: col, Version: Version, Sources: src,
	})
	sum := analysis.Summarize(findings)

	section(e, 2, "detlint test rules/ --pos samples/pos --neg samples/neg", col)
	pos, err := samples.LoadSetFS(demoFS, "demo_repo/samples/pos")
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: demo samples: %v\n", err)
		return exitcode.ToolErr
	}
	neg, err := samples.LoadSetFS(demoFS, "demo_repo/samples/neg")
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: demo samples: %v\n", err)
		return exitcode.ToolErr
	}
	results := samples.EvaluateSets(res.Files, pos, neg)
	_ = samples.WritePretty(e.stdout, results, samples.Options{
		Color: col, MinPrecision: 0.9, MinRecall: 0.9,
	})
	failedRules := 0
	for _, r := range results {
		if !r.Pass(0.9, 0.9) {
			failedRules++
		}
	}
	fmt.Fprintf(e.stdout, "\n%d of %d rules miss the 0.90 precision/recall bar.\n", failedRules, len(results))

	section(e, 3, "detlint noise rules/ --logs logs/yesterday.jsonl --max 20", col)
	logs, err := decodeFS(demoFS, "demo_repo/logs")
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: demo logs: %v\n", err)
		return exitcode.ToolErr
	}
	hits := noise.Analyze(res.Files, logs)
	_ = noise.WritePretty(e.stdout, hits, noise.Options{Top: 8, Max: 20, Color: col})
	noisy := 0
	for _, h := range hits {
		if h.Count > 20 {
			noisy++
		}
	}
	fmt.Fprintf(e.stdout, "\n%d rules exceed 20 hits on an ordinary day.\n", noisy)

	section(e, 4, "detlint map rules/", col)
	rep := coverage.Analyze(res.Files, coverage.Default())
	_ = coverage.WritePretty(e.stdout, rep, coverage.Options{Color: col, ShowMissing: 4})

	fmt.Fprintln(e.stdout)
	fmt.Fprintln(e.stdout, colorDemo("demo summary", "1;36", col))
	fmt.Fprintf(e.stdout, "  %d findings (%d errors), %d rules below sample thresholds, %d noisy rules\n",
		sum.Total, sum.Error, failedRules, noisy)
	fmt.Fprintf(e.stdout, "  ATT&CK coverage: %s\n", rep.String())
	fmt.Fprintln(e.stdout, "  exit status: 1 when run with --fail, 0 otherwise")

	if *fail && (sum.Total > 0 || failedRules > 0 || noisy > 0) {
		return exitcode.Findings
	}
	return exitcode.Clean
}

func section(e *environment, n int, title string, color bool) {
	fmt.Fprintln(e.stdout)
	line := fmt.Sprintf("[%d/4] %s", n, title)
	fmt.Fprintln(e.stdout, colorDemo(line, "1;33", color))
	fmt.Fprintln(e.stdout, colorDemo(strings.Repeat("-", len(line)), "2", color))
}

func colorDemo(s, code string, enabled bool) string {
	if !enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func decodeFS(fsys fs.FS, root string) ([]eval.Record, error) {
	var records []eval.Record
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(pathExt(p)) {
		case ".json", ".jsonl", ".ndjson", ".log", ".txt":
			data, err := fs.ReadFile(fsys, p)
			if err != nil {
				return err
			}
			recs, err := eval.Decode(data, p)
			if err != nil {
				return err
			}
			records = append(records, recs...)
		}
		return nil
	})
	return records, err
}

func pathExt(p string) string {
	i := strings.LastIndex(p, ".")
	if i < 0 {
		return ""
	}
	return p[i:]
}
