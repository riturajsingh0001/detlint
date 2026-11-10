package cli

import (
	"fmt"

	"github.com/riturajsingh0001/detlint/internal/exitcode"
	"github.com/riturajsingh0001/detlint/internal/samples"
)

func runTest(args []string, e *environment) int {
	fs := newFlagSet("test", e)
	var g Globals
	addGlobals(fs, &g)
	pos := fs.String("pos", "", "directory of positive samples")
	neg := fs.String("neg", "", "directory of negative samples")
	minP := fs.Float64("min-precision", 0.9, "minimum precision")
	minR := fs.Float64("min-recall", 0.9, "minimum recall")
	require := fs.Bool("require-samples", false, "fail rules that have no samples")
	fs.Usage = func() {
		fmt.Fprintln(e.stderr, "usage: detlint test <rules/> --pos DIR --neg DIR [flags]")
		fs.PrintDefaults()
	}
	if help, err := parseFlags(fs, args); err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	} else if help {
		return exitcode.Clean
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	if *pos == "" && *neg == "" {
		fmt.Fprintln(e.stderr, "detlint: test needs at least one of --pos or --neg")
		return exitcode.ToolErr
	}
	res, err := loadRules(paths, &g)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	loadErrors := reportLoadErrors(e, res)
	posSet, err := samples.LoadSet(*pos)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: positive samples: %v\n", err)
		return exitcode.ToolErr
	}
	negSet, err := samples.LoadSet(*neg)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: negative samples: %v\n", err)
		return exitcode.ToolErr
	}
	results := samples.EvaluateSets(res.Files, posSet, negSet)
	switch g.Format {
	case "json":
		if err := samples.WriteJSON(e.stdout, results); err != nil {
			fmt.Fprintf(e.stderr, "detlint: %v\n", err)
			return exitcode.ToolErr
		}
	default:
		if !g.Quiet {
			_ = samples.WritePretty(e.stdout, results, samples.Options{
				Color:        useColor(g.Color, e.stdout),
				MinPrecision: *minP,
				MinRecall:    *minR,
			})
		}
	}
	failed := samples.Failed(results, *minP, *minR)
	if *require {
		for _, r := range results {
			if r.Pos == 0 && r.Neg == 0 {
				fmt.Fprintf(e.stderr, "detlint: %s has no samples\n", r.File)
				failed = true
			}
		}
	}
	if failed || loadErrors {
		return exitcode.Findings
	}
	return exitcode.Clean
}
