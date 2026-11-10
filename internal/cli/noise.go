package cli

import (
	"fmt"

	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/exitcode"
	"github.com/riturajsingh0001/detlint/internal/noise"
)

func runNoise(args []string, e *environment) int {
	fs := newFlagSet("noise", e)
	var g Globals
	addGlobals(fs, &g)
	logs := fs.String("logs", "", "log file or directory to scan")
	top := fs.Int("top", 10, "show the top N rules (0 = all)")
	max := fs.Int("max", 0, "fail if a rule fires more than N times")
	fs.Usage = func() {
		fmt.Fprintln(e.stderr, "usage: detlint noise <rules/> --logs FILE [flags]")
		fs.PrintDefaults()
	}
	if help, err := parseFlags(fs, args); err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	} else if help {
		return exitcode.Clean
	}
	if *logs == "" {
		fmt.Fprintln(e.stderr, "detlint: noise needs --logs FILE")
		return exitcode.ToolErr
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	res, err := loadRules(paths, &g)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	loadErrors := reportLoadErrors(e, res)
	records, err := eval.DecodeDir(*logs)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: logs: %v\n", err)
		return exitcode.ToolErr
	}
	if len(records) == 0 {
		fmt.Fprintln(e.stderr, "detlint: no records found in --logs")
		return exitcode.ToolErr
	}
	hits := noise.Analyze(res.Files, records)
	if g.Format == "json" {
		if err := noise.WriteJSON(e.stdout, hits, noise.Options{Top: *top, Max: *max}); err != nil {
			fmt.Fprintf(e.stderr, "detlint: %v\n", err)
			return exitcode.ToolErr
		}
	} else if !g.Quiet {
		_ = noise.WritePretty(e.stdout, hits, noise.Options{Top: *top, Max: *max, Color: useColor(g.Color, e.stdout)})
	}
	if loadErrors || noise.Exceeded(hits, *max) {
		return exitcode.Findings
	}
	return exitcode.Clean
}
