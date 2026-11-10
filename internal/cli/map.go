package cli

import (
	"fmt"

	"github.com/riturajsingh0001/detlint/internal/coverage"
	"github.com/riturajsingh0001/detlint/internal/exitcode"
)

func runMap(args []string, e *environment) int {
	fs := newFlagSet("map", e)
	var g Globals
	addGlobals(fs, &g)
	tactic := fs.String("tactic", "", "limit to one ATT&CK tactic (name or ID)")
	minCoverage := fs.Float64("min-coverage", 0, "fail below this percentage")
	showMissing := fs.Int("show-missing", 6, "missing technique IDs to print per tactic")
	fs.Usage = func() {
		fmt.Fprintln(e.stderr, "usage: detlint map <rules/> [flags]")
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
	res, err := loadRules(paths, &g)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	loadErrors := reportLoadErrors(e, res)
	rep := coverage.Analyze(res.Files, coverage.Default())
	if *tactic != "" {
		filtered := rep.Filter(*tactic)
		if len(filtered.Tactics) == 0 {
			fmt.Fprintf(e.stderr, "detlint: unknown tactic %q\n", *tactic)
			return exitcode.ToolErr
		}
		rep = filtered
	}
	if g.Format == "json" {
		if err := coverage.WriteJSON(e.stdout, rep); err != nil {
			fmt.Fprintf(e.stderr, "detlint: %v\n", err)
			return exitcode.ToolErr
		}
	} else if !g.Quiet {
		_ = coverage.WritePretty(e.stdout, rep, coverage.Options{
			Color:       useColor(g.Color, e.stdout),
			ShowMissing: *showMissing,
		})
	}
	if loadErrors || (*minCoverage > 0 && rep.Percent() < *minCoverage) {
		return exitcode.Findings
	}
	return exitcode.Clean
}
