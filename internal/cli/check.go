package cli

import (
	"fmt"

	"github.com/riturajsingh0001/detlint/internal/analysis"
	"github.com/riturajsingh0001/detlint/internal/exitcode"
)

func runCheck(args []string, e *environment) int {
	fs := newFlagSet("check", e)
	var g Globals
	addGlobals(fs, &g)
	listPasses := fs.Bool("list-passes", false, "list analysis passes and exit")
	fs.Usage = func() {
		fmt.Fprintln(e.stderr, "usage: detlint check <rules/> [flags]")
		fs.PrintDefaults()
	}
	if help, err := parseFlags(fs, args); err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	} else if help {
		return exitcode.Clean
	}
	if *listPasses {
		for _, p := range analysis.Passes() {
			fmt.Fprintf(e.stdout, "%-14s %s\n", p.ID, p.Description)
		}
		return exitcode.Clean
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	schemas, err := loadSchemas(&g)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: schemas: %v\n", err)
		return exitcode.ToolErr
	}
	res, err := loadRules(paths, &g)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	findings := parseFindings(res)
	for _, f := range res.Files {
		findings = append(findings, analysis.Run(f, schemas)...)
	}
	return emitFindings(e, &g, findings, sourcesFrom(res))
}
