// Package cli implements the detlint command line.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/analysis"
	"github.com/riturajsingh0001/detlint/internal/ci"
	"github.com/riturajsingh0001/detlint/internal/exitcode"
	"github.com/riturajsingh0001/detlint/internal/loader"
	"github.com/riturajsingh0001/detlint/internal/report"
	"github.com/riturajsingh0001/detlint/internal/rule"
	"github.com/riturajsingh0001/detlint/internal/schema"
)

// Version information, overridable with -ldflags.
var (
	Version = "0.1.0"
	Commit  = "dev"
	Date    = "unknown"
)

type environment struct {
	getenv func(string) string
	stdout io.Writer
	stderr io.Writer
}

// Globals are flags shared by every subcommand.
type Globals struct {
	Format  string
	FailOn  string
	Color   string
	Schema  string
	CI      bool
	Quiet   bool
	Changed bool
	Base    string
}

// Run executes detlint and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWith(args, stdout, stderr, os.Getenv)
}

// RunWith is Run with an injectable environment, used by tests.
func RunWith(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	e := &environment{getenv: getenv, stdout: stdout, stderr: stderr}
	cmd, rest, err := splitCommand(args)
	if err != nil {
		fmt.Fprintf(stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	switch cmd {
	case "", "help":
		printHelp(stdout)
		return exitcode.Clean
	case "version":
		return runVersion(rest, e)
	case "check":
		return runCheck(rest, e)
	case "test":
		return runTest(rest, e)
	case "noise":
		return runNoise(rest, e)
	case "map":
		return runMap(rest, e)
	case "demo":
		return runDemo(rest, e)
	case "schema":
		return runSchema(rest, e)
	default:
		fmt.Fprintf(stderr, "detlint: unknown command %q\n\n", cmd)
		printHelp(stderr)
		return exitcode.ToolErr
	}
}

func splitCommand(args []string) (string, []string, error) {
	var pre []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			pre = append(pre, a)
			if !strings.Contains(a, "=") && globalTakesValue(a) {
				if i+1 < len(args) {
					pre = append(pre, args[i+1])
					i++
				}
			}
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		for _, a := range pre {
			if a == "--version" || a == "-version" {
				return "version", pre, nil
			}
			if a == "--help" || a == "-h" || a == "-help" {
				return "help", pre, nil
			}
		}
		return "", pre, nil
	}
	cmd := args[i]
	rest := append(pre, args[i+1:]...)
	return cmd, rest, nil
}

func globalTakesValue(flagName string) bool {
	name := strings.TrimLeft(flagName, "-")
	switch name {
	case "format", "fail-on", "color", "schema", "base":
		return true
	}
	return false
}

func newFlagSet(name string, e *environment) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

func addGlobals(fs *flag.FlagSet, g *Globals) {
	fs.StringVar(&g.Format, "format", "pretty", "output format: pretty, json, sarif, markdown")
	fs.StringVar(&g.FailOn, "fail-on", "error", "minimum severity that fails: info, warning, error, never")
	fs.StringVar(&g.Color, "color", "auto", "color output: auto, always, never")
	fs.StringVar(&g.Schema, "schema", "", "directory of schema YAML files")
	fs.BoolVar(&g.CI, "ci", false, "emit GitHub Actions annotations")
	fs.BoolVar(&g.Quiet, "quiet", false, "suppress human-readable findings")
	fs.BoolVar(&g.Changed, "changed", false, "only lint files changed in git")
	fs.StringVar(&g.Base, "base", "", "git base revision for --changed")
}

// reorderArgs lets flags appear before or after positional arguments, which
// the standard flag package does not allow on its own.
func reorderArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			name = name[:eq]
			flags = append(flags, a)
			continue
		}
		if name == "h" || name == "help" {
			flags = append(flags, a)
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			return nil, fmt.Errorf("unknown flag: %s", a)
		}
		flags = append(flags, a)
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("flag needs an argument: %s", a)
		}
		i++
		flags = append(flags, args[i])
	}
	return append(flags, pos...), nil
}

func parseFlags(fs *flag.FlagSet, args []string) (bool, error) {
	reordered, err := reorderArgs(fs, args)
	if err != nil {
		return false, err
	}
	if err := fs.Parse(reordered); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func useColor(mode string, w io.Writer) bool {
	switch strings.ToLower(mode) {
	case "always":
		return true
	case "never":
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func loadSchemas(g *Globals) (*schema.Registry, error) {
	if g.Schema != "" {
		return schema.LoadDir(g.Schema)
	}
	return schema.Default(), nil
}

func loadRules(paths []string, g *Globals) (*loader.Result, error) {
	opts := loader.Options{}
	if g.Changed {
		changed, err := ci.ChangedFiles(g.Base)
		if err != nil {
			return nil, fmt.Errorf("--changed: %w", err)
		}
		opts.Changed = changed
	}
	merged := &loader.Result{Lines: map[string][]string{}}
	for _, p := range paths {
		res, err := loader.LoadDir(p, opts)
		if err != nil {
			return nil, err
		}
		merged.Files = append(merged.Files, res.Files...)
		merged.Errors = append(merged.Errors, res.Errors...)
		for k, v := range res.Lines {
			merged.Lines[k] = v
		}
	}
	return merged, nil
}

func parseFindings(res *loader.Result) []analysis.Finding {
	var out []analysis.Finding
	for _, fe := range res.Errors {
		f := analysis.Finding{
			Pass:     "parse",
			Severity: analysis.Error,
			File:     fe.Path,
			Line:     1,
			Col:      1,
			Message:  fe.Err.Error(),
			Help:     "Fix the YAML or rule syntax. This file was not analyzed.",
		}
		if pe, ok := fe.Err.(*rule.ParseError); ok && !pe.Span.IsZero() {
			f.File = pe.Span.File
			f.Line = pe.Span.Line
			f.Col = pe.Span.Col
			f.EndLine = pe.Span.EndLine
			f.EndCol = pe.Span.EndCol
			f.Message = pe.Msg
		}
		out = append(out, f)
	}
	return out
}

func sourcesFrom(res *loader.Result) *report.Sources {
	src := report.NewSources()
	for path, lines := range res.Lines {
		src.AddLines(path, lines)
	}
	return src
}

// reportLoadErrors prints parse failures and reports whether any occurred.
// Commands that are not `check` still need to fail loudly when a rule could
// not be parsed, otherwise a broken rule is silently skipped.
func reportLoadErrors(e *environment, res *loader.Result) bool {
	for _, fe := range res.Errors {
		fmt.Fprintf(e.stderr, "detlint: %s: %v\n", fe.Path, fe.Err)
	}
	return len(res.Errors) > 0
}

// humanFormat reports whether a format is a human-readable rendering.
// Machine formats (json, sarif, markdown) are documents that scripts and CI
// consume, so --quiet must never swallow them.
func humanFormat(format string) bool {
	switch format {
	case "", "pretty", "text":
		return true
	}
	return false
}

func emitFindings(e *environment, g *Globals, findings []analysis.Finding, src *report.Sources) int {
	analysis.Sort(findings)
	opts := report.Options{
		Format:  g.Format,
		Color:   useColor(g.Color, e.stdout),
		Version: Version,
		Sources: src,
	}
	if !g.Quiet || !humanFormat(g.Format) {
		if err := report.Write(e.stdout, findings, opts); err != nil {
			fmt.Fprintf(e.stderr, "detlint: %v\n", err)
			return exitcode.ToolErr
		}
	}

	failOn, err := analysis.ParseSeverity(g.FailOn)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}

	github := g.CI || ci.IsGitHub(e.getenv)
	if github && (g.Format == "pretty" || g.Format == "text" || g.Format == "markdown") {
		ci.AnnotateAll(e.stdout, findings)
		var md bytes.Buffer
		_ = report.WriteMarkdown(&md, findings, opts)
		if err := ci.WriteStepSummary(e.getenv, md.String()); err != nil {
			fmt.Fprintf(e.stderr, "detlint: step summary: %v\n", err)
		}
	}
	return exitcode.FromFindings(findings, failOn)
}

func runVersion(args []string, e *environment) int {
	fs := newFlagSet("version", e)
	short := fs.Bool("short", false, "print only the version")
	fs.Bool("version", false, "print the version")
	if _, err := parseFlags(fs, args); err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	if *short {
		fmt.Fprintln(e.stdout, Version)
		return exitcode.Clean
	}
	fmt.Fprintf(e.stdout, "detlint %s (commit %s, built %s, %s)\n", Version, Commit, Date, runtime.Version())
	return exitcode.Clean
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `detlint — a bouncer for detection rules

Usage:
  detlint check <rules/> [flags]        find broken rules
  detlint test <rules/> --pos DIR --neg DIR
                                        precision/recall against samples
  detlint noise <rules/> --logs FILE    count rule hits over a log
  detlint map <rules/>                  ATT&CK technique coverage gaps
  detlint demo                          run the embedded broken repo
  detlint schema list                   list bundled schemas
  detlint schema learn <samples>        infer a schema from JSONL samples
  detlint version                       print version

Common flags:
  --format pretty|json|sarif|markdown   output format (default pretty)
  --fail-on info|warning|error|never    failure threshold (default error)
  --color auto|always|never             color output
  --schema DIR                          load custom schemas
  --changed [--base REV]                only lint git-changed files
  --ci                                  emit GitHub Actions annotations

Examples:
  detlint check rules/
  detlint check rules/ --format sarif > detlint.sarif
  detlint test rules/ --pos bad-samples/ --neg good-samples/
  detlint noise rules/ --logs yesterday.log --top 20 --max 1000
  detlint map rules/ --tactic execution
`)
}
