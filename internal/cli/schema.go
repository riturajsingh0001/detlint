package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/riturajsingh0001/detlint/internal/eval"
	"github.com/riturajsingh0001/detlint/internal/exitcode"
	"github.com/riturajsingh0001/detlint/internal/schema"
)

func runSchema(args []string, e *environment) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "usage: detlint schema <list|learn> ...")
		return exitcode.ToolErr
	}
	switch args[0] {
	case "list":
		return runSchemaList(args[1:], e)
	case "learn":
		return runSchemaLearn(args[1:], e)
	case "help", "-h", "--help":
		fmt.Fprintln(e.stdout, "usage: detlint schema <list|learn> ...")
		return exitcode.Clean
	default:
		fmt.Fprintf(e.stderr, "detlint: unknown schema command %q\n", args[0])
		return exitcode.ToolErr
	}
}

func runSchemaList(args []string, e *environment) int {
	fs := newFlagSet("schema list", e)
	var g Globals
	addGlobals(fs, &g)
	if help, err := parseFlags(fs, args); err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	} else if help {
		return exitcode.Clean
	}
	reg, err := loadSchemas(&g)
	if err != nil {
		fmt.Fprintf(e.stderr, "detlint: %v\n", err)
		return exitcode.ToolErr
	}
	sources := append([]*schema.LogSource(nil), reg.Sources...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	for _, s := range sources {
		ls := s.Product
		if s.Service != "" {
			ls += "/" + s.Service
		}
		fmt.Fprintf(e.stdout, "%-24s %-24s %3d fields\n", s.Name, ls, len(s.Fields))
	}
	return exitcode.Clean
}

func runSchemaLearn(args []string, e *environment) int {
	fs := newFlagSet("schema learn", e)
	name := fs.String("name", "learned", "schema name")
	product := fs.String("product", "", "logsource product")
	service := fs.String("service", "", "logsource service")
	out := fs.String("out", "", "output file (default stdout)")
	fs.StringVar(out, "o", "", "output file (default stdout)")
	fs.Usage = func() {
		fmt.Fprintln(e.stderr, "usage: detlint schema learn <samples...> [flags]")
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
		fmt.Fprintln(e.stderr, "detlint: schema learn needs at least one sample file or directory")
		return exitcode.ToolErr
	}
	var records []eval.Record
	for _, p := range paths {
		recs, err := eval.DecodeDir(p)
		if err != nil {
			fmt.Fprintf(e.stderr, "detlint: %s: %v\n", p, err)
			return exitcode.ToolErr
		}
		records = append(records, recs...)
	}
	if len(records) == 0 {
		fmt.Fprintln(e.stderr, "detlint: no sample records found")
		return exitcode.ToolErr
	}
	maps := make([]map[string]any, len(records))
	for i, r := range records {
		maps[i] = map[string]any(r)
	}
	s := schema.Learn(maps, *name, *product, *service)
	data := schema.MarshalYAML(s)
	if *out != "" {
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fmt.Fprintf(e.stderr, "detlint: %v\n", err)
			return exitcode.ToolErr
		}
		fmt.Fprintf(e.stderr, "wrote %s (%d fields from %d records)\n", *out, len(s.Fields), len(records))
		return exitcode.Clean
	}
	_, _ = e.stdout.Write(data)
	return exitcode.Clean
}
