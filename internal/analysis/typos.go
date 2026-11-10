package analysis

import (
	"fmt"
	"strings"
)

func typosPass(ctx *Context) []Finding {
	r := ctx.Rule
	var out []Finding
	sch := ctx.Schemas.Match(r.LogSource)
	if sch == nil {
		if r.LogSource.Product != "" || r.LogSource.Service != "" || r.LogSource.Category != "" {
			help := "No bundled schema matches this logsource."
			if ctx.Schemas != nil && len(ctx.Schemas.Products()) > 0 {
				help += " Known products: " + strings.Join(ctx.Schemas.Products(), ", ") + "."
			}
			help += " Pass --schema <dir> to validate against your own schema."
			out = append(out, newFinding("typos", Warning, r, r.LogSource.Span,
				fmt.Sprintf("no schema for logsource product=%q service=%q; fields cannot be validated",
					r.LogSource.Product, r.LogSource.Service), help))
		}
		return out
	}

	for _, sel := range r.Detection.Selections {
		for _, group := range sel.Groups {
			for _, f := range group {
				if f.Name == "*" {
					continue
				}
				if !sch.HasField(f.Name) {
					if canon, ok := sch.FindCaseInsensitive(f.Name); ok {
						out = append(out, newFinding("typos", Warning, r, f.KeySpan,
							fmt.Sprintf("field %q differs only by case from schema field %q", f.Name, canon),
							fmt.Sprintf("Use the schema spelling %q. Some backends are case-sensitive.", canon)))
					} else {
						msg := fmt.Sprintf("unknown field %q in selection %q (schema %q)", f.Name, sel.Name, sch.Name)
						help := "This rule looks for a field the log source does not contain, so it can never match."
						if sug := sch.Suggest(f.Name); sug != "" {
							msg += fmt.Sprintf("; did you mean %q?", sug)
							help = fmt.Sprintf("Did you mean %q? Run detlint schema list to see known fields.", sug)
						}
						out = append(out, newFinding("typos", Error, r, f.KeySpan, msg, help))
					}
				}
				if f.HasModifier("fieldref") {
					for _, v := range f.Values {
						if !sch.HasField(v.Text) {
							out = append(out, newFinding("typos", Error, r, v.Span,
								fmt.Sprintf("fieldref target %q is not a field in schema %q", v.Text, sch.Name),
								"fieldref compares against another field; use a field that exists in the log source."))
						}
					}
				}
			}
		}
	}
	return out
}
