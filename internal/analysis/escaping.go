package analysis

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

func escapingPass(ctx *Context) []Finding {
	r := ctx.Rule
	var out []Finding
	for _, sel := range r.Detection.Selections {
		for _, group := range sel.Groups {
			for _, f := range group {
				if f.HasModifier("re") {
					for _, v := range f.Values {
						if _, err := regexp.Compile(v.Text); err != nil {
							out = append(out, newFinding("escaping", Error, r, v.Span,
								fmt.Sprintf("invalid regular expression in field %q: %v", f.Name, err),
								"Fix the pattern. Use single quotes for regexes containing backslashes."))
						}
					}
				}
				if f.HasModifier("cidr") {
					for _, v := range f.Values {
						if _, _, err := net.ParseCIDR(v.Text); err != nil {
							out = append(out, newFinding("escaping", Error, r, v.Span,
								fmt.Sprintf("invalid CIDR %q in field %q", v.Text, f.Name),
								"Use CIDR notation such as 10.0.0.0/8 or a bare IP address."))
						}
					}
				}
				if f.HasModifier("re") && (f.HasModifier("contains") || f.HasModifier("startswith") || f.HasModifier("endswith")) {
					out = append(out, newFinding("escaping", Warning, r, f.KeySpan,
						fmt.Sprintf("field %q combines |re with a string modifier", f.Name),
						"|re already defines the match; remove |contains/|startswith/|endswith."))
				}
				for _, v := range f.Values {
					if v.Quoted && v.Style == '"' {
						if bad := badDoubleEscape(v.Raw); bad != "" {
							out = append(out, newFinding("escaping", Warning, r, v.Span,
								fmt.Sprintf("invalid YAML escape %q in a double-quoted value", bad),
								`Use single quotes for backslashes (for example '\d+') or double the backslash.`))
						}
					}
					if !v.Quoted && strings.HasSuffix(v.Text, "\\") {
						out = append(out, newFinding("escaping", Warning, r, v.Span,
							"value ends with a backslash, which is easy to misread",
							"Quote the value explicitly if the backslash is literal."))
					}
				}
			}
		}
	}
	return out
}

func badDoubleEscape(raw string) string {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return `\`
		}
		c := raw[i+1]
		switch c {
		case '0', 'a', 'b', 't', 'n', 'v', 'f', 'r', 'e', ' ', '"', '/', '\\', 'N', '_', 'L', 'P':
			i++
		case 'x':
			if i+3 < len(raw) {
				i += 3
			} else {
				return `\x`
			}
		case 'u':
			if i+5 < len(raw) {
				i += 5
			} else {
				return `\u`
			}
		case 'U':
			if i+9 < len(raw) {
				i += 9
			} else {
				return `\U`
			}
		default:
			return `\` + string(c)
		}
	}
	return ""
}
