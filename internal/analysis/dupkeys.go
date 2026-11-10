package analysis

import (
	"fmt"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

func dupKeysPass(ctx *Context) []Finding {
	var out []Finding
	var walk func(n *rule.Node)
	walk = func(n *rule.Node) {
		if n == nil {
			return
		}
		if n.Kind == rule.MappingNode {
			seen := map[string]*rule.Node{}
			for _, p := range n.Pairs {
				if first, ok := seen[p.Key.Value]; ok {
					out = append(out, newFinding("dupkeys", Error, ctx.Rule, p.Key.Span,
						fmt.Sprintf("duplicate key %q (first defined at line %d)", p.Key.Value, first.Span.Line),
						"YAML silently keeps the last value. Remove or rename one of the keys."))
				} else {
					seen[p.Key.Value] = p.Key
				}
				walk(p.Value)
			}
			return
		}
		for _, item := range n.Items {
			walk(item)
		}
	}
	walk(ctx.File.Root)
	return out
}
