package analysis

import (
	"strings"
)

var validLevels = map[string]bool{
	"informational": true, "info": true, "low": true, "medium": true,
	"high": true, "critical": true,
}

func metadataPass(ctx *Context) []Finding {
	r := ctx.Rule
	var out []Finding
	add := func(sev Severity, msg, help string) {
		out = append(out, newFinding("metadata", sev, r, r.Span, msg, help))
	}

	if strings.TrimSpace(r.Title) == "" {
		add(Warning, "rule has no title", "Add a short title so findings are readable in alerts and pull requests.")
	}
	if strings.TrimSpace(r.ID) == "" {
		add(Warning, "rule has no id", "Add a stable id (UUID or slug) so findings can be tracked across edits.")
	}
	if r.Level == "" {
		add(Info, "rule has no level", "Set level to informational, low, medium, high, or critical.")
	} else if !validLevels[r.Level] {
		add(Warning, "unknown level "+quote(r.Level), "Use informational, low, medium, high, or critical.")
	}
	if r.LogSource.Product == "" && r.LogSource.Service == "" && r.LogSource.Category == "" {
		add(Warning, "rule has no logsource", "Add a logsource block (product/service/category) so fields can be validated.")
	}
	if len(r.Tags) == 0 {
		add(Info, "rule has no tags", "Tag the rule with attack.<tactic> and attack.t<technique> to appear in coverage reports.")
	}
	if strings.TrimSpace(r.Description) == "" {
		add(Info, "rule has no description", "Describe what the rule detects and why it matters.")
	}
	return out
}

func quote(s string) string {
	return "\"" + s + "\""
}
