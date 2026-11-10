package rule

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule/condition"
	"github.com/riturajsingh0001/detlint/internal/span"
)

// ParseError is a rule syntax error with a source location.
type ParseError struct {
	Msg  string
	Span span.Span
}

func (e *ParseError) Error() string {
	if e.Span.IsZero() {
		return e.Msg
	}
	return fmt.Sprintf("%s at %s", e.Msg, e.Span)
}

var knownModifiers = map[string]bool{
	"contains": true, "startswith": true, "endswith": true, "re": true,
	"all": true, "any": true, "exists": true, "cased": true,
	"base64": true, "base64offset": true, "utf16": true, "utf16le": true,
	"utf16be": true, "wide": true, "windash": true, "cidr": true,
	"gt": true, "gte": true, "lt": true, "lte": true, "fieldref": true,
	"eq": true, "neq": true,
}

// Parse parses one YAML rule file.
func Parse(filePath string, data []byte) (*File, error) {
	f := &File{
		Path:  filePath,
		Data:  data,
		Lines: splitLines(data),
	}
	root, err := ParseYAML(data, filePath)
	if err != nil {
		return f, err
	}
	f.Root = root
	if root.Kind != MappingNode {
		return f, &ParseError{Msg: "rule must be a YAML mapping", Span: root.Span}
	}
	r := &Rule{File: filePath, Root: root, Span: root.Span}
	r.Title = scalar(root, "title")
	r.ID = firstScalar(root, "id", "rule_id")
	r.Status = scalar(root, "status")
	r.Description = scalar(root, "description")
	r.Author = scalar(root, "author")
	r.Level = strings.ToLower(scalar(root, "level"))
	r.Date = scalar(root, "date")
	r.Modified = scalar(root, "modified")
	r.Tags = stringList(root.Get("tags"))
	r.References = stringList(root.Get("references"))
	r.FalsePositives = stringList(root.Get("falsepositives"))

	if ls := root.Get("logsource"); ls != nil && ls.Kind == MappingNode {
		r.LogSource = LogSource{
			Product:    scalar(ls, "product"),
			Service:    scalar(ls, "service"),
			Category:   scalar(ls, "category"),
			Definition: scalar(ls, "definition"),
			Span:       ls.Span,
		}
	}

	detNode := root.Get("detection")
	if detNode == nil {
		return f, &ParseError{Msg: "rule has no detection block", Span: root.Span}
	}
	if detNode.Kind != MappingNode {
		return f, &ParseError{Msg: "detection must be a mapping", Span: detNode.Span}
	}
	det := Detection{ByName: map[string]*Selection{}, Span: detNode.Span}
	det.Timeframe = scalar(detNode, "timeframe")
	condNode := detNode.Get("condition")
	if condNode == nil {
		return f, &ParseError{Msg: "detection block has no condition", Span: detNode.Span}
	}
	if condNode.Kind != ScalarNode || condNode.IsNull() {
		return f, &ParseError{Msg: "condition must be a string", Span: condNode.Span}
	}
	det.ConditionRaw = condNode.Value
	det.ConditionSpan = condNode.Span

	for _, p := range detNode.Pairs {
		name := p.Key.Value
		if name == "condition" || name == "timeframe" {
			continue
		}
		sel, err := parseSelection(name, p.Value)
		if err != nil {
			return f, err
		}
		if _, exists := det.ByName[name]; exists {
			// Duplicate selection names are YAML duplicate keys; the dupkeys
			// pass reports them. Keep the last one for evaluation.
			for i, old := range det.Selections {
				if old.Name == name {
					det.Selections = append(det.Selections[:i], det.Selections[i+1:]...)
					break
				}
			}
		}
		det.Selections = append(det.Selections, sel)
		det.ByName[name] = sel
	}

	expr, err := condition.Parse(det.ConditionRaw, det.ConditionSpan)
	if err != nil {
		if ce, ok := err.(*condition.Error); ok {
			return f, &ParseError{Msg: "invalid condition: " + ce.Msg, Span: ce.Span}
		}
		return f, &ParseError{Msg: "invalid condition: " + err.Error(), Span: det.ConditionSpan}
	}
	det.Condition = expr
	seenUndefined := map[string]bool{}
	condition.Walk(expr, func(e condition.Expr) {
		if id, ok := e.(*condition.Ident); ok {
			if det.ByName[id.Name] == nil && !seenUndefined[id.Name] {
				seenUndefined[id.Name] = true
				det.Undefined = append(det.Undefined, id.Name)
			}
		}
	})
	r.Detection = det
	f.Rule = r
	return f, nil
}

func splitLines(data []byte) []string {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func scalar(n *Node, key string) string {
	v := n.Get(key)
	if v == nil || v.Kind != ScalarNode {
		return ""
	}
	return v.Value
}

func firstScalar(n *Node, keys ...string) string {
	for _, k := range keys {
		if v := scalar(n, k); v != "" {
			return v
		}
	}
	return ""
}

func stringList(n *Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case SequenceNode:
		var out []string
		for _, it := range n.Items {
			if it.Kind == ScalarNode && !it.IsNull() {
				out = append(out, it.Value)
			}
		}
		return out
	case ScalarNode:
		if n.IsNull() || n.Value == "" {
			return nil
		}
		return []string{n.Value}
	default:
		return nil
	}
}

func parseSelection(name string, n *Node) (*Selection, error) {
	sel := &Selection{Name: name, Span: n.Span}
	if name == "" {
		return nil, &ParseError{Msg: "selection name cannot be empty", Span: n.Span}
	}
	switch n.Kind {
	case MappingNode:
		g, err := parseFieldGroup(n)
		if err != nil {
			return nil, err
		}
		sel.Groups = []FieldGroup{g}
	case SequenceNode:
		for _, item := range n.Items {
			if item.Kind != MappingNode {
				return nil, &ParseError{
					Msg:  fmt.Sprintf("selection %q must be a mapping or a list of mappings", name),
					Span: item.Span,
				}
			}
			g, err := parseFieldGroup(item)
			if err != nil {
				return nil, err
			}
			sel.Groups = append(sel.Groups, g)
		}
	default:
		return nil, &ParseError{
			Msg:  fmt.Sprintf("selection %q must be a mapping of fields", name),
			Span: n.Span,
		}
	}
	return sel, nil
}

func parseFieldGroup(n *Node) (FieldGroup, error) {
	var group FieldGroup
	for _, p := range n.Pairs {
		f, err := parseField(p.Key, p.Value)
		if err != nil {
			return nil, err
		}
		group = append(group, f)
	}
	return group, nil
}

func parseField(key, value *Node) (Field, error) {
	parts := strings.Split(key.Value, "|")
	name := strings.TrimSpace(parts[0])
	f := Field{Name: name, KeySpan: key.Span, Span: key.Span}
	if name == "" {
		return f, &ParseError{Msg: "field name cannot be empty", Span: key.Span}
	}
	for _, m := range parts[1:] {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" {
			return f, &ParseError{Msg: fmt.Sprintf("empty modifier on field %q", name), Span: key.Span}
		}
		if !knownModifiers[m] {
			return f, &ParseError{
				Msg:  fmt.Sprintf("unknown field modifier %q on field %q", m, name),
				Span: key.Span,
			}
		}
		f.Modifiers = append(f.Modifiers, m)
	}

	switch value.Kind {
	case ScalarNode:
		v := makeValue(value)
		f.Values = []Value{v}
		f.Span = span.Merge(key.Span, value.Span)
	case SequenceNode:
		for _, item := range value.Items {
			if item.Kind != ScalarNode {
				return f, &ParseError{
					Msg:  fmt.Sprintf("field %q has a nested value; only scalar lists are supported", name),
					Span: item.Span,
				}
			}
			f.Values = append(f.Values, makeValue(item))
		}
		f.Span = span.Merge(key.Span, value.Span)
	default:
		return f, &ParseError{
			Msg:  fmt.Sprintf("field %q must have a scalar or list value", name),
			Span: value.Span,
		}
	}
	return f, nil
}

func makeValue(n *Node) Value {
	v := Value{
		Text:   n.Value,
		Raw:    n.Raw,
		Quoted: n.Quoted,
		Style:  n.Style,
		Span:   n.Span,
	}
	if n.IsNull() {
		v.Kind = NullValue
		return v
	}
	if n.Quoted {
		v.Kind = StringValue
		return v
	}
	switch strings.ToLower(strings.TrimSpace(n.Value)) {
	case "true", "false":
		v.Kind = BoolValue
		return v
	}
	if _, err := strconv.ParseInt(strings.TrimSpace(n.Value), 10, 64); err == nil {
		v.Kind = IntValue
		return v
	}
	if _, err := strconv.ParseFloat(strings.TrimSpace(n.Value), 64); err == nil {
		v.Kind = FloatValue
		return v
	}
	v.Kind = StringValue
	return v
}

// SelectionCount returns the number of field constraints in a selection.
func (s *Selection) FieldCount() int {
	n := 0
	for _, g := range s.Groups {
		n += len(g)
	}
	return n
}

// AlwaysTrue reports whether the selection matches every record because one
// of its groups has no field constraints.
func (s *Selection) AlwaysTrue() bool {
	if s == nil || len(s.Groups) == 0 {
		return true
	}
	for _, g := range s.Groups {
		if len(g) == 0 {
			return true
		}
	}
	return false
}
