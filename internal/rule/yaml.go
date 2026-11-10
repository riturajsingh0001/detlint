package rule

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/span"
)

// NodeKind identifies a YAML node type.
type NodeKind int

const (
	ScalarNode NodeKind = iota
	MappingNode
	SequenceNode
)

// Node is a minimal YAML node tree. Unlike encoding/json and most YAML
// libraries, mapping pairs are stored as a slice so duplicate keys survive
// parsing. detlint needs to see them to report them.
type Node struct {
	Kind   NodeKind
	Value  string
	Raw    string // scalar text before unescaping, without surrounding quotes
	Quoted bool
	Style  byte // 0 for plain, otherwise '\'', '"', '|' or '>'
	Null   bool
	Pairs  []Pair
	Items  []*Node
	Span   span.Span
}

// Pair is one mapping entry.
type Pair struct {
	Key   *Node
	Value *Node
}

// Get returns the last value for key, mirroring how YAML consumers resolve
// duplicate keys.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != MappingNode {
		return nil
	}
	for i := len(n.Pairs) - 1; i >= 0; i-- {
		if n.Pairs[i].Key.Value == key {
			return n.Pairs[i].Value
		}
	}
	return nil
}

// GetAll returns every value for key, in source order.
func (n *Node) GetAll(key string) []*Node {
	if n == nil || n.Kind != MappingNode {
		return nil
	}
	var out []*Node
	for _, p := range n.Pairs {
		if p.Key.Value == key {
			out = append(out, p.Value)
		}
	}
	return out
}

// Has reports whether a mapping contains key.
func (n *Node) Has(key string) bool {
	if n == nil || n.Kind != MappingNode {
		return false
	}
	for _, p := range n.Pairs {
		if p.Key.Value == key {
			return true
		}
	}
	return false
}

// Keys returns mapping keys in source order, including duplicates.
func (n *Node) Keys() []string {
	if n == nil || n.Kind != MappingNode {
		return nil
	}
	out := make([]string, 0, len(n.Pairs))
	for _, p := range n.Pairs {
		out = append(out, p.Key.Value)
	}
	return out
}

// Scalars returns sequence items that are scalars.
func (n *Node) Scalars() []*Node {
	if n == nil || n.Kind != SequenceNode {
		return nil
	}
	out := make([]*Node, 0, len(n.Items))
	for _, it := range n.Items {
		if it.Kind == ScalarNode {
			out = append(out, it)
		}
	}
	return out
}

// StringValue returns the scalar value, or "" for non-scalars.
func (n *Node) StringValue() string {
	if n == nil || n.Kind != ScalarNode {
		return ""
	}
	return n.Value
}

// IsNull reports whether the node is an explicit or implicit YAML null.
func (n *Node) IsNull() bool {
	return n == nil || (n.Kind == ScalarNode && n.Null)
}

type yline struct {
	num    int
	indent int
	text   string
	rawIdx int
}

// ParseYAML parses the subset of YAML used by detection rules and schemas.
// It supports nested mappings/sequences, flow sequences, quoted scalars,
// block scalars, comments and duplicate keys.
func ParseYAML(data []byte, file string) (*Node, error) {
	text := strings.TrimPrefix(string(data), "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raws := strings.Split(text, "\n")

	var lines []yline
	seenContent := false
	for i, raw := range raws {
		lineNo := i + 1
		trimmedRight := strings.TrimRight(raw, " \t")
		trimmed := strings.TrimSpace(trimmedRight)
		indent, err := countIndent(trimmedRight)
		if err != nil {
			return nil, &ParseError{Msg: err.Error(), Span: span.New(file, lineNo, 1)}
		}
		if trimmed == "" {
			continue
		}
		if trimmed == "---" || trimmed == "..." {
			if seenContent && trimmed == "---" {
				break // only the first document is a rule
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		content := stripComment(trimmedRight[indent:])
		if strings.TrimSpace(content) == "" {
			continue
		}
		seenContent = true
		lines = append(lines, yline{
			num:    lineNo,
			indent: indent,
			text:   strings.TrimRight(content, " \t"),
			rawIdx: i,
		})
	}
	if len(lines) == 0 {
		return &Node{Kind: ScalarNode, Null: true, Span: span.New(file, 1, 1)}, nil
	}

	idx := 0
	root, err := parseNode(lines, raws, &idx, lines[0].indent, file)
	if err != nil {
		return nil, err
	}
	if idx < len(lines) {
		l := lines[idx]
		return nil, &ParseError{Msg: "unexpected indentation", Span: span.New(file, l.num, l.indent+1)}
	}
	return root, nil
}

func countIndent(s string) (int, error) {
	n := 0
	for _, r := range s {
		switch r {
		case ' ':
			n++
		case '\t':
			return 0, fmt.Errorf("tab characters are not allowed for YAML indentation")
		default:
			return n, nil
		}
	}
	return n, nil
}

func parseNode(lines []yline, raws []string, idx *int, indent int, file string) (*Node, error) {
	if *idx >= len(lines) {
		return &Node{Kind: ScalarNode, Null: true, Span: span.New(file, 1, 1)}, nil
	}
	l := lines[*idx]
	if l.indent < indent {
		return nil, nil
	}
	if isSeqStart(l.text) {
		return parseSequence(lines, raws, idx, l.indent, file)
	}
	return parseMapping(lines, raws, idx, l.indent, file)
}

func isSeqStart(s string) bool {
	return s == "-" || strings.HasPrefix(s, "- ")
}

func parseMapping(lines []yline, raws []string, idx *int, indent int, file string) (*Node, error) {
	if *idx >= len(lines) {
		return nil, nil
	}
	first := lines[*idx]
	node := &Node{Kind: MappingNode, Span: span.New(file, first.num, first.indent+1)}
	for *idx < len(lines) {
		l := lines[*idx]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, &ParseError{
				Msg:  fmt.Sprintf("unexpected indentation (expected %d spaces, got %d)", indent, l.indent),
				Span: span.New(file, l.num, l.indent+1),
			}
		}
		if isSeqStart(l.text) {
			break
		}
		keyText, keyQuoted, valText, colon, ok := splitKeyValue(l.text)
		if !ok {
			return nil, &ParseError{
				Msg:  fmt.Sprintf("expected 'key: value', got %q", l.text),
				Span: span.New(file, l.num, l.indent+1),
			}
		}
		keySpan := span.New(file, l.num, l.indent+1)
		key := &Node{Kind: ScalarNode, Value: keyText, Quoted: keyQuoted, Span: keySpan}
		*idx++

		var val *Node
		var err error
		if valText == "" {
			if *idx < len(lines) && lines[*idx].indent > indent {
				nl := lines[*idx]
				if startsFlow(nl.text) {
					*idx++ // consume the line that starts the flow collection
					flow := collectFlow(lines, idx, indent, nl.text)
					val, err = parseInlineValue(flow, span.New(file, nl.num, nl.indent+1))
					if err != nil {
						return nil, err
					}
				} else {
					val, err = parseNode(lines, raws, idx, nl.indent, file)
					if err != nil {
						return nil, err
					}
				}
			} else {
				val = &Node{Kind: ScalarNode, Null: true, Span: keySpan}
			}
		} else if isBlockScalar(valText) {
			val, err = parseBlockScalar(raws, lines, idx, l, valText, file)
			if err != nil {
				return nil, err
			}
		} else {
			valText = collectFlow(lines, idx, indent, valText)
			valueCol := l.indent + colon + 2
			for valueCol-1 < len(l.text) && (l.text[valueCol-1] == ' ' || l.text[valueCol-1] == '\t') {
				valueCol++
			}
			val, err = parseInlineValue(valText, span.New(file, l.num, valueCol))
			if err != nil {
				return nil, err
			}
		}
		if val == nil {
			val = &Node{Kind: ScalarNode, Null: true, Span: keySpan}
		}
		node.Pairs = append(node.Pairs, Pair{Key: key, Value: val})
		node.Span = span.Merge(node.Span, val.Span)
	}
	return node, nil
}

func parseSequence(lines []yline, raws []string, idx *int, indent int, file string) (*Node, error) {
	first := lines[*idx]
	node := &Node{Kind: SequenceNode, Span: span.New(file, first.num, first.indent+1)}
	for *idx < len(lines) {
		l := lines[*idx]
		if l.indent != indent || !isSeqStart(l.text) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		itemSpan := span.New(file, l.num, l.indent+3)
		*idx++
		var item *Node
		var err error
		switch {
		case rest == "":
			if *idx < len(lines) && lines[*idx].indent > indent {
				item, err = parseNode(lines, raws, idx, lines[*idx].indent, file)
			} else {
				item = &Node{Kind: ScalarNode, Null: true, Span: itemSpan}
			}
		case isMappingEntry(rest):
			item, err = parseInlineMappingItem(lines, raws, idx, indent, rest, l, file)
		default:
			item, err = parseInlineValue(rest, itemSpan)
			if err == nil && *idx < len(lines) && lines[*idx].indent > indent {
				nl := lines[*idx]
				err = &ParseError{
					Msg:  "multi-line plain scalars are not supported; quote the value",
					Span: span.New(file, nl.num, nl.indent+1),
				}
			}
		}
		if err != nil {
			return nil, err
		}
		if item == nil {
			item = &Node{Kind: ScalarNode, Null: true, Span: itemSpan}
		}
		node.Items = append(node.Items, item)
		node.Span = span.Merge(node.Span, item.Span)
	}
	return node, nil
}

// parseInlineMappingItem handles "- key: value" entries.
func parseInlineMappingItem(lines []yline, raws []string, idx *int, seqIndent int, rest string, l yline, file string) (*Node, error) {
	m := &Node{Kind: MappingNode, Span: span.New(file, l.num, l.indent+3)}
	keyText, keyQuoted, valText, colon, ok := splitKeyValue(rest)
	if !ok {
		return nil, &ParseError{Msg: "expected 'key: value' in sequence entry", Span: m.Span}
	}
	key := &Node{Kind: ScalarNode, Value: keyText, Quoted: keyQuoted, Span: m.Span}
	var val *Node
	var err error
	if valText == "" {
		if *idx < len(lines) && lines[*idx].indent > seqIndent+1 {
			val, err = parseNode(lines, raws, idx, lines[*idx].indent, file)
			if err != nil {
				return nil, err
			}
		} else {
			val = &Node{Kind: ScalarNode, Null: true, Span: m.Span}
		}
	} else if isBlockScalar(valText) {
		val, err = parseBlockScalar(raws, lines, idx, l, valText, file)
		if err != nil {
			return nil, err
		}
	} else {
		valText = collectFlow(lines, idx, seqIndent, valText)
		val, err = parseInlineValue(valText, span.New(file, l.num, l.indent+3+colon+2))
		if err != nil {
			return nil, err
		}
	}
	m.Pairs = append(m.Pairs, Pair{Key: key, Value: val})

	// Remaining keys of the same mapping item.
	if *idx < len(lines) && lines[*idx].indent > seqIndent {
		childIndent := lines[*idx].indent
		more, err := parseMapping(lines, raws, idx, childIndent, file)
		if err != nil {
			return nil, err
		}
		if more != nil {
			m.Pairs = append(m.Pairs, more.Pairs...)
			m.Span = span.Merge(m.Span, more.Span)
		}
	}
	return m, nil
}

func isMappingEntry(s string) bool {
	_, _, _, _, ok := splitKeyValue(s)
	return ok
}

func splitKeyValue(s string) (key string, keyQuoted bool, val string, colon int, ok bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				if inSingle && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					inSingle = !inSingle
				}
			}
		case '"':
			if !inSingle && (i == 0 || s[i-1] != '\\') {
				inDouble = !inDouble
			}
		case ':':
			if inSingle || inDouble {
				continue
			}
			if i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
				k := strings.TrimSpace(s[:i])
				v := strings.TrimSpace(s[i+1:])
				if len(k) >= 2 && ((k[0] == '"' && k[len(k)-1] == '"') || (k[0] == '\'' && k[len(k)-1] == '\'')) {
					kn := parseScalar(k, span.Span{})
					return kn.Value, true, v, i, true
				}
				return k, false, v, i, true
			}
		}
	}
	return "", false, "", 0, false
}

func isBlockScalar(s string) bool {
	return s == "|" || s == ">" || s == "|-" || s == ">-" || s == "|+" || s == ">+"
}

func parseBlockScalar(raws []string, lines []yline, idx *int, keyLine yline, header, file string) (*Node, error) {
	style := header[0]
	chomp := byte(0)
	if len(header) > 1 {
		chomp = header[1]
	}
	start := keyLine.rawIdx + 1
	end := start
	blockIndent := -1
	for end < len(raws) {
		raw := strings.TrimRight(raws[end], " \t")
		trimmed := strings.TrimSpace(raw)
		ind := 0
		for ind < len(raw) && raw[ind] == ' ' {
			ind++
		}
		if trimmed == "" {
			end++
			continue
		}
		if ind <= keyLine.indent {
			break
		}
		if blockIndent < 0 || ind < blockIndent {
			blockIndent = ind
		}
		end++
	}
	// Trim trailing blank lines from the block.
	last := end - 1
	for last >= start && strings.TrimSpace(raws[last]) == "" {
		last--
	}
	if blockIndent < 0 {
		blockIndent = keyLine.indent + 2
	}
	var content []string
	for i := start; i <= last; i++ {
		raw := strings.TrimRight(raws[i], " \t")
		if strings.TrimSpace(raw) == "" {
			content = append(content, "")
			continue
		}
		if len(raw) >= blockIndent {
			content = append(content, raw[blockIndent:])
		} else {
			content = append(content, strings.TrimLeft(raw, " "))
		}
	}
	var value string
	if style == '|' {
		value = strings.Join(content, "\n")
		if chomp != '-' {
			value += "\n"
		}
	} else {
		var b strings.Builder
		prevBlank := false
		for i, line := range content {
			if strings.TrimSpace(line) == "" {
				if i > 0 {
					b.WriteString("\n")
				}
				prevBlank = true
				continue
			}
			if b.Len() > 0 && !prevBlank {
				b.WriteString(" ")
			}
			b.WriteString(line)
			prevBlank = false
		}
		value = b.String()
		if chomp != '-' {
			value += "\n"
		}
	}
	// Advance structural lines past everything consumed.
	for *idx < len(lines) && lines[*idx].rawIdx <= end-1 {
		*idx++
	}
	return &Node{
		Kind:   ScalarNode,
		Value:  value,
		Raw:    value,
		Quoted: true,
		Style:  style,
		Span:   span.New(file, keyLine.num, keyLine.indent+1),
	}, nil
}

func parseInlineValue(s string, sp span.Span) (*Node, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return &Node{Kind: ScalarNode, Null: true, Span: sp}, nil
	}
	switch s[0] {
	case '[':
		if !strings.HasSuffix(s, "]") {
			return nil, &ParseError{Msg: "unterminated flow sequence", Span: sp}
		}
		items, err := splitFlow(s[1 : len(s)-1])
		if err != nil {
			return nil, &ParseError{Msg: err.Error(), Span: sp}
		}
		n := &Node{Kind: SequenceNode, Span: sp}
		for _, item := range items {
			if strings.TrimSpace(item) == "" {
				continue
			}
			child, err := parseInlineValue(item, sp)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, child)
		}
		return n, nil
	case '{':
		if !strings.HasSuffix(s, "}") {
			return nil, &ParseError{Msg: "unterminated flow mapping", Span: sp}
		}
		items, err := splitFlow(s[1 : len(s)-1])
		if err != nil {
			return nil, &ParseError{Msg: err.Error(), Span: sp}
		}
		n := &Node{Kind: MappingNode, Span: sp}
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			k, kq, v, _, ok := splitKeyValue(item)
			if !ok {
				return nil, &ParseError{Msg: fmt.Sprintf("invalid flow mapping entry %q", item), Span: sp}
			}
			key := &Node{Kind: ScalarNode, Value: k, Quoted: kq, Span: sp}
			val, err := parseInlineValue(v, sp)
			if err != nil {
				return nil, err
			}
			n.Pairs = append(n.Pairs, Pair{Key: key, Value: val})
		}
		return n, nil
	}
	return parseScalar(s, sp), nil
}

func splitFlow(s string) ([]string, error) {
	var out []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				if inSingle && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					inSingle = !inSingle
				}
			}
		case '"':
			if !inSingle && (i == 0 || s[i-1] != '\\') {
				inDouble = !inDouble
			}
		case '[', '{':
			if !inSingle && !inDouble {
				depth++
			}
		case ']', '}':
			if !inSingle && !inDouble {
				depth--
			}
		case ',':
			if !inSingle && !inDouble && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quoted string in flow value")
	}
	out = append(out, s[start:])
	return out, nil
}

func parseScalar(s string, sp span.Span) *Node {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		raw := s[1 : len(s)-1]
		return &Node{Kind: ScalarNode, Value: unescapeDouble(raw), Raw: raw, Quoted: true, Style: '"', Span: sp}
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		raw := s[1 : len(s)-1]
		return &Node{Kind: ScalarNode, Value: strings.ReplaceAll(raw, "''", "'"), Raw: raw, Quoted: true, Style: '\'', Span: sp}
	}
	lower := strings.ToLower(s)
	if s == "~" || lower == "null" {
		return &Node{Kind: ScalarNode, Null: true, Raw: s, Span: sp}
	}
	return &Node{Kind: ScalarNode, Value: s, Raw: s, Span: sp}
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case '0':
			b.WriteByte(0)
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'v':
			b.WriteByte('\v')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case 'e':
			b.WriteByte(0x1b)
		case ' ':
			b.WriteByte(' ')
		case '"':
			b.WriteByte('"')
		case '/':
			b.WriteByte('/')
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte('x')
		case 'u':
			if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += 4
					continue
				}
			}
			b.WriteString("\\u")
		case 'U':
			if i+8 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+9], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += 8
					continue
				}
			}
			b.WriteString("\\U")
		default:
			// Keep unknown escapes intact. The escaping pass reports them.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func startsFlow(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "[") || strings.HasPrefix(s, "{")
}

func flowBalanced(s string) bool {
	depth := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				if inSingle && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					inSingle = !inSingle
				}
			}
		case '"':
			if !inSingle && (i == 0 || s[i-1] != '\\') {
				inDouble = !inDouble
			}
		case '[', '{':
			if !inSingle && !inDouble {
				depth++
			}
		case ']', '}':
			if !inSingle && !inDouble {
				depth--
			}
		}
	}
	return depth == 0 && !inSingle && !inDouble
}

// collectFlow joins a flow collection that spans multiple lines.
func collectFlow(lines []yline, idx *int, parentIndent int, text string) string {
	if !startsFlow(text) || flowBalanced(text) {
		return text
	}
	for *idx < len(lines) && lines[*idx].indent > parentIndent {
		text += " " + strings.TrimSpace(lines[*idx].text)
		*idx++
		if flowBalanced(text) {
			break
		}
	}
	return text
}

func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				if inSingle && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					inSingle = !inSingle
				}
			}
		case '"':
			if !inSingle && (i == 0 || s[i-1] != '\\') {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return strings.TrimRight(s, " \t")
}
