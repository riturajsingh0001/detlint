package eval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Record is one decoded log event.
type Record map[string]any

// DecodeFile reads JSONL, NDJSON, or a JSON array of objects.
func DecodeFile(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Decode(data, path)
}

// Decode parses sample/log bytes.
func Decode(data []byte, name string) ([]Record, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out := make([]Record, 0, len(arr))
		for _, m := range arr {
			out = append(out, Record(m))
		}
		return out, nil
	}
	// A pretty-printed single object is valid input too.
	if trimmed[0] == '{' {
		var one map[string]any
		if err := json.Unmarshal(trimmed, &one); err == nil {
			return []Record{Record(one)}, nil
		}
	}

	var out []Record
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		out = append(out, Record(m))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// DecodeDir reads every JSON/JSONL/log sample under a file or directory.
func DecodeDir(root string) ([]Record, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return DecodeFile(root)
	}
	var records []Record
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json", ".jsonl", ".ndjson", ".log", ".txt":
			recs, err := DecodeFile(p)
			if err != nil {
				return err
			}
			records = append(records, recs...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

// Lookup resolves a field name. It supports dotted paths and falls back to
// case-insensitive matching at every level.
func Lookup(rec Record, name string) (any, bool) {
	if v, ok := rec[name]; ok {
		return v, true
	}
	if !strings.Contains(name, ".") {
		return lookupCI(rec, name)
	}
	parts := strings.Split(name, ".")
	var cur any = map[string]any(rec)
	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			v, ok = lookupCIMap(m, part)
			if !ok {
				return nil, false
			}
		}
		cur = v
	}
	return cur, true
}

func lookupCI(rec Record, name string) (any, bool) {
	v, ok := lookupCIMap(map[string]any(rec), name)
	return v, ok
}

func lookupCIMap(m map[string]any, name string) (any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

// Flatten returns dotted keys for nested objects.
func Flatten(rec Record) map[string]any {
	out := map[string]any{}
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			if child, ok := v.(map[string]any); ok {
				walk(key, child)
				continue
			}
			out[key] = v
		}
	}
	walk("", map[string]any(rec))
	return out
}

// AsString converts a decoded value to a string.
func AsString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10), true
		}
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case json.Number:
		return x.String(), true
	case nil:
		return "", false
	default:
		return fmt.Sprint(x), true
	}
}

// AsFloat converts a decoded value to a number.
func AsFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

// AsBool converts a decoded value to a bool.
func AsBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		return b, err == nil
	case float64:
		return x != 0, true
	default:
		return false, false
	}
}
