package schema

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

//go:embed embed/*.yaml
var embedded embed.FS

// Default returns the schemas bundled with detlint.
func Default() *Registry {
	reg, err := LoadFS(embedded, "embed")
	if err != nil {
		panic("detlint: bundled schemas are invalid: " + err.Error())
	}
	return reg
}

// LoadDir loads every .yaml/.yml schema in a directory.
func LoadDir(dir string) (*Registry, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		s, err := LoadFile(dir)
		if err != nil {
			return nil, err
		}
		return NewRegistry(s), nil
	}
	return LoadFS(os.DirFS(dir), ".")
}

// LoadFS loads schemas from any fs.FS.
func LoadFS(fsys fs.FS, root string) (*Registry, error) {
	var paths []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(path.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no schema files found under %s", root)
	}
	var sources []*LogSource
	for _, p := range paths {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		s, err := Parse(data, p)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return NewRegistry(sources...), nil
}

// LoadFile loads one schema file.
func LoadFile(path string) (*LogSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse converts schema YAML into a LogSource.
func Parse(data []byte, file string) (*LogSource, error) {
	root, err := rule.ParseYAML(data, file)
	if err != nil {
		return nil, err
	}
	if root.Kind != rule.MappingNode {
		return nil, fmt.Errorf("%s: schema must be a mapping", file)
	}
	s := &LogSource{
		Name:        scalar(root, "name"),
		Product:     scalar(root, "product"),
		Service:     scalar(root, "service"),
		Category:    scalar(root, "category"),
		Description: scalar(root, "description"),
	}
	if s.Name == "" {
		s.Name = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	}
	if s.Product == "" && s.Service == "" && s.Category == "" {
		return nil, fmt.Errorf("%s: schema %q must set product, service, or category", file, s.Name)
	}

	fieldsNode := root.Get("fields")
	if fieldsNode == nil {
		return nil, fmt.Errorf("%s: schema %q has no fields", file, s.Name)
	}
	switch fieldsNode.Kind {
	case rule.SequenceNode:
		for _, item := range fieldsNode.Items {
			if item.Kind != rule.MappingNode {
				return nil, fmt.Errorf("%s: fields must be mappings", file)
			}
			f := parseField(item)
			if f.Name == "" {
				return nil, fmt.Errorf("%s: field without a name", file)
			}
			s.Fields = append(s.Fields, f)
		}
	case rule.MappingNode:
		for _, p := range fieldsNode.Pairs {
			f := Field{Name: p.Key.Value, Type: TypeString}
			if p.Value.Kind == rule.MappingNode {
				f = parseField(p.Value)
				f.Name = p.Key.Value
			} else if p.Value.Kind == rule.ScalarNode && p.Value.Value != "" {
				f.Type = FieldType(strings.ToLower(p.Value.Value))
			}
			s.Fields = append(s.Fields, f)
		}
	default:
		return nil, fmt.Errorf("%s: fields must be a sequence or mapping", file)
	}
	if len(s.Fields) == 0 {
		return nil, fmt.Errorf("%s: schema %q has no fields", file, s.Name)
	}

	if ev := root.Get("eventids"); ev != nil && ev.Kind == rule.SequenceNode {
		for _, item := range ev.Items {
			switch item.Kind {
			case rule.ScalarNode:
				if id, ok := atoi(item.Value); ok {
					s.EventIDs = append(s.EventIDs, EventID{ID: id})
				}
			case rule.MappingNode:
				id, _ := atoi(scalar(item, "id"))
				s.EventIDs = append(s.EventIDs, EventID{
					ID:          id,
					Name:        scalar(item, "name"),
					Description: scalar(item, "description"),
				})
			}
		}
	}
	s.Finalize()
	return s, nil
}

func parseField(n *rule.Node) Field {
	f := Field{
		Name:        scalar(n, "name"),
		Type:        FieldType(strings.ToLower(scalar(n, "type"))),
		Description: scalar(n, "description"),
	}
	if f.Type == "" {
		f.Type = TypeString
	}
	if req := n.Get("required"); req != nil {
		f.Required = strings.EqualFold(req.Value, "true")
	}
	if en := n.Get("enum"); en != nil {
		for _, it := range en.Scalars() {
			f.Enum = append(f.Enum, it.Value)
		}
		if en.Kind == rule.ScalarNode && !en.IsNull() {
			f.Enum = append(f.Enum, en.Value)
		}
	}
	return f
}

func scalar(n *rule.Node, key string) string {
	v := n.Get(key)
	if v == nil || v.Kind != rule.ScalarNode {
		return ""
	}
	return v.Value
}

func atoi(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
