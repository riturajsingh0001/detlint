// Package schema describes the log sources a rule can target.
package schema

import (
	"sort"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

// FieldType is a coarse type used for validation and suggestions.
type FieldType string

const (
	TypeString FieldType = "string"
	TypeInt    FieldType = "int"
	TypeFloat  FieldType = "float"
	TypeBool   FieldType = "bool"
	TypeIP     FieldType = "ip"
	TypeDate   FieldType = "datetime"
	TypeGUID   FieldType = "guid"
	TypeAny    FieldType = "any"
)

// Field describes one field in a log source.
type Field struct {
	Name        string    `json:"name"`
	Type        FieldType `json:"type,omitempty"`
	Enum        []string  `json:"enum,omitempty"`
	Required    bool      `json:"required,omitempty"`
	Description string    `json:"description,omitempty"`
}

// EventID documents a known event identifier.
type EventID struct {
	ID          int    `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// LogSource is a schema for one product/service pair.
type LogSource struct {
	Name        string    `json:"name"`
	Product     string    `json:"product,omitempty"`
	Service     string    `json:"service,omitempty"`
	Category    string    `json:"category,omitempty"`
	Description string    `json:"description,omitempty"`
	Fields      []Field   `json:"fields"`
	EventIDs    []EventID `json:"eventids,omitempty"`

	byName map[string]*Field
	lower  map[string]*Field
}

// Finalize builds lookup tables after loading.
func (s *LogSource) Finalize() {
	s.byName = make(map[string]*Field, len(s.Fields))
	s.lower = make(map[string]*Field, len(s.Fields))
	for i := range s.Fields {
		f := &s.Fields[i]
		if f.Type == "" {
			f.Type = TypeString
		}
		s.byName[f.Name] = f
		s.lower[strings.ToLower(f.Name)] = f
	}
}

// HasField reports an exact, case-sensitive field match.
func (s *LogSource) HasField(name string) bool {
	if s == nil {
		return false
	}
	if s.byName == nil {
		s.Finalize()
	}
	_, ok := s.byName[name]
	return ok
}

// Field returns a field by exact name.
func (s *LogSource) Field(name string) (Field, bool) {
	if s == nil {
		return Field{}, false
	}
	if s.byName == nil {
		s.Finalize()
	}
	f, ok := s.byName[name]
	if !ok {
		return Field{}, false
	}
	return *f, true
}

// FindCaseInsensitive returns the canonical name of a case-insensitive match.
func (s *LogSource) FindCaseInsensitive(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	if s.lower == nil {
		s.Finalize()
	}
	f, ok := s.lower[strings.ToLower(name)]
	if !ok {
		return "", false
	}
	return f.Name, true
}

// FieldNames returns all field names sorted.
func (s *LogSource) FieldNames() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.Fields))
	for _, f := range s.Fields {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// Suggest returns the closest field name, or "" when nothing is close.
func (s *LogSource) Suggest(name string) string {
	if s == nil {
		return ""
	}
	best, bestDist := "", 1<<30
	target := strings.ToLower(name)
	for _, f := range s.Fields {
		d := Levenshtein(target, strings.ToLower(f.Name))
		if d < bestDist {
			best, bestDist = f.Name, d
		}
	}
	limit := len(name) / 3
	if limit < 2 {
		limit = 2
	}
	if bestDist <= limit {
		return best
	}
	return ""
}

// Registry is a collection of schemas.
type Registry struct {
	Sources []*LogSource `json:"sources"`
}

// NewRegistry returns a registry with finalized schemas.
func NewRegistry(sources ...*LogSource) *Registry {
	for _, s := range sources {
		s.Finalize()
	}
	return &Registry{Sources: sources}
}

// Match picks the best schema for a rule's logsource. It returns nil when the
// rule does not identify a log source.
func (r *Registry) Match(ls rule.LogSource) *LogSource {
	if r == nil {
		return nil
	}
	if ls.Product == "" && ls.Service == "" && ls.Category == "" {
		return nil
	}
	var best *LogSource
	bestScore := -1 << 30
	for _, s := range r.Sources {
		score := 0
		if ls.Product != "" {
			if !strings.EqualFold(s.Product, ls.Product) {
				continue
			}
			score += 8
		}
		if ls.Service != "" {
			if !strings.EqualFold(s.Service, ls.Service) {
				continue
			}
			score += 4
		} else if s.Service != "" {
			score--
		}
		if ls.Category != "" {
			if !strings.EqualFold(s.Category, ls.Category) {
				continue
			}
			score += 2
		}
		if score > bestScore {
			best, bestScore = s, score
		}
	}
	return best
}

// Find returns a schema by name.
func (r *Registry) Find(name string) *LogSource {
	if r == nil {
		return nil
	}
	for _, s := range r.Sources {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

// Products returns the unique products in the registry.
func (r *Registry) Products() []string {
	if r == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range r.Sources {
		if s.Product != "" && !seen[s.Product] {
			seen[s.Product] = true
			out = append(out, s.Product)
		}
	}
	sort.Strings(out)
	return out
}

// Levenshtein computes edit distance.
func Levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
