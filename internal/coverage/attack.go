package coverage

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

//go:embed attack.json
var attackData []byte

// Technique is one ATT&CK technique.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Tactic is one ATT&CK tactic and its techniques.
type Tactic struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Techniques []Technique `json:"techniques"`
}

type matrixFile struct {
	Tactics []Tactic `json:"tactics"`
}

// Matrix is the embedded ATT&CK subset.
type Matrix struct {
	Tactics      []Tactic
	byID         map[string]Technique
	tacticByName map[string]Tactic
}

// Default returns the embedded matrix.
func Default() *Matrix {
	m, err := ParseMatrix(attackData)
	if err != nil {
		panic("detlint: embedded ATT&CK matrix is invalid: " + err.Error())
	}
	return m
}

// ParseMatrix parses an ATT&CK matrix JSON document.
func ParseMatrix(data []byte) (*Matrix, error) {
	var f matrixFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	m := &Matrix{Tactics: f.Tactics, byID: map[string]Technique{}, tacticByName: map[string]Tactic{}}
	for ti := range m.Tactics {
		t := &m.Tactics[ti]
		m.tacticByName[strings.ToLower(t.Name)] = *t
		m.tacticByName[strings.ToLower(t.ID)] = *t
		for i := range t.Techniques {
			t.Techniques[i].ID = strings.ToUpper(t.Techniques[i].ID)
			m.byID[t.Techniques[i].ID] = t.Techniques[i]
		}
	}
	return m, nil
}

// Technique looks up a technique by ID.
func (m *Matrix) Technique(id string) (Technique, bool) {
	t, ok := m.byID[strings.ToUpper(id)]
	return t, ok
}

// Tactic looks up a tactic by name or ID.
func (m *Matrix) Tactic(name string) (Tactic, bool) {
	t, ok := m.tacticByName[strings.ToLower(strings.TrimSpace(name))]
	return t, ok
}

// TechniqueIDs returns all unique technique IDs sorted.
func (m *Matrix) TechniqueIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range m.Tactics {
		for _, tech := range t.Techniques {
			if !seen[tech.ID] {
				seen[tech.ID] = true
				out = append(out, tech.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TechniqueCoverage is coverage for one technique.
type TechniqueCoverage struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Rules []string `json:"rules,omitempty"`
}

// TacticCoverage is coverage for one tactic.
type TacticCoverage struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Covered    int                 `json:"covered"`
	Total      int                 `json:"total"`
	Techniques []TechniqueCoverage `json:"techniques"`
}

// Report is the full coverage report.
type Report struct {
	Tactics      []TacticCoverage `json:"tactics"`
	Covered      int              `json:"covered"`
	Total        int              `json:"total"`
	Rules        int              `json:"rules"`
	Untagged     []string         `json:"untagged,omitempty"`
	UnknownTags  []string         `json:"unknown_tags,omitempty"`
	TacticRules  map[string]int   `json:"tactic_rules,omitempty"`
	TechniqueMap map[string][]string
}

// Analyze maps rule tags onto the ATT&CK matrix.
func Analyze(files []*rule.File, m *Matrix) *Report {
	if m == nil {
		m = Default()
	}
	techRules := map[string][]string{}
	tacticRules := map[string]int{}
	var untagged []string
	unknown := map[string]bool{}
	ruleCount := 0

	for _, f := range files {
		r := f.Rule
		if r == nil {
			continue
		}
		ruleCount++
		name := r.Title
		if name == "" {
			name = r.ID
		}
		if name == "" {
			name = f.Path
		}
		found := false
		for _, tag := range r.Tags {
			lt := strings.ToLower(strings.TrimSpace(tag))
			if !strings.HasPrefix(lt, "attack.") {
				continue
			}
			rest := strings.TrimPrefix(lt, "attack.")
			if t, ok := m.Tactic(rest); ok {
				found = true
				tacticRules[t.ID]++
				continue
			}
			if strings.HasPrefix(rest, "t") {
				id := strings.ToUpper(rest)
				found = true
				if _, ok := m.Technique(id); !ok {
					unknown[id] = true
					continue
				}
				techRules[id] = appendUnique(techRules[id], name)
				continue
			}
		}
		if !found {
			untagged = append(untagged, name)
		}
	}

	rep := &Report{
		Rules:        ruleCount,
		Untagged:     untagged,
		TacticRules:  tacticRules,
		TechniqueMap: techRules,
	}
	for _, t := range m.Tactics {
		tc := TacticCoverage{ID: t.ID, Name: t.Name}
		for _, tech := range t.Techniques {
			tech.ID = strings.ToUpper(tech.ID)
			rules := techRules[tech.ID]
			if len(rules) > 0 {
				tc.Covered++
			}
			tc.Techniques = append(tc.Techniques, TechniqueCoverage{ID: tech.ID, Name: tech.Name, Rules: rules})
			tc.Total++
		}
		rep.Tactics = append(rep.Tactics, tc)
	}
	for _, id := range m.TechniqueIDs() {
		if len(techRules[id]) > 0 {
			rep.Covered++
		}
		rep.Total++
	}
	for id := range unknown {
		rep.UnknownTags = append(rep.UnknownTags, id)
	}
	sort.Strings(rep.UnknownTags)
	sort.Strings(rep.Untagged)
	return rep
}

// Filter returns a report restricted to one tactic name or ID.
func (r *Report) Filter(name string) *Report {
	if name == "" {
		return r
	}
	out := &Report{Rules: r.Rules, Untagged: r.Untagged, UnknownTags: r.UnknownTags, TacticRules: r.TacticRules, TechniqueMap: r.TechniqueMap}
	for _, t := range r.Tactics {
		if strings.EqualFold(t.Name, name) || strings.EqualFold(t.ID, name) {
			out.Tactics = append(out.Tactics, t)
			out.Covered += t.Covered
			out.Total += t.Total
		}
	}
	return out
}

// Percent returns coverage as a percentage.
func (r *Report) Percent() float64 {
	if r == nil || r.Total == 0 {
		return 0
	}
	return float64(r.Covered) / float64(r.Total) * 100
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// String is a compact summary.
func (r *Report) String() string {
	return fmt.Sprintf("%d/%d techniques (%.0f%%)", r.Covered, r.Total, r.Percent())
}
