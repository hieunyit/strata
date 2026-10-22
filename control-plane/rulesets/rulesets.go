// Package rulesets holds the built-in rule sets (RS-3,
// docs/plan/rule-sets.md): named filters on the rules' metadata a policy
// gives an action (block, log, off). catalog.yaml is a copy of
// rules/sets/catalog.yaml (a test keeps them equal), built into the
// binary so that a policy's sets mean the same wherever it is compiled.
package rulesets

import (
	_ "embed"
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogYAML []byte

// Filter: a rule is in the set when it matches every non-empty list (Tags:
// any of them), or is one of IDs.
type Filter struct {
	Sources     []string `yaml:"sources" json:"sources,omitempty"`
	AttackTypes []string `yaml:"attack_types" json:"attack_types,omitempty"`
	Tags        []string `yaml:"tags" json:"tags,omitempty"`
	IDs         []uint32 `yaml:"ids" json:"ids,omitempty"`
}

// Matches a rule of `source`, `attackType`, `tags`.
func (f Filter) Matches(id uint32, source, attackType string, tags []string) bool {
	if slices.Contains(f.IDs, id) {
		return true
	}
	if len(f.Sources) == 0 && len(f.AttackTypes) == 0 && len(f.Tags) == 0 {
		return false
	}
	if len(f.Sources) > 0 && !slices.Contains(f.Sources, source) {
		return false
	}
	if len(f.AttackTypes) > 0 && !slices.Contains(f.AttackTypes, attackType) {
		return false
	}
	if len(f.Tags) > 0 && !slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(f.Tags, t) }) {
		return false
	}
	return true
}

// Set is a built-in rule set.
type Set struct {
	Name string `yaml:"name"`
	// Group: attack, signature, technology or bot.
	Group string `yaml:"group"`
	// Class of a bot set: malicious, automation, untrusted or trusted.
	Class string            `yaml:"class"`
	Title map[string]string `yaml:"title"`
	Match Filter            `yaml:"match"`
}

var sets []Set

func init() {
	var doc struct {
		Version int   `yaml:"version"`
		Sets    []Set `yaml:"sets"`
	}
	if err := yaml.Unmarshal(catalogYAML, &doc); err != nil || doc.Version != 1 {
		panic(fmt.Sprintf("rulesets: catalog.yaml: version %d: %v", doc.Version, err))
	}
	sets = doc.Sets
}

// All built-in sets, in the catalog's order.
func All() []Set { return slices.Clone(sets) }

// Get the built-in set name.
func Get(name string) (Set, bool) {
	for _, s := range sets {
		if s.Name == name {
			return s, true
		}
	}
	return Set{}, false
}
