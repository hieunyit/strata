// Package rulecat is the catalog of the rules the control plane compiles
// into bundles (the -rules IR files): what the UI shows next to a Rule ID
// in a decision trace (W09-F-01), such as the author of a Sigma rule.
package rulecat

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Rule is what the decision trace shows about a rule.
type Rule struct {
	Name     string `json:"name"`
	Layer    string `json:"layer,omitempty"`
	Severity string `json:"severity,omitempty"`
	Source   string `json:"source,omitempty"`
	Author   string `json:"author,omitempty"`
	License  string `json:"license,omitempty"`
}

// Catalog maps Rule IDs to their metadata. The zero value is empty.
type Catalog struct {
	rules map[uint32]Rule
}

type irRule struct {
	ID       uint32         `yaml:"id"`
	Name     string         `yaml:"name"`
	Layer    string         `yaml:"layer"`
	Severity string         `yaml:"severity"`
	Metadata map[string]any `yaml:"metadata"`
}

type irDoc struct {
	Rules []irRule `yaml:"rules"`
	Rule  *irRule  `yaml:"rule"`
}

// Load reads IR files (YAML or JSON: a ruleset with "rules", or one
// authored rule under "rule"); a later file wins for a repeated ID.
func Load(paths []string) (*Catalog, error) {
	c := &Catalog{rules: map[uint32]Rule{}}
	for _, p := range paths {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("rulecat: %w", err)
		}
		var doc irDoc
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("rulecat: %s: %w", p, err)
		}
		if doc.Rule != nil {
			doc.Rules = append(doc.Rules, *doc.Rule)
		}
		for _, r := range doc.Rules {
			if r.ID == 0 {
				continue
			}
			c.rules[r.ID] = Rule{
				Name: r.Name, Layer: r.Layer, Severity: r.Severity,
				Source: str(r.Metadata["source"]), Author: str(r.Metadata["author"]),
				License: str(r.Metadata["license"]),
			}
		}
	}
	return c, nil
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// Len is the number of rules in the catalog.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.rules)
}

// For returns the catalog entries of ids, keyed by the decimal Rule ID
// (JSON object keys); IDs the catalog does not know are left out.
func (c *Catalog) For(ids []uint32) map[string]Rule {
	if c == nil || len(c.rules) == 0 {
		return nil
	}
	out := map[string]Rule{}
	for _, id := range ids {
		if r, ok := c.rules[id]; ok {
			out[strconv.FormatUint(uint64(id), 10)] = r
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
