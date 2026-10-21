// Package rulecat is the catalog of the rules the control plane compiles
// into bundles (the -rules IR files): what the UI shows next to a Rule ID
// in a decision trace (W09-F-01), such as the author of a Sigma rule.
package rulecat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is what the decision trace shows about a rule.
type Rule struct {
	Version    string   `json:"version,omitempty"`
	UpstreamID string   `json:"upstream_id,omitempty"`
	AttackType string   `json:"attack_type,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	ReviewBy   string   `json:"review_by,omitempty"`
	Pack       string   `json:"pack"`
	Digest     string   `json:"digest"`
	Paranoia   int      `json:"paranoia_level,omitempty"`
	Plugin     string   `json:"plugin,omitempty"`
	Name       string   `json:"name"`
	Layer      string   `json:"layer,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Source     string   `json:"source,omitempty"`
	Author     string   `json:"author,omitempty"`
	License    string   `json:"license,omitempty"`
}

// Catalog maps Rule IDs to their metadata. The zero value is empty.
type Catalog struct {
	rules map[uint32]Rule
}

type irRule struct {
	Digest   string         `yaml:"-"`
	Paranoia int            `yaml:"paranoia_level"`
	ID       uint32         `yaml:"id"`
	Name     string         `yaml:"name"`
	Layer    string         `yaml:"layer"`
	Severity string         `yaml:"severity"`
	Metadata map[string]any `yaml:"metadata"`
}

type irDoc struct {
	Ruleset struct {
		Version string `yaml:"version"`
	} `yaml:"ruleset"`
	Rules []irRule `yaml:"rules"`
	Rule  *irRule  `yaml:"rule"`
}

// Load reads IR files (YAML or JSON: a ruleset with "rules", or one
// authored rule under "rule"); a later file wins for a repeated ID.
func Load(paths []string) (*Catalog, error) {
	c := &Catalog{rules: map[uint32]Rule{}}
	if len(paths) > 128 {
		return nil, fmt.Errorf("rulecat: at most 128 input files")
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("rulecat: %w", err)
		}
		raw, err := io.ReadAll(io.LimitReader(f, 64<<20+1))
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if len(raw) > 64<<20 {
			return nil, fmt.Errorf("rulecat: input exceeds 64 MiB")
		}
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
		if c.Len()+len(doc.Rules) > 100000 {
			return nil, fmt.Errorf("rulecat: too many rules")
		}
		for _, r := range doc.Rules {
			if r.ID == 0 {
				continue
			}
			c.rules[r.ID] = Rule{
				Name: bounded(r.Name, 200), Layer: bounded(r.Layer, 32), Severity: bounded(r.Severity, 32),
				Version: first(str(r.Metadata["upstream_version"]), doc.Ruleset.Version, str(r.Metadata["revision"])), UpstreamID: bounded(str(r.Metadata["upstream_id"]), 128),
				AttackType: bounded(str(r.Metadata["attack_type"]), 64), CVEs: ruleCVEs(r), Owner: bounded(str(r.Metadata["owner"]), 128), ReviewBy: bounded(str(r.Metadata["review_by"]), 10),
				Pack: pack(str(r.Metadata["source"])), Digest: r.Digest, Paranoia: r.Paranoia, Plugin: bounded(str(r.Metadata["plugin"]), 32),
				Source: bounded(str(r.Metadata["source"]), 64), Author: bounded(str(r.Metadata["author"]), 256),
				License: bounded(str(r.Metadata["license"]), 128),
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

func (r *irRule) UnmarshalYAML(n *yaml.Node) error {
	type plain irRule
	if err := n.Decode((*plain)(r)); err != nil {
		return err
	}
	var raw map[string]any
	if err := n.Decode(&raw); err != nil {
		return err
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	r.Digest = hex.EncodeToString(sum[:])
	return nil
}
func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return bounded(v, 64)
		}
	}
	return ""
}
func pack(source string) string {
	switch source {
	case "sigma", "et-open", "crawler-user-agents":
		return "signature"
	}
	return "core"
}

var cvePattern = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,19}\b`)

func ruleCVEs(r irRule) []string {
	text := bounded(r.Name, 200) + " " + bounded(str(r.Metadata["tags"]), 4096) + " " + bounded(str(r.Metadata["cve"]), 256)
	found := map[string]bool{}
	for _, v := range cvePattern.FindAllString(text, 16) {
		found[strings.ToUpper(v)] = true
	}
	out := []string{}
	for v := range found {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

type Entry struct {
	ID uint32 `json:"id"`
	Rule
}

func (c *Catalog) Entries() []Entry {
	out := []Entry{}
	if c == nil {
		return out
	}
	for id, r := range c.rules {
		out = append(out, Entry{id, r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (c *Catalog) Digest() string {
	raw, _ := json.Marshal(c.Entries())
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
