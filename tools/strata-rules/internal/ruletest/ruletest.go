// Package ruletest runs the match / no_match requests of every rule file
// (rules/schema/rule.schema.json) through libstrata (W04-S-01).
package ruletest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Status of one rule.
type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	// Skip: the rule uses something the engine does not evaluate yet, so
	// it would never match; its tests say nothing.
	Skip Status = "SKIP"
)

// Result of one rule's tests.
type Result struct {
	Rule     uint32
	File     string
	Status   Status
	Reason   string   // for Skip
	Failures []string // for Fail
	Cases    int
}

// File is a parsed rule file.
type File struct {
	Path  string
	Rule  map[string]any
	ID    uint32
	Tests struct {
		Match   []map[string]any `json:"match"`
		NoMatch []map[string]any `json:"no_match"`
	}
}

// Load reads the rule files under dir (files with a top-level "rule";
// IR rulesets and dir/schema are left out).
func Load(dir string) ([]File, error) {
	var out []File
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != dir && d.Name() == "schema" {
			return filepath.SkipDir
		}
		if d.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		rule, ok := doc["rule"].(map[string]any)
		if !ok {
			return nil
		}
		f := File{Path: p, Rule: rule}
		if id, ok := rule["id"].(int); ok {
			f.ID = uint32(id)
		}
		b, _ := json.Marshal(doc["tests"])
		if err := json.Unmarshal(b, &f.Tests); err != nil {
			return fmt.Errorf("%s: tests: %w", p, err)
		}
		out = append(out, f)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// Unsupported lists what of rule the engine does not evaluate.
func Unsupported(rule map[string]any, caps runner.Capabilities) []string {
	var miss []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			miss = append(miss, s)
		}
	}
	m, _ := rule["match"].(map[string]any)
	for _, k := range []string{"all", "any"} {
		conds, _ := m[k].([]any)
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			if op, _ := cm["operator"].(map[string]any); op != nil {
				if t, _ := op["type"].(string); t != "" && !runner.Has(caps.Operators, t) {
					add("operator " + t)
				}
			}
			ts, _ := cm["transforms"].([]any)
			for _, t := range ts {
				if s, _ := t.(string); s != "" && !runner.Has(caps.Transforms, s) {
					add("transform " + s)
				}
			}
			targets, _ := cm["targets"].([]any)
			for _, t := range targets {
				tm, _ := t.(map[string]any)
				if v, _ := tm["var"].(string); v != "" && !runner.Has(caps.Vars, v) {
					add("target " + v)
				}
			}
		}
	}
	return miss
}

// IRDoc wraps rules into one IR document (docs/spec/ir.schema.json).
func IRDoc(name string, rules []map[string]any) ([]byte, error) {
	return json.Marshal(map[string]any{
		"ir_version": 1,
		"ruleset":    map[string]any{"name": name, "version": "1"},
		"rules":      rules,
	})
}

// ToRequest converts a test request of the rule schema.
func ToRequest(id string, m map[string]any) runner.Request {
	r := runner.Request{ID: id}
	r.Method, _ = m["method"].(string)
	r.URI, _ = m["uri"].(string)
	r.Body, _ = m["body"].(string)
	r.RemoteAddr, _ = m["remote_addr"].(string)
	if h, ok := m["headers"].(map[string]any); ok {
		r.Headers = h
	}
	return r
}

// Run compiles every rule file into one bundle and checks its tests.
func Run(tools runner.Tools, files []File) ([]Result, error) {
	caps, err := tools.Capabilities()
	if err != nil {
		return nil, err
	}
	results := make([]Result, len(files))
	var rules []map[string]any
	var reqs []runner.Request
	for i, f := range files {
		results[i] = Result{Rule: f.ID, File: f.Path, Cases: len(f.Tests.Match) + len(f.Tests.NoMatch)}
		if miss := Unsupported(f.Rule, caps); len(miss) > 0 {
			results[i].Status, results[i].Reason = Skip, "engine lacks "+strings.Join(miss, ", ")
			continue
		}
		rules = append(rules, f.Rule)
		for j, m := range f.Tests.Match {
			reqs = append(reqs, ToRequest(fmt.Sprintf("%d/match/%d", i, j), m))
		}
		for j, m := range f.Tests.NoMatch {
			reqs = append(reqs, ToRequest(fmt.Sprintf("%d/no_match/%d", i, j), m))
		}
	}
	if len(rules) == 0 {
		return results, nil
	}
	doc, err := IRDoc("strata-rules-test", rules)
	if err != nil {
		return nil, err
	}
	b, err := tools.Build([][]byte{doc})
	if err != nil {
		return nil, err
	}
	defer b.Close()
	verdicts, err := tools.Eval(b, reqs)
	if err != nil {
		return nil, err
	}
	for _, v := range verdicts {
		parts := strings.SplitN(v.ID, "/", 3)
		i, _ := strconv.Atoi(parts[0])
		f := &files[i]
		want := parts[1] == "match"
		if v.Matched(f.ID) != want {
			n, _ := strconv.Atoi(parts[2])
			sample := f.Tests.NoMatch
			verb := "matched"
			if want {
				sample, verb = f.Tests.Match, "did not match"
			}
			results[i].Failures = append(results[i].Failures, fmt.Sprintf("%s %s %s", parts[1], describe(sample[n]), verb))
		}
	}
	for i := range results {
		if results[i].Status == "" {
			results[i].Status = Pass
			if len(results[i].Failures) > 0 {
				results[i].Status = Fail
			}
		}
	}
	return results, nil
}

func describe(m map[string]any) string {
	method, _ := m["method"].(string)
	if method == "" {
		method = "GET"
	}
	uri, _ := m["uri"].(string)
	if name, _ := m["name"].(string); name != "" {
		return fmt.Sprintf("%q (%s %s)", name, method, uri)
	}
	return method + " " + uri
}
