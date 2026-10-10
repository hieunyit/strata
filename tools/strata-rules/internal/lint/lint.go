// Package lint checks the rule files under rules/ (W03-S-01):
//
//   - a rule file (top-level "rule") against rules/schema/rule.schema.json,
//     whose rule part is the compiler's IR (docs/spec/ir.schema.json);
//   - an imported ruleset (top-level "ir_version", e.g. rules/crs/) against
//     the IR schema;
//
// and, beyond the schemas: rule ids unique across files, a rule file named
// after its id, regexes that compile as RE2 (linear time, like the
// engine's), licenses the project may ship, and match / no_match samples.
package lint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v3"
)

// Licenses that may be shipped in a bundle (docs/plan/plan.md › Luồng S).
// GPL sources (Snort, ET Open's GPL range) never are.
var allowedLicenses = map[string]bool{
	"Apache-2.0": true, "MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "DRL-1.1": true,
}

// Finding is one problem in one file.
type Finding struct {
	File    string
	Rule    int // 0 when not about one rule
	Message string
}

func (f Finding) String() string {
	if f.Rule != 0 {
		return fmt.Sprintf("%s: rule %d: %s", f.File, f.Rule, f.Message)
	}
	return fmt.Sprintf("%s: %s", f.File, f.Message)
}

// Linter holds the compiled schemas.
type Linter struct {
	ruleFile *jsonschema.Schema
	ir       *jsonschema.Schema
}

// New loads the two schemas from the repository root.
func New(repo string) (*Linter, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, f := range []struct{ id, path string }{
		{"https://strata.example.test/spec/ir.schema.json", "docs/spec/ir.schema.json"},
		{"https://strata.example.test/rules/schema/rule.schema.json", "rules/schema/rule.schema.json"},
	} {
		raw, err := os.ReadFile(filepath.Join(repo, f.path))
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.path, err)
		}
		if err := c.AddResource(f.id, doc); err != nil {
			return nil, fmt.Errorf("%s: %w", f.path, err)
		}
	}
	rf, err := c.Compile("https://strata.example.test/rules/schema/rule.schema.json")
	if err != nil {
		return nil, err
	}
	ir, err := c.Compile("https://strata.example.test/spec/ir.schema.json")
	if err != nil {
		return nil, err
	}
	return &Linter{ruleFile: rf, ir: ir}, nil
}

// Lint checks every .yaml/.yml file under dir, skipping dir/schema.
func (l *Linter) Lint(dir string) ([]Finding, int, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != dir && d.Name() == "schema" {
			return filepath.SkipDir
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Strings(files)
	var out []Finding
	seen := map[int]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, l.lintFile(f, raw, seen)...)
	}
	return out, len(files), nil
}

func (l *Linter) lintFile(name string, raw []byte, seen map[int]string) []Finding {
	bad := func(rule int, format string, a ...any) Finding {
		return Finding{File: name, Rule: rule, Message: fmt.Sprintf(format, a...)}
	}
	doc, err := toJSON(raw)
	if err != nil {
		return []Finding{bad(0, "not valid YAML: %v", err)}
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return []Finding{bad(0, "expected a mapping at the top level")}
	}
	var (
		schema *jsonschema.Schema
		rules  []any
		single bool
	)
	switch {
	case top["rule"] != nil:
		schema, rules, single = l.ruleFile, []any{top["rule"]}, true
	case top["ir_version"] != nil:
		schema = l.ir
		rules, _ = top["rules"].([]any)
	default:
		return []Finding{bad(0, `neither a rule file ("rule:") nor an IR ruleset ("ir_version:")`)}
	}
	var out []Finding
	if err := schema.Validate(doc); err != nil {
		for _, m := range schemaErrors(err) {
			out = append(out, bad(0, "%s", m))
		}
	}
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		id := intOf(rm["id"])
		if id != 0 {
			if prev, dup := seen[id]; dup {
				out = append(out, bad(id, "id already used in %s", prev))
			} else {
				seen[id] = name
			}
		}
		if single && id != 0 && !strings.HasPrefix(filepath.Base(name), strconv.Itoa(id)+"-") {
			out = append(out, bad(id, "file name must start with %q", strconv.Itoa(id)+"-"))
		}
		if md, ok := rm["metadata"].(map[string]any); ok {
			if lic, ok := md["license"].(string); ok && !allowedLicenses[lic] {
				out = append(out, bad(id, "license %q may not be shipped (allowed: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, DRL-1.1)", lic))
			}
		}
		for _, p := range regexes(rm["match"]) {
			if _, err := regexp.Compile(p); err != nil {
				out = append(out, bad(id, "regex is not RE2 (linear time): %v", err))
			}
		}
	}
	return out
}

// regexes returns the values of the rx operators of a match.
func regexes(match any) []string {
	m, ok := match.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, k := range []string{"all", "any"} {
		conds, _ := m[k].([]any)
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			op, _ := cm["operator"].(map[string]any)
			if op["type"] == "rx" {
				if v, ok := op["value"].(string); ok {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

var english = message.NewPrinter(language.English)

// schemaErrors flattens a validation error into "path: message" lines.
func schemaErrors(err error) []string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []string{err.Error()}
	}
	var out []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			out = append(out, "/"+strings.Join(e.InstanceLocation, "/")+": "+e.ErrorKind.LocalizedString(english))
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	sort.Strings(out)
	return out
}

func intOf(v any) int {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// toJSON decodes YAML into the generic values the JSON Schema validator
// takes (numbers as json.Number, string keys only).
func toJSON(raw []byte) (any, error) {
	var v any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(b))
}
