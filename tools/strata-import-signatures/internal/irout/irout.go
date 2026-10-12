// Package irout writes what the signature importers produce: IR rulesets
// (docs/spec/ir.schema.json), the rule id of each upstream rule (kept from
// one import to the next), test requests for strata-rules ftw, and the
// import report.
package irout

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is an IR rule (map keys as in the IR).
type Rule map[string]any

// Cond is one IR condition.
type Cond struct {
	Targets    []Target
	Transforms []string
	MultiMatch bool
	Op         string
	Value      any
	Negate     bool
}

// Target is one IR target.
type Target struct {
	Var   string
	Key   string
	Count bool
}

// IR renders the condition.
func (c Cond) IR() map[string]any {
	ts := make([]map[string]any, 0, len(c.Targets))
	for _, t := range c.Targets {
		m := map[string]any{"var": t.Var}
		if t.Key != "" {
			m["key"] = t.Key
		}
		if t.Count {
			m["count"] = true
		}
		ts = append(ts, m)
	}
	op := map[string]any{"type": c.Op}
	if c.Value != nil {
		op["value"] = c.Value
	}
	if c.Negate {
		op["negate"] = true
	}
	out := map[string]any{"targets": ts, "operator": op}
	if len(c.Transforms) > 0 {
		out["transforms"] = c.Transforms
	}
	if c.MultiMatch {
		out["multi_match"] = true
	}
	return out
}

// MaxConds of one IR match.
const MaxConds = 16

// Match renders conditions as an all (and = true) or any match.
func Match(conds []Cond, and bool) map[string]any {
	l := make([]map[string]any, 0, len(conds))
	for _, c := range conds {
		l = append(l, c.IR())
	}
	if and {
		return map[string]any{"all": l}
	}
	return map[string]any{"any": l}
}

// Marshal writes rules (in id order) as one IR ruleset document.
func Marshal(header, name, version string, rules []Rule) ([]byte, error) {
	order := []string{"id", "name", "layer", "stage", "match", "score", "action_mode", "severity", "labels", "metadata"}
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i]["id"].(int) < sorted[j]["id"].(int) })
	for _, r := range sorted {
		if _, ok := r["action_mode"]; !ok {
			// imported signatures add to the anomaly score; none blocks alone
			r["action_mode"] = "score"
		}
		m := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range order {
			v, ok := r[k]
			if !ok {
				continue
			}
			var vn yaml.Node
			if err := vn.Encode(v); err != nil {
				return nil, err
			}
			quoteAmbiguous(&vn)
			m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &vn)
		}
		seq.Content = append(seq.Content, m)
	}
	var ir, rs yaml.Node
	if err := ir.Encode(1); err != nil {
		return nil, err
	}
	if err := rs.Encode(map[string]any{"name": name, "version": version}); err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "ir_version"}, &ir,
		{Kind: yaml.ScalarNode, Value: "ruleset"}, &rs,
		{Kind: yaml.ScalarNode, Value: "rules"}, seq,
	}}
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// quoteAmbiguous quotes string scalars YAML 1.1 parsers read as something
// else ("=" is the value tag, "y" a boolean...), so every parser reads the
// same rules.
func quoteAmbiguous(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!str" && n.Style == 0 {
		switch strings.ToLower(n.Value) {
		case "=", "<<", "y", "n", "yes", "no", "on", "off", "true", "false", "null", "~":
			n.Style = yaml.DoubleQuotedStyle
		}
	}
	for _, c := range n.Content {
		quoteAmbiguous(c)
	}
}

// IDs maps upstream ids to rule ids: an id once given is kept (ids are
// never reused, docs/spec/ir.schema.json), new upstream rules get the next
// free id of the range.
type IDs struct {
	path     string
	min, max int
	byUp     map[string]int
	used     map[int]bool
}

// LoadIDs reads path ("<upstream id> <rule id>" per line; missing: empty).
func LoadIDs(path string, min, max int) (*IDs, error) {
	ids := &IDs{path: path, min: min, max: max, byUp: map[string]int{}, used: map[int]bool{}}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// only the end is trimmed: an upstream id may begin with a space
		// (" DVbot" is not "DVbot")
		line := strings.TrimRight(sc.Text(), " \t\r")
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// the rule id is after the last space (upstream ids may hold spaces)
		sp := strings.LastIndexByte(line, ' ')
		if sp <= 0 {
			return nil, fmt.Errorf("%s: bad line %q", path, line)
		}
		up, n := line[:sp], line[sp+1:]
		id, err := strconv.Atoi(n)
		if err != nil || id < min || id > max || ids.used[id] {
			return nil, fmt.Errorf("%s: bad line %q", path, line)
		}
		ids.byUp[up], ids.used[id] = id, true
	}
	return ids, sc.Err()
}

// Get returns the rule id of an upstream id, giving a new one if needed.
func (ids *IDs) Get(up string) (int, error) {
	if id, ok := ids.byUp[up]; ok {
		return id, nil
	}
	for id := ids.min; id <= ids.max; id++ {
		if !ids.used[id] {
			ids.byUp[up], ids.used[id] = id, true
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free rule id in %d-%d", ids.min, ids.max)
}

// Save writes the map, upstream ids sorted.
func (ids *IDs) Save(header string) error {
	ups := make([]string, 0, len(ids.byUp))
	for u := range ids.byUp {
		ups = append(ups, u)
	}
	sort.Strings(ups)
	var b strings.Builder
	b.WriteString(header)
	for _, u := range ups {
		fmt.Fprintf(&b, "%s %d\n", u, ids.byUp[u])
	}
	return os.WriteFile(ids.path, []byte(b.String()), 0o644)
}

// Test is a request for strata-rules ftw (match or no_match).
type Test struct {
	Rule      int            `json:"rule"`
	Name      string         `json:"test"`
	Desc      string         `json:"desc,omitempty"`
	Expect    string         `json:"expect"`
	Generated bool           `json:"generated,omitempty"` // made from the pattern, not taken from upstream
	Request   map[string]any `json:"request"`
}

// WriteTests writes tests as JSON lines, in rule then name order.
func WriteTests(path string, tests []Test) error {
	sort.SliceStable(tests, func(i, j int) bool {
		if tests[i].Rule != tests[j].Rule {
			return tests[i].Rule < tests[j].Rule
		}
		return tests[i].Name < tests[j].Name
	})
	var b bytes.Buffer
	for _, t := range tests {
		line, err := json.Marshal(t)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

// Skipped is an upstream rule left out, with the reason.
type Skipped struct {
	Upstream, Name, Reason string
}

// BenignUA is the user agent of no_match requests.
const BenignUA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

// NoMatch is the request every imported rule must leave alone.
func NoMatch(rule int) Test {
	return Test{Rule: rule, Name: fmt.Sprintf("%d-benign", rule), Expect: "no_match", Generated: true,
		Request: map[string]any{"method": "GET", "uri": "/products?id=12&sort=price",
			"headers": map[string]any{"Host": "api.example.test", "User-Agent": BenignUA, "Accept": "text/html"}}}
}

// RE2 reports whether pattern compiles as RE2 (Go's regexp), what the lint
// requires: linear time.
func RE2(pattern string) bool {
	_, err := regexp.Compile(pattern)
	return err == nil
}

// Literal escapes s for a regex, bytes outside printable ASCII as \xHH.
func Literal(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		case strings.IndexByte(`\.+*?()|[]{}^$`, c) >= 0:
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Printable reports whether s is printable ASCII (a YAML-safe literal).
func Printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return s != ""
}
