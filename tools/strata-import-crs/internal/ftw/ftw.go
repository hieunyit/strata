// Package ftw converts the go-ftw regression tests of a CRS release
// (tests/regression/tests/<group>/<rule>.yaml) into Strata's test format
// (W04-S-01): one JSON line per expectation,
//
//	{"rule": 942100, "test": "942100-1", "desc": "...", "expect": "match",
//	 "request": {"method": "POST", "uri": "/post", "headers": {...}, "body": "..."}}
//
// with the same request fields as the tests of rules/ files. Tests that
// cannot be expressed that way are listed with the reason.
package ftw

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Case is one converted expectation.
type Case struct {
	Rule    int            `json:"rule"`
	Test    string         `json:"test"`
	Desc    string         `json:"desc,omitempty"`
	Expect  string         `json:"expect"` // match | no_match
	Request map[string]any `json:"request"`
}

// Skipped is a test that was not converted.
type Skipped struct {
	Group  string
	Test   string
	Reason string
}

type file struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		TestID any    `yaml:"test_id"`
		Desc   string `yaml:"desc"`
		Stages []struct {
			Input  map[string]any `yaml:"input"`
			Output map[string]any `yaml:"output"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

// Result of a conversion.
type Result struct {
	Groups  map[string][]Case
	Skipped []Skipped
	Total   int // tests read
}

// Convert reads every test file under dir (tests/regression/tests).
func Convert(dir string) (*Result, error) {
	res := &Result{Groups: map[string][]Case{}}
	groups, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if !g.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, g.Name(), "*.yaml"))
		sort.Strings(files)
		for _, p := range files {
			raw, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			var f file
			if err := yaml.Unmarshal(raw, &f); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, t := range f.Tests {
				res.Total++
				id := fmt.Sprintf("%d-%v", f.RuleID, t.TestID)
				cases, reason := convert(g.Name(), f.RuleID, id, t.Desc, t.Stages)
				if reason != "" {
					res.Skipped = append(res.Skipped, Skipped{Group: g.Name(), Test: id, Reason: reason})
					continue
				}
				res.Groups[g.Name()] = append(res.Groups[g.Name()], cases...)
			}
		}
	}
	return res, nil
}

func convert(group string, _ int, id, desc string, stages []struct {
	Input  map[string]any `yaml:"input"`
	Output map[string]any `yaml:"output"`
}) ([]Case, string) {
	if strings.HasPrefix(group, "RESPONSE-") {
		return nil, "response rules: the harness sends requests only"
	}
	if len(stages) != 1 {
		return nil, fmt.Sprintf("%d stages: later stages depend on earlier ones", len(stages))
	}
	in, out := stages[0].Input, stages[0].Output
	if _, ok := in["encoded_request"]; ok {
		return nil, "encoded_request: raw request bytes, not a structured request"
	}
	if v, ok := in["autocomplete_headers"].(bool); ok && !v {
		return nil, "autocomplete_headers: false: the test depends on headers sent exactly as written"
	}
	if v, _ := in["protocol"].(string); v != "" && v != "http" {
		return nil, "protocol " + v
	}
	if _, ok := out["expect_error"]; ok {
		return nil, "expect_error: the test expects the server to refuse the request"
	}
	log, _ := out["log"].(map[string]any)
	var expect, noExpect []int
	for _, k := range []string{"expect_ids", "no_expect_ids"} {
		ids, _ := log[k].([]any)
		for _, x := range ids {
			n, ok := x.(int)
			if !ok {
				return nil, k + ": not a list of rule ids"
			}
			if k == "expect_ids" {
				expect = append(expect, n)
			} else {
				noExpect = append(noExpect, n)
			}
		}
	}
	if len(expect)+len(noExpect) == 0 {
		switch {
		case log["match_regex"] != nil || log["no_match_regex"] != nil:
			return nil, "expects a pattern in the server log, not rule ids"
		case out["status"] != nil:
			return nil, "expects only an HTTP status"
		default:
			return nil, "no expectation on rule ids"
		}
	}
	req, reason := request(in)
	if reason != "" {
		return nil, reason
	}
	var cases []Case
	for _, n := range expect {
		cases = append(cases, Case{Rule: n, Test: id, Desc: desc, Expect: "match", Request: req})
	}
	for _, n := range noExpect {
		cases = append(cases, Case{Rule: n, Test: id, Desc: desc, Expect: "no_match", Request: req})
	}
	return cases, ""
}

// request builds the structured request. As go-ftw does, a body without a
// Content-Type is sent as application/x-www-form-urlencoded.
func request(in map[string]any) (map[string]any, string) {
	req := map[string]any{}
	method, _ := in["method"].(string)
	if method == "" {
		method = "GET"
	}
	req["method"] = method
	uri, _ := in["uri"].(string)
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		return nil, "absolute or empty request target"
	}
	req["uri"] = uri
	headers := map[string]any{}
	if h, ok := in["headers"].(map[string]any); ok {
		for k, v := range h {
			s, ok := v.(string)
			if !ok {
				s = fmt.Sprint(v)
			}
			headers[k] = s
		}
	}
	if d, ok := in["data"]; ok && d != nil {
		var body string
		switch v := d.(type) {
		case string:
			body = v
		case []any:
			lines := make([]string, len(v))
			for i, x := range v {
				lines[i] = fmt.Sprint(x)
			}
			body = strings.Join(lines, "\r\n")
		default:
			body = fmt.Sprint(v)
		}
		req["body"] = body
		if !hasHeader(headers, "Content-Type") && body != "" {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	}
	if len(headers) > 0 {
		req["headers"] = headers
	}
	return req, ""
}

func hasHeader(h map[string]any, name string) bool {
	for k := range h {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// Write stores one JSONL file per group in out.
func (r *Result) Write(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for g, cases := range r.Groups {
		f, err := os.Create(filepath.Join(out, g+".jsonl"))
		if err != nil {
			return err
		}
		enc := json.NewEncoder(f)
		enc.SetEscapeHTML(false)
		for _, c := range cases {
			if err := enc.Encode(c); err != nil {
				f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Report writes the list of tests that were not converted.
func (r *Result) Report(w io.Writer, version string) {
	converted := r.Total - len(r.Skipped)
	fmt.Fprintf(w, "# go-ftw tests of CRS %s not converted\n\n", version)
	fmt.Fprintf(w, "Generated by `strata-import-crs ftw` (W04-S-01). %d tests read, %d converted to corpus/crs-ftw/, %d not converted:\n\n", r.Total, converted, len(r.Skipped))
	byReason := map[string]int{}
	for _, s := range r.Skipped {
		byReason[s.Reason]++
	}
	reasons := make([]string, 0, len(byReason))
	for k := range byReason {
		reasons = append(reasons, k)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if byReason[reasons[i]] != byReason[reasons[j]] {
			return byReason[reasons[i]] > byReason[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	fmt.Fprintf(w, "| Reason | Tests |\n| --- | ---: |\n")
	for _, k := range reasons {
		fmt.Fprintf(w, "| %s | %d |\n", k, byReason[k])
	}
	fmt.Fprintf(w, "\n| Group | Test | Reason |\n| --- | --- | --- |\n")
	for _, s := range r.Skipped {
		fmt.Fprintf(w, "| %s | %s | %s |\n", s.Group, s.Test, s.Reason)
	}
}
