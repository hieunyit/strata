// Package bots converts crawler-user-agents (one regex per crawler, with
// user agents it was seen with) to IR rules on User-Agent. They identify
// bots, good and bad: score 0 and the label "bot", for policies and
// events; a policy decides what to do with them.
package bots

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
)

// Rule ids (rules/README.md: 500200-509999 crawler-user-agents; 500100
// is a sample rule).
const (
	MinID = 500200
	MaxID = 509999
)

type entry struct {
	Pattern     string   `json:"pattern"`
	URL         string   `json:"url"`
	Instances   []string `json:"instances"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

// Result of an import.
type Result struct {
	Read    int
	Rules   []irout.Rule
	Tests   []irout.Test
	Skipped []irout.Skipped
}

// Import converts the crawler-user-agents.json file. benign: user agents
// of the benign corpus; a pattern matching one of them is left out.
func Import(file, version string, ids *irout.IDs, benign []string) (*Result, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var es []entry
	if err := json.Unmarshal(raw, &es); err != nil {
		return nil, err
	}
	res := &Result{}
	for _, e := range es {
		res.Read++
		skip := func(why string) {
			res.Skipped = append(res.Skipped, irout.Skipped{Upstream: e.Pattern, Name: name(e), Reason: why})
		}
		re, err := regexp.Compile(e.Pattern)
		if err != nil || !irout.Printable(e.Pattern) {
			skip("pattern is not RE2")
			continue
		}
		if re.MatchString("") || re.MatchString(irout.BenignUA) {
			skip("matches an empty or a browser user agent")
			continue
		}
		hit := ""
		for _, ua := range benign {
			if re.MatchString(ua) {
				hit = ua
				break
			}
		}
		if hit != "" {
			skip(fmt.Sprintf("matches the benign corpus (%q)", hit))
			continue
		}
		var samples []string
		for _, s := range e.Instances {
			if irout.Printable(s) && re.MatchString(s) {
				samples = append(samples, s)
			}
		}
		if len(samples) == 0 {
			skip("no upstream user agent the pattern matches")
			continue
		}
		id, err := ids.Get(e.Pattern)
		if err != nil {
			return nil, err
		}
		meta := map[string]any{"source": "crawler-user-agents", "upstream_id": e.Pattern, "upstream_version": version,
			"license": "MIT", "author": "crawler-user-agents contributors", "attack_type": "bot"}
		if len(e.Tags) > 0 {
			meta["tags"] = e.Tags
		}
		c := irout.Cond{Targets: []irout.Target{{Var: "request_headers", Key: "User-Agent"}}, Op: "rx", Value: e.Pattern}
		res.Rules = append(res.Rules, irout.Rule{"id": id, "name": name(e), "layer": "managed", "stage": "request_headers",
			"match": irout.Match([]irout.Cond{c}, true), "score": 0, "severity": "notice", "labels": []string{"bot"}, "metadata": meta})
		res.Tests = append(res.Tests, irout.NoMatch(id))
		for i, s := range samples[:min(3, len(samples))] {
			res.Tests = append(res.Tests, irout.Test{Rule: id, Name: fmt.Sprintf("%d-upstream-%d", id, i+1), Expect: "match",
				Request: map[string]any{"method": "GET", "uri": "/", "headers": map[string]any{"Host": "api.example.test", "User-Agent": s}}})
		}
	}
	return res, nil
}

func name(e entry) string {
	n := strings.TrimSpace(e.Description)
	if n == "" || len(n) > 120 {
		n = "Crawler user agent " + e.Pattern
	}
	return n
}
