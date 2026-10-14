// Package report measures the rules on the corpus through libstrata
// (W04-S-01): false positives on benign requests, and recall (detected and
// blocked) per attack type, with the change from a baseline report.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/strata/strata/tools/strata-rules/internal/corpus"
	"github.com/strata/strata/tools/strata-rules/internal/ruletest"
	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Type is the result for one attack type.
type Type struct {
	Payloads int `json:"payloads"`
	Requests int `json:"requests"`
	Detected int `json:"detected"` // payloads with a request some rule matched
	Blocked  int `json:"blocked"`  // payloads with a request blocked
}

// Report is the outcome of one run.
type Report struct {
	Rules       int            `json:"rules"`
	Skipped     int            `json:"skipped"` // rules the engine cannot run yet
	Benign      int            `json:"benign"`
	BenignHit   int            `json:"benign_detected"`
	BenignBlock int            `json:"benign_blocked"`
	FPByRule    map[string]int `json:"fp_by_rule"`
	// FPSamples: the ids of the first benign requests each rule matched
	// (at most FPSampleMax), to find what to tune (W11-S-01)
	FPSamples map[string][]string `json:"fp_samples,omitempty"`
	Attacks   map[string]Type     `json:"attacks"`
}

// FPSampleMax benign request ids are kept per rule in FPSamples.
const FPSampleMax = 5

// GateAttackTypes are the attack types whose recall the quality targets
// name (plan.md, "Chỉ tiêu chất lượng": SQLi, XSS, CMDi, LFI).
var GateAttackTypes = []string{"sql-injection", "xss", "command-injection", "path-traversal"}

// GateFailures checks the quality targets at the blocking threshold:
// benign requests blocked at most maxFPPct percent (negative: not checked),
// and for each of types at least minRecallPct percent of payloads blocked
// (negative: not checked). One line per target missed; a type absent from
// the corpus is a miss too, so a corpus change cannot pass the gate by
// dropping a type.
func (r *Report) GateFailures(maxFPPct, minRecallPct float64, types []string) []string {
	var out []string
	if maxFPPct >= 0 && pct(r.BenignBlock, r.Benign) >= maxFPPct {
		out = append(out, fmt.Sprintf("benign requests blocked: %d of %d (%.2f%%), target under %g%%",
			r.BenignBlock, r.Benign, pct(r.BenignBlock, r.Benign), maxFPPct))
	}
	if minRecallPct >= 0 {
		for _, t := range types {
			a, ok := r.Attacks[t]
			if !ok || a.Payloads == 0 {
				out = append(out, fmt.Sprintf("%s: no payloads in the corpus", t))
				continue
			}
			if got := pct(a.Blocked, a.Payloads); got < minRecallPct {
				out = append(out, fmt.Sprintf("%s: %.1f%% of payloads blocked, target at least %g%%", t, got, minRecallPct))
			}
		}
	}
	return out
}

// RulesUnder returns every rule of rules dir: rule files and IR rulesets.
func RulesUnder(dir string) ([]map[string]any, error) {
	var out []map[string]any
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
		if r, ok := doc["rule"].(map[string]any); ok {
			out = append(out, r)
		}
		if rs, ok := doc["rules"].([]any); ok && doc["ir_version"] != nil {
			for _, r := range rs {
				if m, ok := r.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
		return nil
	})
	return out, err
}

// Run measures the rules of rulesDir on c.
func Run(tools runner.Tools, rulesDir string, c *corpus.Corpus) (*Report, error) {
	all, err := RulesUnder(rulesDir)
	if err != nil {
		return nil, err
	}
	caps, err := tools.Capabilities()
	if err != nil {
		return nil, err
	}
	rep := &Report{FPByRule: map[string]int{}, FPSamples: map[string][]string{}, Attacks: map[string]Type{}}
	var rules []map[string]any
	for _, r := range all {
		if len(ruletest.Unsupported(r, caps)) > 0 {
			rep.Skipped++
			continue
		}
		rules = append(rules, r)
	}
	rep.Rules = len(rules)
	if len(rules) == 0 {
		return rep, nil
	}
	doc, err := ruletest.IRDoc("strata-rules-report", rules)
	if err != nil {
		return nil, err
	}
	b, err := tools.Build([][]byte{doc})
	if err != nil {
		return nil, err
	}
	defer b.Close()

	bv, err := tools.Eval(b, c.Benign)
	if err != nil {
		return nil, err
	}
	rep.Benign = len(bv)
	for i, v := range bv {
		if len(v.Rules) > 0 {
			rep.BenignHit++
		}
		if v.Action == "block" {
			rep.BenignBlock++
		}
		for _, r := range v.Rules {
			id := strconv.Itoa(int(r))
			rep.FPByRule[id]++
			if i < len(c.Benign) && len(rep.FPSamples[id]) < FPSampleMax {
				rep.FPSamples[id] = append(rep.FPSamples[id], c.Benign[i].ID)
			}
		}
	}

	var reqs []runner.Request
	for i, p := range c.Attacks {
		reqs = append(reqs, corpus.Requests(p, strconv.Itoa(i))...)
	}
	av, err := tools.Eval(b, reqs)
	if err != nil {
		return nil, err
	}
	detected, blocked := map[int]bool{}, map[int]bool{}
	for _, v := range av {
		i, _ := strconv.Atoi(strings.SplitN(v.ID, "/", 2)[0])
		t := rep.Attacks[c.Attacks[i].AttackType]
		t.Requests++
		rep.Attacks[c.Attacks[i].AttackType] = t
		if len(v.Rules) > 0 {
			detected[i] = true
		}
		if v.Action == "block" {
			blocked[i] = true
		}
	}
	for i, p := range c.Attacks {
		t := rep.Attacks[p.AttackType]
		t.Payloads++
		if detected[i] {
			t.Detected++
		}
		if blocked[i] {
			t.Blocked++
		}
		rep.Attacks[p.AttackType] = t
	}
	return rep, nil
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

func delta(cur, base float64, have bool) string {
	if !have {
		return ""
	}
	d := cur - base
	switch {
	case d > 0.05:
		return fmt.Sprintf(" (+%.1f)", d)
	case d < -0.05:
		return fmt.Sprintf(" (%.1f)", d)
	}
	return " (=)"
}

// Markdown writes the report, with changes from base when it is not nil.
func (r *Report) Markdown(w io.Writer, base *Report) {
	have := base != nil
	if !have {
		base = &Report{Attacks: map[string]Type{}}
	}
	fmt.Fprintf(w, "## Rule report (corpus v0, libstrata)\n\n")
	fmt.Fprintf(w, "%d rules evaluated, %d skipped (the engine lacks an operator, transformation or target).\n\n", r.Rules, r.Skipped)
	fmt.Fprintf(w, "### Recall by attack type\n\n| Attack type | Payloads | Detected %% | Blocked %% |\n| --- | ---: | ---: | ---: |\n")
	types := make([]string, 0, len(r.Attacks))
	for t := range r.Attacks {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		a, b := r.Attacks[t], base.Attacks[t]
		fmt.Fprintf(w, "| %s | %d | %.1f%s | %.1f%s |\n", t, a.Payloads,
			pct(a.Detected, a.Payloads), delta(pct(a.Detected, a.Payloads), pct(b.Detected, b.Payloads), have),
			pct(a.Blocked, a.Payloads), delta(pct(a.Blocked, a.Payloads), pct(b.Blocked, b.Payloads), have))
	}
	fmt.Fprintf(w, "\n### False positives on benign requests\n\n| Benign requests | Some rule matched | Blocked |\n| ---: | ---: | ---: |\n")
	fmt.Fprintf(w, "| %d | %d (%.2f%%)%s | %d (%.2f%%)%s |\n", r.Benign,
		r.BenignHit, pct(r.BenignHit, r.Benign), delta(pct(r.BenignHit, r.Benign), pct(base.BenignHit, base.Benign), have),
		r.BenignBlock, pct(r.BenignBlock, r.Benign), delta(pct(r.BenignBlock, r.Benign), pct(base.BenignBlock, base.Benign), have))
	if len(r.FPByRule) > 0 {
		ids := make([]string, 0, len(r.FPByRule))
		for id := range r.FPByRule {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			if r.FPByRule[ids[i]] != r.FPByRule[ids[j]] {
				return r.FPByRule[ids[i]] > r.FPByRule[ids[j]]
			}
			return ids[i] < ids[j]
		})
		fmt.Fprintf(w, "\nRules matching benign requests:\n\n| Rule | Benign requests matched | First requests |\n| --- | ---: | --- |\n")
		for _, id := range ids {
			fmt.Fprintf(w, "| %s | %d | %s |\n", id, r.FPByRule[id], strings.Join(r.FPSamples[id], " "))
		}
	}
}

// Save writes the report as JSON.
func (r *Report) Save(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadReport reads a saved report.
func LoadReport(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	return &r, json.Unmarshal(b, &r)
}
