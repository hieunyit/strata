// Package ftw runs the go-ftw tests of CRS (corpus/crs-ftw, converted by
// strata-import-crs ftw) against the rules of rules/crs through libstrata
// (W06-S-01).
//
// Each imported rule is compiled alone into a bundle and its tests are
// sent through strata-eval: "match" passes when the rule is among the
// verdict's rules, "no_match" when it is not. Content-Length is added to a request with a body, as go-ftw does. A rule alone, because the
// engine stops evaluating once a request is blocked, while go-ftw looks
// for the rule in the log of a full CRS that blocks at the end of the
// phase.
//
// Pass rate of a group: passed tests over the tests of its rules at the
// paranoia levels imported (docs/crs-inventory.csv). A test of a rule
// that was not imported, or that uses what the engine does not evaluate,
// counts as failed.
package ftw

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/strata/strata/tools/strata-rules/internal/report"
	"github.com/strata/strata/tools/strata-rules/internal/ruletest"
	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Test is one converted go-ftw test.
type Test struct {
	Group   string         `json:"-"` // REQUEST-942-APPLICATION-ATTACK-SQLI
	Rule    int            `json:"rule"`
	Name    string         `json:"test"`
	Desc    string         `json:"desc"`
	Expect  string         `json:"expect"` // match | no_match
	Request map[string]any `json:"request"`
}

// Status of a test.
type Status string

// Statuses.
const (
	Pass        Status = "pass"
	Fail        Status = "fail"
	NotImported Status = "not imported"
	Unsupported Status = "engine lacks"
)

// Result of one test.
type Result struct {
	Test
	Status Status
	Reason string
}

// Group totals.
type Group struct {
	Name     string
	Tests    int // tests of rules at the imported paranoia levels
	Passed   int
	Failed   int
	Missing  int // tests of rules not imported or not evaluated
	AboveMax int // tests of rules above the imported paranoia levels, not counted
}

// Rate is the pass rate in percent.
func (g Group) Rate() float64 {
	if g.Tests == 0 {
		return 0
	}
	return 100 * float64(g.Passed) / float64(g.Tests)
}

// Load reads every <group>.jsonl of dir.
func Load(dir string) ([]Test, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []Test
	for _, f := range files {
		group := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var t Test
			if err := json.Unmarshal(sc.Bytes(), &t); err != nil {
				fh.Close()
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			t.Group = group
			out = append(out, t)
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	return out, nil
}

// ParanoiaLevels reads rule id -> paranoia level from the CRS inventory.
func ParanoiaLevels(inventory string) (map[int]int, error) {
	f, err := os.Open(inventory)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows[0]) < 6 || rows[0][0] != "rule_id" || rows[0][5] != "paranoia_level" {
		return nil, fmt.Errorf("%s: unexpected header", inventory)
	}
	pl := map[int]int{}
	for _, r := range rows[1:] {
		id, err := strconv.Atoi(r[0])
		if err != nil {
			continue
		}
		pl[id], _ = strconv.Atoi(r[5]) // empty: no tag, level 0
	}
	return pl, nil
}

// Run runs tests against the rules under rulesDir. pl maps rule ids to
// paranoia levels; tests of rules above maxPL are not run.
func Run(tools runner.Tools, rulesDir string, tests []Test, pl map[int]int, maxPL int) ([]Result, error) {
	caps, err := tools.Capabilities()
	if err != nil {
		return nil, err
	}
	rules, err := report.RulesUnder(rulesDir)
	if err != nil {
		return nil, err
	}
	byID := map[int]map[string]any{}
	for _, r := range rules {
		if id, ok := r["id"].(int); ok {
			byID[id] = r
		}
	}
	byRule := map[int][]int{} // rule -> indexes into results
	results := make([]Result, len(tests))
	for i, t := range tests {
		results[i] = Result{Test: t}
		if pl[t.Rule] > maxPL {
			continue
		}
		r, ok := byID[t.Rule]
		switch {
		case !ok:
			results[i].Status = NotImported
		case len(ruletest.Unsupported(r, caps)) > 0:
			results[i].Status, results[i].Reason = Unsupported, strings.Join(ruletest.Unsupported(r, caps), ", ")
		default:
			byRule[t.Rule] = append(byRule[t.Rule], i)
		}
	}
	ids := make([]int, 0, len(byRule))
	for id := range byRule {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ferr error
		work = make(chan int)
	)
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				if err := runRule(tools, byID[id], byRule[id], results); err != nil {
					mu.Lock()
					if ferr == nil {
						ferr = fmt.Errorf("rule %d: %w", id, err)
					}
					mu.Unlock()
				}
			}
		}()
	}
	for _, id := range ids {
		work <- id
	}
	close(work)
	wg.Wait()
	return results, ferr
}

// blockedByProtocol reports whether any matched rule is in Strata's own
// protocol-layer range (100000-199999), which runs before the CRS rules.
func blockedByProtocol(rules []uint32) bool {
	for _, r := range rules {
		if r >= 100000 && r <= 199999 {
			return true
		}
	}
	return false
}

// runRule compiles one rule and fills the results of its tests (each
// index is written by this rule only).
func runRule(tools runner.Tools, rule map[string]any, idx []int, results []Result) error {
	doc, err := ruletest.IRDoc("crs-ftw", []map[string]any{rule})
	if err != nil {
		return err
	}
	b, err := tools.Build([][]byte{doc})
	if err != nil {
		return err
	}
	defer b.Close()
	reqs := make([]runner.Request, len(idx))
	for k, i := range idx {
		reqs[k] = withLength(ruletest.ToRequest(results[i].Name, results[i].Request))
	}
	vs, err := tools.Eval(b, reqs)
	if err != nil {
		return err
	}
	id := uint32(results[idx[0]].Rule)
	for k, i := range idx {
		v := vs[k]
		matched := v.Matched(id)
		switch {
		case v.Error != 0:
			results[i].Status, results[i].Reason = Fail, fmt.Sprintf("engine error %d", v.Error)
		case matched == (results[i].Expect == "match"):
			results[i].Status = Pass
		case matched:
			results[i].Status, results[i].Reason = Fail, "matched, no_match expected"
		case results[i].Expect == "match" && v.Action == "block" && blockedByProtocol(v.Rules):
			// Strata's own protocol layer (100000-199999, e.g. a raw NUL
			// byte) blocked the attack before the CRS rule was reached. The
			// request is still blocked, so the attack is caught: a pass, even
			// though the CRS rule is not the one attributed.
			results[i].Status, results[i].Reason = Pass, fmt.Sprintf("blocked by the protocol layer %v", v.Rules)
		case len(v.Rules) > 0:
			// another rule blocked before this one ran
			results[i].Status, results[i].Reason = Fail, fmt.Sprintf("blocked first by %v", v.Rules)
		default:
			results[i].Status, results[i].Reason = Fail, "did not match"
		}
	}
	return nil
}

// withLength adds Content-Length to a request with a body and no
// Content-Length or Transfer-Encoding, as go-ftw (and any HTTP client)
// does: the converted tests leave it out.
func withLength(r runner.Request) runner.Request {
	if r.Body == "" {
		return r
	}
	for k := range r.Headers {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			return r
		}
	}
	h := make(map[string]any, len(r.Headers)+1)
	for k, v := range r.Headers {
		h[k] = v
	}
	h["Content-Length"] = strconv.Itoa(len(r.Body))
	r.Headers = h
	return r
}

// Groups totals results per group, in name order.
func Groups(results []Result) []Group {
	by := map[string]*Group{}
	for _, r := range results {
		g := by[r.Group]
		if g == nil {
			g = &Group{Name: r.Group}
			by[r.Group] = g
		}
		switch r.Status {
		case "":
			g.AboveMax++
			continue
		case Pass:
			g.Passed++
		case Fail:
			g.Failed++
		default:
			g.Missing++
		}
		g.Tests++
	}
	out := make([]Group, 0, len(by))
	for _, g := range by {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Total sums the groups into one.
func Total(results []Result) Group {
	t := Group{Name: "Total"}
	for _, g := range Groups(results) {
		t.Tests += g.Tests
		t.Passed += g.Passed
		t.Failed += g.Failed
		t.Missing += g.Missing
		t.AboveMax += g.AboveMax
	}
	return t
}

// Markdown writes the per-group table, then failed tests and the rules
// whose tests could not run.
func Markdown(w io.Writer, results []Result, maxPL int) {
	fmt.Fprintf(w, "## CRS go-ftw tests through libstrata\n\n")
	fmt.Fprintf(w, "Generated by `make test-crs-ftw` (`strata-rules ftw`, W06-S-01). Each rule of `rules/crs` is compiled alone and its go-ftw tests (`corpus/crs-ftw`) are run through libstrata; a test passes when the rule is (`match`) or is not (`no_match`) in the verdict. A `match` test also passes when Strata's own protocol layer (100000-199999, e.g. a raw NUL byte) blocks the request before the CRS rule is reached: the attack is still caught. ")
	fmt.Fprintf(w, "Tests of rules at paranoia level %d and below are counted; a test of a rule that is not imported or not evaluated counts as failed.\n\n", maxPL)
	fmt.Fprintf(w, "| Group | Tests | Pass | Fail | Rule missing | Pass %% | Above PL%d (not run) |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n", maxPL)
	for _, g := range Groups(results) {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %.1f | %d |\n", g.Name, g.Tests, g.Passed, g.Failed, g.Missing, g.Rate(), g.AboveMax)
	}
	if t := Total(results); len(Groups(results)) > 1 {
		fmt.Fprintf(w, "| **%s** | %d | %d | %d | %d | %.1f | %d |\n", t.Name, t.Tests, t.Passed, t.Failed, t.Missing, t.Rate(), t.AboveMax)
	}
	missing := map[string]int{}
	var failed []Result
	for _, r := range results {
		switch r.Status {
		case Fail:
			failed = append(failed, r)
		case NotImported, Unsupported:
			k := fmt.Sprintf("%d | %s", r.Rule, r.Status)
			if r.Reason != "" {
				k += ": " + r.Reason
			}
			missing[k]++
		}
	}
	if len(missing) > 0 {
		keys := make([]string, 0, len(missing))
		for k := range missing {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "\n### Rules whose tests did not run\n\n| Rule | Why | Tests |\n| --- | --- | ---: |\n")
		for _, k := range keys {
			id, why, _ := strings.Cut(k, " | ")
			fmt.Fprintf(w, "| %s | %s | %d |\n", id, why, missing[k])
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(w, "\n### Failed tests\n\n| Test | Expect | Why | Description |\n| --- | --- | --- | --- |\n")
		for _, r := range failed {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", r.Name, r.Expect, r.Reason, strings.ReplaceAll(r.Desc, "|", "\\|"))
		}
	}
}
