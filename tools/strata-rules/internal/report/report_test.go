package report

import (
	"strings"
	"testing"
)

func gateReport() *Report {
	return &Report{
		Benign: 2000, BenignBlock: 12,
		Attacks: map[string]Type{
			"sql-injection":     {Payloads: 807, Blocked: 616},
			"xss":               {Payloads: 529, Blocked: 398},
			"command-injection": {Payloads: 479, Blocked: 451},
			"path-traversal":    {Payloads: 466, Blocked: 432},
		},
	}
}

func TestGateFailuresPass(t *testing.T) {
	if miss := gateReport().GateFailures(1, 70, GateAttackTypes); len(miss) != 0 {
		t.Fatalf("the v0 numbers meet Gate A, got %v", miss)
	}
	// unchecked targets never fail
	r := gateReport()
	r.BenignBlock = 2000
	if miss := r.GateFailures(-1, -1, GateAttackTypes); len(miss) != 0 {
		t.Fatalf("nothing checked, got %v", miss)
	}
}

func TestGateFailuresMiss(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*Report)
		want string
	}{
		{"FP at 1% exactly", func(r *Report) { r.BenignBlock = 20 }, "benign requests blocked: 20 of 2000"},
		{"SQLi recall under 70%", func(r *Report) { r.Attacks["sql-injection"] = Type{Payloads: 100, Blocked: 69} }, "sql-injection: 69.0%"},
		{"a type missing from the corpus", func(r *Report) { delete(r.Attacks, "xss") }, "xss: no payloads"},
		{"a type with no payloads", func(r *Report) { r.Attacks["path-traversal"] = Type{} }, "path-traversal: no payloads"},
	} {
		r := gateReport()
		c.edit(r)
		miss := r.GateFailures(1, 70, GateAttackTypes)
		if len(miss) != 1 || !strings.Contains(miss[0], c.want) {
			t.Errorf("%s: got %v, want one line with %q", c.name, miss, c.want)
		}
	}
}

// W11-S-01: the benign requests a rule matched are named, to tune it.
func TestMarkdownNamesFPSamples(t *testing.T) {
	r := &Report{Benign: 2000, BenignHit: 12, BenignBlock: 12,
		FPByRule:  map[string]int{"942100": 12, "920350": 1},
		FPSamples: map[string][]string{"942100": {"benign-00017", "benign-00123"}, "920350": {"benign-01999"}},
		Attacks:   map[string]Type{}}
	var b strings.Builder
	r.Markdown(&b, nil)
	for _, want := range []string{"| 942100 | 12 | benign-00017 benign-00123 |", "| 920350 | 1 | benign-01999 |"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
}
