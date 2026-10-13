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
