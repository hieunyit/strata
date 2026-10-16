package lifecycle

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)

func rules() []Rule {
	return []Rule{
		{ID: 942100, Name: "SQL Injection Attack Detected via libinjection", Source: "crs", Pack: "core"},
		{ID: 941390, Name: "Javascript method detected", Source: "crs", Pack: "core"},
		{ID: 300001, Name: "LDAP filter injection in a parameter", Source: "strata", Pack: "core", Owner: "rules-team", ReviewBy: "2026-10-01"},
		{ID: 450020, Name: "ET rule", Source: "et-open", Pack: "signature", Owner: "rules-team", ReviewBy: "2027-01-15"},
	}
}

// RV-S-02: a rule needs a review when its suspected false positives reach
// 0.05% of the policy's requests; below, it does not.
func TestReviewThreshold(t *testing.T) {
	st := Stats{
		FP: map[uint32]map[string]FP{
			942100: {"pilot-verify": {Events: 12, Sources: 9, TopPath: "/v1/verify"}, "pilot-upload": {Events: 1, Sources: 1}},
			941390: {"pilot-verify": {Events: 4, Sources: 4}},
		},
		Requests: map[string]uint64{"pilot-verify": 10_000, "pilot-upload": 100_000},
		Matches:  map[uint32]uint64{942100: 13, 941390: 4},
	}
	r := Classify(rules(), st, now, Options{})
	// 12/10000 = 0.12% and 4/10000 = 0.04%; 1/100000 = 0.001%
	if len(r.Review) != 1 || r.Review[0].Rule.ID != 942100 || r.Review[0].Policy != "pilot-verify" {
		t.Fatalf("review %+v", r.Review)
	}
	if r.Review[0].Until != "2026-10-29" {
		t.Errorf("exception until %s", r.Review[0].Until)
	}
	// no denominator (store before RV-N-01): every suspected FP is listed
	st.Requests = nil
	if r := Classify(rules(), st, now, Options{}); len(r.Review) != 3 {
		t.Fatalf("without requests: %d lines", len(r.Review))
	}
}

// Old rules are only judged once the store covers 90 days.
func TestOldRules(t *testing.T) {
	st := Stats{Matches: map[uint32]uint64{942100: 3}, DataSince: now.Add(-30 * 24 * time.Hour)}
	r := Classify(rules(), st, now, Options{})
	if r.OldKnown || len(r.Old) != 0 || int(r.DataDays) != 30 {
		t.Fatalf("30 days of data: %+v", r)
	}
	st.DataSince = now.Add(-100 * 24 * time.Hour)
	r = Classify(rules(), st, now, Options{})
	if !r.OldKnown || len(r.Old) != 3 || r.Old[0].ID != 300001 {
		t.Fatalf("old %+v", r.Old)
	}
}

func TestReviewDatesAndOwners(t *testing.T) {
	r := Classify(rules(), Stats{}, now, Options{})
	if len(r.Due) != 1 || r.Due[0].ID != 300001 {
		t.Fatalf("due %+v", r.Due)
	}
	if r.NoOwner["crs"] != 2 || r.NoReview["crs"] != 2 || r.NoOwner["strata"] != 0 {
		t.Errorf("no owner %v, no review %v", r.NoOwner, r.NoReview)
	}
	var b bytes.Buffer
	Markdown(&b, r)
	for _, want := range []string{"## Rules to review (0)", "Not judged yet", "| 300001 | LDAP filter injection in a parameter | rules-team | 2026-10-01 |", "| crs | 2 | 2 |"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report misses %q:\n%s", want, b.String())
		}
	}
}

func TestLoadRulesAndPins(t *testing.T) {
	dir := t.TempDir()
	must := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(dir, "rules/gaps/300001-x.yaml"), "rule:\n  id: 300001\n  name: x\n  metadata: { source: strata, license: Apache-2.0, owner: rules-team, review_by: 2027-01-15 }\n")
	must(filepath.Join(dir, "rules/et-open/web.yaml"), "ir_version: 1\nrules:\n  - id: 450020\n    name: y\n    metadata: { source: et-open, license: BSD-3-Clause }\n")
	must(filepath.Join(dir, "tools/strata-import-crs/crs.lock"), "# c\nversion=4.25.2\nurl=x\n")
	must(filepath.Join(dir, "tools/strata-import-signatures/sources.lock"), "sigma_version=2026-10-06 (8a48134)\nsigma_url=x\net_version=11308\n")
	rs, err := LoadRules(filepath.Join(dir, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].ID != 300001 || rs[0].ReviewBy != "2027-01-15" || rs[0].Owner != "rules-team" || rs[0].Pack != "core" || rs[1].Pack != "signature" {
		t.Fatalf("rules %+v", rs)
	}
	pins := Pins(dir)
	if len(pins) != 3 || pins[0].Version != "4.25.2" || pins[1].Source != "Sigma" || pins[2].Version != "11308" {
		t.Fatalf("pins %+v", pins)
	}
}

// #98: the share of requests that fail_on_findings: block would answer 503.
func TestBudgetFindings(t *testing.T) {
	st := Stats{Requests: map[string]uint64{"pilot-upload": 4000}, BudgetFindings: map[string]uint64{"pilot-upload": 2, "pilot-verify": 1}}
	r := Classify(rules(), st, now, Options{})
	var b bytes.Buffer
	Markdown(&b, r)
	for _, want := range []string{"## Budget out after a finding (#98)", "| pilot-upload | 2 | 4000 | 0.050% |", "| pilot-verify | 1 | unknown | - |"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report misses %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	Markdown(&b, Classify(rules(), Stats{}, now, Options{}))
	if !strings.Contains(b.String(), "would answer no 503") {
		t.Error("empty case")
	}
}
