package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestClassify(t *testing.T) {
	imported := map[int]bool{944130: true, 930120: true, 920420: true}
	tuned := map[int]string{930120: "Strata tuning: x"}
	known := map[string]bool{"920420-1": true}
	cases := []struct {
		d    RuleDiff
		want string
	}{
		{RuleDiff{Test: "944130-6", Rule: 944130, Expect: "match", Strata: true}, whyCoraza},
		{RuleDiff{Test: "943110-1", Rule: 943110, Expect: "match", Coraza: true}, whyMissing},
		{RuleDiff{Test: "920420-1", Rule: 920420, Expect: "no_match", Strata: true}, whyKnown},
		{RuleDiff{Test: "944130-9", Rule: 944130, Expect: "match", Coraza: true, SBlock: true}, whyEarly},
		{RuleDiff{Test: "930120-2", Rule: 930120, Expect: "match", Coraza: true}, whyTuned},
		{RuleDiff{Test: "944130-2", Rule: 944130, Expect: "match", Coraza: true}, whyStrata},
	}
	for _, c := range cases {
		if got := classify(c.d, imported, tuned, known); got != c.want {
			t.Errorf("%s: %q, want %q", c.d.Test, got, c.want)
		}
	}
}

func TestReadReports(t *testing.T) {
	dir := t.TempDir()
	imp := filepath.Join(dir, "imp.md")
	_ = os.WriteFile(imp, []byte("| Rule | Note |\n| --- | --- |\n| 930120 | Strata tuning: \"program files\" listed as \"program files/\" |\n| 920100 | dropped: not evaluated |\n"), 0o644)
	tuned, err := tunedRules(imp)
	if err != nil || len(tuned) != 1 || !strings.Contains(tuned[930120], "program files/") {
		t.Fatalf("tuned %v %v", tuned, err)
	}
	ftw := filepath.Join(dir, "ftw.md")
	_ = os.WriteFile(ftw, []byte("| Test | Expect | Why | Description |\n| --- | --- | --- | --- |\n| 901360-1 | no_match | matched | x |\n| 911100-6 | match | did not match | y |\n| 920190 | not imported | 2 |\n"), 0o644)
	known, err := knownFailures(ftw)
	if err != nil || len(known) != 2 || !known["901360-1"] || !known["911100-6"] {
		t.Fatalf("known %v %v", known, err)
	}
}

func TestExplainedBy(t *testing.T) {
	tuned := map[int]string{930120: "Strata tuning: x", 942100: "Strata tuning: y"}
	if !(&group{rules: []int{930120, 942100}}).explainedBy(tuned) {
		t.Error("tuned rules only: explained")
	}
	if (&group{rules: []int{930120, 941100}}).explainedBy(tuned) {
		t.Error("an untuned rule: a ticket")
	}
	if (&group{strataOn: true, rules: []int{930120}}).explainedBy(tuned) || (&group{}).explainedBy(tuned) {
		t.Error("Strata blocking, or no rule: a ticket")
	}
}

// Only rules carrying a paranoia tag count; a deny reached through the
// anomaly score is a block.
func TestRunCorazaDetections(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		`SecRule REQUEST_METHOD "@streq GET" "id:920539,phase:1,pass,nolog"`,
		`SecRule ARGS "@contains evil" "id:941100,phase:1,pass,severity:'CRITICAL',tag:'paranoia-level/1',setvar:'tx.score=+5'"`,
		`SecRule TX:score "@ge 5" "id:949110,phase:1,deny,status:403"`,
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	v := runCoraza(waf, Request{Method: "GET", URI: "/v1/search?q=evil", Headers: map[string]string{"Host": "api.example.test"}, RemoteAddr: "192.0.2.10"})
	if !v.Block || len(v.Rules) != 1 || v.Rules[0] != 941100 {
		t.Fatalf("%+v", v)
	}
	v = runCoraza(waf, Request{Method: "GET", URI: "/v1/search?q=fine", Headers: map[string]string{"Host": "api.example.test"}, RemoteAddr: "192.0.2.10"})
	if v.Block || len(v.Rules) != 0 {
		t.Fatalf("%+v", v)
	}
}

// With the CRS release (tools/strata-import-crs/fetch-crs.sh): Strata's
// setup is applied (PATCH allowed) and JSON bodies are parsed.
func TestCorazaSetup(t *testing.T) {
	crs := filepath.Join("..", "..", "build", "crs", "coreruleset-4.25.2")
	if _, err := os.Stat(filepath.Join(crs, "crs-setup.conf.example")); err != nil {
		t.Skip("CRS 4.25.2 not in build/crs (tools/strata-import-crs/fetch-crs.sh)")
	}
	waf, err := newCoraza(crs)
	if err != nil {
		t.Fatal(err)
	}
	h := map[string]string{"Host": "api.example.test", "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Content-Type": "application/json"}
	v := runCoraza(waf, Request{Method: "PATCH", URI: "/v1/items/1", Headers: h, Body: `{"note":"rock and roll"}`, RemoteAddr: "192.0.2.10"})
	if v.Block || contains(v.Rules, 911100) {
		t.Errorf("PATCH with a plain JSON body: %+v", v)
	}
	v = runCoraza(waf, Request{Method: "POST", URI: "/v1/items", Headers: h, Body: `{"q":"1' UNION SELECT password FROM users--"}`, RemoteAddr: "192.0.2.10"})
	if !v.Block || !contains(v.Rules, 942100) {
		t.Errorf("SQLi in a JSON value: %+v", v)
	}
}
