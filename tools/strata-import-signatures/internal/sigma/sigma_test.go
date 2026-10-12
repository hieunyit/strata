package sigma

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
)

func convYAML(t *testing.T, src string) (irout.Rule, []irout.Test, string, error) {
	t.Helper()
	var d doc
	if err := yaml.Unmarshal([]byte(src), &d); err != nil {
		t.Fatal(err)
	}
	ids, _ := irout.LoadIDs(filepath.Join(t.TempDir(), "ids.txt"), MinID, MaxID)
	return convert(d, Source{Version: "test"}, ids)
}

const base = `title: Example
id: 11111111-2222-3333-4444-555555555555
status: test
author: Example Author
date: 2024/01/02
level: high
logsource: { category: webserver }
tags: [attack.initial-access, attack.t1190]
`

func TestSelectionAndNotFilter(t *testing.T) {
	r, tests, note, err := convYAML(t, base+`detection:
  select_method: { cs-method: GET }
  keywords: ['={{', '=%7B%7B']
  filter: { sc-status: 404 }
  condition: select_method and keywords and not filter
`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "sc-status") {
		t.Errorf("response filter not reported: %q", note)
	}
	all := r["match"].(map[string]any)["all"].([]map[string]any)
	if len(all) != 2 || r["score"] != 60 || r["severity"] != "error" {
		t.Fatalf("%+v", r)
	}
	kw := all[1]
	if kw["targets"].([]map[string]any)[0]["var"] != "uri_raw" || kw["multi_match"] != true ||
		kw["operator"].(map[string]any)["type"] != "pm" {
		t.Fatalf("keywords %+v", kw)
	}
	m := r["metadata"].(map[string]any)
	if m["license"] != "DRL-1.1" || m["author"] != "Example Author" || m["revision"] != "2024-01-02" || m["upstream_id"] == "" {
		t.Fatalf("metadata %+v", m)
	}
	if len(tests) != 2 || tests[1].Request["method"] != "GET" || !strings.Contains(tests[1].Request["uri"].(string), "%7B%7B") {
		t.Fatalf("tests %+v", tests)
	}
}

// 1 of selection_*: alternatives on one field merge into one condition.
func TestOneOfMergesIntoOneCondition(t *testing.T) {
	r, _, _, err := convYAML(t, base+`detection:
  selection_a: { c-useragent|contains: [sqlmap, nikto] }
  selection_b: { c-useragent|startswith: 'Mozilla/5.0 (compatible; Nmap' }
  selection_c: { c-useragent|contains: nuclei }
  condition: 1 of selection_*
`)
	if err != nil {
		t.Fatal(err)
	}
	any := r["match"].(map[string]any)["any"].([]map[string]any)
	if len(any) != 2 {
		t.Fatalf("%d conditions, want 2 (a and c merged): %+v", len(any), any)
	}
}

func TestRefusals(t *testing.T) {
	for body, want := range map[string]string{
		`detection:
  a: { cs-uri-query|contains: x, cs-method: GET }
  b: { c-useragent: y, cs-host: z }
  condition: a or b`: "nested any/all",
		`detection:
  a: { sc-status: 500 }
  condition: a`: "needs the response",
		`detection:
  a: { cs-uri-query|base64offset|contains: x }
  condition: a`: "modifier base64offset",
		`detection:
  a: { x-forwarded: y }
  condition: a`: "not mapped",
		`detection:
  a: { cs-uri-query|re: '(?<=a)b' }
  condition: a`: "not RE2",
		`detection:
  a: { cs-uri-query: x }
  condition: not a`: "only negated",
	} {
		if _, _, _, err := convYAML(t, base+body+"\n"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", body, err, want)
		}
	}
	if _, _, _, err := convYAML(t, strings.Replace(base, "level: high", "level: informational", 1)+"detection:\n  a: { cs-method: GET }\n  condition: a\n"); err == nil {
		t.Error("informational rule imported")
	}
}

func TestNullAndWildcards(t *testing.T) {
	r, tests, _, err := convYAML(t, base+`detection:
  selection: { cs-method: POST, cs-uri-query|contains: 'cmd=*read' }
  filter: { cs-referer: null }
  condition: selection and filter
`)
	if err != nil {
		t.Fatal(err)
	}
	all := r["match"].(map[string]any)["all"].([]map[string]any)
	var sawNull, sawRx bool
	for _, c := range all {
		op := c["operator"].(map[string]any)
		tg := c["targets"].([]map[string]any)[0]
		if tg["count"] == true && tg["key"] == "Referer" && op["type"] == "eq" {
			sawNull = true
		}
		if op["type"] == "rx" && op["value"] == "(?:cmd=.*read)" {
			sawRx = true
		}
	}
	if !sawNull || !sawRx {
		t.Fatalf("%+v", all)
	}
	if _, ok := tests[1].Request["headers"].(map[string]any)["Referer"]; ok {
		t.Fatal("sample has the header the rule wants absent")
	}
}
