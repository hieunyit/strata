package importer

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const conf = `SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
    "id:920170,phase:1,block,t:none,msg:'GET or HEAD Request with Body Content',\
    tag:'paranoia-level/1',severity:'CRITICAL',chain"
    SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" "t:none"

SecRule ARGS|ARGS_NAMES|!ARGS:password|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES "@pmFromFile words.data" \
    "id:930120,phase:2,block,t:none,t:lowercase,t:urlDecodeUni,msg:'OS File Access Attempt',\
    tag:'paranoia-level/1',severity:'WARNING'"

SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,t:urlDecodeUni,t:none,t:removeNulls,multiMatch,severity:'CRITICAL',tag:'paranoia-level/1'"

SecRule ARGS "@rx a" "id:942101,phase:2,block,severity:'CRITICAL',tag:'paranoia-level/2'"
SecRule ARGS "@rx a" "id:942102,phase:2,pass,nolog,tag:'paranoia-level/1'"
SecRule TX:foo "@rx a" "id:942103,phase:2,block,severity:'CRITICAL'"
SecRule ARGS "@within a b" "id:942104,phase:2,block,severity:'CRITICAL'"
SecRule ARGS "@rx %{tx.x}" "id:942105,phase:2,block,severity:'CRITICAL'"
SecRule ARGS "@rx a" "id:942106,phase:2,block,t:sqlHexDecode,severity:'CRITICAL'"
SecRule ARGS:/^id/ "@rx a" "id:942107,phase:2,block,severity:'CRITICAL'"
SecRule &REQUEST_HEADERS:Host "@eq 0" "id:920280,phase:1,block,severity:'WARNING'"
SecRule ARGS|XML:/*|XML://@*|XML:/a/b "@rx evil" "id:941100,phase:2,block,severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule REQBODY_PROCESSOR "@streq JSON" "id:920539,phase:2,pass,nolog,skip:1"
SecRule ARGS "@rx (?i)\x5cu[0-9a-f]{4}" "id:920540,phase:2,block,severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule ARGS "@rx a" "id:920541,phase:2,block,severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule ARGS "@rx skip" "id:920542,phase:2,pass,nolog,skip:1"
SecRule ARGS "@rx b" "id:920543,phase:2,block,severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule ARGS "@pm java.lang" "id:944120,phase:2,block,t:none,t:lowercase,severity:'CRITICAL',tag:'paranoia-level/1',chain"
    SecRule MATCHED_VARS "@rx (?:runtime|processbuilder)" "t:none"
`

func importConf(t *testing.T) *Result {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(rules, "x.conf"), []byte(conf), 0o644)
	_ = os.WriteFile(filepath.Join(rules, "words.data"), []byte("# OS files\n.bashrc\n\netc/passwd\n"), 0o644)
	res, err := Import([]Group{{File: "x.conf", Out: "x.yaml", Ruleset: "crs-x", AttackType: "lfi", Layer: "managed"}},
		Options{CRSDir: dir, Version: "4.25.2"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func rule(t *testing.T, res *Result, id int) map[string]any {
	t.Helper()
	for _, r := range res.Groups[0].Rules {
		if r["id"] == id {
			return r
		}
	}
	t.Fatalf("rule %d not imported; skipped: %+v", id, res.Skipped)
	return nil
}

func conds(r map[string]any) []any { return r["match"].(map[string]any)["all"].([]any) }

func TestChainNegationAndScore(t *testing.T) {
	r := rule(t, importConf(t), 920170)
	if r["stage"] != "request_headers" || r["score"] != 100 || r["severity"] != "critical" || r["paranoia_level"] != 1 {
		t.Errorf("920170: %+v", r)
	}
	c := conds(r)
	if len(c) != 2 {
		t.Fatalf("a chain is one condition per link: %+v", c)
	}
	second := c[1].(map[string]any)
	want := map[string]any{
		"targets":  []map[string]any{{"var": "request_headers", "key": "Content-Length"}},
		"operator": map[string]any{"type": "rx", "value": "^0?$", "negate": true},
	}
	if !reflect.DeepEqual(second, want) {
		t.Errorf("negated link: %+v", second)
	}
	if md := r["metadata"].(map[string]any); md["source"] != "crs" || md["upstream_version"] != "4.25.2" || md["attack_type"] != "lfi" {
		t.Errorf("metadata %+v", md)
	}
}

func TestDataFilesExclusionsAndTransforms(t *testing.T) {
	res := importConf(t)
	r := rule(t, res, 930120)
	if r["score"] != 3*ScoreFactor || r["stage"] != "request_body" {
		t.Errorf("930120: %+v", r)
	}
	c := conds(r)[0].(map[string]any)
	if got := c["operator"]; !reflect.DeepEqual(got, map[string]any{"type": "pm", "value": []string{".bashrc", "etc/passwd"}}) {
		t.Errorf("data file words: %+v", got)
	}
	if got := c["transforms"]; !reflect.DeepEqual(got, []string{"lowercase", "url_decode_uni"}) {
		t.Errorf("transforms %v", got)
	}
	ts := c["targets"].([]map[string]any)
	if len(ts) != 3 || !reflect.DeepEqual(ts[0]["exclude"], []string{"password"}) || ts[2]["exclude"] != nil {
		t.Errorf("targets %+v", ts)
	}
	var noted bool
	for _, n := range res.Groups[0].Notes {
		noted = noted || (n.Rule == 930120 && strings.Contains(n.Text, "/__utm/"))
	}
	if !noted {
		t.Errorf("a pattern exclusion that is left out is noted: %+v", res.Groups[0].Notes)
	}

	// t:none drops the transformations before it.
	c942 := conds(rule(t, res, 942100))[0].(map[string]any)
	if got := c942["transforms"]; !reflect.DeepEqual(got, []string{"remove_nulls"}) {
		t.Errorf("942100 transforms %v", got)
	}
	if c942["multi_match"] != true || c["multi_match"] != nil {
		t.Errorf("multiMatch: 942100 %v, 930120 %v", c942["multi_match"], c["multi_match"])
	}
	cnt := conds(rule(t, res, 920280))[0].(map[string]any)
	if !reflect.DeepEqual(cnt["targets"], []map[string]any{{"var": "request_headers", "key": "Host", "count": true}}) ||
		!reflect.DeepEqual(cnt["operator"], map[string]any{"type": "eq", "value": 0}) {
		t.Errorf("920280: %+v", cnt)
	}
}

func TestXMLSelectors(t *testing.T) {
	res := importConf(t)
	got := conds(rule(t, res, 941100))[0].(map[string]any)["targets"]
	want := []map[string]any{{"var": "args"}, {"var": "xml"}, {"var": "xml_attributes"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets %+v", got)
	}
	var noted bool
	for _, n := range res.Groups[0].Notes {
		noted = noted || (n.Rule == 941100 && strings.Contains(n.Text, "XML:/a/b"))
	}
	if !noted {
		t.Errorf("another XPath is noted: %+v", res.Groups[0].Notes)
	}
}

func TestSkipGateBecomesACondition(t *testing.T) {
	res := importConf(t)
	c := conds(rule(t, res, 920540))
	want := map[string]any{
		"targets":  []map[string]any{{"var": "body_processor"}},
		"operator": map[string]any{"type": "streq", "value": "JSON", "negate": true},
	}
	if len(c) != 2 || !reflect.DeepEqual(c[1], want) {
		t.Errorf("920540: %+v", c)
	}
	if c := conds(rule(t, res, 920541)); len(c) != 1 {
		t.Errorf("skip:1 gates one rule only: %+v", c)
	}
}

func TestChainOnMatchedVars(t *testing.T) {
	c := conds(rule(t, importConf(t), 944120))
	if len(c) != 2 || !reflect.DeepEqual(c[1].(map[string]any)["targets"], []map[string]any{{"var": "matched_vars"}}) {
		t.Errorf("944120: %+v", c)
	}
}

func TestRulesLeftOutHaveAReason(t *testing.T) {
	res := importConf(t)
	want := map[int]string{
		942101: "paranoia level 2",
		942102: "does not block or score",
		942103: "variable TX",
		942104: "operator @within",
		942105: "macro in the operator argument",
		942106: "transformation sqlHexDecode",
		942107: "pattern selector ARGS:/^id/",
		920539: "does not block or score",
		920542: "does not block or score",
		920543: "skipped by control rule 920542",
	}
	got := map[int]string{}
	for _, s := range res.Sorted() {
		got[s.Rule] = s.Reason
	}
	for id, w := range want {
		if !strings.HasPrefix(got[id], w) {
			t.Errorf("%d: reason %q, want %q", id, got[id], w)
		}
	}
	if len(got) != len(want) || res.Groups[0].Read != len(want)+8 || len(res.Groups[0].Rules) != 8 {
		t.Errorf("read %d, imported %d, skipped %v", res.Groups[0].Read, len(res.Groups[0].Rules), got)
	}
}

func TestMarshalIsSortedIR(t *testing.T) {
	doc, err := Marshal(importConf(t).Groups[0], "4.25.2")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	if !strings.HasPrefix(s, "# OWASP CRS 4.25.2, x.conf: generated") || !strings.Contains(s, "ir_version: 1\nruleset:\n  name: crs-x\n") {
		t.Errorf("header:\n%s", s[:min(len(s), 300)])
	}
	if i, j := strings.Index(s, "id: 920170"), strings.Index(s, "id: 942100"); i < 0 || j < 0 || i > j {
		t.Errorf("rules are in id order")
	}
}
