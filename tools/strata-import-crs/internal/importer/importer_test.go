package importer

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
	if len(got) != len(want) || res.Groups[0].Read != len(want)+9 || len(res.Groups[0].Rules) != 9 { // 942104 (@within) imported since the W08 review
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

func TestBatch2Operators(t *testing.T) {
	testConf := `
SecRule ARGS "@validateByteRange 32-126" "id:920270,phase:2,block,severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule REQUEST_URI "@validateUrlEncoding" "id:920220,phase:1,block,severity:'WARNING',tag:'paranoia-level/1'"
SecRule ARGS "@validateUtf8Encoding" "id:920250,phase:2,block,severity:'ERROR',tag:'paranoia-level/1'"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8, 192.168.1.1" "id:920350,phase:1,block,severity:'CRITICAL',tag:'paranoia-level/1'"
`
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(rules, "ops.conf"), []byte(testConf), 0o644)
	res, err := Import([]Group{{File: "ops.conf", Out: "ops.yaml", Ruleset: "crs-ops", AttackType: "protocol", Layer: "protocol"}},
		Options{CRSDir: dir, Version: "4.25.2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups[0].Rules) != 4 {
		t.Fatalf("expected 4 rules, got %d, skipped: %+v", len(res.Groups[0].Rules), res.Skipped)
	}

	r270 := rule(t, res, 920270)
	c270 := conds(r270)[0].(map[string]any)
	if !reflect.DeepEqual(c270["operator"], map[string]any{"type": "validate_byte_range", "value": "32-126"}) {
		t.Errorf("920270 op: %+v", c270["operator"])
	}

	r220 := rule(t, res, 920220)
	c220 := conds(r220)[0].(map[string]any)
	if !reflect.DeepEqual(c220["operator"], map[string]any{"type": "validate_url_encoding"}) {
		t.Errorf("920220 op: %+v", c220["operator"])
	}

	r250 := rule(t, res, 920250)
	c250 := conds(r250)[0].(map[string]any)
	if !reflect.DeepEqual(c250["operator"], map[string]any{"type": "validate_utf8_encoding"}) {
		t.Errorf("920250 op: %+v", c250["operator"])
	}

	r350 := rule(t, res, 920350)
	c350 := conds(r350)[0].(map[string]any)
	if !reflect.DeepEqual(c350["operator"], map[string]any{"type": "ip_match", "value": []string{"10.0.0.0/8", "192.168.1.1"}}) {
		t.Errorf("920350 op: %+v", c350["operator"])
	}
}

// W08 review: the crs-setup lists come from REQUEST-901's defaults;
// @within on a request variable and the four capture-then-@within chains
// become conditions on the request value.
const conf901 = `SecRule &TX:allowed_methods "@eq 0" "id:901160,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS'"
SecRule &TX:allowed_request_content_type "@eq 0" "id:901162,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |application/json|'"
SecRule REQUEST_HEADERS:Host "@rx ^x$" "id:901500,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type=%{tx.allowed_request_content_type} |text/x|'"
SecRule &TX:allowed_request_content_type_charset "@eq 0" "id:901168,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type_charset=|utf-8| |iso-8859-1|'"
SecRule &TX:restricted_extensions "@eq 0" "id:901163,phase:1,pass,nolog,setvar:'tx.restricted_extensions=.bak/ .config/'"
SecRule &TX:restricted_headers_basic "@eq 0" "id:901164,phase:1,pass,nolog,setvar:'tx.restricted_headers_basic=/proxy/ /lock-token/'"
`

const confLists = `SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:911100,phase:1,block,severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\s]+" "id:920420,phase:1,block,capture,severity:'CRITICAL',tag:'paranoia-level/1',setvar:'tx.content_type=|%{tx.0}|',chain"
    SecRule TX:content_type "!@within %{tx.allowed_request_content_type}" "t:lowercase"
SecRule REQUEST_HEADERS:Content-Type "@rx charset\s*=\s*[\"']?([^;\"'\s]+)" "id:920480,phase:1,block,capture,severity:'CRITICAL',tag:'paranoia-level/1',setvar:'tx.content_type_charset=|%{tx.1}|',chain"
    SecRule TX:content_type_charset "!@within %{tx.allowed_request_content_type_charset}" "t:lowercase"
SecRule REQUEST_BASENAME "@rx \.([^.]+)$" "id:920440,phase:1,block,capture,severity:'CRITICAL',tag:'paranoia-level/1',setvar:'tx.extension=.%{tx.1}/',chain"
    SecRule TX:EXTENSION "@within %{tx.restricted_extensions}" "t:lowercase"
SecRule REQUEST_HEADERS_NAMES "@rx ^.*$" "id:920450,phase:1,block,capture,severity:'CRITICAL',tag:'paranoia-level/1',setvar:'tx.header_name_920450_%{tx.0}=/%{tx.0}/',chain"
    SecRule TX:/^header_name_920450_/ "@within %{tx.restricted_headers_basic}" "t:lowercase"
SecRule REQUEST_METHOD "@within %{tx.unknown_list}" "id:911101,phase:1,block,severity:'CRITICAL',tag:'paranoia-level/1'"
`

func TestConfigListsFrom901(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	_ = os.MkdirAll(rules, 0o755)
	_ = os.WriteFile(filepath.Join(rules, "REQUEST-901-INITIALIZATION.conf"), []byte(conf901), 0o644)
	_ = os.WriteFile(filepath.Join(rules, "x.conf"), []byte(confLists), 0o644)
	d, err := ReadDefaults(filepath.Join(rules, "REQUEST-901-INITIALIZATION.conf"))
	if err != nil || d["allowed_request_content_type"] != "|application/x-www-form-urlencoded| |application/json|" {
		t.Fatalf("defaults %v %v (the conditional addition must not replace the default)", d, err)
	}
	res, err := Import([]Group{{File: "x.conf", Out: "x.yaml", Ruleset: "crs-x", AttackType: "protocol", Layer: "protocol"}},
		Options{CRSDir: dir, Version: "4.25.2"})
	if err != nil {
		t.Fatal(err)
	}
	op := func(c any) map[string]any { return c.(map[string]any)["operator"].(map[string]any) }
	if c := conds(rule(t, res, 911100)); op(c[0])["value"] != "^(?:GET|HEAD|POST|OPTIONS|PUT|PATCH|DELETE)$" || op(c[0])["negate"] != true {
		t.Errorf("911100: %+v", c)
	}
	if c := conds(rule(t, res, 920420)); len(c) != 2 || op(c[1])["value"] != `^(?:application/x-www-form-urlencoded|application/json)(?:[;\s]|$)` || op(c[1])["negate"] != true {
		t.Errorf("920420: %+v", c)
	}
	if c := conds(rule(t, res, 920480)); len(c) != 2 || !strings.Contains(op(c[1])["value"].(string), "(?:utf-8|iso-8859-1)") {
		t.Errorf("920480: %+v", c)
	}
	if c := conds(rule(t, res, 920440)); op(c[0])["value"] != `\.(?:bak|config)$` {
		t.Errorf("920440: %+v", c)
	}
	if c := conds(rule(t, res, 920450)); op(c[0])["value"] != `^(?:proxy|lock-token)$` {
		t.Errorf("920450: %+v", c)
	}
	if r := rule(t, res, 920420); r["action_mode"] != "score" {
		t.Errorf("action_mode: %v", r["action_mode"])
	}
	for _, s := range res.Skipped {
		if s.Rule == 911101 && strings.Contains(s.Reason, "without a REQUEST-901 default") {
			return
		}
	}
	t.Errorf("911101 with an unknown list not refused: %+v", res.Skipped)
}

// Strata's tuning of two CRS rules (W09-S-01): 930120 lists "program
// files/" instead of "program files", 942100 gets a condition on the value
// libinjection flagged; other rules are left as they are.
func TestTune(t *testing.T) {
	cond := func(op string, v any) map[string]any {
		return map[string]any{"operator": map[string]any{"type": op, "value": v}, "targets": []map[string]any{{"var": "args"}}}
	}
	lfi := map[string]any{"match": map[string]any{"all": []any{cond("pm", []string{".bashrc", "program files", "boot.ini"})}}}
	var notes []string
	tune(930120, lfi, &notes)
	got := lfi["match"].(map[string]any)["all"].([]any)[0].(map[string]any)["operator"].(map[string]any)["value"]
	if !reflect.DeepEqual(got, []string{".bashrc", "program files/", "boot.ini"}) || len(notes) != 1 {
		t.Errorf("930120: %v %v", got, notes)
	}
	sqli := map[string]any{"match": map[string]any{"all": []any{cond("detect_sqli", nil)}}}
	notes = nil
	tune(942100, sqli, &notes)
	all := sqli["match"].(map[string]any)["all"].([]any)
	if len(all) != 2 || len(notes) != 1 {
		t.Fatalf("942100: %v", all)
	}
	c := all[1].(map[string]any)
	if c["operator"].(map[string]any)["value"] != sqlSignal || c["targets"].([]any)[0].(map[string]any)["var"] != "matched_vars" {
		t.Errorf("942100 condition: %v", c)
	}
	re := regexp.MustCompile(sqlSignal)
	for _, s := range []string{"1' or '1'='1", "1 union select", "x)--", "1;drop table t", "admin'--"} {
		if !re.MatchString(s) {
			t.Errorf("sqlSignal misses %q", s)
		}
	}
	for _, s := range []string{"50% off -- today only", "see you -- bye"} {
		if re.MatchString(s) {
			t.Errorf("sqlSignal matches prose %q", s)
		}
	}
	other := map[string]any{"match": map[string]any{"all": []any{cond("rx", "x")}}}
	notes = nil
	tune(941100, other, &notes)
	if len(other["match"].(map[string]any)["all"].([]any)) != 1 || notes != nil {
		t.Error("tune changed another rule")
	}
}

// W11-S-01: 942100's extra condition looks for the SQL signal before the
// first SQL comment, where an injection puts it.
func TestSQLSignalBeforeComment(t *testing.T) {
	re := regexp.MustCompile(sqlSignal)
	for _, v := range []string{
		"admin'--", "admin' -- x", "1 OR 1=1 --", "'; DROP TABLE t; #", "1' or '1'='1",
		"1 union select 1,2", "x-'y", "-1)--", "admin\"#", "1;sleep(5)",
	} {
		if !re.MatchString(v) {
			t.Errorf("%q: injection not flagged", v)
		}
	}
	for _, v := range []string{
		"50% off -- today only. drop me a line", "50% off -- today only. #hashtag",
		"50% off -- today only. where is my order?", "50% off -- today only. it's 5 o'clock",
		"50% off -- today only. SELECT the best plan", "great deal # call (now)", "10-20 items -- sale; ok",
	} {
		if re.MatchString(v) {
			t.Errorf("%q: prose flagged", v)
		}
	}
}

// 15/10/2026 (docs/decisions/base64-args.md): GoTestWAF's false-positive set
// is prose that four CRS PL1 rules block on their own. The tuning lets the
// prose through and keeps the injections those rules are for.
func TestTuneProseFalsePositives(t *testing.T) {
	sql := regexp.MustCompile(sqlSignal)
	for _, v := range []string{"1 or 1", "x or true", "1 union select 1", "admin' or 'a", "2 and sleep 5"} {
		if !sql.MatchString(v) {
			t.Errorf("sqlSignal misses %q", v)
		}
	}
	for _, v := range []string{"john or@var.es", "john+or@var.es", "rock and roll"} {
		if sql.MatchString(v) {
			t.Errorf("sqlSignal matches prose %q", v)
		}
	}

	shell := regexp.MustCompile(shellSignal)
	for _, v := range []string{"ls -la", "cat /etc/passwd", "id", " whoami ", "ls|nc x 1", "zsh -c x", "wget x>y", "sh $(id)", "wget evil.example"} {
		if !shell.MatchString(v) {
			t.Errorf("shellSignal misses %q", v)
		}
	}
	for _, v := range []string{"ls 300 lexus", "zsh is the best!", "who am i"} {
		if shell.MatchString(v) {
			t.Errorf("shellSignal matches prose %q", v)
		}
	}

	// 942190, on the part tune rewrites
	union := regexp.MustCompile(`(?i)` + unionTight)
	for _, v := range []string{"union select 1", "UNION ALL SELECT", "union  distinct (select", "union(select", "union0select", "union(all(select", "union\ndistinctrow\x0bselect", "unionx\nselect"} {
		if !union.MatchString(v) {
			t.Errorf("942190 misses %q", v)
		}
	}
	for _, v := range []string{"union was a great select", "the union will select a leader"} {
		if union.MatchString(v) {
			t.Errorf("942190 matches prose %q", v)
		}
	}

	cond := func(op string, v any) map[string]any {
		return map[string]any{"operator": map[string]any{"type": op, "value": v}, "targets": []any{map[string]any{"var": "args"}}, "transforms": []any{"html_entity_decode"}}
	}
	for _, id := range []int{932250, 941210} {
		r := map[string]any{"match": map[string]any{"all": []any{cond("rx", "x")}}}
		var notes []string
		tune(id, r, &notes)
		all := r["match"].(map[string]any)["all"].([]any)
		if len(all) != 2 || len(notes) != 1 {
			t.Fatalf("%d: %v", id, all)
		}
		c := all[1].(map[string]any)
		if c["targets"].([]any)[0].(map[string]any)["var"] != "matched_vars" {
			t.Errorf("%d condition: %v", id, c)
		}
		if _, ok := c["transforms"]; ok != (id == 941210) {
			t.Errorf("%d transforms: %v", id, c)
		}
	}
	js := regexp.MustCompile(jsSignal)
	for _, v := range []string{"javascript: alert(1)", "javascript:x=1", "ja\tvascript: ", "ja&tab;vascript: ", "ja&newline;vascript:"} {
		if !js.MatchString(v) {
			t.Errorf("jsSignal misses %q", v)
		}
	}
	if js.MatchString("JavaScript: Basics of JavaScript Language") {
		t.Error("jsSignal matches prose")
	}
	r := map[string]any{"match": map[string]any{"all": []any{cond("rx", "(?i)x|"+unionAnyWords+"|y")}}}
	var notes []string
	tune(942190, r, &notes)
	got := r["match"].(map[string]any)["all"].([]any)[0].(map[string]any)["operator"].(map[string]any)["value"]
	if got != "(?i)x|"+unionTight+"|y" || len(notes) != 1 {
		t.Errorf("942190: %v %v", got, notes)
	}
}
