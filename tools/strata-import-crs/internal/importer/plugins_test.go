package importer

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const pluginConf = `SecRule TX:example-rule-exclusions-plugin_enabled "@eq 0" "id:9599099,phase:1,pass,nolog,ctl:ruleRemoveById=9599100-9599999"
SecRule &TX:example-rule-exclusions-plugin_extra_enabled "@eq 0" "id:9599098,phase:1,pass,nolog,ctl:ruleRemoveById=9599130"

SecRule REQUEST_FILENAME "@endsWith /login.php" \
    "id:9599100,phase:1,pass,t:none,nolog,\
    ctl:ruleRemoveTargetById=942100;ARGS:pwd,\
    ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:comment,\
    ctl:ruleRemoveTargetById=942100-942110;REQUEST_BODY,\
    ctl:ruleRemoveById=921180,\
    ctl:ruleRemoveById=9599200,\
    ctl:ruleRemoveTargetById=942100;TX:x"

SecRule REQUEST_FILENAME "@streq /x" "id:9599101,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS/DATA-LEAKAGES-PHP"

SecRule REQUEST_FILENAME "!@contains /admin/" "id:9599110,phase:1,pass,t:none,nolog,skipAfter:END-EXAMPLE-ADMIN"
SecRule REQUEST_FILENAME "@endsWith /admin/save.php" "id:9599120,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body"
SecRule REQUEST_FILENAME "@endsWith /admin/save.php" "id:9599121,phase:2,pass,t:none,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body"
SecMarker "END-EXAMPLE-ADMIN"

SecRule REQUEST_FILENAME "@endsWith /optional.php" "id:9599130,phase:1,pass,nolog,ctl:ruleRemoveById=942100"

SecRule TX:example-rule-exclusions-plugin_url_format "@streq new" "id:9599140,phase:1,pass,nolog,skipAfter:END-EXAMPLE-OLD"
SecRule REQUEST_FILENAME "@endsWith /old.php" "id:9599141,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
SecMarker "END-EXAMPLE-OLD"

SecRule REQUEST_FILENAME "@contains /dav/" \
    "id:9599150,phase:1,pass,nolog,chain"
    SecRule REQUEST_METHOD "@streq GET" "ctl:ruleRemoveById=920340,setvar:'tx.allowed_methods=%{tx.allowed_methods} PROPFIND MKCOL'"

SecRule REQUEST_FILENAME "@unconditionalMatch" "id:9599160,phase:2,pass,nolog,ctl:ruleRemoveTargetById=920273;REQUEST_HEADERS:X-Token"
SecRule RESPONSE_STATUS "@streq 200" "id:9599170,phase:3,pass,nolog,ctl:ruleRemoveById=950100"
`

func TestImportPlugin(t *testing.T) {
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	_ = os.MkdirAll(plugins, 0o755)
	_ = os.WriteFile(filepath.Join(plugins, "example-rule-exclusions-before.conf"), []byte(pluginConf), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "example-rule-exclusions-config.conf"), []byte(
		`SecAction "id:9599010,phase:1,pass,nolog,setvar:'tx.example-rule-exclusions-plugin_enabled=1',setvar:'tx.example-rule-exclusions-plugin_url_format=new'"`+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "example-rule-exclusions-after.conf"), []byte(
		`SecRuleUpdateTargetById 942200 "!REQUEST_COOKIES:/^pma[0-9]+$/"`+"\n"), 0o644)
	universe := []int{920340, 921180, 941100, 942100, 942101, 942110, 942120, 950100}
	tags := map[string][]int{
		"attack-sqli":                 {942100, 942101, 942120},
		"OWASP_CRS":                   universe,
		"OWASP_CRS/DATA-LEAKAGES-PHP": {950100},
	}
	res, err := ImportPlugin(Plugin{Name: "example", Version: "v1.0.0", Dir: dir}, tags, universe, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int]map[string]any{}
	for _, r := range res.Imported.Rules {
		byID[r["id"].(int)] = r
	}
	reasons := map[int]string{}
	for _, s := range res.Skipped {
		reasons[s.Rule] = s.Reason
	}

	// removals by target, tags as runs of the universe, own rules dropped
	r := byID[9599100]
	if r == nil {
		t.Fatalf("9599100 not imported: %v", reasons)
	}
	want := []any{
		map[string]any{"rules": []int{942100}, "target": map[string]any{"var": "args", "key": "pwd"}},
		map[string]any{"rule_ranges": [][2]int{{942100, 942101}}, "rules": []int{942120}, "target": map[string]any{"var": "args", "key": "comment"}},
		map[string]any{"rule_ranges": [][2]int{{942100, 942110}}, "target": map[string]any{"var": "request_body"}},
		map[string]any{"rules": []int{921180}},
	}
	if !reflect.DeepEqual(r["exclude"], want) {
		t.Errorf("9599100 exclude:\n%#v\nwant\n%#v", r["exclude"], want)
	}
	var dropped []string
	for _, d := range res.Dropped {
		dropped = append(dropped, d.Text)
	}
	if !strings.Contains(strings.Join(dropped, "\n"), "ruleRemoveById=9599200: the plugin's own rules") ||
		!strings.Contains(strings.Join(dropped, "\n"), "no Strata target for TX:x") {
		t.Errorf("dropped %q", dropped)
	}
	// a tag with a slash
	if !reflect.DeepEqual(byID[9599101]["exclude"], []any{map[string]any{"rules": []int{950100}}}) {
		t.Errorf("9599101 %v", byID[9599101])
	}
	// the gate's negation, for the rules of its phase only (skipAfter
	// skips within its phase: the phase 2 rule is not gated)
	all := byID[9599120]["match"].(map[string]any)["all"].([]any)
	gate := all[len(all)-1].(map[string]any)
	if len(all) != 2 || gate["operator"].(map[string]any)["value"] != "/admin/" || gate["operator"].(map[string]any)["negate"] != nil {
		t.Errorf("9599120 not gated: %v", all)
	}
	if n := len(byID[9599121]["match"].(map[string]any)["all"].([]any)); n != 1 {
		t.Errorf("9599121 gated by a phase 1 gate: %d conditions", n)
	}
	// an option off by default, a section another option skips
	for id, want := range map[int]string{
		9599098: "plugin option gate: turns plugin rules off by default",
		9599130: "off by default: rule 9599098",
		9599141: "skipped by default: rule 9599140",
		9599099: "plugin switch",
		9599110: "skipAfter gate",
		9599170: "phase 3",
	} {
		if !strings.HasPrefix(reasons[id], want) {
			t.Errorf("%d: %q, want %q", id, reasons[id], want)
		}
	}
	// a list option: a second rule, ID + 100000, with the added methods
	if !reflect.DeepEqual(byID[9599150]["exclude"], []any{map[string]any{"rules": []int{920340}}}) {
		t.Errorf("9599150 %v", byID[9599150]["exclude"])
	}
	w := byID[9699150]
	if w == nil || !reflect.DeepEqual(w["exclude"], []any{map[string]any{"rules": []int{911100}}}) {
		t.Fatalf("9699150 %v", w)
	}
	all = w["match"].(map[string]any)["all"].([]any)
	if last := all[len(all)-1].(map[string]any); last["operator"].(map[string]any)["value"] != "^(?:PROPFIND|MKCOL)$" {
		t.Errorf("9699150 condition %v", last)
	}
	// unconditional, header keys
	if c := byID[9599160]["match"].(map[string]any)["all"].([]any)[0].(map[string]any); c["operator"].(map[string]any)["value"] != "^" {
		t.Errorf("9599160 %v", c)
	}
	after := false
	for _, s := range res.Skipped {
		after = after || (s.Group == "example-rule-exclusions-after.conf" && strings.HasPrefix(s.Reason, "SecRuleUpdateTargetById"))
	}
	if !after {
		t.Errorf("after file: %v", res.Skipped)
	}
}

func TestRanges(t *testing.T) {
	u := []int{1, 2, 3, 5, 6, 9}
	// a run spans gaps of IDs outside the universe (7, 8), never a member
	// of the universe left out (3)
	if got := ranges(u, []int{1, 2, 5, 6, 9}); !reflect.DeepEqual(got, [][2]int{{1, 2}, {5, 9}}) {
		t.Errorf("%v", got)
	}
	if got := ranges(u, []int{1, 3, 9}); !reflect.DeepEqual(got, [][2]int{{1, 1}, {3, 3}, {9, 9}}) {
		t.Errorf("%v", got)
	}
	if got := ranges(u, nil); got != nil {
		t.Errorf("%v", got)
	}
}
