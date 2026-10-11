package ftw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

func tools(t *testing.T) runner.Tools {
	t.Helper()
	tl, err := runner.Find("../../../..")
	if err != nil {
		if os.Getenv("STRATA_RULES_REQUIRE_TOOLS") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	return tl
}

const rules = `ir_version: 1
ruleset: { name: crs-test, version: "1" }
rules:
  - id: 942100
    name: SQL injection
    layer: managed
    stage: request_body
    match:
      all:
        - targets: [{ var: args }]
          operator: { type: detect_sqli }
    score: 100
    severity: critical
    metadata: { source: crs, license: Apache-2.0, upstream_id: "942100", upstream_version: 4.25.2, author: OWASP CRS project }
  - id: 942101
    name: needs ip_match
    layer: managed
    stage: request_headers
    match:
      all:
        - targets: [{ var: remote_addr }]
          operator: { type: ip_match, value: [192.0.2.0/24] }
    score: 100
    severity: critical
    metadata: { source: crs, license: Apache-2.0, upstream_id: "942101", upstream_version: 4.25.2, author: OWASP CRS project }
`

const tests = `{"rule":942100,"test":"942100-1","expect":"match","request":{"method":"GET","uri":"/q?id=1%27%20or%20%271%27=%271","headers":{"Host":"localhost"}}}
{"rule":942100,"test":"942100-2","expect":"no_match","request":{"method":"GET","uri":"/q?id=12","headers":{"Host":"localhost"}}}
{"rule":942100,"test":"942100-3","expect":"no_match","request":{"method":"GET","uri":"/q?id=1%27%20or%20%271%27=%271","headers":{"Host":"localhost"}}}
{"rule":942100,"test":"942100-4","expect":"match","request":{"method":"GET","uri":"/q?id=1%00%27%20or%20%271%27=%271","headers":{"Host":"localhost"}}}
{"rule":942101,"test":"942101-1","expect":"match","request":{"method":"GET","uri":"/","headers":{"Host":"localhost"}}}
{"rule":942102,"test":"942102-1","expect":"match","request":{"method":"GET","uri":"/","headers":{"Host":"localhost"}}}
{"rule":942103,"test":"942103-1","expect":"match","request":{"method":"GET","uri":"/","headers":{"Host":"localhost"}}}
`

func TestRunCountsEveryTestOfTheParanoiaLevel(t *testing.T) {
	tl := tools(t)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "rules"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "rules", "942.yaml"), []byte(rules), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "ftw"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "ftw", "REQUEST-942-APPLICATION-ATTACK-SQLI.jsonl"), []byte(tests), 0o644)
	inv := "rule_id,file,line,directive,phase,paranoia_level\n942100,x,1,SecRule,2,1\n942101,x,2,SecRule,2,1\n942102,x,3,SecRule,2,1\n942103,x,4,SecRule,2,2\n"
	_ = os.WriteFile(filepath.Join(dir, "inv.csv"), []byte(inv), 0o644)

	ts, err := Load(filepath.Join(dir, "ftw"))
	if err != nil || len(ts) != 7 || ts[0].Group != "REQUEST-942-APPLICATION-ATTACK-SQLI" {
		t.Fatalf("load: %v %+v", err, ts)
	}
	pl, err := ParanoiaLevels(filepath.Join(dir, "inv.csv"))
	if err != nil || pl[942103] != 2 {
		t.Fatalf("paranoia levels: %v %v", err, pl)
	}
	res, err := Run(tl, filepath.Join(dir, "rules"), ts, pl, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"942100-1": Pass, "942100-2": Pass, "942100-3": Fail, "942100-4": Fail,
		"942101-1": Unsupported, "942102-1": NotImported, "942103-1": "",
	}
	for _, r := range res {
		if r.Status != want[r.Name] {
			t.Errorf("%s: %s (%s), want %q", r.Name, r.Status, r.Reason, want[r.Name])
		}
		if r.Name == "942100-4" && !strings.HasPrefix(r.Reason, "blocked first by") {
			t.Errorf("942100-4: the protocol layer blocks a NUL first: %q", r.Reason)
		}
	}
	g := Groups(res)
	if len(g) != 1 || g[0].Tests != 6 || g[0].Passed != 2 || g[0].Failed != 2 || g[0].Missing != 2 || g[0].AboveMax != 1 {
		t.Fatalf("groups %+v", g)
	}
	var b strings.Builder
	Markdown(&b, res, 1)
	for _, s := range []string{"| REQUEST-942-APPLICATION-ATTACK-SQLI | 6 | 2 | 2 | 2 | 33.3 | 1 |", "| 942102 | not imported | 1 |", "942100-3 | no_match | matched"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("markdown lacks %q:\n%s", s, b.String())
		}
	}
}

func TestWithLength(t *testing.T) {
	r := withLength(runner.Request{Body: "a=1", Headers: map[string]any{"Host": "x"}})
	if r.Headers["Content-Length"] != "3" {
		t.Errorf("%v", r.Headers)
	}
	r = withLength(runner.Request{Body: "a=1", Headers: map[string]any{"transfer-encoding": "chunked"}})
	if _, ok := r.Headers["Content-Length"]; ok {
		t.Errorf("chunked: %v", r.Headers)
	}
	if r := withLength(runner.Request{}); r.Headers != nil {
		t.Errorf("no body: %v", r.Headers)
	}
}
