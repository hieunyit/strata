package ftw

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const sample = `---
rule_id: 942100
tests:
  - test_id: 1
    desc: "body"
    stages:
      - input: { method: POST, uri: /post, data: "var=1 OR 1=1", headers: { Host: localhost } }
        output: { log: { expect_ids: [942100] } }
  - test_id: 2
    stages:
      - input: { uri: "/get?x=1", headers: { Host: localhost } }
        output: { log: { no_expect_ids: [942100, 942101] } }
  - test_id: 3
    stages:
      - input: { encoded_request: "R0VUIC8=" }
        output: { log: { expect_ids: [942100] } }
  - test_id: 4
    stages:
      - input: { uri: / }
        output: { status: 400 }
  - test_id: 5
    stages:
      - input: { uri: /a }
        output: { log: { expect_ids: [942100] } }
      - input: { uri: /b }
        output: { log: { expect_ids: [942100] } }
`

func TestConvert(t *testing.T) {
	dir := t.TempDir()
	g := filepath.Join(dir, "REQUEST-942-APPLICATION-ATTACK-SQLI")
	_ = os.MkdirAll(g, 0o755)
	_ = os.WriteFile(filepath.Join(g, "942100.yaml"), []byte(sample), 0o644)
	res, err := Convert(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := res.Groups["REQUEST-942-APPLICATION-ATTACK-SQLI"]
	if res.Total != 5 || len(cases) != 3 || len(res.Skipped) != 3 {
		t.Fatalf("total %d, cases %d, skipped %+v", res.Total, len(cases), res.Skipped)
	}
	c := cases[0]
	h := c.Request["headers"].(map[string]any)
	if c.Expect != "match" || c.Request["method"] != "POST" || c.Request["body"] != "var=1 OR 1=1" ||
		h["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Errorf("body test: %+v", c)
	}
	if cases[1].Expect != "no_match" || cases[2].Rule != 942101 || cases[1].Request["method"] != "GET" {
		t.Errorf("no_expect_ids: %+v %+v", cases[1], cases[2])
	}
	var buf bytes.Buffer
	res.Report(&buf, "4.25.2")
	for _, want := range []string{"encoded_request", "expects only an HTTP status", "2 stages"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

// corpus/crs-ftw and docs/crs-ftw-unconverted.md are what the converter
// writes for the pinned CRS release.
func TestCommittedConversionIsCurrent(t *testing.T) {
	lock, _ := os.ReadFile("../../crs.lock")
	v := regexp.MustCompile(`(?m)^version=(.+)$`).FindSubmatch(lock)
	crs := filepath.Join("../../../../build/crs", "coreruleset-"+string(v[1]))
	if d := os.Getenv("STRATA_CRS_DIR"); d != "" {
		crs = d
	}
	if _, err := os.Stat(filepath.Join(crs, ".verified")); err != nil && os.Getenv("STRATA_CRS_DIR") == "" {
		t.Fatalf("CRS %s is not fetched: run tools/strata-import-crs/fetch-crs.sh", v[1])
	}
	res, err := Convert(filepath.Join(crs, "tests", "regression", "tests"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := res.Write(out); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.jsonl"))
	committed, _ := filepath.Glob("../../../../corpus/crs-ftw/*.jsonl")
	if len(files) != len(committed) {
		t.Fatalf("%d groups converted, %d committed: run make crs-ftw", len(files), len(committed))
	}
	for _, f := range files {
		got, _ := os.ReadFile(f)
		want, _ := os.ReadFile(filepath.Join("../../../../corpus/crs-ftw", filepath.Base(f)))
		if !bytes.Equal(got, want) {
			t.Fatalf("corpus/crs-ftw/%s is stale: run make crs-ftw", filepath.Base(f))
		}
	}
}
