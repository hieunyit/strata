package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repo = "../../../.."

const good = `rule:
  id: 800010
  name: Example rule
  layer: managed
  stage: request_headers
  match:
    all:
      - targets: [{ var: path }]
        operator: { type: rx, value: '^/admin(/|$)' }
  score: 10
  severity: warning
  metadata: { source: organization, license: Apache-2.0, author: example-secops }
tests:
  match: [{ uri: /admin/users }]
  no_match: [{ uri: /home }]
`

func lintFiles(t *testing.T, files map[string]string) []Finding {
	t.Helper()
	l, err := New(repo)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, _, err := l.Lint(dir)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func expectFinding(t *testing.T, findings []Finding, want string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.String(), want) {
			return
		}
	}
	t.Fatalf("no finding containing %q in %v", want, findings)
}

// The ten samples in rules/ pass (W03-S-01: "10 rule mẫu pass").
func TestRepositoryRulesPass(t *testing.T) {
	l, err := New(repo)
	if err != nil {
		t.Fatal(err)
	}
	f, n, err := l.Lint(filepath.Join(repo, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Fatalf("findings: %v", f)
	}
	if n < 10 {
		t.Fatalf("%d rule files, want at least 10", n)
	}
}

func TestGoodRule(t *testing.T) {
	if f := lintFiles(t, map[string]string{"800010-example.yaml": good}); len(f) != 0 {
		t.Fatalf("findings: %v", f)
	}
}

func TestMissingLicense(t *testing.T) {
	body := strings.Replace(good, "license: Apache-2.0, ", "", 1)
	expectFinding(t, lintFiles(t, map[string]string{"800010-example.yaml": body}), "license")
}

func TestImportedRuleNeedsUpstream(t *testing.T) {
	body := strings.NewReplacer(
		"id: 800010", "id: 942999",
		"source: organization", "source: crs",
	).Replace(good)
	f := lintFiles(t, map[string]string{"942999-example.yaml": body})
	expectFinding(t, f, "upstream_id")
	expectFinding(t, f, "upstream_version")
}

func TestIDRangeOfSource(t *testing.T) {
	// A CRS rule keeps its original 9xxxxx id.
	body := strings.NewReplacer("source: organization", "source: crs, upstream_id: '1', upstream_version: 4.25.0").Replace(good)
	expectFinding(t, lintFiles(t, map[string]string{"800010-example.yaml": body}), "/rule/id")
}

func TestDuplicateID(t *testing.T) {
	expectFinding(t, lintFiles(t, map[string]string{"800010-a.yaml": good, "800010-b.yaml": good}), "id already used")
}

func TestFileName(t *testing.T) {
	expectFinding(t, lintFiles(t, map[string]string{"example.yaml": good}), `file name must start with "800010-"`)
}

func TestRegexMustBeRE2(t *testing.T) {
	body := strings.Replace(good, `'^/admin(/|$)'`, `'^/admin(?!/public)'`, 1)
	expectFinding(t, lintFiles(t, map[string]string{"800010-example.yaml": body}), "not RE2")
}

func TestGPLLicenseRefused(t *testing.T) {
	body := strings.Replace(good, "license: Apache-2.0", "license: GPL-2.0-only", 1)
	expectFinding(t, lintFiles(t, map[string]string{"800010-example.yaml": body}), "may not be shipped")
}

func TestSamplesRequired(t *testing.T) {
	body := strings.Replace(good, "  no_match: [{ uri: /home }]\n", "", 1)
	expectFinding(t, lintFiles(t, map[string]string{"800010-example.yaml": body}), "no_match")
	body = strings.Replace(good, "match: [{ uri: /admin/users }]", "match: []", 1)
	expectFinding(t, lintFiles(t, map[string]string{"800010-example.yaml": body}), "/tests/match")
}

func TestRulesetFile(t *testing.T) {
	set := `ir_version: 1
ruleset: { name: crs-930-lfi, version: 4.25.0 }
rules:
  - id: 930100
    name: Path Traversal Attack (/../)
    layer: managed
    stage: request_body
    match:
      all:
        - targets: [{ var: uri_raw }]
          operator: { type: rx, value: '(?i)(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))(?:%(?:(?:f(?:(?:c%80|8)%8)?0%8|e)0%80%ae|2(?:(?:5(?:c0%25a|2))?e|%45)|u(?:(?:002|ff0)e|2024)|%32(?:%(?:%6|4)5|E)|c0(?:%[256aef]e|\.))|\.(?:%0[01])?|0x2e){2,3}(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))' }
    score: 5
    severity: critical
    metadata: { source: crs, upstream_id: "930100", upstream_version: 4.25.0, license: Apache-2.0, author: OWASP CRS project }
`
	if f := lintFiles(t, map[string]string{"930-lfi.yaml": set}); len(f) != 0 {
		t.Fatalf("findings: %v", f)
	}
	bad := strings.Replace(set, "license: Apache-2.0, ", "", 1)
	expectFinding(t, lintFiles(t, map[string]string{"930-lfi.yaml": bad}), "license")
}
