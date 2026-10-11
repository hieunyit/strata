package ruletest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// tools finds strata-compile and strata-eval. The rules CI job sets
// STRATA_RULES_REQUIRE_TOOLS=1, so these tests cannot pass by skipping
// there; elsewhere they skip when the binaries are not built.
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

const rule = `rule:
  id: 800010
  name: Example rule
  layer: managed
  stage: request_headers
  match:
    all:
      - targets: [{ var: path }]
        operator: { type: begins_with, value: /admin }
  score: 10
  severity: warning
  metadata: { source: organization, license: Apache-2.0, author: example-secops }
tests:
  match: [{ uri: /admin/users }]
  no_match: [{ uri: /home }, { uri: /administrator-guide, name: a prefix that also matches }]
`

const unsupported = `rule:
  id: 800011
  name: Needs response_status
  layer: response
  stage: response_headers
  match:
    all:
      - targets: [{ var: response_status }]
        operator: { type: eq, value: 500 }
  score: 10
  severity: warning
  metadata: { source: organization, license: Apache-2.0, author: example-secops }
tests:
  match: [{ uri: /run }]
  no_match: [{ uri: /run }]
`

func TestRunReportsPassFailSkip(t *testing.T) {
	tl := tools(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "800010-example.yaml"), []byte(rule), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "800011-ip.yaml"), []byte(unsupported), 0o644)
	files, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(tl, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("results %+v", res)
	}
	// The second no_match request starts with /admin: a real failure.
	if res[0].Status != Fail || len(res[0].Failures) != 1 || !strings.Contains(res[0].Failures[0], "a prefix that also matches") {
		t.Errorf("800010: %+v", res[0])
	}
	if res[1].Status != Skip || !strings.Contains(res[1].Reason, "target response_status") {
		t.Errorf("800011: %+v", res[1])
	}
}

// The ten sample rules of rules/ pass or are skipped for a named reason.
func TestRepositorySamples(t *testing.T) {
	tl := tools(t)
	files, err := Load("../../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(tl, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Status == Fail {
			t.Errorf("%d: %v", r.Rule, r.Failures)
		}
		if r.Status == Skip && r.Reason == "" {
			t.Errorf("%d skipped without a reason", r.Rule)
		}
	}
}
