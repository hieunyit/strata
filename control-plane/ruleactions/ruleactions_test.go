package ruleactions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/rulesets"
)

func catalog(t *testing.T) *rulecat.Catalog {
	t.Helper()
	f := filepath.Join(t.TempDir(), "rules.yaml")
	ir := `ir_version: 1
ruleset: { name: example, version: "1" }
rules:
  - { id: 500901, name: scanner, layer: managed, metadata: { source: crawler-user-agents, attack_type: bot, tags: [scanner] } }
  - { id: 942100, name: sqli, layer: managed, metadata: { source: crs, attack_type: sql-injection } }
  - { id: 942200, name: sqli pl2, layer: managed, paranoia_level: 2, metadata: { source: crs, attack_type: sql-injection } }
  - { id: 9507100, name: plugin exclusion, layer: pre, metadata: { source: crs, plugin: wordpress } }
`
	if err := os.WriteFile(f, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := rulecat.Load([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// RS-5: what changes between two drafts, custom set copies included;
// exclusions are no detection rules.
func TestChanges(t *testing.T) {
	c := catalog(t)
	from := Of(policy.Spec{Mode: "enforce"})
	to := Of(policy.Spec{Mode: "enforce", CRSParanoiaShadow: 2, RuleSets: []policy.RuleSetRef{
		{Set: "custom-ours", Action: "block", Match: &rulesets.Filter{IDs: []uint32{500901, 9507100}}},
	}})
	got, n := Changes(c, from, to)
	if n != 2 || len(got) != 2 || got[0] != (Change{Rule: 500901, Name: "scanner", From: "log", To: "block", Source: "set", Set: "custom-ours"}) ||
		got[1] != (Change{Rule: 942200, Name: "sqli pl2", From: "off", To: "log", Source: "paranoia"}) {
		t.Fatalf("%d %+v", n, got)
	}
	if got, n := Changes(c, to, to); n != 0 || len(got) != 0 {
		t.Fatalf("no change: %d %+v", n, got)
	}
	// a custom set without its copy matches nothing
	if r := Resolve(c, c.Entries()[0], Draft{RuleSets: []policy.RuleSetRef{{Set: "custom-x", Action: "block"}}}); r.Action != "log" {
		t.Fatalf("%+v", r)
	}
}
