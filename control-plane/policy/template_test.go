package policy

import (
	"reflect"
	"slices"
	"testing"

	"github.com/strata/strata/control-plane/rulesets"
)

// W20-S-01: every template is a valid spec that starts in shadow; a new
// policy starts from one, the request's fields on top, and records it.
func TestTemplates(t *testing.T) {
	if !reflect.DeepEqual(TemplateNames(), []string{"api", "base", "strict", "web"}) {
		t.Fatalf("templates %v", TemplateNames())
	}
	for name, tpl := range Templates {
		if err := tpl.Spec.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if tpl.Spec.Mode != "shadow" || tpl.Name != name || tpl.Version < 1 || tpl.Description == "" {
			t.Errorf("%s: %+v", name, tpl)
		}
	}
	api, err := FromTemplate("api", Spec{})
	if err != nil {
		t.Fatal(err)
	}
	want := Templates["api"].Spec
	want.Template = &TemplateRef{Name: "api", Version: 2}
	if !reflect.DeepEqual(api, want) {
		t.Errorf("api\n%+v\nwant\n%+v", api, want)
	}
	if api.Oversize != "block" || api.MaxArgs != 256 || api.FailOnFindings != "block" || !api.Response.DBErrors ||
		!slices.Contains(api.Response.DataGuard, "jwt") || !slices.Contains(api.Privacy.SensitiveFields, "password") {
		t.Errorf("api template %+v", api)
	}
	// the request's fields win, the others stay the template's
	over, err := FromTemplate("api", Spec{Mode: "enforce", MaxArgs: 64, CRSPlugins: []string{"wordpress"}})
	if err != nil {
		t.Fatal(err)
	}
	if over.Mode != "enforce" || over.MaxArgs != 64 || over.Oversize != "block" || !reflect.DeepEqual(over.CRSPlugins, []string{"wordpress"}) {
		t.Errorf("over %+v", over)
	}
	if err := over.Validate(); err != nil {
		t.Error(err)
	}
	// a copy: changing the policy never changes the template
	over.Privacy.SensitiveFields[0] = "changed"
	over.Response.DataGuard[0] = "pan"
	if Templates["api"].Spec.Privacy.SensitiveFields[0] == "changed" || Templates["api"].Spec.Response.DataGuard[0] == "pan" {
		t.Error("template shares its lists with a policy")
	}
	if _, err := FromTemplate("nope", Spec{}); err == nil {
		t.Error("unknown template")
	}
	if err := (Spec{Mode: "shadow", Template: &TemplateRef{Name: "API!", Version: 1}}).Validate(); err == nil {
		t.Error("bad template reference")
	}
}

// RS-3: every template logs every bot set (PO 22/10/2026) and blocks none;
// strict blocks the virtual patches and the CISA KEV signatures.
func TestTemplatesLogEveryBot(t *testing.T) {
	for name, tpl := range Templates {
		bots := 0
		for _, r := range tpl.Spec.RuleSets {
			set, ok := rulesets.Get(r.Set)
			if !ok {
				t.Fatalf("%s: unknown set %s", name, r.Set)
			}
			if set.Group == "bot" {
				bots++
				if r.Action != "log" {
					t.Errorf("%s: %s is %s", name, r.Set, r.Action)
				}
			}
		}
		n := 0
		for _, set := range rulesets.All() {
			if set.Group == "bot" {
				n++
			}
		}
		if bots != n {
			t.Errorf("%s lists %d of the %d bot sets", name, bots, n)
		}
	}
	strict := Templates["strict"].Spec
	if strict.CRSParanoia != 2 || !slices.Contains(strict.RuleSets, RuleSetRef{Set: "signatures-kev", Action: "block"}) ||
		!slices.Contains(strict.RuleSets, RuleSetRef{Set: "virtual-patches", Action: "block"}) {
		t.Errorf("strict %+v", strict)
	}
	// templates do not share their rule set lists
	a, b := Templates["base"].Spec.RuleSets, Templates["web"].Spec.RuleSets
	a[0].Action = "block"
	if b[0].Action != "log" {
		t.Error("templates share a rule set list")
	}
	a[0].Action = "log"
}

func TestRuleSetValidation(t *testing.T) {
	ok := Spec{Mode: "shadow", RuleSets: []RuleSetRef{{Set: "bots-scanners", Action: "block"}, {Set: "attack-sqli", Action: "default"}},
		RuleOverrides: []RuleOverride{{Rule: 942100, Action: "log", Reason: "FP on /search"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'x'
	}
	for name, s := range map[string]Spec{
		"unknown set":     {Mode: "shadow", RuleSets: []RuleSetRef{{Set: "bots-everything", Action: "block"}}},
		"set twice":       {Mode: "shadow", RuleSets: []RuleSetRef{{Set: "bots-scanners", Action: "block"}, {Set: "bots-scanners", Action: "log"}}},
		"bad set action":  {Mode: "shadow", RuleSets: []RuleSetRef{{Set: "bots-scanners", Action: "allow"}}},
		"no rule":         {Mode: "shadow", RuleOverrides: []RuleOverride{{Action: "off", Reason: "x"}}},
		"rule twice":      {Mode: "shadow", RuleOverrides: []RuleOverride{{Rule: 1, Action: "off", Reason: "x"}, {Rule: 1, Action: "log", Reason: "y"}}},
		"no reason":       {Mode: "shadow", RuleOverrides: []RuleOverride{{Rule: 1, Action: "off", Reason: "  "}}},
		"long reason":     {Mode: "shadow", RuleOverrides: []RuleOverride{{Rule: 1, Action: "off", Reason: string(long)}}},
		"bad rule action": {Mode: "shadow", RuleOverrides: []RuleOverride{{Rule: 1, Action: "allow", Reason: "x"}}},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// overrides are kept by rule: their order is no change
	a := Spec{Mode: "shadow", RuleOverrides: []RuleOverride{{Rule: 9, Action: "off", Reason: "x"}, {Rule: 2, Action: "log", Reason: "y"}}}
	a.Normalize()
	if a.RuleOverrides[0].Rule != 2 {
		t.Fatalf("not sorted: %+v", a.RuleOverrides)
	}
	// the compiler gets the filters, not the names
	got := expandRuleSets([]RuleSetRef{{Set: "bots-scanners", Action: "block"}})
	if len(got) != 1 || got[0].Name != "bots-scanners" || got[0].Action != "block" || !slices.Contains(got[0].Match.Tags, "scanner") {
		t.Fatalf("expanded %+v", got)
	}
}
