package admin

import (
	"encoding/json"
	"testing"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
)

// W20-S-01: templates through the admin API.
func TestPolicyTemplates(t *testing.T) {
	p := &policyAdmin{}
	list, err := p.ListPolicyTemplates(t.Context(), &adminv1.ListPolicyTemplatesRequest{})
	if err != nil || len(list.GetTemplates()) != 4 || list.GetTemplates()[0].GetName() != "api" ||
		list.GetTemplates()[0].GetSpec().GetOversize() != adminv1.PolicySpec_OVERSIZE_BLOCK || list.GetTemplates()[0].GetDescription() == "" {
		t.Fatalf("templates %+v %v", list, err)
	}
	// a new policy from the api template, with its own mode
	raw, err := specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_ENFORCE}, fromTemplate("api"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["mode"] != "enforce" || got["oversize"] != "block" || got["max_args"] != 256.0 || got["template"] == nil {
		t.Errorf("from template: %s", raw)
	}
	// the reference survives a later edit (the UI sends the spec back)
	pb := specPB(raw)
	if pb.GetTemplate().GetName() != "api" || pb.GetTemplate().GetVersion() != 2 {
		t.Errorf("template ref %+v", pb.GetTemplate())
	}
	if again, err := specOf(pb); err != nil || string(again) != string(raw) {
		t.Errorf("round trip %s %v", again, err)
	}
	// only the mode unset: the template's
	raw, err = specOf(&adminv1.PolicySpec{}, fromTemplate("web"))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &got)
	if got["mode"] != "shadow" || got["oversize"] != "pass" {
		t.Errorf("web: %s", raw)
	}
	if _, err := specOf(&adminv1.PolicySpec{}, fromTemplate("nope")); err == nil {
		t.Error("unknown template accepted")
	}
}

// RS-3: rule sets and overrides through the admin API.
func TestPolicyRuleActions(t *testing.T) {
	in := &adminv1.PolicySpec{
		Mode: adminv1.PolicySpec_MODE_SHADOW,
		RuleSets: []*adminv1.PolicyRuleSet{
			{Set: "bots-scanners", Action: adminv1.PolicyRuleAction_POLICY_RULE_ACTION_BLOCK},
			{Set: "attack-sqli", Action: adminv1.PolicyRuleAction_POLICY_RULE_ACTION_UNSPECIFIED},
		},
		RuleOverrides: []*adminv1.PolicyRuleOverride{
			{Rule: 942100, Action: adminv1.PolicyRuleAction_POLICY_RULE_ACTION_OFF, Reason: "FP on /search"},
		},
	}
	raw, err := specOf(in)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		RuleSets      []map[string]any `json:"rule_sets"`
		RuleOverrides []map[string]any `json:"rule_overrides"`
	}
	_ = json.Unmarshal(raw, &got)
	if len(got.RuleSets) != 2 || got.RuleSets[0]["action"] != "block" || got.RuleSets[1]["action"] != "default" ||
		len(got.RuleOverrides) != 1 || got.RuleOverrides[0]["action"] != "off" {
		t.Fatalf("spec %s", raw)
	}
	if again, err := specOf(specPB(raw)); err != nil || string(again) != string(raw) {
		t.Errorf("round trip %s %v", again, err)
	}
	for _, bad := range []*adminv1.PolicySpec{
		{RuleSets: []*adminv1.PolicyRuleSet{nil}},
		{RuleSets: []*adminv1.PolicyRuleSet{{Set: "bots-scanners", Action: 99}}},
		{RuleSets: []*adminv1.PolicyRuleSet{{Set: "no-such-set", Action: adminv1.PolicyRuleAction_POLICY_RULE_ACTION_LOG}}},
		{RuleOverrides: []*adminv1.PolicyRuleOverride{{Rule: 1, Action: adminv1.PolicyRuleAction_POLICY_RULE_ACTION_OFF}}},
	} {
		if _, err := specOf(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
