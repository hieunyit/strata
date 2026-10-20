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
	if err != nil || len(list.GetTemplates()) != 3 || list.GetTemplates()[0].GetName() != "api" ||
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
	if pb.GetTemplate().GetName() != "api" || pb.GetTemplate().GetVersion() != 1 {
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
