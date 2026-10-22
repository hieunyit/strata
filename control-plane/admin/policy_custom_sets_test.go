package admin

import (
	"context"
	"testing"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/rulesets"
	"github.com/strata/strata/control-plane/store"
)

type customSetStore struct{ PolicyStore }

func (customSetStore) GetCustomRuleSet(_ context.Context, name string) (store.CustomRuleSet, error) {
	if name != "custom-internal-scanners" {
		return store.CustomRuleSet{}, store.ErrNotFound
	}
	return store.CustomRuleSet{Name: name, Match: rulesets.Filter{Tags: []string{"scanner"}, IDs: []uint32{913100}}}, nil
}

// RS-3c: a custom set just added gets the set's filter; a copy already in
// the spec stays as it is (editing the set changes no saved policy).
func TestPolicyCustomRuleSets(t *testing.T) {
	p := &policyAdmin{store: customSetStore{}}
	block := adminv1.PolicyRuleAction_POLICY_RULE_ACTION_BLOCK
	raw, err := specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, RuleSets: []*adminv1.PolicyRuleSet{
		{Set: "bots-scanners", Action: block}, {Set: "custom-internal-scanners", Action: block},
	}}, p.fillCustomSets(t.Context()))
	want := `{"mode":"shadow","rule_sets":[{"set":"bots-scanners","action":"block"},{"set":"custom-internal-scanners","action":"block","match":{"tags":["scanner"],"ids":[913100]}}]}`
	if err != nil || string(raw) != want {
		t.Fatalf("stored\n%s\nwant\n%s\n%v", raw, want, err)
	}
	pb := specPB(raw)
	if m := pb.GetRuleSets()[1].GetMatch(); m == nil || m.GetIds()[0] != 913100 {
		t.Fatalf("read back %+v", pb.GetRuleSets()[1])
	}
	// the copy round-trips unchanged, even if the set changed since
	pb.GetRuleSets()[1].Match = &adminv1.PolicyRuleSetFilter{Tags: []string{"old-tag"}}
	again, err := specOf(pb, p.fillCustomSets(t.Context()))
	if err != nil || string(again) != `{"mode":"shadow","rule_sets":[{"set":"bots-scanners","action":"block"},{"set":"custom-internal-scanners","action":"block","match":{"tags":["old-tag"]}}]}` {
		t.Fatalf("copy kept: %s %v", again, err)
	}
	for _, bad := range []*adminv1.PolicyRuleSet{
		{Set: "custom-no-such-set", Action: block},
		{Set: "bots-scanners", Action: block, Match: &adminv1.PolicyRuleSetFilter{Tags: []string{"x"}}},
		{Set: "custom-internal-scanners", Action: block, Match: &adminv1.PolicyRuleSetFilter{}},
		{Set: "not-custom", Action: block, Match: &adminv1.PolicyRuleSetFilter{Tags: []string{"x"}}},
	} {
		if _, err := specOf(&adminv1.PolicySpec{RuleSets: []*adminv1.PolicyRuleSet{bad}}, p.fillCustomSets(t.Context())); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// a store without custom sets
	if _, err := specOf(&adminv1.PolicySpec{RuleSets: []*adminv1.PolicyRuleSet{{Set: "custom-internal-scanners", Action: block}}}, (&policyAdmin{store: geoStore{}}).fillCustomSets(t.Context())); err == nil {
		t.Error("custom set without a store")
	}
}
