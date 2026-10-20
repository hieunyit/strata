package admin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/store"
)

// geoStore: two policies, example-a with geo rule 190000 in an old
// version and 190002 in the current one.
type geoStore struct{ PolicyStore }

func (geoStore) ListPolicies(context.Context) ([]store.Policy, error) {
	return []store.Policy{{ID: "example-a"}, {ID: "example-b"}}, nil
}

func (geoStore) ListPolicyVersions(_ context.Context, id string) ([]store.PolicyVersion, error) {
	if id != "example-a" {
		return nil, nil
	}
	return []store.PolicyVersion{
		{Spec: json.RawMessage(`{"mode":"shadow","geo_rules":[{"id":190000,"countries":["US"],"action":"block"}]}`)},
		{Spec: json.RawMessage(`{"mode":"shadow","geo_rules":[{"id":190002,"countries":["US"],"action":"block"}]}`)},
	}, nil
}

// W19-G2-01: geo rules through the admin API; new rules get free ids.
func TestPolicyGeoRules(t *testing.T) {
	p := &policyAdmin{store: geoStore{}}
	in := &adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_ENFORCE, GeoRules: []*adminv1.PolicyGeoRule{
		{Countries: []string{"VN", "CN"}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK},
		{Id: 190001, Asns: []uint32{64501, 64500}, Not: true, Action: adminv1.PolicyGeoRule_ACTION_LOG},
		{Asns: []uint32{64502}, Action: adminv1.PolicyGeoRule_ACTION_LOG},
	}}
	raw, err := specOf(in, p.assignGeoIDs(t.Context(), "example-b"))
	if err != nil {
		t.Fatal(err)
	}
	// 190000 and 190002 are example-a's, 190001 is this rule's own
	want := `{"mode":"enforce","geo_rules":[{"id":190003,"countries":["CN","VN"],"action":"block"},{"id":190001,"asns":[64500,64501],"not":true,"action":"log"},{"id":190004,"asns":[64502],"action":"log"}]}`
	if string(raw) != want {
		t.Errorf("stored\n%s\nwant\n%s", raw, want)
	}
	pb := specPB(raw)
	if again, err := specOf(pb, p.assignGeoIDs(t.Context(), "example-b")); err != nil || string(again) != string(raw) {
		t.Errorf("round trip %s %v", again, err)
	}
	if pb.GetGeoRules()[1].GetAction() != adminv1.PolicyGeoRule_ACTION_LOG || !pb.GetGeoRules()[1].GetNot() {
		t.Errorf("read back %+v", pb.GetGeoRules()[1])
	}
	// example-a keeps its own ids
	a := &adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, GeoRules: []*adminv1.PolicyGeoRule{{Id: 190002, Countries: []string{"US"}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK}}}
	if _, err := specOf(a, p.assignGeoIDs(t.Context(), "example-a")); err != nil {
		t.Errorf("own id: %v", err)
	}
	for _, bad := range []*adminv1.PolicyGeoRule{
		{Id: 190000, Countries: []string{"US"}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK}, // example-a's
		{Countries: []string{"us"}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK},
		{Countries: []string{"US"}},
		{Action: adminv1.PolicyGeoRule_ACTION_BLOCK},
		{Asns: []uint32{0}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK},
		{Id: 1, Countries: []string{"US"}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK},
	} {
		_, err := specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, GeoRules: []*adminv1.PolicyGeoRule{bad}}, p.assignGeoIDs(t.Context(), "example-b"))
		if err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	_, err = specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, GeoRules: []*adminv1.PolicyGeoRule{{Id: 190000, Countries: []string{"US"}, Action: adminv1.PolicyGeoRule_ACTION_BLOCK}}}, p.assignGeoIDs(t.Context(), "example-b"))
	if err == nil || !strings.Contains(err.Error(), "example-a") {
		t.Errorf("taken id: %v", err)
	}
}
