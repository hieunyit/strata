package admin

import (
	"encoding/json"
	"testing"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
)

// W17-S-01: CRS paranoia levels through the admin API.
func TestPolicyParanoiaRoundTrip(t *testing.T) {
	raw, err := specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, CrsParanoia: 1, CrsParanoiaShadow: 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"mode":"shadow","crs_paranoia_shadow":2}` {
		t.Errorf("stored %s", raw)
	}
	pb := specPB(raw)
	if pb.GetCrsParanoia() != 0 || pb.GetCrsParanoiaShadow() != 2 {
		t.Errorf("read back %+v", pb)
	}
	again, err := specOf(pb)
	if err != nil || string(again) != string(raw) {
		t.Errorf("round trip %s %v", again, err)
	}
	// defaults are stored as absent: the spec of an unchanged policy keeps its JSON
	raw, err = specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_ENFORCE, CrsParanoia: 1, CrsParanoiaShadow: 1})
	if err != nil || string(raw) != `{"mode":"enforce"}` {
		t.Errorf("defaults stored as %s %v", raw, err)
	}
	var s map[string]any
	raw, _ = specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_ENFORCE, CrsParanoia: 2, CrsParanoiaShadow: 2})
	_ = json.Unmarshal(raw, &s)
	if s["crs_paranoia"] != 2.0 || s["crs_paranoia_shadow"] != nil {
		t.Errorf("enforce 2: %s", raw)
	}
	for _, bad := range []*adminv1.PolicySpec{
		{Mode: adminv1.PolicySpec_MODE_SHADOW, CrsParanoia: 5},
		{Mode: adminv1.PolicySpec_MODE_SHADOW, CrsParanoia: 3, CrsParanoiaShadow: 2},
		{Mode: adminv1.PolicySpec_MODE_SHADOW, CrsParanoiaShadow: 1 << 31},
	} {
		if _, err := specOf(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// W17-S-01: CRS plugins through the admin API, stored sorted.
func TestPolicyPluginsRoundTrip(t *testing.T) {
	raw, err := specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, CrsPlugins: []string{"wordpress", "drupal"}})
	if err != nil || string(raw) != `{"mode":"shadow","crs_plugins":["drupal","wordpress"]}` {
		t.Fatalf("stored %s %v", raw, err)
	}
	pb := specPB(raw)
	if len(pb.GetCrsPlugins()) != 2 || pb.GetCrsPlugins()[0] != "drupal" {
		t.Errorf("read back %v", pb.GetCrsPlugins())
	}
	if again, err := specOf(pb); err != nil || string(again) != string(raw) {
		t.Errorf("round trip %s %v", again, err)
	}
	for _, bad := range [][]string{{"Drupal"}, {"x", "x"}, {"a/b"}} {
		if _, err := specOf(&adminv1.PolicySpec{Mode: adminv1.PolicySpec_MODE_SHADOW, CrsPlugins: bad}); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
