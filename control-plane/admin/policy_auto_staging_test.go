package admin

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/strata/strata/control-plane/policy"
)

func TestPolicyAutoStagingProtoRoundTrip(t *testing.T) {
	want := policy.Spec{Mode: "enforce", AutoStaging: &policy.AutoStaging{Enabled: true, RuleIDs: []uint32{942100}, WindowSeconds: 300, MinMatches: 100, MinReports: 5, FPThresholdBPS: 500}}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	pb := specPB(raw)
	encoded, err := specOf(pb)
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Parse(encoded)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	pb.AutoStaging.RuleIds[0] = 0
	if _, err := specOf(pb); err == nil {
		t.Fatal("invalid delegation accepted")
	}
	if want.AutoStaging.RuleIDs[0] != 942100 {
		t.Fatal("protobuf shares source slice")
	}
}
