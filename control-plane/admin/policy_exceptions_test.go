package admin

import (
	"encoding/json"
	"reflect"
	"testing"

	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/policy"
)

func TestPolicyExceptionProtoRoundTrip(t *testing.T) {
	e := policy.Exception{ID: "exc-0123456789abcdef0123456789abcdef", RuleID: 700011,
		Method: "GET", Host: "api.example.test", Path: "/search", Field: "ARGS:Name",
		ExpiresUnixMS: 4000000000000, Reason: "legitimate query", SourceBlockID: "STR-0000-0000-0000-0001"}
	want := policy.Spec{Mode: "enforce", Exceptions: []policy.Exception{e}}
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
		t.Fatalf("round trip: %+v %v", got, err)
	}
	pb.Exceptions[0].Field = "ARGS:*"
	if _, err := specOf(pb); err == nil {
		t.Fatal("broad exception accepted")
	}
	pb.Exceptions = []*adminv1.PolicyException{nil}
	if _, err := specOf(pb); err == nil {
		t.Fatal("nil exception accepted")
	}
}
