package policy

import (
	"encoding/json"
	"testing"
)

func exampleAutoStaging() *AutoStaging {
	return &AutoStaging{Enabled: true, RuleIDs: []uint32{942100, 700011}, WindowSeconds: 300, MinMatches: 100, MinReports: 5, FPThresholdBPS: 500}
}

func TestAutoStagingOptInAndBounds(t *testing.T) {
	for _, raw := range []string{`{"mode":"enforce"}`, `{"mode":"enforce","auto_staging":{"enabled":false}}`} {
		s, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if s.AutoStaging != nil && s.AutoStaging.Enabled {
			t.Fatal("default opted in")
		}
	}
	for _, enabled := range []bool{true, false} {
		a := exampleAutoStaging()
		a.Enabled = enabled
		raw, err := json.Marshal(Spec{Mode: "enforce", AutoStaging: a})
		if err != nil {
			t.Fatal(err)
		}
		s, err := Parse(raw)
		if err != nil || s.AutoStaging == nil || s.AutoStaging.Enabled != enabled || len(s.AutoStaging.RuleIDs) != 2 {
			t.Fatalf("roundtrip: %+v %v", s, err)
		}
	}
	edits := []func(*AutoStaging){
		func(a *AutoStaging) { a.RuleIDs = nil }, func(a *AutoStaging) { a.RuleIDs = make([]uint32, 17) },
		func(a *AutoStaging) { a.RuleIDs = []uint32{0} }, func(a *AutoStaging) { a.RuleIDs = []uint32{42, 42} },
		func(a *AutoStaging) { a.WindowSeconds = 59 }, func(a *AutoStaging) { a.WindowSeconds = 86401 },
		func(a *AutoStaging) { a.MinMatches = 0 }, func(a *AutoStaging) { a.MinMatches = 1000000001 },
		func(a *AutoStaging) { a.MinReports = 0 }, func(a *AutoStaging) { a.MinReports = a.MinMatches + 1 },
		func(a *AutoStaging) { a.FPThresholdBPS = 0 }, func(a *AutoStaging) { a.FPThresholdBPS = 10001 },
	}
	for i, edit := range edits {
		a := exampleAutoStaging()
		edit(a)
		if err := (Spec{Mode: "enforce", AutoStaging: a}).Validate(); err == nil {
			t.Errorf("invalid case %d accepted", i)
		}
	}
	// A dormant configured delegation still has validated bounds.
	a := exampleAutoStaging()
	a.Enabled = false
	a.WindowSeconds = 0
	if err := a.Validate(); err == nil {
		t.Fatal("invalid dormant configuration accepted")
	}
	a = exampleAutoStaging()
	a.RuleIDs = []uint32{^uint32(0)}
	a.WindowSeconds = 86400
	a.FPThresholdBPS = 10000
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	} // membership is verified at compilation, not guessed by ID range.
}
