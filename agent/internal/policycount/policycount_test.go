package policycount

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func TestSumsWorkersAndExports(t *testing.T) {
	tt := New(time.UnixMilli(1760000000000))
	tt.Add(&eventv1.PolicyCounters{Policies: []*eventv1.PolicyCount{
		{Policy: "example-api", Requests: 10, Partial: 1}, {Policy: "", Requests: 2, Error: 2}}})
	tt.Add(&eventv1.PolicyCounters{Policies: []*eventv1.PolicyCount{
		{Policy: "example-api", Requests: 5, BodySkipped: 2, Degraded: 1}}})
	got := tt.Snapshot()
	if len(got) != 2 || got[0].Policy != "" || got[1].Requests != 15 || got[1].Partial != 1 || got[1].BodySkipped != 2 || got[1].Degraded != 1 {
		t.Fatalf("%v", got)
	}
	if tt.StartedMs() != 1760000000000 {
		t.Fatal(tt.StartedMs())
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(tt)
	want := `
# HELP strata_policy_not_inspected_total Requests per policy not fully inspected (the fail mode decided), by reason: partial (CPU budget), body_skipped, error.
# TYPE strata_policy_not_inspected_total counter
strata_policy_not_inspected_total{policy="",reason="body_skipped"} 0
strata_policy_not_inspected_total{policy="",reason="error"} 2
strata_policy_not_inspected_total{policy="",reason="partial"} 0
strata_policy_not_inspected_total{policy="example-api",reason="body_skipped"} 2
strata_policy_not_inspected_total{policy="example-api",reason="error"} 0
strata_policy_not_inspected_total{policy="example-api",reason="partial"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "strata_policy_not_inspected_total"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyNamesAreBounded(t *testing.T) {
	tt := New(time.Now())
	var ps []*eventv1.PolicyCount
	for i := 0; i < MaxPolicies+5; i++ {
		ps = append(ps, &eventv1.PolicyCount{Policy: strings.Repeat("p", 1+i%50) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)), Requests: 1})
	}
	tt.Add(&eventv1.PolicyCounters{Policies: ps})
	if n := len(tt.Snapshot()); n > MaxPolicies {
		t.Fatalf("%d policies kept", n)
	}
}
