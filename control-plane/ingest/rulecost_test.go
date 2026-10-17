package ingest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMalformedRuleCostsDoNotLoseSecurityEvent(t *testing.T) {
	for name, costs := range map[string][]RuleCost{
		"impossible average": {{RuleID: 1, Samples: 2, TotalNS: 10, MaxNS: 4}},
		"zero maximum":       {{RuleID: 1, Samples: 2, TotalNS: 10}},
		"zero samples":       {{RuleID: 1, TotalNS: 10, MaxNS: 10}},
		"max exceeds total":  {{RuleID: 1, Samples: 1, TotalNS: 10, MaxNS: 20}},
		"duplicate ID":       {{RuleID: 1, Samples: 1}, {RuleID: 1, Samples: 1}},
		"over limit":         make([]RuleCost, MaxEventRuleCosts+1),
	} {
		t.Run(name, func(t *testing.T) {
			e := Event{BlockID: "STR-8F3K-Q2VD-7XNM-A1PC", Timestamp: time.Now(), HTTPMethod: "GET", Action: "block", RuleCosts: costs}
			if err := ValidateEvent(&e, time.Now()); err != nil || len(e.RuleCosts) != 0 || e.Action != "block" {
				t.Fatalf("malformed optional telemetry lost security event: %+v, %v", e, err)
			}
		})
	}
}

func TestRuleCostsStayOutOfPublicEventJSON(t *testing.T) {
	e := Event{RuleCosts: []RuleCost{{RuleID: 942100, Samples: 1, TotalNS: 1234, MaxNS: 1234}}}
	b, err := json.Marshal(e)
	if err != nil || strings.Contains(string(b), "1234") || strings.Contains(string(b), "RuleCost") {
		t.Fatalf("internal telemetry exposed: %s, %v", b, err)
	}
}

func TestRuleCostUInt64Extremes(t *testing.T) {
	costs := []RuleCost{
		{RuleID: 0, Samples: ^uint64(0), TotalNS: ^uint64(0), MaxNS: 1},
		{RuleID: 1, Samples: 1, TotalNS: ^uint64(0), MaxNS: ^uint64(0)},
		{RuleID: 2, Samples: 1}, // sub-nanosecond measurement can round to zero
	}
	e := Event{BlockID: "STR-8F3K-Q2VD-7XNM-A1PC", Timestamp: time.Now(), HTTPMethod: "GET", Action: "block", RuleCosts: costs}
	if err := ValidateEvent(&e, time.Now()); err != nil || !reflect.DeepEqual(e.RuleCosts, costs) {
		t.Fatalf("valid boundary sample lost: %+v, %v", e.RuleCosts, err)
	}
}
