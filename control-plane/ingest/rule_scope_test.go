package ingest

import (
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
)

func TestRuleTelemetryRespectsRouteScope(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	events := []Event{{BlockID: "STR-0000-0000-0000-0001", Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "api.example.test", HTTPPath: "/allowed/search", MatchedRules: []uint32{942100}, RuleCosts: []RuleCost{{RuleID: 942100, Samples: 1, TotalNS: 100, MaxNS: 100}}}, {BlockID: "STR-0000-0000-0000-0002", Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "api.example.test", HTTPPath: "/private/search", MatchedRules: []uint32{942100}, RuleCosts: []RuleCost{{RuleID: 942100, Samples: 1, TotalNS: 900, MaxNS: 900}}}}
	if err := ch.SaveEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	scoped := auth.WithPrincipal(ctx, &auth.Principal{Roles: []auth.Role{auth.RoleViewer}, Access: &auth.Access{Events: []auth.EventScope{{Policy: "example-api", Host: "api.example.test", Prefix: "/allowed", Nodes: []string{"node-a"}}}}})
	got, err := ch.RuleTelemetry(scoped, 942100, "", now.Add(-time.Second), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got.MatchedEvents != 1 || got.CostSamples != "1" || got.CostTotalNS != "100" {
		t.Fatalf("cross-route telemetry leak: %+v", got)
	}
	empty := auth.WithPrincipal(ctx, &auth.Principal{Access: &auth.Access{}})
	got, err = ch.RuleTelemetry(empty, 942100, "", now.Add(-time.Second), now.Add(time.Second))
	if err != nil || got.MatchedEvents != 0 || got.CostSamples != "0" {
		t.Fatalf("empty scope: %+v %v", got, err)
	}
}
