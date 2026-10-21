package ingest

import (
	"fmt"
	"github.com/strata/strata/control-plane/auth"
	"testing"
	"time"
)

func TestHealthCountersAndReadOnlySchemaProbe(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC()
	if _, err := ch.ReadCHSchemaVersion(ctx); err == nil {
		t.Fatal("unexpected migration ledger in fixture")
	}
	var ledgers uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database=currentDatabase() AND name='strata_schema_migrations'").Scan(&ledgers); err != nil || ledgers != 0 {
		t.Fatal("doctor probe initialized migration ledger")
	}
	quiet, err := ch.DeliveryHealth(ctx)
	if err != nil || quiet.ObservedAt != nil || quiet.MaxLagSeconds != nil {
		t.Fatalf("quiet stream became measured zero: %+v %v", quiet, err)
	}
	if err := ch.EnsurePolicyRequests(ctx, 90); err != nil {
		t.Fatal(err)
	}
	// More than TopN policies: health must count every node/policy, not just
	// the dashboard's top list, and use the oldest node's latest observation.
	counts := []PolicyRequests{}
	for i := range 30 {
		counts = append(counts, PolicyRequests{NodeID: "edge-a", PolicyID: fmt.Sprintf("example-api-%d", i), Time: now.Add(-time.Minute), Requests: 10, BodySkipped: 1})
	}
	counts = append(counts, PolicyRequests{NodeID: "edge-b", PolicyID: "other-api", Time: now.Add(-3 * time.Minute), Requests: 10, Degraded: 1})
	if err := ch.SavePolicyRequests(ctx, counts); err != nil {
		t.Fatal(err)
	}
	e := geoEvent("health-event", now.Add(-40*time.Second), "shadow", nil, "VN", 7552, 21, 105)
	e.HTTPHost = "api.example.test"
	e.HTTPPath = "/owned"
	e.ReceivedAt = now
	if err := ch.SaveEvents(ctx, []Event{e}); err != nil {
		t.Fatal(err)
	}
	health, err := ch.InspectionHealth(ctx, now)
	if err != nil || health.Requests != 310 || health.BodySkipped != 30 || health.Breaker != 1 || health.Shadow != 1 || health.ObservedAt == nil {
		t.Fatalf("inspection: %+v %v", health, err)
	}
	lag, err := ch.DeliveryHealth(ctx)
	if err != nil || lag.MaxLagSeconds == nil || *lag.MaxLagSeconds != 40 {
		t.Fatalf("lag: %+v %v", lag, err)
	}
	p := &auth.Principal{Roles: []auth.Role{auth.RoleViewer}, Access: &auth.Access{Events: []auth.EventScope{{Policy: "example-api", Host: "api.example.test", Prefix: "/other", Nodes: []string{"example-node"}}}}}
	restricted, err := ch.InspectionHealth(auth.WithPrincipal(ctx, p), now)
	if err != nil || !restricted.Scoped || restricted.Requests != 0 || restricted.Shadow != 0 {
		t.Fatalf("health scoped data leak: %+v %v", restricted, err)
	}
}
