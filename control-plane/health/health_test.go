package health

import (
	"context"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
	"testing"
	"time"
)

func TestUnknownStaleAndMeasuredZero(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-2 * Freshness)
	n := store.HealthNode{ID: "example-node", LastSeen: &now, Connected: true, Telemetry: &store.NodeTelemetry{MetricsAvailable: true, Spool: &store.SpoolTelemetry{}}, TelemetryAt: &now}
	data := nodeHealth(n, now, false)
	for _, c := range data.Checks {
		if c.ID == "fail_open" && (c.State != Healthy || c.Value == nil || *c.Value != "0") {
			t.Fatalf("measured zero became missing: %+v", c)
		}
	}
	n.TelemetryAt = &old
	for _, c := range nodeHealth(n, now, false).Checks {
		if c.ID == "fail_open" && c.State != Stale {
			t.Fatal("old telemetry was green")
		}
	}
	n.Telemetry = nil
	for _, c := range nodeHealth(n, now, false).Checks {
		if c.ID == "fail_open" && c.State != Unknown {
			t.Fatal("missing telemetry became zero")
		}
	}
	n.Telemetry = &store.NodeTelemetry{MetricsAvailable: true, FailOpen: 99, Spool: &store.SpoolTelemetry{DroppedEvents: 99}}
	for _, c := range nodeHealth(n, now, true).Checks {
		if (c.ID == "fail_open" || c.ID == "spool_dropped") && (c.State != Unknown || c.Value != nil) {
			t.Fatal("scoped user saw whole-node traffic counters")
		}
	}
}

type trafficProbe struct {
	*ingest.MockEventStore
	calls int
}

func (p *trafficProbe) DeliveryHealth(context.Context) (ingest.DeliveryHealth, error) {
	p.calls++
	return ingest.DeliveryHealth{}, nil
}
func (p *trafficProbe) InspectionHealth(context.Context, time.Time) (ingest.InspectionHealth, error) {
	p.calls++
	return ingest.InspectionHealth{}, nil
}
func TestMachineScopeCeilingHidesTrafficHealth(t *testing.T) {
	events := &trafficProbe{MockEventStore: ingest.NewMockEventStore()}
	service := Service{Events: events, Ingest: func() *ingest.IngestStats { return &ingest.IngestStats{TotalEventsInvalid: 99} }}
	p := &auth.Principal{Roles: []auth.Role{auth.RoleAdmin}, Scopes: []auth.Permission{auth.PermNodesRead}}
	snapshot := service.Collect(t.Context(), p)
	if events.calls != 0 {
		t.Fatal("nodes-only machine credential queried traffic")
	}
	for _, c := range snapshot.Checks {
		if c.ID == "invalid_events" && (c.Value != nil || c.State != Unknown) {
			t.Fatal("traffic count escaped token ceiling")
		}
	}
}

func TestDependencyFailureAndFullArtifactDiskAreVisible(t *testing.T) {
	service := Service{Ready: func(context.Context) (map[string]string, bool) {
		return map[string]string{"postgres": "error", "clickhouse": "degraded", "lease": "held"}, false
	}, FreeBytes: func() (uint64, error) { return 0, nil }}
	result := service.Collect(t.Context(), nil)
	states := map[string]Check{}
	for _, c := range result.Checks {
		states[c.ID] = c
	}
	if states["postgres"].State != Unavailable || states["clickhouse"].State != Unavailable || states["artifact_disk"].State != Degraded || states["artifact_disk"].Value == nil || *states["artifact_disk"].Value != "0" {
		t.Fatalf("failure became healthy: %+v", result.Checks)
	}
}
