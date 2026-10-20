package ingest

import (
	"context"
	"testing"
	"time"
)

// W20-F-01: quantiles from the summed buckets, as the bucket's bound.
func TestEngineLatencyOf(t *testing.T) {
	if latencyOf([]uint64{0, 0}, 0) != nil {
		t.Error("no requests")
	}
	// 100 requests: 60 under 50 us, 35 under 100 us, 4 under 1 ms, 1 past 10 ms
	l := latencyOf([]uint64{60, 35, 0, 0, 4, 0, 0, 0, 1}, 100*80_000)
	if l.Requests != 100 || l.MeanUS != 80 || l.P50US != 50 || l.P95US != 100 || l.P99US != 1000 {
		t.Errorf("%+v", l)
	}
	if l := latencyOf([]uint64{0, 0, 0, 0, 0, 0, 0, 0, 3}, 3e7); l.P50US != -1 || l.P99US != -1 {
		t.Errorf("past the last bound: %+v", l)
	}
}

// The table on a real ClickHouse, and the Overview's engine part.
func TestEngineTimeClickHouse(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if _, err := ch.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := ch.SaveEngineTime(ctx, []EngineTime{
		{Time: now.Add(-time.Hour), NodeID: "node-1", Buckets: []uint64{50, 40, 0, 0, 0, 0, 0, 0, 0}, Nanos: 90 * 60_000},
		{Time: now.Add(-time.Minute), NodeID: "node-2", Buckets: []uint64{0, 0, 0, 0, 10, 0, 0, 0, 0}, Nanos: 10 * 900_000},
		{Time: now.Add(-48 * time.Hour), NodeID: "node-1", Buckets: []uint64{0, 0, 0, 0, 0, 0, 0, 0, 1000}, Nanos: 1e12},
	}); err != nil {
		t.Fatal(err)
	}
	l, err := ch.engineLatency(ctx, now.Add(-24*time.Hour), now)
	if err != nil || l == nil || l.Requests != 100 || l.P50US != 50 || l.P95US != 1000 {
		t.Fatalf("%+v %v", l, err)
	}
	if err := ch.SavePolicyRequests(ctx, []PolicyRequests{
		{Time: now.Add(-time.Hour), NodeID: "node-1", PolicyID: "example-api", Requests: 70},
		{Time: now.Add(-time.Minute), NodeID: "node-2", PolicyID: "example-web", Requests: 30},
	}); err != nil {
		t.Fatal(err)
	}
	o, err := ch.Overview(ctx, OverviewFilter{From: now.Add(-24 * time.Hour), To: now})
	if err != nil || o.Engine == nil || o.Engine.Requests != 100 || o.Totals.Requests != 100 {
		t.Fatalf("overview engine %+v %v", o, err)
	}
	if n, err := ch.requestsCounted(ctx, now.Add(-24*time.Hour), now, "example-web"); err != nil || n != 30 {
		t.Errorf("one policy: %d %v", n, err)
	}
}
