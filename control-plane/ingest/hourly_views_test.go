package ingest

import (
	"context"
	"testing"
	"time"
)

func TestMockEventStore_LatencyPopulation(t *testing.T) {
	mock := NewMockEventStore()
	now := time.Now().UTC()

	// Push an event so totals.events > 0
	err := mock.SaveEvents(context.Background(), []Event{
		{
			BlockID:   "STR-LAT-0001",
			Timestamp: now.Add(-1 * time.Hour),
			Action:    "block",
			ClientIP:  "192.0.2.1",
			NodeID:    "node-1",
			PolicyID:  "test-policy",
		},
	})
	if err != nil {
		t.Fatalf("SaveEvents: %v", err)
	}

	res, err := mock.Overview(context.Background(), OverviewFilter{
		From: now.Add(-2 * time.Hour),
		To:   now,
	})
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}

	if res.Latency == nil {
		t.Fatal("expected Latency to be populated on MockEventStore when events exist")
	}

	if res.Latency.P50Micros == 0 || res.Latency.P99Micros == 0 {
		t.Errorf("expected non-zero latency percentiles, got %+v", res.Latency)
	}

	if res.Latency.P99Micros >= 1000 {
		t.Errorf("expected p99 latency to meet SLA (< 1ms = 1000us), got %d us", res.Latency.P99Micros)
	}
}

func TestHourlyViews_SchemaDDL(t *testing.T) {
	// Verify that table and MV names are correctly configured
	if hourlyStatsTable != "events_stats_hourly" {
		t.Errorf("unexpected table name: %s", hourlyStatsTable)
	}
	if hourlyRulesTable != "events_rules_hourly" {
		t.Errorf("unexpected table name: %s", hourlyRulesTable)
	}
	if hourlyRoutesTable != "events_routes_hourly" {
		t.Errorf("unexpected table name: %s", hourlyRoutesTable)
	}
}
