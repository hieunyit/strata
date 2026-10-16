package ingest

import (
	"context"
	"testing"
	"time"
)

func TestMockEventStore_GeoStats(t *testing.T) {
	ctx := context.Background()
	store := NewMockEventStore()

	now := time.Now().UTC()

	// Seed sample events
	events := []Event{
		{
			BlockID:    "EVT-VN-1",
			Timestamp:  now.Add(-10 * time.Minute),
			PolicyID:   "web-api",
			Action:     "block",
			ScoreSQLi:  25,
			CountryISO: "VN",
			City:       "Hanoi",
			Lat:        21.0285,
			Lon:        105.8542,
			ASN:        7552,
			ASOrg:      "Viettel Group",
		},
		{
			BlockID:       "EVT-VN-2",
			Timestamp:     now.Add(-5 * time.Minute),
			PolicyID:      "web-api",
			Action:        "allow",
			ScoreProtocol: 10,
			CountryISO:    "VN",
			City:          "Ho Chi Minh City",
			Lat:           10.8231,
			Lon:           106.6297,
			ASN:           7552,
			ASOrg:         "Viettel Group",
		},
		{
			BlockID:    "EVT-US-1",
			Timestamp:  now.Add(-2 * time.Minute),
			PolicyID:   "web-api",
			Action:     "block",
			ScoreXSS:   20,
			CountryISO: "US",
			City:       "Ashburn",
			Lat:        39.0438,
			Lon:        -77.4874,
			ASN:        14618,
			ASOrg:      "Amazon.com",
		},
		{
			BlockID:    "EVT-INTERNAL-1",
			Timestamp:  now.Add(-1 * time.Minute),
			PolicyID:   "web-api",
			Action:     "allow",
			CountryISO: "INTERNAL",
			City:       "Internal Network",
		},
	}

	if err := store.SaveEvents(ctx, events); err != nil {
		t.Fatalf("saving events: %v", err)
	}

	// 1. Query Country aggregation
	res, err := store.GeoStats(ctx, GeoStatsFilter{
		From:    now.Add(-1 * time.Hour),
		To:      now,
		GroupBy: "country",
	})
	if err != nil {
		t.Fatalf("geostats query failed: %v", err)
	}

	if len(res.Countries) != 2 {
		t.Fatalf("expected 2 countries (excluding INTERNAL), got %d", len(res.Countries))
	}
	// VN has 2 events (1 block, 1 allow)
	if res.Countries[0].CountryISO != "VN" || res.Countries[0].Events != 2 || res.Countries[0].Blocked != 1 {
		t.Errorf("unexpected top country: %+v", res.Countries[0])
	}
	// US has 1 event (1 block)
	if res.Countries[1].CountryISO != "US" || res.Countries[1].Events != 1 || res.Countries[1].Blocked != 1 {
		t.Errorf("unexpected second country: %+v", res.Countries[1])
	}

	// 2. Query ASN aggregation
	resASN, err := store.GeoStats(ctx, GeoStatsFilter{
		From:    now.Add(-1 * time.Hour),
		To:      now,
		GroupBy: "asn",
	})
	if err != nil {
		t.Fatalf("asn geostats query failed: %v", err)
	}
	if len(resASN.ASNs) != 2 {
		t.Fatalf("expected 2 ASNs, got %d", len(resASN.ASNs))
	}
	if resASN.ASNs[0].ASN != 7552 || resASN.ASNs[0].Events != 2 {
		t.Errorf("unexpected top ASN: %+v", resASN.ASNs[0])
	}

	// 3. Query Grid aggregation
	resGrid, err := store.GeoStats(ctx, GeoStatsFilter{
		From:    now.Add(-1 * time.Hour),
		To:      now,
		GroupBy: "city",
	})
	if err != nil {
		t.Fatalf("grid geostats query failed: %v", err)
	}
	if len(resGrid.Grid) != 3 {
		t.Fatalf("expected 3 distinct geo coordinates, got %d", len(resGrid.Grid))
	}
}
