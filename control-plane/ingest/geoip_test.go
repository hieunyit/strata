package ingest

import (
	"context"
	"testing"
	"time"
)

func TestGeoIP_PrivateAndInternalIPs(t *testing.T) {
	enricher := NewGeoIPEnricher(nil)

	privateIPs := []string{
		"127.0.0.1",
		"10.0.1.42",
		"10.0.1.42:54321", // IP with port
		"192.168.1.100",
		"192.168.1.100:8080", // IP with port
		"172.16.5.20",
		"172.31.255.255",
		"::1",
		"[::1]:8443", // IPv6 with port
	}

	for _, ip := range privateIPs {
		evt := &Event{
			BlockID:  "STR-TEST-1234",
			ClientIP: ip,
		}
		enricher.Enrich(evt)

		if evt.CountryISO != "INTERNAL" {
			t.Errorf("for IP %s, expected CountryISO 'INTERNAL', got %q", ip, evt.CountryISO)
		}
		if evt.City != "Internal Network" {
			t.Errorf("for IP %s, expected City 'Internal Network', got %q", ip, evt.City)
		}
	}

	// Negative test: invalid IP should not panic or set location
	badEvt := &Event{ClientIP: "invalid-ip-format"}
	enricher.Enrich(badEvt)
	if badEvt.CountryISO != "" {
		t.Errorf("expected empty CountryISO for invalid IP, got %q", badEvt.CountryISO)
	}
}

func TestGeoIP_PublicIPResolutionAndCaching(t *testing.T) {
	mockData := map[string]GeoIPLocation{
		"203.0.113.195": {
			CountryISO: "VN",
			City:       "Ho Chi Minh City",
			Lat:        10.8231,
			Lon:        106.6297,
			ASN:        7552,
			ASOrg:      "Viettel Group",
		},
		"198.51.100.42": {
			CountryISO: "US",
			City:       "San Jose",
			Lat:        37.3382,
			Lon:        -121.8863,
			ASN:        13335,
			ASOrg:      "Cloudflare Inc.",
		},
	}

	reader := NewMockGeoIPReader(mockData)
	enricher := NewGeoIPEnricher(reader)

	// 1. Resolve VN IP
	evtVN := &Event{ClientIP: "203.0.113.195"}
	enricher.Enrich(evtVN)

	if evtVN.CountryISO != "VN" || evtVN.City != "Ho Chi Minh City" || evtVN.ASN != 7552 {
		t.Errorf("expected VN metadata, got %+v", evtVN)
	}

	// 2. Resolve US IP
	evtUS := &Event{ClientIP: "198.51.100.42"}
	enricher.Enrich(evtUS)

	if evtUS.CountryISO != "US" || evtUS.City != "San Jose" || evtUS.ASN != 13335 {
		t.Errorf("expected US metadata, got %+v", evtUS)
	}

	// 3. Second call hits cache (clear mockData to verify)
	reader.data = nil
	evtCached := &Event{ClientIP: "203.0.113.195"}
	enricher.Enrich(evtCached)
	if evtCached.CountryISO != "VN" {
		t.Errorf("expected cached VN result even when reader data is cleared, got %q", evtCached.CountryISO)
	}

	// 4. Client with ephemeral port hits the same cached IP without calling reader
	evtPort := &Event{ClientIP: "203.0.113.195:49152"}
	enricher.Enrich(evtPort)
	if evtPort.CountryISO != "VN" || evtPort.City != "Ho Chi Minh City" {
		t.Errorf("expected cached VN result for IP with ephemeral port, got %+v", evtPort)
	}

	// 5. Test ResetCache
	enricher.ResetCache()
	evtAfterReset := &Event{ClientIP: "203.0.113.195"}
	enricher.Enrich(evtAfterReset)
	if evtAfterReset.CountryISO != "" {
		t.Errorf("expected empty CountryISO after ResetCache when reader is nil, got %q", evtAfterReset.CountryISO)
	}
}

func TestGeoIP_IngestServiceIntegration(t *testing.T) {
	mockStore := NewMockEventStore()
	batcherCfg := BatcherConfig{
		MaxBatchSize:  5,
		FlushInterval: 50 * time.Millisecond,
		BufferSize:    100,
	}

	ctx := context.Background()
	svc := NewIngestService(mockStore, batcherCfg, 1*time.Minute)
	defer svc.Close(ctx)

	mockData := map[string]GeoIPLocation{
		"203.0.113.88": {
			CountryISO: "SG",
			City:       "Singapore",
			ASN:        60068,
			ASOrg:      "Datacenter SG",
		},
	}
	enricher := NewGeoIPEnricher(NewMockGeoIPReader(mockData))
	svc.SetGeoIPEnricher(enricher)

	now := time.Now().UTC()
	batch := EventBatch{
		NodeID: "edge-test-01",
		Seq:    1,
		Events: []Event{
			{
				BlockID:       "STR-AAAA-1111-2222-3333",
				Timestamp:     now,
				NodeID:        "edge-test-01",
				ConnectorType: "nginx",
				PolicyID:      "default",
				PolicyVersion: 1,
				ClientIP:      "10.0.1.5", // internal
				HTTPMethod:    "GET",
				HTTPHost:      "example.test",
				HTTPPath:      "/",
				StatusCode:    200,
				Action:        "pass",
			},
			{
				BlockID:       "STR-BBBB-4444-5555-6666",
				Timestamp:     now,
				NodeID:        "edge-test-01",
				ConnectorType: "nginx",
				PolicyID:      "default",
				PolicyVersion: 1,
				ClientIP:      "203.0.113.88", // public SG
				HTTPMethod:    "POST",
				HTTPHost:      "example.test",
				HTTPPath:      "/login",
				StatusCode:    403,
				Action:        "block",
			},
		},
	}

	ack, err := svc.ProcessBatch(ctx, batch)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if !ack.Success {
		t.Fatalf("expected ack success")
	}

	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	e0, err := mockStore.GetEvent(ctx, "STR-AAAA-1111-2222-3333")
	if err != nil {
		t.Fatalf("failed to get e0: %v", err)
	}
	if e0.CountryISO != "INTERNAL" {
		t.Errorf("expected e0 country INTERNAL, got %q", e0.CountryISO)
	}

	e1, err := mockStore.GetEvent(ctx, "STR-BBBB-4444-5555-6666")
	if err != nil {
		t.Fatalf("failed to get e1: %v", err)
	}
	if e1.CountryISO != "SG" || e1.ASN != 60068 {
		t.Errorf("expected e1 country SG / ASN 60068, got %+v", e1)
	}
}
