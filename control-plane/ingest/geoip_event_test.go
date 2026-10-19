package ingest

import (
	"context"
	"errors"
	"math"
	"net"
	"testing"
	"time"
)

func TestIngestGeoIPAuthoritativeAndLossless(t *testing.T) {
	reader, err := NewMMDBReader(t.Context(), cityFixture, asnFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, ip, country, city string
		geo                     *GeoIPEnricher
		asn                     uint32
		coordinates             bool
		failures                uint64
	}{
		{name: "disabled", ip: "81.2.69.142"},
		{name: "missing", ip: "192.0.2.1", geo: NewGeoIPEnricher(reader)},
		{name: "malformed", ip: "not-an-ip", geo: NewGeoIPEnricher(reader)},
		{name: "failure", ip: "81.2.69.142", geo: NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { return nil, errors.New("synthetic failure") })), failures: 1},
		{name: "invalid-metadata", ip: "81.2.69.142", geo: NewGeoIPEnricher(geoReaderFunc(func(net.IP) (*GeoIPLocation, error) { return &GeoIPLocation{CountryISO: "invalid"}, nil })), failures: 1},
		{name: "city", ip: "81.2.69.142", geo: NewGeoIPEnricher(reader), country: "GB", city: "London", coordinates: true},
		{name: "asn-only", ip: "1.0.0.1", geo: NewGeoIPEnricher(reader), asn: 15169},
		{name: "internal", ip: "10.0.0.1", geo: NewGeoIPEnricher(reader), country: "INTERNAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := NewMockEventStore()
			svc := NewIngestService(st, BatcherConfig{MaxBatchSize: 1, FlushInterval: time.Millisecond, BufferSize: 16}, time.Hour)
			svc.GeoIP = tc.geo
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := svc.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			nan := math.NaN()
			accuracy := uint16(1)
			event := Event{BlockID: "STR-GE00-0000-0000-0001", Timestamp: time.Now().UTC(), NodeID: "example-node", ClientIP: tc.ip, HTTPMethod: "GET", Action: "block", CountryISO: "US", City: "forged", Region: "forged", Lat: &nan, Lon: &nan, AccuracyKM: &accuracy, ASN: 123, ASOrg: "forged", GeoIPVersion: "forged"}
			batch := EventBatch{NodeID: event.NodeID, Seq: 1, Events: []Event{event}}
			ack, err := svc.ProcessBatch(t.Context(), batch)
			if err != nil || !ack.Success || st.Count() != 1 {
				t.Fatalf("GeoIP dropped security event: %+v %v", ack, err)
			}
			got, err := st.GetEvent(t.Context(), event.BlockID)
			if err != nil {
				t.Fatal(err)
			}
			if got.CountryISO != tc.country || got.City != tc.city || got.ASN != tc.asn || (got.Lat != nil) != tc.coordinates || (got.Lon != nil) != tc.coordinates {
				t.Fatalf("untrusted or fabricated location persisted: %+v", got)
			}
			if tc.coordinates {
				if got.Region != "England" || got.AccuracyKM == nil || *got.AccuracyKM != 10 || math.Abs(*got.Lat-51.5142) > 0.00001 || math.Abs(*got.Lon+0.0931) > 0.00001 || len(got.GeoIPVersion) != 64 {
					t.Fatalf("real MMDB metadata missing: %+v", got)
				}
			} else if got.Region != "" || got.AccuracyKM != nil {
				t.Fatalf("forged optional metadata retained: %+v", got)
			}
			if tc.asn != 0 {
				if got.ASOrg != "Google Inc." || len(got.GeoIPVersion) != 64 {
					t.Fatalf("ASN provenance missing: %+v", got)
				}
			} else if got.ASOrg != "" {
				t.Fatal("forged AS organization retained")
			}
			if tc.country != "GB" && tc.asn == 0 && got.GeoIPVersion != "" {
				t.Fatal("forged database version retained")
			}
			ack, err = svc.ProcessBatch(t.Context(), batch)
			if err != nil || !ack.Duplicate || st.Count() != 1 || svc.Stats().TotalGeoIPErrors != tc.failures {
				t.Fatalf("dedup or observable lookup error changed: %+v %v stats=%+v", ack, err, svc.Stats())
			}
		})
	}
}
