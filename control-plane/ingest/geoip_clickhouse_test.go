package ingest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

func geoIPTestStore(t *testing.T) *ClickHouseStore {
	t.Helper()
	if os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR") == "" {
		t.Skip("STRATA_TEST_CLICKHOUSE_ADDR not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cfg := ClickHouseConfig{Addr: os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR"), Database: "default",
		Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")}
	admin, err := NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error(err)
		}
	})
	db := fmt.Sprintf("geoip_review_%d", time.Now().UnixNano())
	if err := admin.conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := admin.conn.Exec(ctx, "DROP DATABASE IF EXISTS "+db); err != nil {
			t.Error(err)
		}
	})
	cfg.Database = db
	ch, err := NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ch.Close(); err != nil {
			t.Error(err)
		}
	})
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(stmt) != "" {
			if err := ch.conn.Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	return ch
}

func TestGeoIPClickHouseMigrationAndEnrichment(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_float32_%t", legacy), func(t *testing.T) {
			ch := geoIPTestStore(t)
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			for _, col := range []string{"country_iso", "region", "city", "lat", "lon", "accuracy_km", "asn", "as_org", "geoip_version"} {
				if err := ch.conn.Exec(ctx, "ALTER TABLE events DROP COLUMN IF EXISTS "+col); err != nil {
					t.Fatal(err)
				}
			}
			if legacy {
				if err := ch.conn.Exec(ctx, "ALTER TABLE events ADD COLUMN lat Float32, ADD COLUMN lon Float32"); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			if err := ch.conn.Exec(ctx, "INSERT INTO events (block_id,timestamp,node_id,action) VALUES (?,?,?,?)",
				"STR-0000-0000-0000-0000", now, "example-node", "block"); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := ch.EnsureColumns(ctx); err != nil {
					t.Fatal(err)
				}
			}
			for col, want := range map[string]string{"lat": "Nullable(Float64)", "lon": "Nullable(Float64)", "accuracy_km": "Nullable(UInt16)", "geoip_version": "String"} {
				var got string
				if err := ch.conn.QueryRow(ctx, "SELECT type FROM system.columns WHERE database=currentDatabase() AND table='events' AND name=?", col).Scan(&got); err != nil || got != want {
					t.Fatalf("migration %s: got %q want %q: %v", col, got, want, err)
				}
			}
			old, err := ch.GetEvent(ctx, "STR-0000-0000-0000-0000")
			if err != nil || old.Lat != nil || old.Lon != nil || old.GeoIPVersion != "" {
				t.Fatalf("old unknown coordinates fabricated: %+v %v", old, err)
			}
			if legacy {
				var raw float64
				if err := ch.conn.QueryRow(ctx, "SELECT lat FROM events WHERE block_id=?", old.BlockID).Scan(&raw); err != nil || raw != 0 {
					t.Fatalf("legacy raw value lost: %v", err)
				}
			}
			reader, err := NewMMDBReader(ctx, cityFixture, asnFixture)
			if err != nil {
				t.Fatal(err)
			}
			svc := NewIngestService(ch, BatcherConfig{MaxBatchSize: 1, FlushInterval: time.Millisecond, BufferSize: 16}, time.Hour)
			svc.GeoIP = NewGeoIPEnricher(reader)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := svc.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			var events []Event
			for i, ip := range []string{"81.2.69.142", "1.0.0.1", "192.0.2.1", "10.0.0.1"} {
				fake := 999.0
				events = append(events, Event{BlockID: fmt.Sprintf("STR-0000-0000-0000-%04d", i+1), Timestamp: now, NodeID: "example-node", PolicyID: "example-api", HTTPMethod: "GET", Action: "block", ClientIP: ip,
					CountryISO: "US", City: "forged", Lat: &fake, Lon: &fake, ASN: 123, GeoIPVersion: "forged", UserAgent: "synthetic", Inspection: "partial", RuleCosts: []RuleCost{{RuleID: 942100, Samples: 1, TotalNS: 10, MaxNS: 10}}})
			}
			batch := EventBatch{NodeID: "example-node", Seq: 1, Events: events}
			ack, err := svc.ProcessBatch(ctx, batch)
			if err != nil || !ack.Success {
				t.Fatalf("ingest: %+v %v", ack, err)
			}
			ack, err = svc.ProcessBatch(ctx, batch)
			if err != nil || !ack.Duplicate {
				t.Fatalf("duplicate: %+v %v", ack, err)
			}
			city, err := ch.GetEvent(ctx, events[0].BlockID)
			if err != nil || city.CountryISO != "GB" || city.Region != "England" || city.City != "London" || city.Lat == nil || city.Lon == nil || math.Abs(*city.Lat-51.5142) > 0.00001 || math.Abs(*city.Lon+0.0931) > 0.00001 || city.AccuracyKM == nil || *city.AccuracyKM != 10 || len(city.GeoIPVersion) != 64 || city.Inspection != "partial" || city.UserAgent != "synthetic" || len(city.RuleCosts) != 1 {
				t.Fatalf("real enrichment/context lost: %+v %v", city, err)
			}
			zero := 0.0
			if err := ch.SaveEvents(ctx, []Event{{BlockID: "STR-0000-0000-0000-0005", Timestamp: now, ReceivedAt: now, NodeID: "example-node", PolicyID: "example-api", Action: "block", Lat: &zero, Lon: &zero, GeoIPVersion: city.GeoIPVersion}}); err != nil {
				t.Fatal(err)
			}
			if err := ch.conn.Exec(ctx, "SYSTEM STOP MERGES events"); err != nil {
				t.Fatal(err)
			}
			city.HTTPPath, city.ReceivedAt = "/latest", city.ReceivedAt.Add(time.Second)
			if err := ch.SaveEvents(ctx, []Event{*city}); err != nil {
				t.Fatal(err)
			}
			found, err := ch.SearchEvents(ctx, SearchFilter{PolicyID: "example-api", Limit: 20})
			if err != nil || found.Total != 5 || len(found.Events) != 5 {
				t.Fatalf("FINAL search/dedup: %+v %v", found, err)
			}
			for _, event := range found.Events {
				switch event.BlockID {
				case events[0].BlockID:
					if event.HTTPPath != "/latest" || event.City != "London" || event.Lat == nil || event.GeoIPVersion != city.GeoIPVersion {
						t.Fatalf("latest geo row lost: %+v", event)
					}
				case events[1].BlockID:
					if event.ASN != 15169 || event.ASOrg != "Google Inc." || event.Lat != nil || event.Lon != nil || event.CountryISO != "" || len(event.GeoIPVersion) != 64 {
						t.Fatalf("ASN-only/fake coordinates: %+v", event)
					}
				case events[2].BlockID:
					if event.CountryISO != "" || event.City != "" || event.ASN != 0 || event.Lat != nil || event.GeoIPVersion != "" {
						t.Fatalf("missing lookup preserved forged values: %+v", event)
					}
				case events[3].BlockID:
					if event.CountryISO != "INTERNAL" || event.Lat != nil || event.Lon != nil {
						t.Fatalf("internal coordinates fabricated: %+v", event)
					}
				case "STR-0000-0000-0000-0005":
					if event.Lat == nil || event.Lon == nil || *event.Lat != 0 || *event.Lon != 0 {
						t.Fatalf("real zero coordinates lost: %+v", event)
					}
				default:
					t.Fatalf("unrelated event returned: %s", event.BlockID)
				}
			}
		})
	}
}

var errGeoTestStream = errors.New("synthetic interrupted ClickHouse result")

type interruptedGeoRows struct {
	driver.Rows
	count       int
	interrupted bool
}

func (r *interruptedGeoRows) Next() bool {
	if r.count == 1 {
		r.interrupted = true
		return false
	}
	ok := r.Rows.Next()
	if ok {
		r.count++
	}
	return ok
}
func (r *interruptedGeoRows) Err() error {
	if r.interrupted {
		return errGeoTestStream
	}
	return r.Rows.Err()
}

type interruptedGeoConn struct{ driver.Conn }

func (c interruptedGeoConn) Query(ctx context.Context, q string, args ...any) (driver.Rows, error) {
	rows, err := c.Conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return &interruptedGeoRows{Rows: rows}, nil
}

func TestSearchClickHousePropagatesStreamFailure(t *testing.T) {
	ch := geoIPTestStore(t)
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		if err := ch.SaveEvents(t.Context(), []Event{{BlockID: fmt.Sprintf("STR-0000-0000-0000-%04d", i), Timestamp: now, ReceivedAt: now, NodeID: "example-node", Action: "block"}}); err != nil {
			t.Fatal(err)
		}
	}
	faulty := *ch
	faulty.conn = interruptedGeoConn{ch.conn}
	if result, err := faulty.SearchEvents(t.Context(), SearchFilter{Limit: 20}); !errors.Is(err, errGeoTestStream) || result != nil {
		t.Fatalf("partial rows reported as a complete successful search: %+v %v", result, err)
	}
}

func TestGeoIPClickHouseRejectsUnsupportedCoordinateSchema(t *testing.T) {
	ch := geoIPTestStore(t)
	if err := ch.conn.Exec(t.Context(), "ALTER TABLE events DROP COLUMN lat"); err != nil {
		t.Fatal(err)
	}
	if err := ch.conn.Exec(t.Context(), "ALTER TABLE events ADD COLUMN lat String"); err != nil {
		t.Fatal(err)
	}
	if err := ch.conn.Exec(t.Context(), "INSERT INTO events (block_id,timestamp,node_id,action,lat) VALUES (?,?,?,? ,?)", "STR-0000-0000-0000-0009", time.Now().UTC(), "example-node", "block", "legacy-invalid"); err != nil {
		t.Fatal(err)
	}
	if err := ch.EnsureColumns(t.Context()); err == nil || !strings.Contains(err.Error(), "unsupported GeoIP lat column type") {
		t.Fatalf("unsupported schema silently converted: %v", err)
	}
	var raw string
	if err := ch.conn.QueryRow(t.Context(), "SELECT lat FROM events WHERE block_id=?", "STR-0000-0000-0000-0009").Scan(&raw); err != nil || raw != "legacy-invalid" {
		t.Fatalf("failed migration changed raw data: %q %v", raw, err)
	}
}
