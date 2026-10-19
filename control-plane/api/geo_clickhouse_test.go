package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

func geoClickHouse(t *testing.T) *ingest.ClickHouseStore {
	t.Helper()
	addr := os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR")
	if addr == "" {
		t.Skip("STRATA_TEST_CLICKHOUSE_ADDR not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cfg := ingest.ClickHouseConfig{Addr: addr, Database: "default", Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")}
	admin, err := ingest.NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	db := fmt.Sprintf("geo_api_%d", time.Now().UnixNano())
	if err := admin.Conn().Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := admin.Conn().Exec(c, "DROP DATABASE IF EXISTS "+db); err != nil {
			t.Error(err)
		}
	})
	cfg.Database = db
	ch, err := ingest.NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	schema, err := os.ReadFile("../ingest/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(stmt) != "" {
			if err := ch.Conn().Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := ch.EnsureGeoAggregates(ctx, 13); err != nil {
		t.Fatal(err)
	}
	return ch
}

func geoEv(id string, ts time.Time, action, country string, asn uint32, lat, lon float64, rules ...uint32) ingest.Event {
	return ingest.Event{BlockID: id, Timestamp: ts, ReceivedAt: ts, NodeID: "example-node", PolicyID: "example-api",
		HTTPMethod: "GET", Action: action, MatchedRules: rules, CountryISO: country, ASN: asn,
		ASOrg: fmt.Sprintf("AS%d Example", asn), City: "Example City", Lat: &lat, Lon: &lon, GeoIPVersion: "example-v1"}
}

// W18-G2-01 against ClickHouse: groupBy country, city, asn; the timeline;
// a new event reaches a live stream within 5 seconds.
func TestGeoStatsAPI_ClickHouse(t *testing.T) {
	ch := geoClickHouse(t)
	ctx := t.Context()
	now := time.Now().UTC().Add(-10 * time.Minute)
	if err := ch.SaveEvents(ctx, []ingest.Event{
		geoEv("STR-0000-0000-0000-0001", now, "block", "VN", 7552, 21.03, 105.85, 942100),
		geoEv("STR-0000-0000-0000-0002", now, "shadow", "VN", 7552, 21.03, 105.85, 941100),
		geoEv("STR-0000-0000-0000-0003", now.Add(-3*time.Hour), "block", "US", 15169, 37.42, -122.08, 913100),
	}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(ServerConfig{Auth: tokenRoles{}}, ch)

	rows := func(q string) map[string]ingest.GeoCount {
		var resp GeoResponse
		if code := getJSON(t, s, "/v1/stats/geo?"+q, "viewer", &resp); code != http.StatusOK {
			t.Fatalf("%s: %d", q, code)
		}
		m := map[string]ingest.GeoCount{}
		for _, r := range resp.Rows {
			m[r.Key] = r
		}
		return m
	}
	if c := rows("groupBy=country"); c["VN"].Events != 2 || c["VN"].Blocked != 1 || c["US"].Events != 1 {
		t.Errorf("countries: %+v", c)
	}
	if a := rows("groupBy=asn&action=block"); a["7552"].Events != 1 || a["7552"].Label != "AS7552 Example" || a["15169"].Events != 1 {
		t.Errorf("ASNs: %+v", a)
	}
	cells := rows("groupBy=city&country=VN")
	if len(cells) != 1 {
		t.Fatalf("cells: %+v", cells)
	}
	for _, c := range cells {
		if c.Events != 2 || c.Lat == nil || *c.Lat < 20.8 || *c.Lat > 21.3 || *c.Lon < 105.5 || *c.Lon > 106.1 {
			t.Errorf("VN cell: %+v", c)
		}
	}

	var tl TimelineResponse
	q := fmt.Sprintf("/v1/stats/timeline?from=%s&to=%s&step=1h", now.Add(-4*time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	if code := getJSON(t, s, q, "viewer", &tl); code != http.StatusOK {
		t.Fatalf("timeline: %d", code)
	}
	var block, shadow uint64
	for _, b := range tl.Buckets {
		block, shadow = block+b.Block, shadow+b.Shadow
	}
	if len(tl.Buckets) < 5 || block != 2 || shadow != 1 {
		t.Errorf("timeline: %d buckets, block %d shadow %d", len(tl.Buckets), block, shadow)
	}

	// live: a new event, through the materialized view, within 5 seconds
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, hs.URL+"/v1/stats/geo:watch?interval=2s", nil)
	req.Header.Set("Authorization", "Bearer viewer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	events := make(chan sseEvent, 16)
	go readSSE(bufio.NewReader(resp.Body), events)
	next(t, events, "snapshot", 5*time.Second)
	saved := time.Now()
	if err := ch.SaveEvents(ctx, []ingest.Event{geoEv("STR-0000-0000-0000-0004", time.Now().UTC(), "block", "DE", 3320, 50.11, 8.68, 942100)}); err != nil {
		t.Fatal(err)
	}
	var d GeoDelta
	if err := json.Unmarshal([]byte(next(t, events, "delta", 5*time.Second).data), &d); err != nil {
		t.Fatal(err)
	}
	took := time.Since(saved)
	if len(d.Changed) != 1 || d.Changed[0].Key != "DE" || d.Changed[0].Events != 1 || took > 5*time.Second {
		t.Fatalf("delta %+v after %s", d, took)
	}
	t.Logf("new event in the live stream after %s", took.Round(time.Millisecond))
}
