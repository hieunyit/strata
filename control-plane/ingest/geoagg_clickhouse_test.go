package ingest

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func geoEvent(id string, ts time.Time, action string, rules []uint32, country string, asn uint32, lat, lon float64) Event {
	e := Event{BlockID: id, Timestamp: ts, NodeID: "example-node", PolicyID: "example-api",
		HTTPMethod: "GET", HTTPPath: "/", Action: action, MatchedRules: rules, ReceivedAt: ts,
		CountryISO: country, ASN: asn, ASOrg: fmt.Sprintf("AS%d Example", asn), City: "Example City",
		GeoIPVersion: "example-v1"}
	if !math.IsNaN(lat) {
		e.Lat, e.Lon = &lat, &lon
	}
	return e
}

func byKey(rows []GeoCount) map[string]GeoCount {
	m := map[string]GeoCount{}
	for _, r := range rows {
		m[r.Key] = r
	}
	return m
}

// W17-G2-01: distinct events per bucket (a resent batch and a rerun
// backfill are not counted twice), attack types from the matched rules,
// unverified location withheld, grid at the cell center.
func TestGeoAggregates_ClickHouse(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Minute)
	nan := math.NaN()

	// stored before the views exist: only the backfill sees these
	before := []Event{
		geoEvent("STR-0000-0000-0000-0001", now, "block", []uint32{942100}, "VN", 7552, 21.03, 105.85),
		geoEvent("STR-0000-0000-0000-0002", now, "block", []uint32{942100, 941100}, "VN", 7552, 21.03, 105.85),
	}
	legacy := geoEvent("STR-0000-0000-0000-0003", now, "block", []uint32{913100}, "CN", 4134, 39.9, 116.4)
	legacy.GeoIPVersion = "" // unverified metadata of an old branch
	before = append(before, legacy)
	if err := ch.SaveEvents(ctx, before); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := ch.EnsureGeoAggregates(ctx, 13); err != nil {
			t.Fatal(err)
		}
	}
	if done, err := ch.GeoBackfillDone(ctx); err != nil || done {
		t.Fatalf("backfill done before running: %v %v", done, err)
	}

	after := []Event{
		geoEvent("STR-0000-0000-0000-0004", now.Add(time.Minute), "block", []uint32{942100}, "VN", 7552, 21.03, 105.85),
		geoEvent("STR-0000-0000-0000-0005", now.Add(time.Minute), "shadow", []uint32{941100}, "VN", 18403, 10.82, 106.63),
		geoEvent("STR-0000-0000-0000-0006", now.Add(2*time.Minute), "block", []uint32{913100}, "US", 15169, 37.42, -122.08),
		geoEvent("STR-0000-0000-0000-0007", now.Add(2*time.Minute), "block", []uint32{913110}, "US", 15169, 37.42, -122.08),
		geoEvent("STR-0000-0000-0000-0008", now.Add(3*time.Minute), "error", nil, "INTERNAL", 0, nan, nan),
		// outside the queried window
		geoEvent("STR-0000-0000-0000-0009", now.Add(-2*time.Hour), "block", []uint32{942100}, "VN", 7552, 21.03, 105.85),
	}
	after[4].GeoIPVersion = "" // INTERNAL is resolved without a database
	for range 2 {              // a resent batch: the same events again
		if err := ch.SaveEvents(ctx, after); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 { // an interrupted backfill is run again
		if err := ch.BackfillGeoAggregates(ctx, now.Add(-3*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if done, err := ch.GeoBackfillDone(ctx); err != nil || !done {
		t.Fatalf("backfill not marked done: %v %v", done, err)
	}

	f := GeoFilter{From: now.Add(-time.Minute), To: now.Add(10 * time.Minute)}
	// the resent batch is in the events table twice until it merges: a
	// count() view (the W17 source's) would give 6 for VN, not 4
	var raw uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM events WHERE country_iso = 'VN' AND timestamp >= ? AND timestamp < ?",
		f.From, f.To).Scan(&raw); err != nil || raw != 6 {
		t.Fatalf("events table rows for VN: %d %v (want the 2 resent duplicates)", raw, err)
	}
	countries, err := ch.GeoByCountry(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	c := byKey(countries)
	if v := c["VN"]; v.Events != 4 || v.Blocked != 3 || v.TopAttack != "sqli" {
		t.Errorf("VN: %+v", v)
	}
	if v := c["US"]; v.Events != 2 || v.Blocked != 2 || v.TopAttack != "scanner" {
		t.Errorf("US: %+v", v)
	}
	if v := c["INTERNAL"]; v.Events != 1 || v.TopAttack != "none" {
		t.Errorf("INTERNAL: %+v", v)
	}
	if v, ok := c["CN"]; ok {
		t.Errorf("unverified country counted: %+v", v)
	}
	if v := c[""]; v.Events != 1 || v.TopAttack != "scanner" {
		t.Errorf("unknown location: %+v", v)
	}
	if countries[0].Key != "VN" {
		t.Errorf("not ranked: %+v", countries)
	}

	asns, err := ch.GeoByASN(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	a := byKey(asns)
	if v := a["7552"]; v.Events != 3 || v.Label != "AS7552 Example" {
		t.Errorf("AS7552: %+v", v)
	}
	if v := a["0"]; v.Events != 2 { // INTERNAL and the unverified one
		t.Errorf("ASN 0: %+v", v)
	}

	cells, err := ch.GeoByCell(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	total := uint64(0)
	for _, cell := range cells {
		total += cell.Events
		if cell.Lat == nil || cell.Lon == nil || len(cell.Key) != 4 {
			t.Fatalf("cell without center: %+v", cell)
		}
		var lon, lat float64
		if err := ch.conn.QueryRow(ctx, "SELECT tupleElement(geohashDecode(?), 1), tupleElement(geohashDecode(?), 2)",
			cell.Key, cell.Key).Scan(&lon, &lat); err != nil {
			t.Fatal(err)
		}
		if math.Abs(lon-*cell.Lon) > 1e-9 || math.Abs(lat-*cell.Lat) > 1e-9 {
			t.Errorf("cell %s center %v,%v, ClickHouse %v,%v", cell.Key, *cell.Lon, *cell.Lat, lon, lat)
		}
	}
	if total != 6 || len(cells) != 3 { // INTERNAL and the unverified one have no cell
		t.Errorf("cells: %d events in %+v", total, cells)
	}
	hanoi := cells[0]
	if hanoi.Events != 3 || hanoi.Label != "Example City" || math.Abs(*hanoi.Lat-21.03) > 0.2 || math.Abs(*hanoi.Lon-105.85) > 0.2 {
		t.Errorf("Hanoi cell: %+v", hanoi)
	}

	// filters
	for _, tc := range []struct {
		f    GeoFilter
		want map[string]uint64
	}{
		{GeoFilter{Action: "block"}, map[string]uint64{"VN": 3, "US": 2, "": 1}},
		{GeoFilter{AttackType: "xss"}, map[string]uint64{"VN": 1}},
		{GeoFilter{ASN: 15169}, map[string]uint64{"US": 2}},
		{GeoFilter{PolicyID: "example-other"}, map[string]uint64{}},
		{GeoFilter{CountryISO: "VN", Action: "shadow"}, map[string]uint64{"VN": 1}},
	} {
		tc.f.From, tc.f.To = f.From, f.To
		got, err := ch.GeoByCountry(ctx, tc.f)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]uint64{}
		for _, r := range got {
			m[r.Key] = r.Events
		}
		if fmt.Sprint(m) != fmt.Sprint(tc.want) {
			t.Errorf("%+v: %v, want %v", tc.f, m, tc.want)
		}
	}

	// retention: set once, changed when it differs
	ttl := func(table string) string {
		var q string
		if err := ch.conn.QueryRow(ctx, "SELECT create_table_query FROM system.tables WHERE database = currentDatabase() AND name = ?", table).Scan(&q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	if q := ttl(GeoMinuteTable); !strings.Contains(q, "TTL minute + toIntervalMonth(13)") {
		t.Errorf("minute TTL: %s", q)
	}
	if err := ch.EnsureGeoAggregates(ctx, 6); err != nil {
		t.Fatal(err)
	}
	if q := ttl(GeoGridTable); !strings.Contains(q, "TTL window_start + toIntervalMonth(6)") {
		t.Errorf("grid TTL: %s", q)
	}
}

// AttackTypeSQL over matched rule IDs, in ClickHouse.
func TestGeoAttackTypes_ClickHouse(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for _, tc := range []struct {
		rules []uint32
		want  string
	}{
		{nil, "none"},
		{[]uint32{942100}, "sqli"},
		{[]uint32{300002}, "sqli"},
		{[]uint32{941100, 942100}, "sqli"},
		{[]uint32{941100}, "xss"},
		{[]uint32{932160}, "rce"},
		{[]uint32{930120}, "lfi"},
		{[]uint32{931100}, "rfi"},
		{[]uint32{933100}, "injection_other"},
		{[]uint32{300008}, "injection_other"},
		{[]uint32{913100}, "scanner"},
		{[]uint32{700001}, "virtual_patch"},
		{[]uint32{450123}, "signature"},
		{[]uint32{400200}, "signature"},
		{[]uint32{500200}, "bot"},
		{[]uint32{920350}, "protocol"},
		{[]uint32{100013}, "protocol"},
		{[]uint32{800001}, "custom"},
		{[]uint32{600001}, "other"},
	} {
		var got string
		q := fmt.Sprintf("SELECT %s FROM (SELECT CAST(? AS Array(UInt32)) AS matched_rules)", AttackTypeSQL)
		if err := ch.conn.QueryRow(ctx, q, tc.rules).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%v: %s, want %s", tc.rules, got, tc.want)
		}
	}
}
