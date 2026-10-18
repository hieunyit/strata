package ingest

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestOverview_ClickHouseMatchesMock runs the ClickHouse queries on a real
// server and compares them with the in-memory aggregation of the same
// events. Skipped unless STRATA_TEST_CLICKHOUSE_ADDR (native protocol,
// host:9000) is set; a throwaway database is created and dropped.
func TestOverview_ClickHouseMatchesMock(t *testing.T) {
	addr := os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR")
	if addr == "" {
		t.Skip("STRATA_TEST_CLICKHOUSE_ADDR not set")
	}
	ctx := context.Background()
	admin, err := NewClickHouseStore(ctx, ClickHouseConfig{Addr: addr, Database: "default",
		Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	db := fmt.Sprintf("overview_test_%d", time.Now().UnixNano())
	if err := admin.conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.conn.Exec(ctx, "DROP DATABASE IF EXISTS "+db) }()

	ch, err := NewClickHouseStore(ctx, ClickHouseConfig{Addr: addr, Database: db,
		Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(schema), ";") {
		var lines []string
		for _, l := range strings.Split(stmt, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				lines = append(lines, l)
			}
		}
		if s := strings.TrimSpace(strings.Join(lines, "\n")); s != "" {
			if err := ch.conn.Exec(ctx, s); err != nil {
				t.Fatalf("schema: %v", err)
			}
		}
	}

	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	mock := NewMockEventStore()
	var events []Event
	actions := []string{"block", "shadow", "pass", "block", "error"}
	paths := []string{"/v1/verify/abc?x=1", "/v1/upload", "/search?q=1", "/", "/a/b/c#f"}
	policies := []string{"pilot-verify", "pilot-upload", "example-api"}
	for i := 0; i < 400; i++ {
		rules := []uint32{942100 + uint32(i%13)}
		if i%3 == 0 {
			rules = append(rules, 941100, 941100) // a rule matched twice counts once
		}
		events = append(events, Event{
			BlockID:   fmt.Sprintf("STR-TEST-%04d-0000-0000", i),
			Timestamp: base.Add(-time.Duration(i) * 97 * time.Minute), // spread over ~27 days
			NodeID:    fmt.Sprintf("node-%02d", i%4), PolicyID: policies[i%3],
			ClientIP: fmt.Sprintf("198.51.100.%d", i%17), HTTPHost: "api.example.test",
			HTTPPath: paths[i%5], Action: actions[i%5], MatchedRules: rules,
		})
	}
	if err := ch.SaveEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	if err := mock.SaveEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	// Keep duplicate parts unmerged: query correctness must not depend on timing.
	if err := ch.conn.Exec(ctx, "SYSTEM STOP MERGES events"); err != nil {
		t.Fatal(err)
	}
	if err := ch.SaveEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	search, err := ch.SearchEvents(ctx, SearchFilter{From: base.Add(-30 * 24 * time.Hour), To: base.Add(time.Second), Limit: 200})
	if err != nil || search.Total != uint64(len(events)) || len(search.Events) != 200 {
		t.Fatalf("unmerged retry search: %+v, %v", search, err)
	}
	// RV-N-01: requests per node and policy, every 15 minutes
	var counts []PolicyRequests
	for i := 0; i < 300; i++ {
		counts = append(counts, PolicyRequests{Time: base.Add(-time.Duration(i) * 15 * time.Minute),
			NodeID: fmt.Sprintf("node-%02d", i%4), PolicyID: policies[i%3], Requests: uint64(100 + i),
			Partial: uint64(i % 5), BodySkipped: uint64(i % 3), Error: uint64(i % 2), Degraded: uint64(i % 7)})
	}
	if err := ch.SavePolicyRequests(ctx, counts); err != nil {
		t.Fatal(err)
	}
	if err := mock.SavePolicyRequests(ctx, counts); err != nil {
		t.Fatal(err)
	}

	for _, f := range []OverviewFilter{
		{From: base.Add(-24 * time.Hour), To: base, Clients: true},
		{From: base.Add(-7 * 24 * time.Hour), To: base, PolicyID: "pilot-verify"},
		{From: base.Add(-30 * 24 * time.Hour), To: base, Clients: true},
		{From: base.Add(-90 * time.Minute), To: base.Add(-30 * time.Minute), Step: time.Hour},
	} {
		got, err := ch.Overview(ctx, f)
		if err != nil {
			t.Fatalf("%+v: %v", f, err)
		}
		want, _ := mock.Overview(ctx, f)
		for i := range got.Series {
			got.Series[i].Start = got.Series[i].Start.UTC()
		}
		got.From, got.To = got.From.UTC(), got.To.UTC()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("window %v..%v policy %q:\nclickhouse %+v\nmock       %+v", f.From, f.To, f.PolicyID, got, want)
		}
		if len(got.Inspection) == 0 && f.Step == 0 {
			t.Errorf("window %v..%v: no requests per policy", f.From, f.To)
		}
		if got.Totals.Events == 0 && f.Step == 0 {
			t.Errorf("window %v..%v counted nothing: the test data is wrong", f.From, f.To)
		}
	}
}
