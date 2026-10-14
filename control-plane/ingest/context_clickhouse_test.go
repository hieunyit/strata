package ingest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// RV-G2-01 on a real ClickHouse (skipped unless STRATA_TEST_CLICKHOUSE_ADDR):
// a table made with the schema from before the context columns gets them
// from EnsureColumns, keeps its old rows, and stores and returns the
// context of new events; searches do not read it.
func TestContext_ClickHouseOldTableAndLookup(t *testing.T) {
	addr := os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR")
	if addr == "" {
		t.Skip("STRATA_TEST_CLICKHOUSE_ADDR not set")
	}
	ctx := context.Background()
	cfg := func(db string) ClickHouseConfig {
		return ClickHouseConfig{Addr: addr, Database: db,
			Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")}
	}
	admin, err := NewClickHouseStore(ctx, cfg("default"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	db := fmt.Sprintf("context_test_%d", time.Now().UnixNano())
	if err := admin.conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.conn.Exec(ctx, "DROP DATABASE IF EXISTS "+db) }()
	ch, err := NewClickHouseStore(ctx, cfg(db))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

	// the events table as schema.sql made it before the context columns
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := string(schema)
	i, j := strings.Index(old, "    -- RV-G2-01"), strings.Index(old, "    inspection       LowCardinality(String),\n")
	if i < 0 || j < 0 {
		t.Fatal("schema.sql: context columns not found")
	}
	old = old[:i] + old[j+len("    inspection       LowCardinality(String),\n"):]
	for _, stmt := range strings.Split(old, ";") {
		var lines []string
		for _, l := range strings.Split(stmt, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				lines = append(lines, l)
			}
		}
		if s := strings.TrimSpace(strings.Join(lines, "\n")); s != "" {
			if err := ch.conn.Exec(ctx, s); err != nil {
				t.Fatalf("old schema: %v", err)
			}
		}
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := ch.conn.Exec(ctx, fmt.Sprintf(`INSERT INTO events (block_id, timestamp, node_id, action, received_at)
		VALUES ('STR-AAAA-AAAA-AAAA-AAAA', '%s', 'n', 'block', now64(3))`, now.Format("2006-01-02 15:04:05.000"))); err != nil {
		t.Fatal(err)
	}

	if err := ch.EnsureColumns(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ch.EnsureColumns(ctx); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if e, err := ch.GetEvent(ctx, "STR-AAAA-AAAA-AAAA-AAAA"); err != nil || e.UserAgent != "" || len(e.Headers) != 0 {
		t.Fatalf("old row: %+v, %v", e, err)
	}

	ev := Event{
		BlockID: "STR-BBBB-BBBB-BBBB-BBBB", Timestamp: now, NodeID: "n", PolicyID: "example-api",
		HTTPMethod: "GET", Action: "block", ReceivedAt: now,
		Violations: []Violation{{RuleID: 942100, Layer: "managed", Field: "ARGS:q", Snippet: strings.Repeat("x", 4096)}},
		UserAgent:  "sqlmap/1.8", Referer: "https://app.example.test/?access_token=[MASKED]",
		Headers:    []Header{{Name: "Authorization", Value: "[MASKED]"}, {Name: "Accept", Value: "*/*"}},
		Inspection: "partial",
	}
	if err := ch.SaveEvents(ctx, []Event{ev}); err != nil {
		t.Fatal(err)
	}
	got, err := ch.GetEvent(ctx, ev.BlockID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserAgent != ev.UserAgent || got.Referer != ev.Referer || got.Inspection != "partial" ||
		len(got.Headers) != 2 || got.Headers[0] != ev.Headers[0] || got.Headers[1] != ev.Headers[1] ||
		len(got.Violations) != 1 || len(got.Violations[0].Snippet) != 4096 {
		t.Fatalf("context lost: %+v", got)
	}
	res, err := ch.SearchEvents(ctx, SearchFilter{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: 10})
	if err != nil || res.Total != 2 {
		t.Fatalf("search: %+v, %v", res, err)
	}
}
