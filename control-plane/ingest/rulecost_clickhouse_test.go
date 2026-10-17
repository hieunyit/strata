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

func TestRuleCosts_ClickHouseMigrationAndRetry(t *testing.T) {
	addr := os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR")
	if addr == "" {
		t.Skip("STRATA_TEST_CLICKHOUSE_ADDR not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cfg := ClickHouseConfig{Addr: addr, Database: "default", Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")}
	admin, err := NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error(err)
		}
	})
	db := fmt.Sprintf("rulecost_test_%d", time.Now().UnixNano())
	if err := admin.conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := admin.conn.Exec(cleanup, "DROP DATABASE IF EXISTS "+db); err != nil {
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
	if err := ch.conn.Exec(ctx, "ALTER TABLE events DROP COLUMN rule_costs"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := ch.conn.Exec(ctx, "INSERT INTO events (block_id,timestamp,node_id,action) VALUES (?,?,?,?)", "STR-AAAA-AAAA-AAAA-AAAA", now, "example-node", "block"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := ch.EnsureColumns(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if old, err := ch.GetEvent(ctx, "STR-AAAA-AAAA-AAAA-AAAA"); err != nil || len(old.RuleCosts) != 0 {
		t.Fatalf("old event changed: %+v, %v", old, err)
	}
	if err := ch.conn.Exec(ctx, "SYSTEM STOP MERGES events"); err != nil {
		t.Fatal(err)
	}
	e := Event{BlockID: "STR-BBBB-BBBB-BBBB-BBBB", Timestamp: now, ReceivedAt: now, NodeID: "example-node", PolicyID: "example-api", Action: "block",
		RuleCosts: []RuleCost{{RuleID: 0, Samples: 1, TotalNS: 100, MaxNS: 100}, {RuleID: 942100, Samples: 2, TotalNS: 700, MaxNS: 500}}}
	for range 2 {
		if err := ch.SaveEvents(ctx, []Event{e}); err != nil {
			t.Fatal(err)
		}
		e.ReceivedAt = now.Add(time.Second)
	}
	got, err := ch.GetEvent(ctx, e.BlockID)
	if err != nil || !reflect.DeepEqual(got.RuleCosts, e.RuleCosts) {
		t.Fatalf("sampled costs lost: %+v, %v", got, err)
	}
	// Aggregate with FINAL before ARRAY JOIN: unmerged delivery retries must
	// not count samples twice. Keep shared prefilter work (ID 0) separate.
	var samples, total uint64
	if err := ch.conn.QueryRow(ctx, "SELECT sum(rule_costs.samples), sum(rule_costs.total_ns) FROM events FINAL ARRAY JOIN rule_costs WHERE block_id = ? AND rule_costs.rule_id = 942100", e.BlockID).Scan(&samples, &total); err != nil {
		t.Fatal(err)
	}
	if samples != 2 || total != 700 {
		t.Fatalf("retry double counted: samples=%d ns=%d", samples, total)
	}
}
