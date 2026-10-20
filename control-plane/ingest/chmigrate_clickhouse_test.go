package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// CP-A08: an empty database gets every migration once, in order; a second
// run applies none; a database of a newer build is left alone.
func TestMigrateClickHouse(t *testing.T) {
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
	db := fmt.Sprintf("migrate_test_%d", time.Now().UnixNano())
	if err := admin.conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.conn.Exec(ctx, "DROP DATABASE IF EXISTS "+db) }()
	ch, err := OpenClickHouseStore(cfg(db))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if ch.Migrated() {
		t.Fatal("migrated before Migrate")
	}
	applied, err := ch.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []uint32{1, 2, 3, 4, 5, 6}) || !ch.Migrated() {
		t.Fatalf("first run: %v %v", applied, err)
	}
	if err := ch.Configure(ctx, 30, 13); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events", "node_seq", "policy_requests", GeoMinuteTable, GeoGridTable, StatsHourTable, StatsRulesTable, StatsRoutesTable, StatsClientsTable, StatsGeoTable, "engine_time"} {
		var n uint64
		if err := ch.conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = ?", table).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s: %d %v", table, n, err)
		}
	}
	// the store works on the migrated schema
	now := time.Now().UTC()
	if err := ch.SaveEvents(ctx, []Event{{BlockID: "STR-0000-0000-0000-0001", Timestamp: now, ReceivedAt: now, NodeID: "example-node", Action: "block", JA4: "t13d"}}); err != nil {
		t.Fatal(err)
	}
	if applied, err := ch.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second run: %v %v", applied, err)
	}
	if err := ch.conn.Exec(ctx, "INSERT INTO "+migrationsTable+" (version, name) VALUES (?, 'from a newer build')", LatestCHMigration()+1); err != nil {
		t.Fatal(err)
	}
	newer, err := OpenClickHouseStore(cfg(db))
	if err != nil {
		t.Fatal(err)
	}
	defer newer.Close()
	if _, err := newer.Migrate(ctx); !errors.Is(err, ErrCHSchemaNewer) || newer.Migrated() {
		t.Fatalf("newer schema: %v", err)
	}
}
