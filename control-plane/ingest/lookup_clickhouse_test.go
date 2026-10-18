package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// A narrow first lookup must preserve delayed/skewed event lookup and FINAL's
// latest-row semantics. The large-dataset latency regression is exercised by
// TestClickHouseAPIPerf, not a timing assertion on this small fixture.
func TestLookup_ClickHouseSkewAndUnmergedRetry(t *testing.T) {
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
	db := fmt.Sprintf("lookup_test_%d", time.Now().UnixNano())
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
	if err := ch.conn.Exec(ctx, "SYSTEM STOP MERGES events"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	id := func(seq uint64) string {
		ms := uint64(now.UnixMilli())
		hi, lo := ms>>26, ms<<38|seq
		var code [16]byte
		for i := 15; i >= 0; i-- {
			code[i] = crockfordAlphabet[lo&31]
			lo = lo>>5 | hi<<59
			hi >>= 5
		}
		out := fmt.Sprintf("STR-%s-%s-%s-%s", code[:4], code[4:8], code[8:12], code[12:])
		if decoded, ok := BlockIDTime(out); !ok || !decoded.Equal(now) {
			t.Fatal("invalid fixture ID", out)
		}
		return out
	}
	for i, skew := range []time.Duration{0, 2 * time.Minute, 48 * time.Hour} {
		event := Event{BlockID: id(uint64(i)), Timestamp: now.Add(skew), ReceivedAt: now,
			NodeID: "example-node", PolicyID: "example-api", HTTPMethod: "GET", HTTPPath: "/old", Action: "block"}
		if err := ch.SaveEvents(ctx, []Event{event}); err != nil {
			t.Fatal(err)
		}
		event.HTTPPath, event.ReceivedAt = "/latest", now.Add(time.Second)
		if err := ch.SaveEvents(ctx, []Event{event}); err != nil {
			t.Fatal(err)
		}
		got, err := ch.GetEvent(ctx, event.BlockID)
		if err != nil || got.HTTPPath != "/latest" || !got.Timestamp.Equal(event.Timestamp) {
			t.Fatalf("skew %v: latest row lost: %+v, %v", skew, got, err)
		}
	}
	if _, err := ch.GetEvent(ctx, id(99)); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("missing event: %v", err)
	}
}
