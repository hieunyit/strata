package ingest

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestInvestigationExactRouteFilters(t *testing.T) {
	ctx := t.Context()
	var stores []EventStore
	mock := NewMockEventStore()
	stores = append(stores, mock)
	if addr := os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR"); addr != "" {
		cfg := ClickHouseConfig{Addr: addr, Database: "default"}
		admin, err := NewClickHouseStore(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close()
		name := fmt.Sprintf("investigation_%d", time.Now().UnixNano())
		if err := admin.conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = admin.conn.Exec(ctx, "DROP DATABASE "+name) }()
		cfg.Database = name
		ch, err := NewClickHouseStore(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer ch.Close()
		if _, err := ch.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		stores = append(stores, ch)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, st := range stores {
		events := []Event{{BlockID: "STR-0000-0000-0000-0001", Timestamp: now, HTTPMethod: "POST", HTTPHost: "api.example.test", HTTPPath: "/api/search", PolicyID: "example-api"}, {BlockID: "STR-0000-0000-0000-0002", Timestamp: now, HTTPMethod: "GET", HTTPHost: "api.example.test", HTTPPath: "/api/search", PolicyID: "example-api"}, {BlockID: "STR-0000-0000-0000-0003", Timestamp: now, HTTPMethod: "POST", HTTPHost: "other.example.test", HTTPPath: "/api/search", PolicyID: "example-api"}}
		if err := st.SaveEvents(ctx, events); err != nil {
			t.Fatal(err)
		}
		filter := SearchFilter{HTTPMethod: "POST", HTTPHost: "api.example.test", HTTPPath: "/api/search", PolicyID: "example-api", Limit: 200}
		got, err := st.SearchEvents(ctx, filter)
		if err != nil || len(got.Events) != 1 || got.Total != 1 {
			t.Fatalf("%T query %+v %v", st, got, err)
		}
		filter.HTTPPath = "/api/search' OR 1=1 --"
		got, err = st.SearchEvents(ctx, filter)
		if err != nil || got.Total != 0 {
			t.Fatalf("%T SQL injection: %+v %v", st, got, err)
		}
	}
}

func TestEvidenceIPMask(t *testing.T) {
	for raw, want := range map[string]string{"198.51.100.42": "198.51.100.0/24", "::ffff:198.51.100.42": "198.51.100.0/24", "2001:db8:1234:5678::12": "2001:db8:1234::/48", "::1": "::/48", "2001:db8::abcd": "2001:db8::/48", "invalid": "[REDACTED]"} {
		if got := MaskIP(raw); got != want {
			t.Errorf("%q -> %q want %q", raw, got, want)
		}
	}
}
