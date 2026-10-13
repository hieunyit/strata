package ingest

// W09-G2-01: the event store on a real ClickHouse, filled by
// tests/perf/clickhouse.sh (about 10 million events in the last 24 hours
// and 10 million over the 29 days before). Skipped unless
// CLICKHOUSE_PERF_ADDR (native protocol) and CLICKHOUSE_PERF_PASSWORD are
// set; the script sets them.
//
//   TestClickHousePerf  Block ID lookup (target under 1 s) and 24-hour
//                       searches with the filters of the Events page
//                       (target under 2 s), through ClickHouseStore, the
//                       code GET /v1/events and GET /v1/events/{id} run
//   TestClickHouseTTL   EnsureTTL changes the table's TTL, ClickHouse drops
//                       the rows past it, a second call changes nothing

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func perfStore(t *testing.T, table string) *ClickHouseStore {
	t.Helper()
	addr := os.Getenv("CLICKHOUSE_PERF_ADDR")
	if addr == "" {
		t.Skip("CLICKHOUSE_PERF_ADDR not set (run tests/perf/clickhouse.sh)")
	}
	s, err := NewClickHouseStore(context.Background(), ClickHouseConfig{
		Addr: addr, Database: "default", Username: "strata",
		Password: os.Getenv("CLICKHOUSE_PERF_PASSWORD"), Table: table,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

type timings []time.Duration

func (d timings) pct(p float64) time.Duration {
	s := append(timings(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[min(int(float64(len(s))*p), len(s)-1)]
}

func TestClickHousePerf(t *testing.T) {
	s := perfStore(t, "events")
	ctx := context.Background()
	var total, day uint64
	if err := s.Conn().QueryRow(ctx, "SELECT count(), countIf(timestamp >= now() - INTERVAL 1 DAY) FROM events").Scan(&total, &day); err != nil {
		t.Fatal(err)
	}
	if day < 5_000_000 {
		t.Fatalf("only %d events in the last 24 h (%d in all): fill the table first", day, total)
	}
	t.Logf("events: %d in all, %d in the last 24 h", total, day)

	// 200 Block IDs picked at random over the whole table
	rows, err := s.Conn().Query(ctx, "SELECT block_id FROM events WHERE cityHash64(block_id) % 100000 = 7 LIMIT 200")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) < 100 {
		t.Fatalf("only %d Block IDs sampled", len(ids))
	}
	var lookup timings
	for _, id := range ids {
		start := time.Now()
		e, err := s.GetEvent(ctx, id)
		lookup = append(lookup, time.Since(start))
		if err != nil || e.BlockID != id {
			t.Fatalf("GetEvent(%s): %v", id, err)
		}
	}
	// and a miss: an ID nobody has
	start := time.Now()
	if _, err := s.GetEvent(ctx, "STR-0000-0000-0000-0000"); err != ErrEventNotFound {
		t.Fatalf("missing ID: %v", err)
	}
	miss := time.Since(start)
	t.Logf("Block ID lookup, %d IDs: p50 %v, p99 %v, max %v; an unknown ID %v",
		len(lookup), lookup.pct(0.5), lookup.pct(0.99), lookup.pct(1), miss)
	if lookup.pct(0.99) > time.Second || miss > time.Second {
		t.Errorf("Block ID lookup over 1 s")
	}

	// 24-hour searches with the filters of the Events page, first page and a
	// deep page; each run 10 times
	to := time.Now()
	from := to.Add(-24 * time.Hour)
	searches := []struct {
		name string
		f    SearchFilter
	}{
		{"all", SearchFilter{}},
		{"policy", SearchFilter{PolicyID: "example-api"}},
		{"action block", SearchFilter{Action: "block"}},
		{"rule 942100", SearchFilter{RuleID: 942100}},
		{"client IP", SearchFilter{ClientIP: "203.0.113.1"}},
		{"node + method", SearchFilter{NodeID: "node-3", HTTPMethod: "POST"}},
		{"policy + rule + action", SearchFilter{PolicyID: "example-api", RuleID: 941100, Action: "block"}},
		{"all, page 41", SearchFilter{Offset: 2000}},
	}
	var report []string
	worst := time.Duration(0)
	for _, q := range searches {
		q.f.From, q.f.To, q.f.Limit = from, to, 50
		var d timings
		var n uint64
		for i := 0; i < 10; i++ {
			start := time.Now()
			res, err := s.SearchEvents(ctx, q.f)
			d = append(d, time.Since(start))
			if err != nil {
				t.Fatalf("%s: %v", q.name, err)
			}
			n = res.Total
		}
		worst = max(worst, d.pct(0.99))
		report = append(report, fmt.Sprintf("%-24s total %9d  p50 %8v  p99 %8v", q.name, n, d.pct(0.5).Round(time.Millisecond), d.pct(0.99).Round(time.Millisecond)))
	}
	t.Logf("24-hour searches (count + first 50):\n%s", strings.Join(report, "\n"))

	// the page read through the primary key is the page of the one-step
	// query: same events, same order
	for _, f := range []SearchFilter{{PolicyID: "example-api", Offset: 100}, {RuleID: 942100}} {
		f.From, f.To, f.Limit = from, to, 50
		res, err := s.SearchEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		where, args := "timestamp >= ? AND timestamp <= ?", []any{from, to}
		if f.PolicyID != "" {
			where, args = where+" AND policy_id = ?", append(args, f.PolicyID)
		}
		if f.RuleID != 0 {
			where, args = where+" AND has(matched_rules, ?)", append(args, f.RuleID)
		}
		rows, err := s.Conn().Query(ctx, "SELECT block_id FROM events WHERE "+where+
			" ORDER BY timestamp DESC, block_id DESC LIMIT 50 OFFSET ?", append(args, f.Offset)...)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			want = append(want, id)
		}
		rows.Close()
		var got []string
		for _, e := range res.Events {
			got = append(got, e.BlockID)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") || len(got) != 50 {
			t.Errorf("filter %+v: page differs from the one-step query:\n got %v\nwant %v", f, got, want)
		}
	}
	if worst > 2*time.Second {
		t.Errorf("a 24-hour search took %v (target under 2 s)", worst)
	}
}

func TestClickHouseTTL(t *testing.T) {
	s := perfStore(t, "events")
	ctx := context.Background()
	c := s.Conn()
	if err := c.Exec(ctx, "DROP TABLE IF EXISTS events_ttl_test"); err != nil {
		t.Fatal(err)
	}
	if err := c.Exec(ctx, "CREATE TABLE events_ttl_test AS events"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Exec(context.Background(), "DROP TABLE IF EXISTS events_ttl_test") })
	tt := &ClickHouseStore{conn: c, tableName: "events_ttl_test"}

	now := time.Now().UTC()
	ev := func(id string, ts time.Time) Event {
		return Event{BlockID: id, Timestamp: ts, NodeID: "node-1", ConnectorType: "nginx", PolicyID: "example-api",
			Action: "block", HTTPMethod: "GET", ReceivedAt: now}
	}
	if err := tt.SaveEvents(ctx, []Event{
		ev("STR-TT00-0000-0000-0001", now.Add(-40*24*time.Hour)),
		ev("STR-TT00-0000-0000-0002", now.Add(-24*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := tt.EnsureTTL(ctx, 30); err != nil {
		t.Fatal(err)
	}
	var create string
	if err := c.QueryRow(ctx, "SELECT create_table_query FROM system.tables WHERE name = 'events_ttl_test'").Scan(&create); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(create, "toIntervalDay(30)") {
		t.Fatalf("TTL not set: %s", create)
	}
	if err := c.Exec(ctx, "OPTIMIZE TABLE events_ttl_test FINAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := tt.GetEvent(ctx, "STR-TT00-0000-0000-0001"); err != ErrEventNotFound {
		t.Errorf("an event 40 days old is still there after a 30-day TTL: %v", err)
	}
	if _, err := tt.GetEvent(ctx, "STR-TT00-0000-0000-0002"); err != nil {
		t.Errorf("an event of yesterday is gone: %v", err)
	}
	// unchanged TTL: no ALTER (the mutation count stays)
	var before, after uint64
	_ = c.QueryRow(ctx, "SELECT count() FROM system.mutations WHERE table = 'events_ttl_test'").Scan(&before)
	if err := tt.EnsureTTL(ctx, 30); err != nil {
		t.Fatal(err)
	}
	_ = c.QueryRow(ctx, "SELECT count() FROM system.mutations WHERE table = 'events_ttl_test'").Scan(&after)
	if after != before {
		t.Errorf("EnsureTTL with the same TTL altered the table again (%d -> %d mutations)", before, after)
	}
}
