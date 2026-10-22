package ingest

import (
	"context"
	"maps"
	"testing"
	"time"
)

// RS-4b on a real ClickHouse (skipped unless STRATA_TEST_CLICKHOUSE_ADDR):
// the events of each rule, from the events table before the rollup's first
// run and from the rollup after, the same numbers.
func TestRuleCountsClickHouse(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if _, err := ch.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	ev := func(id string, at time.Time, policy string, rules ...uint32) Event {
		return Event{BlockID: "STR-0000-0000-0000-" + id, Timestamp: at, ReceivedAt: time.Now().UTC(), NodeID: "example-node",
			PolicyID: policy, Action: "shadow", ClientIP: "198.51.100.1", HTTPHost: "api.example.test", HTTPPath: "/", MatchedRules: rules}
	}
	if err := ch.SaveEvents(ctx, []Event{
		ev("AA00", base.Add(10*time.Minute), "example-api", 500901, 500901, 942100),
		ev("AB00", base.Add(70*time.Minute), "example-web", 500901),
		ev("AC00", base.Add(-30*time.Hour), "example-api", 500901),
	}); err != nil {
		t.Fatal(err)
	}
	from, to := base, base.Add(3*time.Hour)
	want := map[uint32]uint64{500901: 2, 942100: 1}
	raw, err := ch.RuleCounts(ctx, "", from, to)
	if err != nil || !maps.Equal(raw, want) {
		t.Fatalf("raw %v %v", raw, err)
	}
	if one, err := ch.RuleCounts(ctx, "example-web", from, to); err != nil || !maps.Equal(one, map[uint32]uint64{500901: 1}) {
		t.Fatalf("one policy %v %v", one, err)
	}
	if _, err := ch.RollupStats(ctx); err != nil {
		t.Fatal(err)
	}
	if ready, _ := ch.StatsReady(ctx); !ready {
		t.Fatal("rollup not ready")
	}
	rolled, err := ch.RuleCounts(ctx, "", from, to)
	if err != nil || !maps.Equal(rolled, want) {
		t.Fatalf("rolled %v %v", rolled, err)
	}
}
