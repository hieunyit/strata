package ingest

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// W20-G2-01: the hourly rollup gives the numbers of the events table, each
// event once (a resent event is not counted twice), and follows new and
// late events at its next run.
func TestStatsRollup(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if _, err := ch.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if ready, err := ch.StatsReady(ctx); err != nil || ready {
		t.Fatalf("ready before the first run: %v %v", ready, err)
	}
	base := time.Now().UTC().Truncate(time.Hour).Add(-5 * time.Hour)
	n := 0
	ev := func(at time.Time, action, policy, ip, path string, rules ...uint32) Event {
		n++
		return Event{BlockID: "STR-0000-0000-0000-" + string(rune('A'+n/26)) + string(rune('A'+n%26)) + "00", Timestamp: at, ReceivedAt: time.Now().UTC(),
			NodeID: "example-node", PolicyID: policy, Action: action, ClientIP: ip, HTTPHost: "api.example.test", HTTPPath: path, MatchedRules: rules,
			CountryISO: "VN", ASN: 7552, GeoIPVersion: "v1"}
	}
	batch := []Event{
		ev(base.Add(10*time.Minute), "block", "example-api", "198.51.100.1", "/v1/items/1?x=1", 942100, 941100),
		ev(base.Add(20*time.Minute), "shadow", "example-api", "198.51.100.2", "/v1/items/2", 942100),
		ev(base.Add(70*time.Minute), "block", "example-web", "198.51.100.1", "/login", 932160),
		ev(base.Add(130*time.Minute), "pass", "example-api", "198.51.100.3", "/v1/search", 0),
	}
	if err := ch.SaveEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	// the same batch again (resent after a timeout), one event of it changed
	resent := append([]Event(nil), batch...)
	resent[1].ReceivedAt = time.Now().UTC()
	if err := ch.SaveEvents(ctx, resent); err != nil {
		t.Fatal(err)
	}
	check := func(what string) {
		t.Helper()
		f := OverviewFilter{From: base, To: base.Add(5 * time.Hour), Step: time.Hour, Clients: true}
		ready, _ := ch.StatsReady(ctx)
		if !ready {
			t.Fatalf("%s: rollup not ready", what)
		}
		got, err := ch.overviewRolled(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ch.overviewRaw(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Approximate || got.Totals.Events != raw.Totals.Events || got.Totals.Block != raw.Totals.Block ||
			got.Totals.Shadow != raw.Totals.Shadow || got.Totals.Other != raw.Totals.Other || got.Totals.Nodes != raw.Totals.Nodes ||
			got.Totals.Policies != raw.Totals.Policies || got.Totals.Clients != raw.Totals.Clients {
			t.Errorf("%s: totals rolled %+v raw %+v", what, got.Totals, raw.Totals)
		}
		if !reflect.DeepEqual(got.Series, raw.Series) || !reflect.DeepEqual(got.TopRules, raw.TopRules) ||
			!reflect.DeepEqual(got.TopRoutes, raw.TopRoutes) || !reflect.DeepEqual(got.TopClients, raw.TopClients) {
			t.Errorf("%s:\nrolled %+v %+v %+v %+v\nraw    %+v %+v %+v %+v", what, got.Series, got.TopRules, got.TopRoutes, got.TopClients,
				raw.Series, raw.TopRules, raw.TopRoutes, raw.TopClients)
		}
		g, err := ch.geoRankRolled(ctx, GeoFilter{From: base, To: base.Add(5 * time.Hour)}, "country_iso", "''")
		if err != nil || len(g) != 1 || g[0].Key != "VN" || g[0].Events != got.Totals.Events {
			t.Errorf("%s: geo %+v %v", what, g, err)
		}
	}
	if h, err := ch.RollupStats(ctx); err != nil || h != 3 {
		t.Fatalf("first run: %d hours, %v", h, err)
	}
	check("first run")
	if got, _ := ch.overviewRolled(ctx, OverviewFilter{From: base, To: base.Add(5 * time.Hour), Step: time.Hour}); got.Totals.Events != 4 {
		t.Errorf("a resent event counted twice: %d", got.Totals.Events)
	}
	// nothing new: nothing recomputed beyond the overlap
	if _, err := ch.RollupStats(ctx); err != nil {
		t.Fatal(err)
	}
	// a late event in an old hour and a new one: both counted at the next run
	if err := ch.SaveEvents(ctx, []Event{
		ev(base.Add(15*time.Minute), "block", "example-web", "198.51.100.9", "/admin", 942100),
		ev(base.Add(250*time.Minute), "error", "example-api", "198.51.100.4", "/v1/items/3", 0),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.RollupStats(ctx); err != nil {
		t.Fatal(err)
	}
	check("after late and new events")
	// the window is whole hours
	got, err := ch.overviewRolled(ctx, OverviewFilter{From: base.Add(30 * time.Minute), To: base.Add(90 * time.Minute), Step: time.Hour})
	if err != nil || !got.From.Equal(base) || !got.To.Equal(base.Add(2*time.Hour)) {
		t.Errorf("window %s..%s %v", got.From, got.To, err)
	}
	// retention as the GeoIP aggregates, set once
	for range 2 {
		if err := ch.EnsureStatsTTL(ctx, 13); err != nil {
			t.Fatal(err)
		}
	}
	var create string
	if err := ch.conn.QueryRow(ctx, "SELECT create_table_query FROM system.tables WHERE database = currentDatabase() AND name = ?", StatsRulesTable).Scan(&create); err != nil || !strings.Contains(create, "TTL hour + toIntervalMonth(13)") {
		t.Errorf("TTL: %v %s", err, create)
	}
	// the Overview takes the rollup once ready
	o, err := ch.Overview(ctx, OverviewFilter{From: base, To: base.Add(5 * time.Hour)})
	if err != nil || !o.Approximate || o.Totals.Events != 6 {
		t.Errorf("Overview %+v %v", o, err)
	}
}
