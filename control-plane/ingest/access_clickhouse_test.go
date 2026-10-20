package ingest

import (
	"errors"
	"github.com/strata/strata/control-plane/auth"
	"testing"
	"time"
)

func TestApplicationScopeClickHouse(t *testing.T) {
	ch := geoIPTestStore(t)
	ctx := t.Context()
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	events := []Event{}
	for i := 0; i < 5; i++ {
		e := geoEvent(string(rune('A'+i)), at, "block", []uint32{942100}, "VN", 7552, 21.03, 105.85)
		e.HTTPHost = "api.example.test"
		e.HTTPPath = "/owned/item"
		e.NodeID = "edge-a"
		events = append(events, e)
	}
	events[1].HTTPHost = "b.example.test"
	events[2].HTTPPath = "/other"
	events[3].NodeID = "edge-b"
	events[4].PolicyID = "other-policy"
	if err := ch.SaveEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	if err := ch.EnsureGeoAggregates(ctx, 13); err != nil {
		t.Fatal(err)
	}
	p := &auth.Principal{Roles: []auth.Role{auth.RoleViewer}, Access: &auth.Access{Events: []auth.EventScope{{Policy: "example-api", Host: "api.example.test", Prefix: "/owned", Nodes: []string{"edge-a"}}}}}
	ctx = auth.WithPrincipal(ctx, p)
	f := OverviewFilter{From: at.Add(-time.Minute), To: at.Add(time.Minute)}
	if err := f.Normalize(); err != nil {
		t.Fatal(err)
	}
	result, err := ch.Overview(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if result.Totals.Events != 1 || result.TelemetryScope != "events_only" || result.Engine != nil || len(result.Inspection) != 0 {
		t.Fatalf("overview leak: %+v", result)
	}
	search, err := ch.SearchEvents(ctx, SearchFilter{From: f.From, To: f.To, Limit: 20})
	if err != nil || search.Total != 1 {
		t.Fatalf("search leak: %+v %v", search, err)
	}
	if _, err := ch.GetEvent(ctx, events[1].BlockID); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("Block ID IDOR: %v", err)
	}
	if _, err := ch.GetEvent(ctx, events[0].BlockID); err != nil {
		t.Fatal(err)
	}
	geo := GeoFilter{From: f.From, To: f.To}
	for _, query := range []func() ([]GeoCount, error){func() ([]GeoCount, error) { return ch.GeoByCountry(ctx, geo) }, func() ([]GeoCount, error) { return ch.GeoByASN(ctx, geo) }, func() ([]GeoCount, error) { return ch.GeoByCell(ctx, geo) }} {
		got, err := query()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Events != 1 {
			t.Fatalf("geo leak: %+v", got)
		}
	}
	timeline, err := ch.GeoTimeline(ctx, geo, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, b := range timeline {
		total += b.Block
	}
	if total != 1 {
		t.Fatalf("timeline leak: %d", total)
	}
	p.Access.Events = nil
	search, err = ch.SearchEvents(ctx, SearchFilter{From: f.From, To: f.To, Limit: 20})
	if err != nil || search.Total != 0 {
		t.Fatalf("empty scope widened: %+v %v", search, err)
	}
}
