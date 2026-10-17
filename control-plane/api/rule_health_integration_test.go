package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulehealth"
	"github.com/strata/strata/control-plane/store"
)

func TestRuleHealthDurableSources(t *testing.T) {
	addr := os.Getenv("STRATA_TEST_CLICKHOUSE_ADDR")
	if addr == "" || os.Getenv("STRATA_TEST_POSTGRES_DSN") == "" {
		t.Skip("real ClickHouse and PostgreSQL required; run tests/e2e/rule-health.sh")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	p := localauthtest.Pool(t)
	cfg := ingest.ClickHouseConfig{Addr: addr, Database: "default", Username: os.Getenv("STRATA_TEST_CLICKHOUSE_USER"), Password: os.Getenv("STRATA_TEST_CLICKHOUSE_PASSWORD")}
	admin, err := ingest.NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error(err)
		}
	})
	db := fmt.Sprintf("health_api_%d", time.Now().UnixNano())
	if err := admin.Conn().Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := admin.Conn().Exec(cleanup, "DROP DATABASE IF EXISTS "+db); err != nil {
			t.Error(err)
		}
	})
	cfg.Database = db
	ch, err := ingest.NewClickHouseStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ch.Close(); err != nil {
			t.Error(err)
		}
	})
	schema, err := os.ReadFile("../ingest/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(stmt) != "" {
			if err := ch.Conn().Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := ch.Conn().Exec(ctx, "SYSTEM STOP MERGES events"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second).Add(250 * time.Millisecond)
	e := ingest.Event{BlockID: "STR-8F3K-Q2VD-7XNM-A1PC", Timestamp: now, ReceivedAt: now, NodeID: "example-node", PolicyVersion: 7, PolicyID: "example-api", Action: "block", HTTPMethod: "GET",
		MatchedRules: []uint32{942100}, RuleCosts: []ingest.RuleCost{{RuleID: 942100, Samples: 2, TotalNS: 700, MaxNS: 500}}}
	for range 2 {
		if err := ch.SaveEvents(ctx, []ingest.Event{e}); err != nil {
			t.Fatal(err)
		}
		e.ReceivedAt = now.Add(time.Millisecond)
	}
	server := func() *Server {
		pg := store.New(p)
		return NewServer(ServerConfig{Auth: tokenRoles{}, Annotations: pg, Health: rulehealth.NewService(ch, pg)}, ch)
	}
	s := server()
	query := url.Values{"policy_id": {e.PolicyID}, "from": {now.Add(-time.Second).Format(time.RFC3339Nano)}, "to": {now.Add(time.Second).Format(time.RFC3339Nano)}}
	path := "/v1/rules/942100/health?" + query.Encode()
	check := func(wantFP float64) {
		t.Helper()
		code, body := do(t, s, http.MethodGet, path, "viewer", nil)
		if code != 200 || body["matched_events"] != float64(1) || body["reported_fp_events"] != wantFP || body["cost_samples"] != "2" || body["cost_mean_ns"] != float64(350) || body["status"] != "observing" {
			t.Fatalf("wrong durable health: %d %v", code, body)
		}
	}
	check(0)
	if code, body := do(t, s, http.MethodPost, "/v1/events/"+e.BlockID+":markFalsePositive", "operator", map[string]string{"reason": "legitimate fixture request", "request_id": "health-fixture"}); code != 200 {
		t.Fatalf("mark FP: %d %v", code, body)
	}
	check(1)
	// Staging evaluation must use the same exact deployed bundle in both
	// stores. Retry rows remain unmerged, but only one event/report counts.
	spec := policy.Spec{Mode: "enforce", AutoStaging: &policy.AutoStaging{Enabled: true, RuleIDs: []uint32{942100}, WindowSeconds: 300, MinMatches: 1, MinReports: 1, FPThresholdBPS: 10000}}
	evaluator := rulehealth.NewService(ch, store.New(p))
	for _, bundle := range []uint64{7, 8} {
		out, err := evaluator.Evaluate(ctx, spec, 942100, e.PolicyID, bundle, time.Now().Add(time.Second))
		want := uint64(0)
		if bundle == 7 {
			want = 1
		}
		if err != nil || out.ThresholdMet != (bundle == 7) || out.MatchedEvents != want || out.FPReports != want {
			t.Fatalf("cross-store evaluation bundle %d: %+v %v", bundle, out, err)
		}
	}
	if n, err := ch.RuleMatchCount(ctx, 942100, e.PolicyID, 7, now.Add(time.Nanosecond), now.Add(time.Second)); err != nil || n != 0 {
		t.Fatalf("fractional evaluation window: %d %v", n, err)
	}
	s = server() // new API/reader/store instances, same durable data
	check(1)
	query.Set("from", now.Add(time.Nanosecond).Format(time.RFC3339Nano))
	if code, body := do(t, s, http.MethodGet, "/v1/rules/942100/health?"+query.Encode(), "viewer", nil); code != 200 || body["matched_events"] != float64(0) || body["reported_fp_events"] != float64(0) || body["reported_fp_share"] != nil {
		t.Fatalf("two stores disagree at fractional boundary: %d %v", code, body)
	}
	if audits, err := store.New(p).AuditEntries(ctx, 10); err != nil || len(audits) != 1 {
		t.Fatalf("read created extra audit/state: %d %v", len(audits), err)
	}
	var raw uint64
	if err := ch.Conn().QueryRow(ctx, "SELECT count() FROM events").Scan(&raw); err != nil || raw != 2 {
		t.Fatalf("read rewrote raw events: %d %v", raw, err)
	}
}
