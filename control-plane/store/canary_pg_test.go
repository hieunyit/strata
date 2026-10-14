package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN, an empty database):
// migration 0011 and the canary trips of the cluster fallback (W12-G2-01):
// one open trip per group, renewal, clearing policy by policy, and the
// policies with a canary; then down to 0009 and up again.
func TestCanaryTripsInPostgres(t *testing.T) {
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close) // after the migration back to 0 below
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups (id, name) VALUES ('edge', 'Edge');
		INSERT INTO nodes (id, group_id) VALUES ('node-a', 'edge'), ('node-b', 'edge')`); err != nil {
		t.Fatal(err)
	}
	s := store.New(pool)
	a := store.Audit{Actor: "canary-monitor", Channel: "system", Action: "trip", Resource: "groups/edge:canaryFallback"}
	for _, p := range []struct{ id, spec string }{
		{"example-canary", `{"mode":"enforce","canary_percent":5}`},
		{"example-api", `{"mode":"enforce"}`},
	} {
		if _, err := s.CreatePolicy(ctx, store.Policy{ID: p.id, Name: p.id, Spec: json.RawMessage(p.spec)}, a); err != nil {
			t.Fatal(err)
		}
	}
	if ps, err := s.CanaryPolicies(ctx); err != nil || !slices.Equal(ps, []string{"example-canary"}) {
		t.Fatalf("canary policies %v %v", ps, err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	exp := now.Add(24 * time.Hour)
	cmds := []store.Command{
		{ID: "c1", NodeID: "node-a", Kind: store.CommandForceShadow, PolicyID: "example-canary", DurationSeconds: 86400, ExpiresAt: exp},
		{ID: "c2", NodeID: "node-b", Kind: store.CommandForceShadow, PolicyID: "example-canary", DurationSeconds: 86400, ExpiresAt: exp},
	}
	trip := store.CanaryTrip{GroupID: "edge", Reason: "block_rate", Detail: map[string]any{"canary_block": 0.4},
		Policies: []string{"example-canary", "example-web"}, TrippedAt: now}
	got, out, err := s.OpenCanaryTrip(ctx, trip, cmds, a)
	if err != nil || got.ID == 0 || len(out) != 2 || out[0].State != store.CommandPending {
		t.Fatalf("open: %+v %+v %v", got, out, err)
	}
	if _, _, err := s.OpenCanaryTrip(ctx, trip, nil, a); !errors.Is(err, store.ErrTripOpen) {
		t.Fatalf("second open trip: %v", err)
	}
	open, err := s.OpenCanaryTrips(ctx)
	if err != nil || len(open) != 1 || open[0].Detail["canary_block"] != 0.4 || !open[0].RenewedAt.Equal(now) {
		t.Fatalf("open trips %+v %v", open, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE actor = 'canary-monitor' AND resource = 'groups/edge:canaryFallback'
		AND (after->'trip'->>'reason') = 'block_rate'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit %d %v", n, err)
	}

	later := now.Add(12 * time.Hour)
	if out, err := s.RenewCanaryTrip(ctx, got.ID, []store.Command{{ID: "c3", NodeID: "node-a", Kind: store.CommandForceShadow,
		PolicyID: "example-canary", DurationSeconds: 86400, ExpiresAt: later.Add(24 * time.Hour)}}, later); err != nil || len(out) != 1 {
		t.Fatalf("renew %v %v", out, err)
	}

	// one policy lifted: the trip holds the other
	if err := s.ClearCanaryTrip(ctx, "edge", "example-canary", "alice", later); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenCanaryTrips(ctx); len(open) != 1 || !slices.Equal(open[0].Policies, []string{"example-web"}) || !open[0].RenewedAt.Equal(later) {
		t.Fatalf("after one: %+v", open)
	}
	// the last one: cleared, and a new trip may open
	if err := s.ClearCanaryTrip(ctx, "edge", "example-web", "alice", later); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenCanaryTrips(ctx); len(open) != 0 {
		t.Fatalf("after both: %+v", open)
	}
	if _, err := s.RenewCanaryTrip(ctx, got.ID, nil, later); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("renew a cleared trip: %v", err)
	}
	if _, _, err := s.OpenCanaryTrip(ctx, trip, nil, a); err != nil {
		t.Fatalf("new trip: %v", err)
	}
	// every policy at once ("")
	if err := s.ClearCanaryTrip(ctx, "edge", "", "alice", later); err != nil {
		t.Fatal(err)
	}
	var by string
	if err := pool.QueryRow(ctx, `SELECT cleared_by FROM canary_trips ORDER BY id DESC LIMIT 1`).Scan(&by); err != nil || by != "alice" {
		t.Fatalf("cleared_by %q %v", by, err)
	}
	if err := db.Migrate(ctx, pool, 9); err != nil {
		t.Fatalf("down to 9: %v", err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
