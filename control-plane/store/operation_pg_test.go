package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// Against a real PostgreSQL (STRATA_TEST_POSTGRES_DSN): migration 0013, the
// replay operations of policy versions (W13-G2-01): queued, claimed once
// by one of several control planes, finished, the newest of a version;
// a RUNNING one whose control plane stopped fails.
func TestOperationsInPostgres(t *testing.T) {
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
	t.Cleanup(pool.Close)
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	s := store.New(pool)
	a := store.Audit{Actor: "alice", Channel: "api", Action: "ReplayPolicy", Resource: "policies/example-api"}
	p, err := s.CreatePolicy(ctx, store.Policy{ID: "example-api", Name: "example-api", Spec: json.RawMessage(`{"mode":"shadow"}`)},
		store.Audit{Actor: "alice", Action: "CreatePolicy", Resource: "policies/example-api"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateReplayOperation(ctx, "example-api", 9, a); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no such version: %v", err)
	}
	if _, err := s.LatestReplay(ctx, "example-api", 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no replay yet: %v", err)
	}
	o1, err := s.CreateReplayOperation(ctx, p.ID, 1, a)
	if err != nil || o1.State != store.OpPending || o1.Kind != store.OpReplay || o1.Done() || len(o1.ID) != 27 {
		t.Fatalf("create: %+v %v", o1, err)
	}
	o2, err := s.CreateReplayOperation(ctx, p.ID, 1, a)
	if err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE resource = 'policies/example-api' AND action = 'ReplayPolicy'`).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("audit: %d %v", audited, err)
	}

	// two control planes claim at once: each gets another operation
	type claim struct {
		o  store.Operation
		ok bool
		e  error
	}
	ch := make(chan claim, 2)
	for range 2 {
		go func() {
			o, ok, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour))
			ch <- claim{o, ok, err}
		}()
	}
	c1, c2 := <-ch, <-ch
	if c1.e != nil || c2.e != nil || !c1.ok || !c2.ok || c1.o.ID == c2.o.ID || c1.o.State != store.OpRunning || c1.o.StartedAt == nil {
		t.Fatalf("claims: %+v %+v", c1, c2)
	}
	if _, ok, err := s.ClaimOperation(ctx, time.Now().Add(-time.Hour)); ok || err != nil {
		t.Fatalf("nothing left: %v %v", ok, err)
	}

	if err := s.FinishOperation(ctx, o1.ID, json.RawMessage(`{"samples":3}`), ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOperation(ctx, o1.ID)
	if err != nil || got.State != store.OpDone || !got.Done() || string(got.Result) != `{"samples": 3}` || got.FinishedAt == nil {
		t.Fatalf("done: %+v %s %v", got, got.Result, err)
	}
	// finishing again does nothing: it is no longer RUNNING
	if err := s.FinishOperation(ctx, o1.ID, nil, "late"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetOperation(ctx, o1.ID); got.State != store.OpDone {
		t.Fatalf("finished twice: %+v", got)
	}

	// o2 is RUNNING; its control plane stops: the next claim fails it
	if _, ok, err := s.ClaimOperation(ctx, time.Now().Add(time.Second)); ok || err != nil {
		t.Fatalf("claim after stale: %v %v", ok, err)
	}
	got, err = s.GetOperation(ctx, o2.ID)
	if err != nil || got.State != store.OpFailed || got.Error == "" || got.Result != nil {
		t.Fatalf("stale: %+v %v", got, err)
	}
	newest, err := s.LatestReplay(ctx, p.ID, 1)
	if err != nil || newest.ID != o2.ID {
		t.Fatalf("newest of version 1: %+v %v (want %s)", newest, err, o2.ID)
	}
	if _, err := s.GetOperation(ctx, "op-000000000000000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
