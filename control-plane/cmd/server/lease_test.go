package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

// CP-A03: the keeper renews its lease; a second control plane cannot take
// it while it is held; when it is taken over anyway (after expiry), the old
// one exits; a clean stop releases it.
func TestLeaseKeeperInPostgres(t *testing.T) {
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	s := store.New(pool)

	a := &leaseKeeper{store: s, ttl: 900 * time.Millisecond}
	if err := a.acquire(ctx, "cp-a"); err != nil || !a.held.Load() {
		t.Fatal(err)
	}
	actx, stopA := context.WithCancel(ctx)
	exited := make(chan string, 1)
	go a.keep(actx, func(msg string) { exited <- msg })
	time.Sleep(1500 * time.Millisecond) // past the first ttl: renewed meanwhile
	b := &leaseKeeper{store: s, ttl: time.Second}
	if _, err := s.AcquireLease(ctx, "cp-b", time.Second); !errors.Is(err, store.ErrLeaseHeld) {
		t.Fatalf("lease taken while renewed: %v", err)
	}
	// a clean stop releases the lease: cp-b can take it at once (well
	// before cp-a's ttl would have run out)
	stopA()
	_ = b
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := s.AcquireLease(ctx, "cp-b", time.Second); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("lease not released after a clean stop: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// a keeper whose lease was taken over (cp-b holds it now) exits
	c := &leaseKeeper{store: s, ttl: 900 * time.Millisecond, lease: store.Lease{Holder: "cp-a", Fencing: 1}}
	c.held.Store(true)
	cctx, stopC := context.WithCancel(ctx)
	defer stopC()
	go c.keep(cctx, func(msg string) { exited <- msg })
	select {
	case msg := <-exited:
		if c.held.Load() {
			t.Fatalf("still held after %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a keeper whose lease was taken over did not exit")
	}
}

// A restart on the same host after a crash takes the lease over at once;
// a live control plane on the same host, or one on another host, is waited
// for.
func TestLeaseTakeOverAfterCrashHere(t *testing.T) {
	host, _ := os.Hostname()
	if !deadHere(fmt.Sprintf("%s/%d/abcd", host, os.Getpid())) {
		t.Fatal("a previous run with our pid is not dead")
	}
	if deadHere(fmt.Sprintf("%s/%d/abcd", host, os.Getppid())) {
		t.Fatal("our parent counted as dead")
	}
	if !deadHere(fmt.Sprintf("%s/%d/abcd", host, 1<<22-7)) {
		t.Fatal("a pid that does not exist counted as alive")
	}
	if deadHere(fmt.Sprintf("other-host/%d/abcd", os.Getpid())) || deadHere("garbage") {
		t.Fatal("another host or a malformed holder counted as dead")
	}
	dsn := os.Getenv("STRATA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STRATA_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	latest, _ := db.Latest()
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	s := store.New(pool)
	crashed := fmt.Sprintf("%s/%d/dead", host, 1<<22-7)
	if _, err := s.AcquireLease(ctx, crashed, time.Hour); err != nil {
		t.Fatal(err)
	}
	k := &leaseKeeper{store: s, ttl: time.Hour}
	start := time.Now()
	if err := k.acquire(ctx, leaseHolder()); err != nil || time.Since(start) > 5*time.Second {
		t.Fatalf("restart after a crash waited: %v after %s", err, time.Since(start))
	}
	if k.lease.Fencing != 2 {
		t.Fatalf("fencing %d", k.lease.Fencing)
	}
}
