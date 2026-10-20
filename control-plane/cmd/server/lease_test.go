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

// A hostname and PID are not proof that a holder is dead: containers can
// share a hostname but have separate PID namespaces. Even a missing PID
// in this namespace must not allow stealing an unexpired lease.
func TestLeaseDoesNotStealAcrossPIDNamespaces(t *testing.T) {
	dsn := ownDatabase(t)
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
	s := store.New(pool)
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{os.Getpid(), 1<<22 - 7} {
		t.Run(fmt.Sprint(pid), func(t *testing.T) {
			if _, err := pool.Exec(ctx, "DELETE FROM control_plane_lease"); err != nil {
				t.Fatal(err)
			}
			holder := fmt.Sprintf("%s/%d/existing-container", host, pid)
			original, err := s.AcquireLease(ctx, holder, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			k := &leaseKeeper{store: s, ttl: time.Minute}
			waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			if err := k.acquire(waitCtx, leaseHolder()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unexpired holder was not respected: %v", err)
			}
			got, err := s.CurrentLease(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got.Holder != original.Holder || got.Fencing != original.Fencing || k.held.Load() {
				t.Fatalf("unexpired lease changed: got %+v, original %+v", got, original)
			}
			// An actually expired lease remains recoverable after a crash.
			if _, err := pool.Exec(ctx, "UPDATE control_plane_lease SET expires_at = now() - interval '1 second'"); err != nil {
				t.Fatal(err)
			}
			if err := k.acquire(ctx, leaseHolder()); err != nil {
				t.Fatal(err)
			}
			if k.lease.Fencing != original.Fencing+1 {
				t.Fatalf("fencing %d", k.lease.Fencing)
			}
		})
	}
}
