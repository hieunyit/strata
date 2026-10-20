package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/strata/strata/control-plane/db"
	"github.com/strata/strata/control-plane/store"
)

func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
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
	latest, err := db.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Migrate(context.Background(), pool, 0) })
	return pool
}

// CP-A03: one control plane holds the lease; another takes it only once it
// expired, with a new fencing value; the old holder then cannot renew.
func TestControlPlaneLeaseInPostgres(t *testing.T) {
	s := store.New(migratedPool(t))
	ctx := context.Background()
	if _, err := s.CurrentLease(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no lease yet: %v", err)
	}
	a, err := s.AcquireLease(ctx, "cp-a", time.Second)
	if err != nil || a.Fencing != 1 {
		t.Fatalf("acquire: %+v %v", a, err)
	}
	if again, err := s.AcquireLease(ctx, "cp-a", time.Second); err != nil || again.Fencing != 1 {
		t.Fatalf("same holder again: %+v %v", again, err)
	}
	if held, err := s.AcquireLease(ctx, "cp-b", time.Second); !errors.Is(err, store.ErrLeaseHeld) || held.Holder != "cp-a" {
		t.Fatalf("second control plane: %+v %v", held, err)
	}
	if a, err = s.RenewLease(ctx, a, 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	b, err := s.AcquireLease(ctx, "cp-b", time.Minute)
	if err != nil || b.Fencing != 2 || b.Holder != "cp-b" {
		t.Fatalf("takeover after expiry: %+v %v", b, err)
	}
	if _, err := s.RenewLease(ctx, a, time.Minute); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("old holder renewed: %v", err)
	}
	if err := s.ReleaseLease(ctx, b); err != nil {
		t.Fatal(err)
	}
	if c, err := s.AcquireLease(ctx, "cp-c", time.Minute); err != nil || c.Fencing != 3 {
		t.Fatalf("after a clean release: %+v %v", c, err)
	}
}

// CP-A03 (gap found by CP-A01): concurrent deploys are serialized under the
// bundle lock, get distinct versions in order, and a deploy that waits past
// BundleLockWait is told another one is in progress.
func TestConcurrentDeploysSerializedInPostgres(t *testing.T) {
	pool := migratedPool(t)
	s := store.New(pool)
	ctx := context.Background()
	var mu sync.Mutex
	inside, maxInside := 0, 0
	var versions []uint64
	deploy := func() error {
		return s.WithBundleLock(ctx, func(next uint64) error {
			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()
			time.Sleep(50 * time.Millisecond) // compiling
			_, err := s.RecordBundle(ctx, store.Bundle{Version: next, SHA256: make([]byte, 32), ObjectKey: fmt.Sprintf("bundles/%d", next), SizeBytes: 1,
				Contents: map[string]int{}}, store.Audit{Actor: "deployer"})
			mu.Lock()
			inside--
			versions = append(versions, next)
			mu.Unlock()
			return err
		})
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- deploy() }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if maxInside != 1 || len(versions) != 4 {
		t.Fatalf("overlapping deploys: max %d inside, versions %v", maxInside, versions)
	}
	for i, v := range versions {
		if v != uint64(i+1) {
			t.Fatalf("versions %v", versions)
		}
	}

	// one deploy holds the lock; another gives up after BundleLockWait
	holding, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = s.WithBundleLock(ctx, func(uint64) error { close(holding); <-release; return nil })
	}()
	<-holding
	impatient := store.New(pool)
	impatient.BundleLockWait = 200 * time.Millisecond
	start := time.Now()
	err := impatient.WithBundleLock(ctx, func(uint64) error { return nil })
	close(release)
	if !errors.Is(err, store.ErrBundleBusy) || time.Since(start) > 5*time.Second {
		t.Fatalf("busy: %v after %s", err, time.Since(start))
	}
	// the lock is free again afterwards
	if err := impatient.WithBundleLock(ctx, func(uint64) error { return nil }); err != nil {
		t.Fatalf("after release: %v", err)
	}
}
