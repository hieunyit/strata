package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestBundleLockCleanupAfterCancellationAndSessionFailure(t *testing.T) {
	p := localauthtest.Pool(t)
	s := store.New(p)
	ctx, cancel := context.WithCancel(t.Context())
	sentinel := errors.New("build failed")
	if err := s.WithBundleLock(ctx, func(uint64) error { cancel(); return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("build failure lost: %v", err)
	}
	// Cleanup has its own bounded context: a canceled build still unlocks.
	retry, retryCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer retryCancel()
	if err := s.WithBundleLock(retry, func(uint64) error { return nil }); err != nil {
		t.Fatalf("canceled build leaked lock: %v", err)
	}
	// Terminate exactly this fixture database's lock session, not other tests.
	err := s.WithBundleLock(t.Context(), func(uint64) error {
		var killed bool
		err := p.QueryRow(t.Context(), `SELECT pg_terminate_backend(pid) FROM pg_locks
   WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND classid=$1::oid AND objid=$2::oid AND objsubid=1 AND granted`, int64(0x53545241), int64(0x54410002)).Scan(&killed)
		if err != nil || !killed {
			t.Fatalf("fixture session not terminated: %v %v", killed, err)
		}
		return nil
	})
	if err == nil {
		t.Fatal("failed unlock silently reported success")
	}
	recovery, recoveryCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer recoveryCancel()
	if err = s.WithBundleLock(recovery, func(uint64) error { return nil }); err != nil {
		t.Fatalf("discarded session poisoned pool: %v", err)
	}
}

func TestBundleLockCanceledWaitDoesNotPoisonNextBuild(t *testing.T) {
	s := store.New(localauthtest.Pool(t))
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithBundleLock(t.Context(), func(uint64) error { close(held); <-release; return nil })
	}()
	<-held
	waiting, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	err := s.WithBundleLock(waiting, func(uint64) error { t.Error("canceled waiter entered build"); return nil })
	cancel()
	close(release)
	if err == nil {
		t.Fatal("wait cancellation ignored")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	next, cancelNext := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancelNext()
	if err = s.WithBundleLock(next, func(uint64) error { return nil }); err != nil {
		t.Fatalf("canceled waiter leaked a lock: %v", err)
	}
}
