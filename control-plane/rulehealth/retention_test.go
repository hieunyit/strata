package rulehealth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

type pruneFunc func(context.Context, time.Time, int) (int64, error)

func (f pruneFunc) PruneRuleAnnotationContext(ctx context.Context, before time.Time, limit int) (int64, error) {
	return f(ctx, before, limit)
}

func startRetention(t *testing.T, sink ContextPruner, interval time.Duration) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		(ContextRetention{Store: sink, Interval: interval}).Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("retention goroutine did not stop")
		}
	})
	return cancel, done
}

func TestContextRetentionUsesBoundedBatchAndRetries(t *testing.T) {
	var calls atomic.Int64
	observed := make(chan struct{}, 1)
	sink := pruneFunc(func(ctx context.Context, before time.Time, limit int) (int64, error) {
		deadline, ok := ctx.Deadline()
		delta := time.Since(before) - ingest.MaxEventAge
		if !ok || time.Until(deadline) > 5*time.Second || limit != 1000 || delta < 0 || delta > time.Second {
			t.Errorf("unbounded or incorrect retention: limit=%d before=%v deadline=%v", limit, before, deadline)
		}
		if calls.Add(1) == 1 {
			return 0, errors.New("fixture database unavailable")
		}
		select {
		case observed <- struct{}{}:
		default:
		}
		return 1000, nil
	})
	cancel, _ := startRetention(t, sink, time.Millisecond)
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("retention did not retry database failure")
	}
	cancel()
}

func TestContextRetentionHonorsShorterAgeAndCapsLongerAge(t *testing.T) {
	for _, age := range []time.Duration{7 * 24 * time.Hour, 180 * 24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sink := pruneFunc(func(_ context.Context, before time.Time, _ int) (int64, error) {
				want := min(age, ingest.MaxEventAge)
				if d := time.Since(before) - want; d < 0 || d > time.Second {
					t.Errorf("retention cutoff %v differs from %v", before, want)
				}
				cancel()
				return 0, nil
			})
			(ContextRetention{Store: sink, MaxAge: age}).Run(ctx)
		})
	}
}

func TestContextRetentionCancellationInterruptsStoreCall(t *testing.T) {
	entered := make(chan struct{})
	sink := pruneFunc(func(ctx context.Context, _ time.Time, _ int) (int64, error) {
		close(entered)
		<-ctx.Done()
		return 0, ctx.Err()
	})
	cancel, done := startRetention(t, sink, 0)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial retention sweep did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt retention I/O")
	}
}

func TestContextRetentionAlreadyCancelledDoesNotCallStore(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	(ContextRetention{Store: pruneFunc(func(context.Context, time.Time, int) (int64, error) {
		t.Fatal("called store after shutdown")
		return 0, nil
	})}).Run(ctx)
}
