package rulehealth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

type eventReadFunc func(context.Context, uint32, string, time.Time, time.Time) (ingest.RuleTelemetry, error)

func (f eventReadFunc) RuleTelemetry(ctx context.Context, id uint32, p string, from, to time.Time) (ingest.RuleTelemetry, error) {
	return f(ctx, id, p, from, to)
}

type fpReadFunc func(context.Context, uint32, string, time.Time, time.Time) (uint64, error)

func (f fpReadFunc) RuleFalsePositiveEvents(ctx context.Context, id uint32, p string, from, to time.Time) (uint64, error) {
	return f(ctx, id, p, from, to)
}

func TestHealthReportsObservationsAndMissingOrInconsistentData(t *testing.T) {
	for _, tc := range []struct {
		matches, fp uint64
		status      string
	}{{10, 2, "observing"}, {0, 0, "insufficient_telemetry"}, {1, 2, "inconsistent_snapshot"}} {
		var deadline time.Time
		events := eventReadFunc(func(ctx context.Context, _ uint32, _ string, _, _ time.Time) (ingest.RuleTelemetry, error) {
			var ok bool
			deadline, ok = ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second {
				t.Error("event read has no shared five-second deadline")
			}
			return ingest.RuleTelemetry{MatchedEvents: tc.matches, CostSamples: "0", CostTotalNS: "0"}, nil
		})
		annotations := fpReadFunc(func(ctx context.Context, _ uint32, _ string, _, _ time.Time) (uint64, error) {
			if d, ok := ctx.Deadline(); !ok || !d.Equal(deadline) {
				t.Error("annotation read gets a second independent timeout")
			}
			return tc.fp, nil
		})
		now := time.Now()
		h, err := NewService(events, annotations).Read(t.Context(), 942100, "example-api", now.Add(-time.Minute), now)
		if err != nil || h.Status != tc.status || h.ReportedFPEvents != tc.fp || h.MatchedEvents != tc.matches || h.CostMeanNS != nil {
			t.Fatalf("misleading health: %+v %v", h, err)
		}
		if (h.ReportedFPShare != nil) != (tc.status == "observing") {
			t.Fatalf("invented FP share: %+v", h)
		}
		if tc.status == "observing" && *h.ReportedFPShare != 0.2 {
			t.Fatalf("wrong reported share: %v", *h.ReportedFPShare)
		}
	}
}

func TestHealthPropagatesStoreFailureAndValidatesBeforeIO(t *testing.T) {
	want := errors.New("fixture database down")
	events := eventReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (ingest.RuleTelemetry, error) {
		return ingest.RuleTelemetry{}, want
	})
	annotations := fpReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (uint64, error) {
		t.Fatal("read annotations after event failure")
		return 0, nil
	})
	now := time.Now()
	svc := NewService(events, annotations)
	if _, err := svc.Read(t.Context(), 942100, "", now.Add(-time.Minute), now); !errors.Is(err, want) {
		t.Fatalf("store failure lost: %v", err)
	}
	for _, id := range []uint32{0, 942100} {
		if _, err := svc.Read(t.Context(), id, "", now, now.Add(25*time.Hour)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unbounded query allowed: %v", err)
		}
	}
	if _, err := svc.Read(t.Context(), 0, "", now.Add(-time.Minute), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prefilter allowed as a rule: %v", err)
	}
	okEvents := eventReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (ingest.RuleTelemetry, error) {
		return ingest.RuleTelemetry{}, nil
	})
	badAnnotations := fpReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (uint64, error) { return 0, want })
	if _, err := NewService(okEvents, badAnnotations).Read(t.Context(), 942100, "", now.Add(-time.Minute), now); !errors.Is(err, want) {
		t.Fatalf("annotation failure hidden: %v", err)
	}
	if _, err := NewService(nil, nil).Read(t.Context(), 942100, "", now.Add(-time.Minute), now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing stores hidden: %v", err)
	}
}

func TestHealthBoundsConcurrentQueriesAndCancelsIO(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, results := make(chan struct{}, 4), make(chan error, 4)
	events := eventReadFunc(func(ctx context.Context, _ uint32, _ string, _, _ time.Time) (ingest.RuleTelemetry, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return ingest.RuleTelemetry{}, ctx.Err()
	})
	annotations := fpReadFunc(func(context.Context, uint32, string, time.Time, time.Time) (uint64, error) { return 0, nil })
	svc, now := NewService(events, annotations), time.Now()
	for range 4 {
		go func() {
			_, err := svc.Read(ctx, 942100, "", now.Add(-time.Minute), now)
			results <- err
		}()
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("query did not enter store")
		}
	}
	if _, err := svc.Read(ctx, 942100, "", now.Add(-time.Minute), now); !errors.Is(err, ErrBusy) {
		t.Fatalf("fifth concurrent query allowed: %v", err)
	}
	cancel()
	for range 4 {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancellation lost: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("query did not release after cancellation")
		}
	}
}
