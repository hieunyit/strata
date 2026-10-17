package policy_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/fleet"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/rulehealth"
	"github.com/strata/strata/control-plane/store"
)

type workerTelemetry struct {
	firstMatches uint64
	calls        atomic.Int32
}

func (*workerTelemetry) RuleTelemetry(context.Context, uint32, string, time.Time, time.Time) (ingest.RuleTelemetry, error) {
	return ingest.RuleTelemetry{}, nil
}
func (s *workerTelemetry) RuleMatchCount(_ context.Context, rule uint32, name string, bundle uint64, from, to time.Time) (uint64, error) {
	s.calls.Add(1)
	if name != "example-api" || bundle != 1 || to.Sub(from) != 5*time.Minute {
		return 0, errors.New("worker lost scope")
	}
	if rule == 700011 {
		return s.firstMatches, nil
	}
	if rule == 700012 {
		return 100, nil
	}
	return 0, errors.New("unexpected rule")
}
func reportWorkerFPs(t *testing.T, f *writerFixture, rule uint32) {
	t.Helper()
	for i := 0; i < 5; i++ {
		block := fmt.Sprintf("example-%d-%d", rule, i)
		if _, err := f.store.MarkEventFalsePositive(t.Context(), block, "normal", "", store.Audit{Actor: "operator", Subject: "operator", RuleContext: &store.EventRuleContext{PolicyID: "example-api", EventTime: time.Now().Add(-time.Second), BundleVersion: 1, RuleIDs: []uint32{rule}}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStagingWorkerDurableFPToSignedRolloutAndRestart(t *testing.T) {
	f := newStagingWriter(t, true)
	reportWorkerFPs(t, f, 700011)
	telemetry := &workerTelemetry{firstMatches: 100}
	service := rulehealth.NewService(telemetry, f.store)
	f.writer.Now = time.Now
	f.writer.Observe = service.Observe
	presence := fleet.NewPresence()
	_, messages, detach := presence.AttachControl(t.Context(), "example-node")
	defer detach()
	rollouts := fleet.NewRollouts(f.store, presence, []float64{1}, 0)
	worker := &rulehealth.StagingWorker{Store: f.store, Writer: f.writer, Evaluate: service.Evaluate, Publish: rollouts.StartStaging}
	started := time.Now()
	runCtx, stop := context.WithCancel(t.Context())
	defer stop()
	runDone := make(chan struct{})
	go func() { worker.Run(runCtx); close(runDone) }()
	select {
	case message := <-messages:
		if message.GetBundleAvailable().GetVersion() != 2 {
			t.Fatal(message)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("automatic worker did not notify Fleet")
	}
	notifiedAfter := time.Since(started)
	stop()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after publication")
	}
	action, err := f.store.LatestStagingAction(t.Context())
	if err != nil || action.BundleVersion != 2 || action.RolloutID == nil {
		t.Fatalf("FP did not record/publish: %+v %v", action, err)
	}
	// No runtime claim: the node still reports ACTIVE v1 until an ACK arrives.
	ready, err := f.store.StagingSourceReady(t.Context(), 2)
	if err != nil || ready {
		t.Fatalf("record/notice confused with activation: %v %v", ready, err)
	}
	// Another worker, after a crash, recovers the linked rollout and notices.
	restarted := &rulehealth.StagingWorker{Store: store.New(f.pool), Writer: f.writer, Evaluate: service.Evaluate, Publish: rollouts.StartStaging}
	if err = restarted.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	again, err := f.store.LatestStagingAction(t.Context())
	if err != nil || again.ID != action.ID || *again.RolloutID != *action.RolloutID {
		t.Fatalf("restart duplicated action: %+v %v", again, err)
	}
	if err = f.store.ReportBundleStatus(t.Context(), "example-node", 2, "ACTIVE", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AdvanceRollout(t.Context(), *action.RolloutID); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	latest, err := f.store.LatestBundle(t.Context())
	if err != nil || latest.Version != 2 {
		t.Fatalf("restart reset/restaged: %+v %v", latest, err)
	}
	t.Logf("FP candidate to recorded signed bundle and Fleet notice: %s (ACK above is simulated, not a real agent)", notifiedAfter)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() { restarted.Run(canceled); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop on cancellation")
	}
}

func TestStagingWorkerSkipsDisabledAndLowShareWithoutStarvingNextRule(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			f := newStagingWriter(t, enabled)
			reportWorkerFPs(t, f, 700011)
			reportWorkerFPs(t, f, 700012)
			telemetry := &workerTelemetry{firstMatches: 101}
			service := rulehealth.NewService(telemetry, f.store)
			f.writer.Now = time.Now
			f.writer.Observe = service.Observe
			rollouts := fleet.NewRollouts(f.store, fleet.NewPresence(), []float64{1}, 0)
			worker := &rulehealth.StagingWorker{Store: f.store, Writer: f.writer, Evaluate: service.Evaluate, Publish: rollouts.StartStaging}
			if err := worker.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			latest, err := f.store.LatestBundle(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !enabled {
				if latest.Version != 1 || telemetry.calls.Load() != 0 {
					t.Fatal("disabled policy evaluated/deployed")
				}
				return
			}
			action, err := f.store.LatestStagingAction(t.Context())
			if err != nil || action.RuleID != 700012 || latest.Version != 2 {
				t.Fatalf("low-share first rule starved eligible next: %+v %v", action, err)
			}
		})
	}
}
