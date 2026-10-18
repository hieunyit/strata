package rulehealth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
)

type evaluationSource struct {
	matches, reports    uint64
	matchErr, reportErr error
	calls               atomic.Int32
	deadline            time.Time
	block               bool
	started             chan struct{}
}

func (e *evaluationSource) RuleTelemetry(context.Context, uint32, string, time.Time, time.Time) (ingest.RuleTelemetry, error) {
	return ingest.RuleTelemetry{}, nil
}
func (e *evaluationSource) RuleFalsePositiveEvents(context.Context, uint32, string, time.Time, time.Time) (uint64, error) {
	return 0, nil
}
func (e *evaluationSource) RuleMatchCount(ctx context.Context, rule uint32, name string, bundle uint64, from, to time.Time) (uint64, error) {
	e.calls.Add(1)
	if e.block {
		e.started <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if rule != 942100 || name != "example-api" || bundle != 7 || to.Sub(from) != 300*time.Second {
		return 0, errors.New("scope was lost")
	}
	e.deadline, _ = ctx.Deadline()
	if time.Until(e.deadline) > 5*time.Second {
		return 0, errors.New("unbounded query")
	}
	return e.matches, e.matchErr
}
func (e *evaluationSource) RuleFPReportCount(ctx context.Context, rule uint32, name string, bundle uint64, ef, et, rf, rt time.Time) (uint64, error) {
	e.calls.Add(1)
	deadline, _ := ctx.Deadline()
	if deadline != e.deadline || ef != rf || et != rt || rule != 942100 || name != "example-api" || bundle != 7 {
		return 0, errors.New("scope/deadline changed between stores")
	}
	return e.reports, e.reportErr
}
func delegationSpec() policy.Spec {
	return policy.Spec{Mode: "enforce", AutoStaging: &policy.AutoStaging{Enabled: true, RuleIDs: []uint32{942100}, WindowSeconds: 300, MinMatches: 100, MinReports: 5, FPThresholdBPS: 500}}
}

func TestDelegationThresholdEvaluation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		matches, reports uint64
		bps              uint32
		want             bool
	}{
		{"equal", 100, 5, 500, true}, {"too few matches", 99, 5, 500, false}, {"too few reports", 100, 4, 500, false},
		{"below", 1000, 49, 500, false}, {"threshold", 1000, 50, 500, true}, {"inconsistent", 100, 101, 500, false},
		{"empty", 0, 0, 500, false}, {"max equal", ^uint64(0), ^uint64(0), 10000, true},
		{"max below", ^uint64(0), ^uint64(0) - 1, 10000, false},
		{"large below 5 percent", ^uint64(0), 922337203685477580, 500, false},
		{"large above 5 percent", ^uint64(0), 922337203685477581, 500, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &evaluationSource{matches: tc.matches, reports: tc.reports}
			spec := delegationSpec()
			spec.AutoStaging.FPThresholdBPS = tc.bps
			out, err := NewService(source, source).Evaluate(t.Context(), spec, 942100, "example-api", 7, time.Now())
			if err != nil || out.ThresholdMet != tc.want || out.MatchedEvents != tc.matches || out.FPReports != tc.reports {
				t.Fatalf("evaluation=%+v %v", out, err)
			}
		})
	}
}
func TestDelegationDefaultDenyAndQueryErrors(t *testing.T) {
	now := time.Now()
	for _, edit := range []func(*policy.Spec){func(s *policy.Spec) { s.AutoStaging = nil }, func(s *policy.Spec) { s.AutoStaging.Enabled = false }, func(s *policy.Spec) { s.Mode = "shadow" }, func(s *policy.Spec) { s.AutoStaging.RuleIDs = []uint32{42} }} {
		source := &evaluationSource{}
		spec := delegationSpec()
		edit(&spec)
		out, err := NewService(source, source).Evaluate(t.Context(), spec, 942100, "example-api", 7, now)
		if err != nil || out.ThresholdMet || source.calls.Load() != 0 {
			t.Fatalf("nondelegated scope queried: %+v %v", out, err)
		}
	}
	for _, which := range []string{"matches", "reports"} {
		sentinel := errors.New("database unavailable")
		source := &evaluationSource{matches: 100, reports: 5}
		if which == "matches" {
			source.matchErr = sentinel
		} else {
			source.reportErr = sentinel
		}
		out, err := NewService(source, source).Evaluate(t.Context(), delegationSpec(), 942100, "example-api", 7, now)
		if !errors.Is(err, sentinel) || out.ThresholdMet {
			t.Fatalf("query error authorized: %+v %v", out, err)
		}
	}
	for _, tc := range []struct {
		rule   uint32
		name   string
		bundle uint64
		now    time.Time
	}{{0, "example-api", 7, now}, {942100, "", 7, now}, {942100, "Example", 7, now}, {942100, "example-api", 0, now}, {942100, "example-api", 7, time.Time{}}} {
		if _, err := NewService(nil, nil).Evaluate(t.Context(), delegationSpec(), tc.rule, tc.name, tc.bundle, tc.now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid scope: %v", err)
		}
	}
	if _, err := NewService(nil, nil).Evaluate(t.Context(), delegationSpec(), 942100, "example-api", 7, now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing stores: %v", err)
	}
	source := &evaluationSource{}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewService(source, source).Evaluate(cancelled, delegationSpec(), 942100, "example-api", 7, now); !errors.Is(err, context.Canceled) || source.calls.Load() != 0 {
		t.Fatalf("cancelled query: %v", err)
	}
}
func TestEvaluationSharesHealthCapacityAndCancels(t *testing.T) {
	source := &evaluationSource{block: true, started: make(chan struct{}, 4)}
	svc := NewService(source, source)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 4)
	for range 4 {
		go func() {
			_, err := svc.Evaluate(ctx, delegationSpec(), 942100, "example-api", 7, time.Now())
			done <- err
		}()
	}
	for range 4 {
		select {
		case <-source.started:
		case <-time.After(2 * time.Second):
			t.Fatal("evaluation did not start")
		}
	}
	if _, err := svc.Evaluate(ctx, delegationSpec(), 942100, "example-api", 7, time.Now()); !errors.Is(err, ErrBusy) {
		t.Fatalf("capacity exceeded: %v", err)
	}
	now := time.Now()
	if _, err := svc.Read(ctx, 942100, "example-api", now.Add(-time.Minute), now); !errors.Is(err, ErrBusy) {
		t.Fatalf("health bypassed shared limit: %v", err)
	}
	cancel()
	for range 4 {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("query goroutine leaked")
		}
	}
}
