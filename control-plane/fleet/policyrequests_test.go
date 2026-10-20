package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/control-plane/ingest"
)

type failingSink struct{ err error }

func (f failingSink) SavePolicyRequests(context.Context, []ingest.PolicyRequests) error { return f.err }
func (f failingSink) SaveEngineTime(context.Context, []ingest.EngineTime) error         { return f.err }

func hb(started uint64, ps ...*eventv1.PolicyCount) *fleetv1.NodeCounters {
	return &fleetv1.NodeCounters{AgentStartedMs: started, Policies: ps}
}

// RV-N-01: heartbeats carry sums since the agent started; the recorder
// writes the differences, per node and policy.
func TestPolicyRequestsRecorderWritesDifferences(t *testing.T) {
	store := ingest.NewMockEventStore()
	r := NewPolicyRequestsRecorder(store)
	at := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	api := func(n, partial uint64) *eventv1.PolicyCount {
		return &eventv1.PolicyCount{Policy: "example-api", Requests: n, Partial: partial}
	}
	r.Observe("node-1", hb(1, api(100, 2)), at) // starting point only
	r.Observe("node-1", hb(1, api(160, 5), &eventv1.PolicyCount{Policy: "", Requests: 3}), at.Add(15*time.Second))
	r.Observe("node-1", hb(1, api(160, 5)), at.Add(30*time.Second)) // nothing new
	r.Observe("node-1", hb(1, api(150, 5)), at.Add(45*time.Second)) // went down without a restart
	r.Observe("node-1", hb(2, api(40, 1)), at.Add(60*time.Second))  // agent restarted: all new
	r.Observe("node-2", &fleetv1.NodeCounters{Requests: 9}, at)     // an older agent: nothing
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.PolicyRequestRows()
	want := []ingest.PolicyRequests{
		{Time: at.Add(15 * time.Second), NodeID: "node-1", PolicyID: "example-api", Requests: 60, Partial: 3},
		{Time: at.Add(15 * time.Second), NodeID: "node-1", PolicyID: "", Requests: 3},
		{Time: at.Add(60 * time.Second), NodeID: "node-1", PolicyID: "example-api", Requests: 40, Partial: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("rows %+v", got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Errorf("missing %+v in %+v", w, got)
		}
	}
	if err := r.Flush(context.Background()); err != nil || len(store.PolicyRequestRows()) != 3 {
		t.Fatalf("second flush wrote again: %v", err)
	}
}

// A failing store keeps the rows for the next flush, within a bound.
func TestPolicyRequestsRecorderKeepsRowsOnError(t *testing.T) {
	r := NewPolicyRequestsRecorder(failingSink{errors.New("down")})
	at := time.Now()
	r.Observe("n", hb(1, &eventv1.PolicyCount{Policy: "p", Requests: 1}), at)
	r.Observe("n", hb(1, &eventv1.PolicyCount{Policy: "p", Requests: 5}), at)
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("no error")
	}
	store := ingest.NewMockEventStore()
	r.Sink = store
	if err := r.Flush(context.Background()); err != nil || len(store.PolicyRequestRows()) != 1 {
		t.Fatalf("%v %+v", err, store.PolicyRequestRows())
	}
	r.Sink = failingSink{errors.New("down")}
	for i := uint64(0); i < MaxPendingPolicyRows+10; i++ {
		r.Observe("n", hb(1, &eventv1.PolicyCount{Policy: "p", Requests: 10 + i}), at)
	}
	r.mu.Lock()
	n, d := len(r.pending), r.dropped
	r.mu.Unlock()
	if n != MaxPendingPolicyRows || d != 10 {
		t.Fatalf("pending %d dropped %d", n, d)
	}
}

// W20-F-01: heartbeats carry engine time sums since NGINX made its metrics
// file; the recorder writes the increase per node and interval.
func TestEngineTimeRecorder(t *testing.T) {
	store := ingest.NewMockEventStore()
	r := NewPolicyRequestsRecorder(store)
	at := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	eh := func(created uint64, ns uint64, b ...uint64) *fleetv1.NodeCounters {
		return &fleetv1.NodeCounters{MetricsCreatedMs: created, EngineTime: b, EngineNs: ns}
	}
	r.Observe("node-1", eh(1, 1000, 10, 5, 0, 0, 0, 0, 0, 0, 0), at) // starting point only
	r.Observe("node-1", eh(1, 1600, 14, 6, 0, 0, 0, 0, 0, 0, 1), at.Add(15*time.Second))
	r.Observe("node-1", eh(1, 1600, 14, 6, 0, 0, 0, 0, 0, 0, 1), at.Add(30*time.Second)) // nothing new
	r.Observe("node-1", eh(1, 100, 1, 0, 0, 0, 0, 0, 0, 0, 0), at.Add(45*time.Second))   // went down: skipped
	r.Observe("node-1", eh(2, 300, 3, 0, 0, 0, 0, 0, 0, 0, 0), at.Add(60*time.Second))   // NGINX reloaded: all new
	r.Observe("node-2", &fleetv1.NodeCounters{Requests: 9}, at)                          // an older agent
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.EngineTimeRows()
	if len(got) != 2 || got[0].Nanos != 600 || got[0].Buckets[0] != 4 || got[0].Buckets[8] != 1 ||
		!got[1].Time.Equal(at.Add(60*time.Second)) || got[1].Nanos != 300 || got[1].Buckets[0] != 3 {
		t.Fatalf("rows %+v", got)
	}
	r.Forget("node-1")
	r.Observe("node-1", eh(2, 400, 4, 0, 0, 0, 0, 0, 0, 0, 0), at.Add(75*time.Second)) // starting point again
	if err := r.Flush(context.Background()); err != nil || len(store.EngineTimeRows()) != 2 {
		t.Fatalf("after forget: %v %d", err, len(store.EngineTimeRows()))
	}
}
